from __future__ import annotations

import json
import shutil
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from .models import ScanState, ScanStatus


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class ScansStore:
    def __init__(self, root_dir: Path):
        self.root_dir = root_dir
        self.root_dir.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()  # RLock: list_scan_summaries holds lock and calls get_status which also needs it

    def scan_dir(self, scan_id: str) -> Path:
        return self.root_dir / scan_id

    def status_path(self, scan_id: str) -> Path:
        return self.scan_dir(scan_id) / "status.json"

    def inventory_path(self, scan_id: str) -> Path:
        return self.scan_dir(scan_id) / "inventory.json"

    def init_scan(self, scan_id: str, state: ScanState) -> ScanStatus:
        with self._lock:
            d = self.scan_dir(scan_id)
            d.mkdir(parents=True, exist_ok=True)

            now = _utc_now_iso()
            status = ScanStatus(
                scan_id=scan_id,
                state=state,
                created_at=now,
                updated_at=now,
            )
            self.write_status(status)
            return status

    def write_status(self, status: ScanStatus) -> None:
        with self._lock:
            self.scan_dir(status.scan_id).mkdir(parents=True, exist_ok=True)
            payload = status.model_dump()
            payload["updated_at"] = _utc_now_iso()
            with open(self.status_path(status.scan_id), "w") as f:
                json.dump(payload, f, indent=2)

    def set_error(self, scan_id: str, error: str) -> None:
        with self._lock:
            path = self.status_path(scan_id)
            if not path.exists():
                return
            with open(path, "r") as f:
                status_payload = json.load(f)
            status_payload["state"] = "failed"
            status_payload["error"] = error
            status_payload["updated_at"] = _utc_now_iso()
            with open(path, "w") as f:
                json.dump(status_payload, f, indent=2)

    def write_inventory(self, scan_id: str, inventory: Dict[str, Any]) -> None:
        with self._lock:
            self.scan_dir(scan_id).mkdir(parents=True, exist_ok=True)
            with open(self.inventory_path(scan_id), "w") as f:
                json.dump(inventory, f, indent=2)

    def get_status(self, scan_id: str) -> Optional[ScanStatus]:
        path = self.status_path(scan_id)
        if not path.exists():
            return None
        with self._lock:
            with open(path, "r") as f:
                payload = json.load(f)
            return ScanStatus.model_validate(payload)

    def get_inventory(self, scan_id: str) -> Optional[Dict[str, Any]]:
        path = self.inventory_path(scan_id)
        if not path.exists():
            return None
        with self._lock:
            with open(path, "r") as f:
                return json.load(f)

    def list_scan_summaries(self, limit: int = 50) -> List[Dict[str, Any]]:
        with self._lock:
            if not self.root_dir.exists():
                return []

            items: List[Dict[str, Any]] = []
            for d in self.root_dir.iterdir():
                if not d.is_dir():
                    continue
                status = self.get_status(d.name)
                if not status:
                    continue
                payload = {
                    "scan_id": status.scan_id,
                    "state": status.state,
                    "scan_time": None,
                    "hosts_found": status.progress.hosts_found,
                    "updated_at": status.updated_at,
                }
                inv = self.get_inventory(d.name)
                if inv and inv.get("scan_metadata"):
                    payload["scan_time"] = inv["scan_metadata"].get("scan_time")
                    payload["hosts_found"] = inv["scan_metadata"].get("hosts_found")
                items.append(payload)

            items.sort(key=lambda x: x.get("updated_at") or "", reverse=True)
            return items[:limit]

    def delete_scan(self, scan_id: str) -> bool:
        """Remove a scan directory. Returns True if deleted, False if not found."""
        with self._lock:
            path = self.scan_dir(scan_id)
            if path.exists() and path.is_dir():
                shutil.rmtree(path)
                return True
            return False

    def clear_history(
        self,
        *,
        exclude_states: Optional[tuple[str, ...]] = ("queued", "running"),
    ) -> int:
        """Delete scans that are not in exclude_states. Returns number deleted."""
        with self._lock:
            if not self.root_dir.exists():
                return 0
            excluded = exclude_states or ()
            deleted = 0
            for d in list(self.root_dir.iterdir()):
                if not d.is_dir():
                    continue
                status = self.get_status(d.name)
                if not status:
                    continue
                if status.state in excluded:
                    continue
                shutil.rmtree(d)
                deleted += 1
            return deleted

