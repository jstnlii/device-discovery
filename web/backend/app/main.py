from __future__ import annotations

import os
import sys
import json
from pathlib import Path
from typing import Any, Dict, List
from datetime import datetime, timezone

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware

# Ensure `/Users/.../2026` is importable so `device_discover.scanner` works.
REPO_ROOT = Path(__file__).resolve().parents[4]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from .models import GetScanResponse, ScanSummary, StartScanRequest, StartScanResponse
from .scans_store import ScansStore
from .scan_manager import ScanManager
from device_discover.networking import get_default_local_subnet, get_local_ipv4_interfaces


def _default_scans_dir() -> Path:
    # .../web/backend/app/main.py -> .../web/backend
    backend_dir = Path(__file__).resolve().parents[1]
    return backend_dir / "data" / "scans"


def _debug_log(run_id: str, hypothesis_id: str, location: str, message: str, data: Dict[str, Any] | None = None) -> None:
    # region agent log
    try:
        payload = {
            "sessionId": "8721f5",
            "runId": run_id,
            "hypothesisId": hypothesis_id,
            "location": location,
            "message": message,
            "data": data or {},
            "timestamp": int(datetime.now(timezone.utc).timestamp() * 1000),
        }
        with open("/Users/justinli/Documents/Code/2026/.cursor/debug-8721f5.log", "a") as f:
            f.write(json.dumps(payload) + "\n")
    except Exception:
        pass
    # endregion


def create_app() -> FastAPI:
    app = FastAPI(title="Device Discovery Scanner", version="0.1.0")

    scans_dir = Path(os.environ.get("SCANS_DIR", str(_default_scans_dir())))
    store = ScansStore(scans_dir)
    scan_manager = ScanManager(store=store, max_workers=1)

    allowed_origins_env = os.environ.get("ALLOWED_ORIGINS", "")
    if allowed_origins_env.strip():
        allowed_origins: List[str] = [o.strip() for o in allowed_origins_env.split(",") if o.strip()]
    else:
        allowed_origins = ["*"]  # local dev

    app.add_middleware(
        CORSMiddleware,
        allow_origins=allowed_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    @app.post("/api/scans", response_model=StartScanResponse)
    def start_scan(req: StartScanRequest) -> StartScanResponse:
        try:
            _debug_log("baseline", "H2", "main.py:start_scan", "request_received", {"subnet": req.subnet, "skip_ping_sweep": req.skip_ping_sweep})
            scan_id = scan_manager.start_scan(subnet=req.subnet, skip_ping_sweep=req.skip_ping_sweep)
            _debug_log("baseline", "H2", "main.py:start_scan", "scan_started", {"scan_id": scan_id})
            return StartScanResponse(scan_id=scan_id)
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e))

    @app.get("/api/scans", response_model=List[ScanSummary])
    def list_scans() -> List[ScanSummary]:
        _debug_log("baseline", "H1", "main.py:list_scans", "request_received", {})
        summaries = store.list_scan_summaries(limit=50)
        _debug_log("baseline", "H1", "main.py:list_scans", "request_completed", {"count": len(summaries)})
        return [
            ScanSummary(
                scan_id=s["scan_id"],
                state=s["state"],
                scan_time=s.get("scan_time"),
                hosts_found=s.get("hosts_found"),
                updated_at=s["updated_at"],
            )
            for s in summaries
        ]

    @app.get("/api/scans/{scan_id}", response_model=GetScanResponse)
    def get_scan(scan_id: str) -> GetScanResponse:
        _debug_log("baseline", "H3", "main.py:get_scan", "request_received", {"scan_id": scan_id})
        status = store.get_status(scan_id)
        if not status:
            raise HTTPException(status_code=404, detail="Scan not found")

        inventory_payload = store.get_inventory(scan_id)
        inventory = None
        if inventory_payload and status.state in ("completed", "cancelled"):
            # Keep shape consistent with the original `devicefinder.py` JSON.
            inventory = {
                "scan_metadata": inventory_payload.get("scan_metadata", {}),
                "devices": inventory_payload.get("devices", []),
            }

        return GetScanResponse(scan=status, inventory=inventory)

    @app.get("/api/network/local")
    def get_local_network() -> Dict[str, Any]:
        detected = get_default_local_subnet()
        interfaces = get_local_ipv4_interfaces()
        return {
            "detected": None
            if not detected
            else {
                "interface": detected.interface,
                "ip": detected.ip,
                "netmask": detected.netmask,
                "cidr": detected.cidr,
            },
            "interfaces": [
                {
                    "interface": i.interface,
                    "ip": i.ip,
                    "netmask": i.netmask,
                    "cidr": i.cidr,
                }
                for i in interfaces
            ],
        }

    @app.delete("/api/scans")
    def clear_scan_history() -> Dict[str, Any]:
        deleted = store.clear_history(exclude_states=("queued", "running"))
        return {"deleted": deleted}

    @app.post("/api/scans/{scan_id}/cancel")
    def cancel_scan(scan_id: str) -> Dict[str, Any]:
        _debug_log("baseline", "H4", "main.py:cancel_scan", "request_received", {"scan_id": scan_id})
        ok = scan_manager.cancel_scan(scan_id)
        if not ok:
            raise HTTPException(status_code=404, detail="Scan not found or cannot be cancelled")
        return {"cancelled": True}

    return app


app = create_app()

