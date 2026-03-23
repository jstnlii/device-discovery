from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Any, Dict, List

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware

def _find_project_root() -> Path:
    """Find repo root (directory containing scanner.py) for sys.path."""
    p = Path(__file__).resolve()
    for _ in range(8):
        p = p.parent
        if (p / "scanner.py").exists():
            return p
    return Path(__file__).resolve().parents[3]


REPO_ROOT = _find_project_root()
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from .models import GetScanResponse, ScanSummary, StartScanRequest, StartScanResponse
from .scans_store import ScansStore
from .scan_manager import ScanManager
from networking import get_default_gateway, get_default_local_subnet, get_local_ipv4_interfaces


def _default_scans_dir() -> Path:
    # .../web/backend/app/main.py -> .../web/backend
    backend_dir = Path(__file__).resolve().parents[1]
    return backend_dir / "data" / "scans"


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
            scan_id = scan_manager.start_scan(subnet=req.subnet, skip_ping_sweep=req.skip_ping_sweep)
            return StartScanResponse(scan_id=scan_id)
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e))

    @app.get("/api/scans", response_model=List[ScanSummary])
    def list_scans() -> List[ScanSummary]:
        summaries = store.list_scan_summaries(limit=50)
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
        status = store.get_status(scan_id)
        if not status:
            raise HTTPException(status_code=404, detail="Scan not found")

        inventory_payload = store.get_inventory(scan_id)
        inventory = None
        default_gateway = get_default_gateway()
        if inventory_payload and status.state in ("completed", "cancelled"):
            # Keep shape consistent with CLI output JSON.
            inventory = {
                "scan_metadata": inventory_payload.get("scan_metadata", {}),
                "devices": inventory_payload.get("devices", []),
                "default_gateway": default_gateway,
            }

        return GetScanResponse(scan=status, inventory=inventory)

    @app.get("/api/network/local")
    def get_local_network() -> Dict[str, Any]:
        detected = get_default_local_subnet()
        interfaces = get_local_ipv4_interfaces()
        gateway = get_default_gateway()
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
            "default_gateway": gateway,
        }

    @app.delete("/api/scans")
    def clear_scan_history() -> Dict[str, Any]:
        deleted = store.clear_history(exclude_states=("queued", "running"))
        return {"deleted": deleted}

    @app.post("/api/scans/{scan_id}/cancel")
    def cancel_scan(scan_id: str) -> Dict[str, Any]:
        ok = scan_manager.cancel_scan(scan_id)
        if not ok:
            raise HTTPException(status_code=404, detail="Scan not found or cannot be cancelled")
        return {"cancelled": True}

    return app


app = create_app()

