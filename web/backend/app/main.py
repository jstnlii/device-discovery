from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Any, Dict, List

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware

# Ensure `/Users/.../2026` is importable so `device_discover.scanner` works.
REPO_ROOT = Path(__file__).resolve().parents[4]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from .models import GetScanResponse, ScanSummary, StartScanRequest, StartScanResponse
from .scans_store import ScansStore
from .scan_manager import ScanManager


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
            scan_id = scan_manager.start_scan(subnet=req.subnet)
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
        if inventory_payload and status.state in ("completed", "cancelled"):
            # Keep shape consistent with the original `devicefinder.py` JSON.
            inventory = {
                "scan_metadata": inventory_payload.get("scan_metadata", {}),
                "devices": inventory_payload.get("devices", []),
            }

        return GetScanResponse(scan=status, inventory=inventory)

    @app.post("/api/scans/{scan_id}/cancel")
    def cancel_scan(scan_id: str) -> Dict[str, Any]:
        ok = scan_manager.cancel_scan(scan_id)
        if not ok:
            raise HTTPException(status_code=404, detail="Scan not found or cannot be cancelled")
        return {"cancelled": True}

    return app


app = create_app()

