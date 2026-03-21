from __future__ import annotations

import threading
import traceback
import ipaddress
import os
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from typing import Any, Dict, Optional
from uuid import uuid4

from scanner import ScannerConfig, run_scan

from .models import ScanState, ScanStatus
from .scans_store import ScansStore, _utc_now_iso


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


class ScanManager:
    def __init__(self, store: ScansStore, max_workers: int = 1):
        self.store = store
        self.executor = ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="scan")
        self._lock = threading.Lock()
        self.max_scan_hosts = int(os.environ.get("MAX_SCAN_HOSTS", "1024"))
        self._cancel_events: Dict[str, threading.Event] = {}
        self._cancel_lock = threading.Lock()

    def start_scan(self, subnet: str, *, skip_ping_sweep: bool = False) -> str:
        # Prevent accidentally starting a massive scan from the UI.
        net = ipaddress.IPv4Network(subnet, strict=False)
        prefixlen = net.prefixlen
        if prefixlen <= 30:
            hosts_count = net.num_addresses - 2
        elif prefixlen == 31:
            hosts_count = 2
        else:  # /32
            hosts_count = 1
        if hosts_count > self.max_scan_hosts:
            raise ValueError(f"Refusing to scan {hosts_count} hosts (max {self.max_scan_hosts}).")

        scan_id = str(uuid4())
        cancel_event = threading.Event()
        with self._cancel_lock:
            self._cancel_events[scan_id] = cancel_event
        # Create initial queued state on disk immediately.
        self.store.init_scan(scan_id=scan_id, state="queued")
        self.executor.submit(self._run_scan_job, scan_id, subnet, cancel_event, skip_ping_sweep)
        return scan_id

    def cancel_scan(self, scan_id: str) -> bool:
        with self._cancel_lock:
            cancel_event = self._cancel_events.get(scan_id)
        if not cancel_event:
            return False

        cancel_event.set()
        # UI should clearly show cancellation request immediately.
        self._update_progress(scan_id, message="Cancellation requested…", current_ip=None)
        return True

    def _update_progress(
        self,
        scan_id: str,
        state: Optional[ScanState] = None,
        *,
        message: Optional[str] = None,
        hosts_found: Optional[int] = None,
        devices_scanned: Optional[int] = None,
        total_devices: Optional[int] = None,
        current_ip: Optional[str] = None,
        error: Optional[str] = None,
    ) -> None:
        with self._lock:
            status = self.store.get_status(scan_id)
            if not status:
                return

            changed = False
            if state and status.state != state:
                status.state = state
                changed = True

            if message is not None:
                status.progress.message = message
                changed = True
            if hosts_found is not None:
                status.progress.hosts_found = hosts_found
                changed = True
            if devices_scanned is not None:
                status.progress.devices_scanned = devices_scanned
                changed = True
            if total_devices is not None:
                status.progress.total_devices = total_devices
                changed = True
            if current_ip is not None:
                status.progress.current_ip = current_ip
                changed = True
            if error is not None:
                status.error = error
                changed = True

            if changed:
                # `write_status` will bump updated_at.
                self.store.write_status(status)

    def _run_scan_job(
        self,
        scan_id: str,
        subnet: str,
        cancel_event: threading.Event,
        skip_ping_sweep: bool,
    ) -> None:
        def on_event(event: Dict[str, Any]) -> None:
            if cancel_event.is_set():
                return
            etype = event.get("type")

            if etype == "scan_started":
                self._update_progress(scan_id, state="running", message="Discovering live hosts...")
            elif etype == "host_up":
                # Keep message generic to avoid too many writes.
                pass
            elif etype == "hosts_found":
                hosts_found = event.get("hosts_found")
                self._update_progress(
                    scan_id,
                    state="running",
                    message="Scanning discovered hosts...",
                    hosts_found=hosts_found,
                    devices_scanned=0,
                    total_devices=hosts_found,
                )
            elif etype == "host_scanning":
                self._update_progress(
                    scan_id,
                    message="Scanning host...",
                    current_ip=event.get("ip"),
                    devices_scanned=event.get("index", 0) - 1,
                )
            elif etype == "device_scanned":
                device = event.get("device") or {}
                self._update_progress(
                    scan_id,
                    message="Scanning host...",
                    current_ip=event.get("ip"),
                    devices_scanned=event.get("index"),
                )

        try:
            cfg = ScannerConfig(subnet=subnet, discover_via_ping=not skip_ping_sweep)

            # Pre-set an updated message so the UI doesn't show stale "queued".
            self._update_progress(scan_id, state="running", message="Starting...")

            result = run_scan(subnet=subnet, config=cfg, on_event=on_event, cancel_event=cancel_event)
            inventory = result.inventory

            self.store.write_inventory(scan_id, inventory)
            if result.cancelled:
                self._update_progress(
                    scan_id,
                    state="cancelled",
                    message="Scan cancelled.",
                    devices_scanned=len(inventory.get("devices", [])),
                    hosts_found=inventory.get("scan_metadata", {}).get("hosts_found"),
                    total_devices=inventory.get("scan_metadata", {}).get("hosts_found"),
                    current_ip=None,
                )
            else:
                self._update_progress(
                    scan_id,
                    state="completed",
                    message="Scan complete.",
                    devices_scanned=len(inventory.get("devices", [])),
                    hosts_found=inventory.get("scan_metadata", {}).get("hosts_found"),
                    total_devices=inventory.get("scan_metadata", {}).get("hosts_found"),
                    current_ip=None,
                )
        except Exception as e:
            err = "".join(traceback.format_exception(type(e), e, e.__traceback__))
            self.store.set_error(scan_id=scan_id, error=err)
        finally:
            with self._cancel_lock:
                self._cancel_events.pop(scan_id, None)

