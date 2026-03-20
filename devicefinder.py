from __future__ import annotations

import argparse
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Dict

# ─────────────────────────────────────────
# DEFAULTS (can be overridden via CLI)
# ─────────────────────────────────────────
PORT_SCAN_TIMEOUT = 0.5  # seconds per port
PING_TIMEOUT = 1  # seconds per ping
MAX_THREADS = 50  # concurrent threads


def _ensure_import_path() -> None:
    """
    When running `python devicefinder.py` from within the `device_discover/` folder,
    Python's sys.path points at that folder and the `device_discover` package import
    can fail. This adds the parent directory so the package is importable.
    """
    repo_root = Path(__file__).resolve().parent.parent
    repo_root_str = str(repo_root)
    if repo_root_str not in sys.path:
        sys.path.insert(0, repo_root_str)


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Network Asset Discovery Tool")
    p.add_argument(
        "--subnet",
        default="",
        help="Subnet input: accepts CIDR (e.g. 172.22.172.0/24) or IP (e.g. 172.22.172.92). If omitted, tries to auto-detect.",
    )
    p.add_argument("--output-dir", default="", help="Where to write inventory JSON (default: this folder).")
    p.add_argument("--port-scan-timeout", type=float, default=PORT_SCAN_TIMEOUT, help="Seconds per port connect attempt.")
    p.add_argument("--ping-timeout", type=int, default=PING_TIMEOUT, help="Seconds per ping request.")
    p.add_argument("--max-threads", type=int, default=MAX_THREADS, help="Concurrent threads for scanning.")
    p.add_argument(
        "--skip-ping-sweep",
        action="store_true",
        help="Do not use ICMP ping sweep for host discovery. Scan the whole CIDR instead (useful when ICMP is blocked).",
    )
    p.add_argument(
        "--dry-run",
        action="store_true",
        help="Validate/normalize subnet input and exit without scanning.",
    )
    return p


def main() -> None:
    _ensure_import_path()

    # Import after sys.path fix so `python devicefinder.py` works when run from
    # inside the `device_discover/` folder.
    from device_discover.scanner import ScannerConfig, run_scan_to_file
    from device_discover.networking import get_default_local_subnet, normalize_subnet_input

    parser = _build_parser()
    args = parser.parse_args()

    detected = get_default_local_subnet()
    default_subnet = detected.cidr if detected else "10.0.0.0/24"

    raw_subnet = (args.subnet or "").strip()
    subnet_input = raw_subnet if raw_subnet else default_subnet

    try:
        subnet = normalize_subnet_input(subnet_input)
    except ValueError as e:
        print(f"[!] Invalid subnet input: {e}")
        print("    Examples:")
        print("      - CIDR: 172.22.172.0/24")
        print("      - IP:    172.22.172.92")
        raise SystemExit(2)

    print("=" * 50)
    print("  Network Asset Discovery Tool")
    print("=" * 50)
    print(f"Subnet resolved to: {subnet}")

    if args.dry_run:
        raise SystemExit(0)

    cfg = ScannerConfig(
        subnet=subnet,
        port_scan_timeout=args.port_scan_timeout,
        ping_timeout=args.ping_timeout,
        max_threads=args.max_threads,
        discover_via_ping=not args.skip_ping_sweep,
    )

    output_filename = f"inventory_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    output_dir = Path(args.output_dir) if args.output_dir else Path(__file__).resolve().parent
    output_path = output_dir / output_filename

    def on_event(event: Dict[str, Any]) -> None:
        etype = event.get("type")
        if etype == "scan_started":
            subnet = event.get("subnet")
            print(f"\n[*] Scanning subnet {subnet} for live hosts...")
        elif etype == "host_up":
            print(f"    [+] Host up: {event.get('ip')}")
        elif etype == "hosts_found":
            print(f"\n[*] Found {event.get('hosts_found')} live host(s)")
        elif etype == "host_scanning":
            ip = event.get("ip")
            idx = event.get("index")
            total = event.get("total")
            print(f"\n[*] Scanning {ip} ({idx}/{total})...")
        elif etype == "device_scanned":
            device = event.get("device") or {}
            hostname = device.get("hostname", "unknown")
            mac = device.get("mac", "unknown")
            manufacturer = device.get("manufacturer", "unknown")
            open_ports = device.get("open_ports", {})

            print(f"    Hostname:     {hostname}")
            print(f"    MAC:          {mac} ({manufacturer})")
            print(f"    Open ports:   {open_ports if open_ports else 'none found'}")

    start_time = datetime.now()
    run_scan_to_file(
        subnet=subnet,
        output_filename=str(output_path),
        config=cfg,
        on_event=on_event,
    )

    # Step 4 — print summary (re-open inventory we just wrote)
    import json

    with open(output_path, "r") as f:
        inventory = json.load(f)

    print("\n" + "=" * 50)
    print("  INVENTORY SUMMARY")
    print("=" * 50)
    for device in inventory.get("devices", []):
        print(f"\n  {device['ip']} ({device['hostname']})")
        print(f"  MAC: {device['mac']} — {device['manufacturer']}")
        if device["open_ports"]:
            for port, service in device["open_ports"].items():
                print(f"    → Port {port}: {service}")
        else:
            print(f"    → No common ports open")

    print(f"\n[✓] Inventory saved to {output_filename}")
    print(f"[✓] Scan complete in {(datetime.now() - start_time).seconds} seconds")


if __name__ == "__main__":
    main()