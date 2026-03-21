from __future__ import annotations

import argparse
import json
from datetime import datetime
from pathlib import Path
from typing import Any, Dict

import textwrap

from networking import get_default_local_subnet, normalize_subnet_input
from scanner import ScannerConfig, run_scan_to_file

# ─────────────────────────────────────────
# DEFAULTS (can be overridden via CLI)
# ─────────────────────────────────────────
PORT_SCAN_TIMEOUT = 0.5  # seconds per port
PING_TIMEOUT = 1  # seconds per ping
MAX_THREADS = 50  # concurrent threads


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


# Terminal width for wrapping long port/service lines
_TERM_WIDTH = 76


def _print_port_line(port: int | str, service: str, *, prefix: str = "", indent: str = "") -> None:
    """Print a port line, wrapping long service names with proper indent."""
    first_part = f"{prefix}{port}: "
    line = f"{first_part}{service}"
    if len(line) <= _TERM_WIDTH:
        print(line)
        return
    width = min(_TERM_WIDTH - len(first_part), _TERM_WIDTH - len(indent))
    wrapped = textwrap.wrap(service, width=max(20, width))
    print(f"{first_part}{wrapped[0]}")
    for rest in wrapped[1:]:
        print(f"{indent}{rest}")


def main() -> None:
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
            if open_ports:
                print("    Open ports:")
                for port, service in open_ports.items():
                    _print_port_line(port, service, prefix="      → ", indent="          ")
            else:
                print("    Open ports:   none found")

    start_time = datetime.now()
    run_scan_to_file(
        subnet=subnet,
        output_filename=str(output_path),
        config=cfg,
        on_event=on_event,
    )

    # Print summary (re-open inventory we just wrote)
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
                _print_port_line(port, service, prefix="    → Port ", indent="         ")
        else:
            print(f"    → No common ports open")

    print(f"\n[✓] Inventory saved to {output_filename}")
    print(f"[✓] Scan complete in {(datetime.now() - start_time).seconds} seconds")


if __name__ == "__main__":
    main()
