from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any, Dict

from device_discover.scanner import ScannerConfig, run_scan_to_file


# ─────────────────────────────────────────
# CONFIGURATION
# ─────────────────────────────────────────
SUBNET = "10.0.0.0/24"  # change to your subnet
PORT_SCAN_TIMEOUT = 0.5  # seconds per port
PING_TIMEOUT = 1  # seconds per ping
MAX_THREADS = 50  # concurrent threads


def main() -> None:
    print("=" * 50)
    print("  Network Asset Discovery Tool")
    print("=" * 50)

    cfg = ScannerConfig(
        subnet=SUBNET,
        port_scan_timeout=PORT_SCAN_TIMEOUT,
        ping_timeout=PING_TIMEOUT,
        max_threads=MAX_THREADS,
    )

    output_filename = f"inventory_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    output_path = Path(__file__).resolve().parent / output_filename

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
        subnet=SUBNET,
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