#!/usr/bin/env python3
"""
Quick mDNS diagnostic: run from the device_discover folder or repo root.
Prints any mDNS services found on the network. Use this to verify mDNS works
before relying on it in scans.
"""
from __future__ import annotations

import socket
import sys
import time

from zeroconf import IPVersion, ServiceBrowser, ServiceStateChange, Zeroconf


def main() -> None:
    print("Testing mDNS discovery (5 second browse)...")
    print()
    try:
        print("  Zeroconf imported OK, creating socket...")
        zc = Zeroconf(ip_version=IPVersion.V4Only)
        print("  Zeroconf bound OK, browsing...")

        result = {}
        services = ["_http._tcp.local.", "_ipp._tcp.local.", "_googlecast._tcp.local."]

        def handler(*, zeroconf, service_type, name, state_change):
            if state_change in (ServiceStateChange.Added, ServiceStateChange.Updated):
                info = zeroconf.get_service_info(service_type, name)
                if info and getattr(info, "addresses", None):
                    for addr in info.addresses:
                        if len(addr) == 4:
                            ip = socket.inet_ntoa(addr)
                            hostname = (info.server or name).rstrip(".")
                            result[ip] = hostname
                            print(f"  -> {ip} ({hostname})")
                            break

        ServiceBrowser(zc, services, handlers=[handler])
        time.sleep(5)
        zc.close()
        print()
        if not result:
            print("No mDNS services found.")
            print()
            print("Possible causes:")
            print("  - No devices on your network advertise via mDNS")
            print("  - Multicast is blocked (some corporate/guest WiFi)")
            print("  - Zeroconf failed to bind (port 5353 in use, e.g. by Avahi)")
            print("  - Permission issue (e.g. sandbox, restricted env)")
            sys.exit(1)
        print(f"Found {len(result)} host(s) via mDNS")
    except Exception as e:
        print(f"mDNS test failed: {e}")
        import traceback

        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
