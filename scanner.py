import json
import os
import threading
import time
import ipaddress
import platform
import re
import socket
import subprocess
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Callable, Dict, List, Optional


OnEvent = Callable[[Dict[str, Any]], None]


@dataclass(frozen=True)
class ScannerConfig:
    subnet: str = "10.0.0.0/24"
    port_scan_timeout: float = 0.5
    ping_timeout: int = 1
    max_threads: int = 50
    # When True, discovery is done via ICMP ping sweep first.
    # Some networks block ICMP; setting this to False makes scanning run
    # across the whole CIDR (safer + more reliable, but can be slower).
    discover_via_ping: bool = True
    # Safety cap when `discover_via_ping` is False (or when a large subnet is provided).
    max_discovered_hosts: Optional[int] = 1024


@dataclass(frozen=True)
class ScanResult:
    inventory: Dict[str, Any]
    cancelled: bool


# Fallback when ports.json is missing or unreadable.
COMMON_PORTS: Dict[int, str] = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    67: "DHCP",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    161: "SNMP",
    443: "HTTPS",
    445: "SMB",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
}

_ports_lock = threading.Lock()
_ports_cache: Optional[Dict[int, str]] = None


def _load_ports() -> Dict[int, str]:
    """Load port list from data/ports.json, fallback to COMMON_PORTS."""
    global _ports_cache
    if _ports_cache is not None:
        return _ports_cache
    with _ports_lock:
        if _ports_cache is not None:
            return _ports_cache
        try:
            path = Path(__file__).resolve().parent / "data" / "ports.json"
            if path.exists():
                with open(path, encoding="utf-8") as f:
                    raw = json.load(f)
                _ports_cache = {int(k): str(v) for k, v in raw.items()}
            else:
                _ports_cache = dict(COMMON_PORTS)
        except Exception:
            _ports_cache = dict(COMMON_PORTS)
        return _ports_cache


# Optional overrides when the Wireshark DB has no match (first 3 octets, lower case, `:` separators).
MANUFACTURER_OVERRIDES: Dict[str, str] = {
    "c4:50:9c": "Apple, Inc.",
    "ac:bc:32": "Apple, Inc.",
    "f0:b4:29": "Apple, Inc.",
    "3c:95:09": "Samsung Electronics Co.,Ltd",
    "00:80:92": "Nortel Networks",
    "82:32:4b": "Apple, Inc.",
}

_manuf_lock = threading.Lock()
_manuf_parser: Optional[Any] = None
_manuf_load_attempted = False


def _get_wireshark_manuf_parser() -> Optional[Any]:
    """
    Lazy-load Wireshark's OUI database via the `manuf` package (bundled data file, offline).
    Returns None if `manuf` is missing or the database cannot be loaded.
    """
    global _manuf_parser, _manuf_load_attempted
    if _manuf_load_attempted:
        return _manuf_parser
    with _manuf_lock:
        if _manuf_load_attempted:
            return _manuf_parser
        _manuf_load_attempted = True
        try:
            from manuf import MacParser

            path = os.environ.get("DEVICE_DISCOVER_MANUF_PATH", "").strip()
            _manuf_parser = MacParser(manuf_name=path) if path else MacParser()
        except Exception:
            _manuf_parser = None
        return _manuf_parser


def _is_windows() -> bool:
    return platform.system().lower() == "windows"


def _cancelled(cancel_event: Optional[threading.Event]) -> bool:
    return cancel_event is not None and cancel_event.is_set()


def ping_host(ip: str, config: ScannerConfig, cancel_event: Optional[threading.Event] = None) -> bool:
    """
    Returns True if host responds to ping.
    """
    if _cancelled(cancel_event):
        return False
    if _is_windows():
        param = "-n"
        timeout_param = "-w"
        # Windows `ping -w` is in milliseconds.
        timeout_ms = max(1, int(config.ping_timeout * 1000))
        timeout_str = str(timeout_ms)
        command = ["ping", param, "1", timeout_param, timeout_str, ip]
    else:
        param = "-c"
        timeout_param = "-W"
        command = ["ping", param, "1", timeout_param, str(config.ping_timeout), ip]

    # mute STDOUT/STDERR outputs for console usage
    result = subprocess.run(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return result.returncode == 0


def discover_hosts(
    subnet: str,
    config: ScannerConfig,
    on_host_found: Optional[OnEvent] = None,
    cancel_event: Optional[threading.Event] = None,
) -> List[str]:
    """
    Ping sweep entire subnet, return list of live IPs.
    """
    network = ipaddress.IPv4Network(subnet, strict=False)
    if not config.discover_via_ping:
        live_hosts: List[str] = []
        for ip in network.hosts():
            if _cancelled(cancel_event):
                break
            live_hosts.append(str(ip))
            if config.max_discovered_hosts is not None and len(live_hosts) >= config.max_discovered_hosts:
                break
        return live_hosts

    live_hosts: List[str] = []

    with ThreadPoolExecutor(max_workers=config.max_threads) as executor:
        futures = {
            executor.submit(ping_host, str(ip), config, cancel_event): str(ip)
            for ip in network.hosts()
        }

        for future in as_completed(futures):
            if _cancelled(cancel_event):
                break
            ip = futures[future]
            if future.result():
                live_hosts.append(ip)
                if on_host_found:
                    on_host_found({"type": "host_up", "ip": ip})

    return sorted(live_hosts)


def _grab_ssh_banner(ip: str, timeout: float) -> Optional[str]:
    """Read SSH banner (e.g. SSH-2.0-OpenSSH_8.2) and return enhanced label."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            sock.connect((ip, 22))
            data = sock.recv(256).decode("utf-8", errors="ignore").strip()
        if not data:
            return None
        # SSH-2.0-OpenSSH_8.2 or SSH-1.99-dropbear_2022.83
        m = re.match(r"SSH-[0-9.]+-(.+)", data, re.IGNORECASE)
        if m:
            return f"SSH ({m.group(1).strip()})"
        return "SSH"
    except Exception:
        return None


def _grab_http_server(ip: str, timeout: float) -> Optional[str]:
    """Send HTTP request, parse Server header, return enhanced label."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            sock.connect((ip, 80))
            sock.sendall(b"HEAD / HTTP/1.0\r\nHost: " + ip.encode() + b"\r\n\r\n")
            data = sock.recv(2048).decode("utf-8", errors="ignore")
        for line in data.split("\n"):
            if line.lower().startswith("server:"):
                server = line.split(":", 1)[1].strip()
                if server:
                    return f"HTTP ({server})"
                break
        return "HTTP"
    except Exception:
        return None


def scan_port(
    ip: str,
    port: int,
    config: ScannerConfig,
    cancel_event: Optional[threading.Event] = None,
) -> Optional[int]:
    """
    Attempts TCP connect on ip:port.
    Returns port if open, None if closed/filtered.
    """
    if _cancelled(cancel_event):
        return None
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(config.port_scan_timeout)
            result = sock.connect_ex((ip, port))
            return port if result == 0 else None
    except Exception:
        return None


def scan_ports(ip: str, config: ScannerConfig, cancel_event: Optional[threading.Event] = None) -> Dict[int, str]:
    """
    Scan all common ports on a host, return dict of open ports (port -> service).
    Uses data/ports.json (top ~100), with banner grabs for SSH (22) and HTTP (80).
    """
    ports = _load_ports()
    open_ports: Dict[int, str] = {}

    with ThreadPoolExecutor(max_workers=config.max_threads) as executor:
        futures = {
            executor.submit(scan_port, ip, port, config, cancel_event): port for port in ports
        }
        for future in as_completed(futures):
            if _cancelled(cancel_event):
                break
            port = futures[future]
            if future.result() is not None:
                open_ports[port] = ports[port]

    # Banner grabs for richer labels on high-value ports
    if 22 in open_ports and not _cancelled(cancel_event):
        banner = _grab_ssh_banner(ip, config.port_scan_timeout)
        if banner:
            open_ports[22] = banner
    if 80 in open_ports and not _cancelled(cancel_event):
        server = _grab_http_server(ip, config.port_scan_timeout)
        if server:
            open_ports[80] = server

    return open_ports


def _collect_mdns_hostnames(
    timeout: float = 2.5,
    cancel_event: Optional[threading.Event] = None,
) -> Dict[str, str]:
    """
    Browse mDNS for common service types, return IP -> hostname map.
    Runs for up to `timeout` seconds. Returns {} if zeroconf unavailable or on error.
    """
    result: Dict[str, str] = {}
    lock = threading.Lock()

    def on_added(zc: Any, service_type: str, name: str) -> None:
        try:
            info = zc.get_service_info(service_type, name)
            if not info or not info.addresses:
                return
            for addr_bytes in getattr(info, "addresses", []) or []:
                if len(addr_bytes) != 4:
                    continue
                try:
                    ip = socket.inet_ntoa(addr_bytes)
                    hostname = (info.server or name).rstrip(".")
                    with lock:
                        if ip not in result or len(hostname) < len(result[ip]):
                            result[ip] = hostname
                    break
                except (OSError, TypeError):
                    continue
        except Exception:
            pass

    try:
        from zeroconf import IPVersion, ServiceBrowser, ServiceStateChange, Zeroconf

        zc = Zeroconf(ip_version=IPVersion.V4Only)
        services = [
            "_http._tcp.local.",
            "_https._tcp.local.",
            "_ssh._tcp.local.",
            "_ipp._tcp.local.",
            "_ipps._tcp.local.",
            "_workstation._tcp.local.",
            "_googlecast._tcp.local.",
            "_airplay._tcp.local.",
            "_raop._tcp.local.",
        ]

        def handler(
            *,
            zeroconf: Any,
            service_type: str,
            name: str,
            state_change: Any,
        ) -> None:
            if state_change in (ServiceStateChange.Added, ServiceStateChange.Updated):
                on_added(zeroconf, service_type, name)

        ServiceBrowser(zc, services, handlers=[handler])
        elapsed = 0.0
        step = 0.2
        while elapsed < timeout:
            if _cancelled(cancel_event):
                break
            time.sleep(step)
            elapsed += step
        zc.close()
    except Exception:
        pass
    return result


def _query_netbios_name(ip: str, timeout: float = 2.0) -> Optional[str]:
    """
    Query NetBIOS Name Service (NBNS) for hostname at given IP.
    Returns name if found, None on failure or if pysmb unavailable.
    Works on LAN without WINS (broadcast query).
    """
    try:
        from nmb.NetBIOS import NetBIOS

        nb = NetBIOS()
        try:
            names = nb.queryIPForName(ip, port=137, timeout=timeout)
            if names and len(names) > 0:
                name = names[0].strip()
                if name and name != ip:
                    return name
        finally:
            nb.close()
    except Exception:
        pass
    return None


def get_hostname(ip: str, mdns_map: Optional[Dict[str, str]] = None) -> str:
    """Resolve hostname: reverse DNS first (2s timeout), then mDNS, then NetBIOS fallback."""
    result: List[Optional[str]] = [None]

    def _reverse_dns() -> None:
        try:
            result[0] = socket.gethostbyaddr(ip)[0]
        except (socket.herror, socket.gaierror, OSError):
            pass

    t = threading.Thread(target=_reverse_dns, daemon=True)
    t.start()
    t.join(timeout=2.0)
    name = result[0]
    if name and name != ip:
        return name
    if mdns_map and ip in mdns_map:
        return mdns_map[ip]
    nb_name = _query_netbios_name(ip, timeout=2.0)
    if nb_name:
        return nb_name
    return "unknown"


def get_mac(ip: str, config: ScannerConfig, cancel_event: Optional[threading.Event] = None) -> str:
    """
    Grab MAC address from ARP cache.
    Triggers ARP by pinging first, then reads cache.
    """
    try:
        if _cancelled(cancel_event):
            return "unknown"

        # ping to populate ARP cache
        ping_host(ip, config, cancel_event=cancel_event)

        if _is_windows():
            output = subprocess.check_output(["arp", "-a", ip]).decode()
            match = re.search(
                r"([0-9a-f]{2}[-:][0-9a-f]{2}[-:][0-9a-f]{2}[-:][0-9a-f]{2}[-:][0-9a-f]{2}[-:][0-9a-f]{2})",
                output,
                re.IGNORECASE,
            )
        else:
            output = subprocess.check_output(["arp", "-a", ip]).decode()
            match = re.search(
                r"([0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2})",
                output,
                re.IGNORECASE,
            )

        return match.group(0) if match else "unknown"
    except Exception:
        return "unknown"


def get_manufacturer(mac: str) -> str:
    """Resolve vendor from MAC: Wireshark OUI database (offline), then optional overrides."""
    if mac == "unknown":
        return "unknown"

    # Normalize: ARP on Windows often uses `-`; `manuf` accepts `:` / `-` / `.`
    mac_norm = mac.lower().replace("-", ":")

    parser = _get_wireshark_manuf_parser()
    if parser is not None:
        try:
            v = parser.get_all(mac_norm)
            if v.manuf_long:
                return v.manuf_long
            if v.manuf:
                return v.manuf
        except ValueError:
            pass

    prefix = mac_norm[:8]
    return MANUFACTURER_OVERRIDES.get(prefix, "unknown")


def scan_host(
    ip: str,
    config: ScannerConfig,
    cancel_event: Optional[threading.Event] = None,
    mdns_map: Optional[Dict[str, str]] = None,
) -> Optional[Dict[str, Any]]:
    """
    Full scan of a single host — returns device record.
    """
    if _cancelled(cancel_event):
        return None
    hostname = get_hostname(ip, mdns_map=mdns_map)
    if _cancelled(cancel_event):
        return None
    mac = get_mac(ip, config, cancel_event=cancel_event)
    manufacturer = get_manufacturer(mac)
    if _cancelled(cancel_event):
        return None
    open_ports = scan_ports(ip, config, cancel_event=cancel_event)

    device = {
        "ip": ip,
        "hostname": hostname,
        "mac": mac,
        "manufacturer": manufacturer,
        "open_ports": open_ports,
        "scanned_at": datetime.now().isoformat(),
    }
    return device


def run_scan(
    subnet: str,
    config: Optional[ScannerConfig] = None,
    on_event: Optional[OnEvent] = None,
    cancel_event: Optional[threading.Event] = None,
) -> ScanResult:
    """
    Run discovery + inventory scan for a subnet.

    Returns the inventory dict matching the existing `devicefinder.py` JSON format.
    """
    cfg = config or ScannerConfig(subnet=subnet)

    start_time = datetime.now()

    if on_event:
        on_event({"type": "scan_started", "subnet": subnet, "scan_time": start_time.isoformat()})

    mdns_map: Dict[str, str] = {}
    mdns_done = threading.Event()

    def run_mdns() -> None:
        try:
            mdns_map.update(
                _collect_mdns_hostnames(timeout=4.0, cancel_event=cancel_event)
            )
        finally:
            mdns_done.set()

    mdns_thread = threading.Thread(target=run_mdns, daemon=True)
    mdns_thread.start()

    live_hosts = discover_hosts(subnet, cfg, on_host_found=on_event, cancel_event=cancel_event)

    mdns_done.wait(timeout=5.0)
    mdns_thread.join(timeout=0.5)

    if on_event:
        on_event({"type": "hosts_found", "hosts_found": len(live_hosts), "live_hosts": live_hosts})

    devices: List[Dict[str, Any]] = []
    total = len(live_hosts)

    for i, ip in enumerate(live_hosts):
        if _cancelled(cancel_event):
            break
        if on_event:
            on_event({"type": "host_scanning", "ip": ip, "index": i + 1, "total": total})

        device = scan_host(ip, cfg, cancel_event=cancel_event, mdns_map=mdns_map)
        if device is not None:
            devices.append(device)
        else:
            break

        if on_event:
            on_event(
                {
                    "type": "device_scanned",
                    "ip": ip,
                    "index": i + 1,
                    "total": total,
                    "device": device,
                }
            )

    output = {
        "scan_metadata": {
            "subnet": subnet,
            "scan_time": start_time.isoformat(),
            "duration_seconds": int((datetime.now() - start_time).total_seconds()),
            "hosts_found": len(devices),
            "mdns_hosts_found": len(mdns_map),
        },
        "devices": devices,
    }
    return ScanResult(inventory=output, cancelled=_cancelled(cancel_event))


def run_scan_to_file(
    subnet: str,
    output_filename: str,
    config: Optional[ScannerConfig] = None,
    on_event: Optional[OnEvent] = None,
) -> Dict[str, Any]:
    """
    Run scan and write inventory JSON to `output_filename`.
    """
    import json

    result = run_scan(subnet=subnet, config=config, on_event=on_event)
    inventory = result.inventory
    with open(output_filename, "w") as f:
        json.dump(inventory, f, indent=2)
    return inventory

