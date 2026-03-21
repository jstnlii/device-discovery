import os
import threading
import ipaddress
import platform
import re
import socket
import subprocess
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
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(config.port_scan_timeout)
        result = sock.connect_ex((ip, port))  # returns 0 if open
        sock.close()
        return port if result == 0 else None
    except Exception:
        return None


def scan_ports(ip: str, config: ScannerConfig, cancel_event: Optional[threading.Event] = None) -> Dict[int, str]:
    """
    Scan all common ports on a host, return dict of open ports (port -> service).
    """
    open_ports: Dict[int, str] = {}

    with ThreadPoolExecutor(max_workers=config.max_threads) as executor:
        futures = {
            executor.submit(scan_port, ip, port, config, cancel_event): port for port in COMMON_PORTS
        }
        for future in as_completed(futures):
            if _cancelled(cancel_event):
                break
            port = futures[future]
            if future.result() is not None:
                open_ports[port] = COMMON_PORTS[port]

    return open_ports


def get_hostname(ip: str) -> str:
    """Reverse DNS lookup — IP to hostname."""
    try:
        return socket.gethostbyaddr(ip)[0]
    except socket.herror:
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
            output = subprocess.check_output(["arp", "-n", ip]).decode()
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
) -> Optional[Dict[str, Any]]:
    """
    Full scan of a single host — returns device record.
    """
    if _cancelled(cancel_event):
        return None
    hostname = get_hostname(ip)
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

    live_hosts = discover_hosts(subnet, cfg, on_host_found=on_event, cancel_event=cancel_event)

    if on_event:
        on_event({"type": "hosts_found", "hosts_found": len(live_hosts), "live_hosts": live_hosts})

    devices: List[Dict[str, Any]] = []
    total = len(live_hosts)

    for i, ip in enumerate(live_hosts):
        if _cancelled(cancel_event):
            break
        if on_event:
            on_event({"type": "host_scanning", "ip": ip, "index": i + 1, "total": total})

        device = scan_host(ip, cfg, cancel_event=cancel_event)
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
            "duration_seconds": (datetime.now() - start_time).seconds,
            "hosts_found": len(devices),
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

