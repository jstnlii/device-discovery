import socket
import subprocess
import platform
import json
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
import re

# ─────────────────────────────────────────
# CONFIGURATION
# ─────────────────────────────────────────
SUBNET = "10.0.0.0/24"          # change to your subnet
PORT_SCAN_TIMEOUT = 0.5          # seconds per port
PING_TIMEOUT = 1                 # seconds per ping
MAX_THREADS = 50                 # concurrent threads

# Common ports to scan with service names
COMMON_PORTS = {
    21:   "FTP",
    22:   "SSH",
    23:   "Telnet",
    25:   "SMTP",
    53:   "DNS",
    67:   "DHCP",
    80:   "HTTP",
    110:  "POP3",
    143:  "IMAP",
    161:  "SNMP",
    443:  "HTTPS",
    445:  "SMB",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
}

# ─────────────────────────────────────────
# PING SWEEP — discover live hosts
# ─────────────────────────────────────────
def ping_host(ip):
    """
    Returns True if host responds to ping.
    """

    param = "-n" if platform.system().lower() == "windows" else "-c"
    timeout_param = "-w" if platform.system().lower() == "windows" else "-W"

    command = ["ping", param, "1", timeout_param, str(PING_TIMEOUT), str(ip)]
    result = subprocess.run(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) # mute STDOUT and STDERR outputs for console
    
    return result.returncode == 0

def discover_hosts(subnet):
    """
    Ping sweep entire subnet, return list of live IPs.
    """

    print(f"\n[*] Scanning subnet {subnet} for live hosts...")
    network = ipaddress.IPv4Network(subnet, strict=False)
    live_hosts = []

    with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        futures = {executor.submit(ping_host, str(ip)): str(ip) for ip in network.hosts()}

        for future in as_completed(futures):
            ip = futures[future]
            if future.result():
                print(f"    [+] Host up: {ip}")
                live_hosts.append(ip)

    return sorted(live_hosts)

# ─────────────────────────────────────────
# PORT SCANNER — TCP connect scan
# ─────────────────────────────────────────
def scan_port(ip, port):
    """
    Attempts TCP three way handshake on ip:port.
    Returns port if open, None if closed/filtered.
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(PORT_SCAN_TIMEOUT)
        result = sock.connect_ex((ip, port))  # returns 0 if open
        sock.close()
        return port if result == 0 else None
    except Exception:
        return None

def scan_ports(ip):
    """
    Scan all common ports on a host, return dict of open ports.
    """
    open_ports = {}
    with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        futures = {executor.submit(scan_port, ip, port): port for port in COMMON_PORTS}
        for future in as_completed(futures):
            port = futures[future]
            if future.result() is not None:
                open_ports[port] = COMMON_PORTS[port]
    return open_ports

# ─────────────────────────────────────────
# HOSTNAME RESOLUTION — reverse DNS lookup
# ─────────────────────────────────────────
def get_hostname(ip):
    """Reverse DNS lookup — IP to hostname."""
    try:
        return socket.gethostbyaddr(ip)[0]
    except socket.herror:
        return "unknown"

# ─────────────────────────────────────────
# MAC ADDRESS — grab from ARP cache
# ─────────────────────────────────────────
def get_mac(ip):
    """
    Grab MAC address from ARP cache.
    Triggers ARP by pinging first, then reads cache.
    """
    try:
        # ping to populate ARP cache
        param = "-n" if platform.system().lower() == "windows" else "-c"
        subprocess.run(["ping", param, "1", str(ip)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        # read ARP cache
        if platform.system().lower() == "windows":
            output = subprocess.check_output(["arp", "-a", str(ip)]).decode()
            match = re.search(r"([0-9a-f]{2}[-:][0-9a-f]{2}[-:][0-9a-f]{2}[-:][0-9a-f]{2}[-:][0-9a-f]{2}[-:][0-9a-f]{2})", output, re.IGNORECASE)
        else:
            output = subprocess.check_output(["arp", "-n", str(ip)]).decode()
            match = re.search(r"([0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2})", output, re.IGNORECASE)

        return match.group(0) if match else "unknown"
    except Exception:
        return "unknown"

# ─────────────────────────────────────────
# MAC MANUFACTURER LOOKUP
# ─────────────────────────────────────────
# OUI prefix → manufacturer mapping (first 3 bytes of MAC)
OUI_TABLE = {
    "c4:50:9c": "Apple",
    "ac:bc:32": "Apple",
    "f0:b4:29": "Apple",
    "3c:95:09": "Samsung",
    "00:80:92": "Nortel Networks",
    "4e:8e:66": "Unknown",
    "76:cd:f3": "Unknown",
    "82:32:4b": "Apple",
    "26:13:4a": "Unknown",
}

def get_manufacturer(mac):
    """Look up manufacturer from MAC OUI prefix."""
    if mac == "unknown":
        return "unknown"
    prefix = mac[:8].lower()
    return OUI_TABLE.get(prefix, "unknown")

# ─────────────────────────────────────────
# MAIN — build inventory
# ─────────────────────────────────────────
def scan_host(ip):
    """
    Full scan of a single host — returns device record.
    """

    print(f"\n[*] Scanning {ip}...")

    hostname = get_hostname(ip)
    mac = get_mac(ip)
    manufacturer = get_manufacturer(mac)
    open_ports = scan_ports(ip)

    device = {
        "ip": ip,
        "hostname": hostname,
        "mac": mac,
        "manufacturer": manufacturer,
        "open_ports": open_ports,
        "scanned_at": datetime.now().isoformat()
    }

    print(f"    Hostname:     {hostname}")
    print(f"    MAC:          {mac} ({manufacturer})")
    print(f"    Open ports:   {open_ports if open_ports else 'none found'}")

    return device

def main():
    print("=" * 50)
    print("  Network Asset Discovery Tool")
    print("=" * 50)

    start_time = datetime.now()

    # Step 1 — discover live hosts
    live_hosts = discover_hosts(SUBNET)
    print(f"\n[*] Found {len(live_hosts)} live host(s)")

    # Step 2 — scan each host
    inventory = []
    for ip in live_hosts:
        device = scan_host(ip)
        inventory.append(device)

    # Step 3 — output JSON inventory
    output = {
        "scan_metadata": {
            "subnet": SUBNET,
            "scan_time": start_time.isoformat(),
            "duration_seconds": (datetime.now() - start_time).seconds,
            "hosts_found": len(inventory)
        },
        "devices": inventory
    }

    filename = f"inventory_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(filename, "w") as f:
        json.dump(output, f, indent=2)

    # Step 4 — print summary
    print("\n" + "=" * 50)
    print("  INVENTORY SUMMARY")
    print("=" * 50)
    for device in inventory:
        print(f"\n  {device['ip']} ({device['hostname']})")
        print(f"  MAC: {device['mac']} — {device['manufacturer']}")
        if device['open_ports']:
            for port, service in device['open_ports'].items():
                print(f"    → Port {port}: {service}")
        else:
            print(f"    → No common ports open")

    print(f"\n[✓] Inventory saved to {filename}")
    print(f"[✓] Scan complete in {(datetime.now() - start_time).seconds} seconds")

if __name__ == "__main__":
    main()