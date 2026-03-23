from __future__ import annotations

import ipaddress
import re
import subprocess
from dataclasses import dataclass
from typing import List, Optional


@dataclass(frozen=True)
class LocalInterfaceIPv4:
    interface: str
    ip: str
    netmask: str
    cidr: str


def _parse_ifconfig_output(ifconfig_output: str) -> List[LocalInterfaceIPv4]:
    interfaces: List[LocalInterfaceIPv4] = []
    current_iface: Optional[str] = None

    for raw_line in ifconfig_output.splitlines():
        line = raw_line.rstrip()

        stripped = line.strip()
        if not stripped:
            continue

        # Example: en0: flags=...
        if not line.startswith("\t") and line.endswith(":") is False and ":" in line:
            maybe_iface = line.split(":", 1)[0].strip()
            if maybe_iface and re.match(r"^[a-zA-Z0-9_.-]+$", maybe_iface):
                current_iface = maybe_iface

        if not current_iface:
            continue

        # Example: inet 192.168.1.10 netmask 0xffffff00 broadcast ...
        if stripped.startswith("inet ") and "netmask" in stripped:
            tokens = stripped.split()
            if len(tokens) < 4:
                continue

            ip = tokens[1]
            mask_hex = tokens[3]
            if not mask_hex.lower().startswith("0x"):
                continue

            try:
                mask_int = int(mask_hex, 16)
                netmask = str(ipaddress.IPv4Address(mask_int))
                network = ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False)
            except Exception:
                continue

            interfaces.append(
                LocalInterfaceIPv4(
                    interface=current_iface,
                    ip=str(ip),
                    netmask=netmask,
                    cidr=str(network),
                )
            )

    return interfaces


def get_local_ipv4_interfaces() -> List[LocalInterfaceIPv4]:
    """
    Detect local IPv4 interface(s) on macOS using `ifconfig`.
    """
    try:
        output = subprocess.check_output(["ifconfig"], stderr=subprocess.DEVNULL).decode()
    except Exception:
        return []

    candidates = _parse_ifconfig_output(output)

    # Filter out loopback, link-local, and /32.
    filtered: List[LocalInterfaceIPv4] = []
    for i in candidates:
        if i.ip.startswith("127."):
            continue
        if i.ip.startswith("169.254."):
            continue
        if ipaddress.IPv4Network(i.cidr).prefixlen == 32:
            continue
        filtered.append(i)

    # Prefer the most specific (largest prefixlen).
    filtered.sort(key=lambda x: ipaddress.IPv4Network(x.cidr).prefixlen, reverse=True)
    return filtered


def get_default_local_subnet() -> Optional[LocalInterfaceIPv4]:
    interfaces = get_local_ipv4_interfaces()
    if not interfaces:
        return None
    return interfaces[0]


def get_default_gateway() -> Optional[str]:
    """
    Return the default gateway IP address, or None if not found.
    Works on macOS, Linux, and Windows.
    """
    import platform

    system = platform.system().lower()

    if system == "darwin":
        try:
            output = subprocess.check_output(
                ["route", "-n", "get", "default"],
                stderr=subprocess.DEVNULL,
                text=True,
            )
            match = re.search(r"gateway:\s*(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", output)
            if match:
                return match.group(1).strip()
        except Exception:
            try:
                output = subprocess.check_output(
                    ["netstat", "-rn"],
                    stderr=subprocess.DEVNULL,
                    text=True,
                )
                for line in output.splitlines():
                    if "default" in line.lower() or "0.0.0.0" in line:
                        parts = line.split()
                        for p in parts:
                            if re.match(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", p):
                                return p
            except Exception:
                pass
        return None

    if system == "linux":
        try:
            with open("/proc/net/route", encoding="utf-8") as f:
                for line in f:
                    fields = line.strip().split()
                    if len(fields) < 3:
                        continue
                    dest = fields[1]
                    gateway = fields[2]
                    flags = int(fields[3], 16) if len(fields) > 3 else 0
                    if dest == "00000000" and (flags & 2):
                        g = int(gateway, 16)
                        return f"{(g & 0xFF)}.{(g >> 8) & 0xFF}.{(g >> 16) & 0xFF}.{(g >> 24) & 0xFF}"
        except Exception:
            pass
        try:
            output = subprocess.check_output(
                ["ip", "route", "show", "default"],
                stderr=subprocess.DEVNULL,
                text=True,
            )
            match = re.search(r"via\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", output)
            if match:
                return match.group(1).strip()
        except Exception:
            pass
        return None

    if system == "windows":
        try:
            output = subprocess.check_output(
                ["route", "print", "0.0.0.0"],
                stderr=subprocess.DEVNULL,
                text=True,
                creationflags=0x08000000 if hasattr(subprocess, "CREATE_NO_WINDOW") else 0,
            )
            for line in output.splitlines():
                match = re.search(r"0\.0\.0\.0\s+0\.0\.0\.0\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", line)
                if match:
                    return match.group(1).strip()
        except Exception:
            pass
        return None

    return None


def _is_valid_netmask(mask_str: str) -> bool:
    """
    Returns True if `mask_str` is a valid dotted-quad netmask (contiguous 1s).
    """
    try:
        mask_int = int(ipaddress.IPv4Address(mask_str))
    except Exception:
        return False

    # Contiguous 1s test: mask like 111..1100..00
    bin_str = bin(mask_int)[2:].zfill(32)
    return "01" not in bin_str


def normalize_subnet_input(value: str) -> str:
    """
    Accepts:
    - CIDR: `10.0.0.0/24`
    - IP/netmask: `10.0.0.187/255.255.255.0`
    - Plain IP (failsafe): `10.0.0.187` -> converted to the detected local CIDR it belongs to

    Also detects likely user mistakes:
    - If the input looks like `255.255.255.0/24` (netmask provided as the "IP" portion),
      raises a helpful error telling you to provide an IP or CIDR network instead.
    """
    v = (value or "").strip()
    if not v:
        raise ValueError("Subnet cannot be empty.")

    # CIDR or IP/mask
    if "/" in v:
        left, right = v.split("/", 1)
        left = left.strip()
        right = right.strip()

        # Heuristic: if "left" is a netmask, user likely provided mask instead of IP/network.
        if _is_valid_netmask(left):
            raise ValueError(
                "It looks like you entered a netmask as the IP (e.g. `255.255.255.0/24`). "
                "Please enter either a CIDR network (e.g. `172.22.172.0/24`) or an IP (e.g. `172.22.172.92`)."
            )

        try:
            net = ipaddress.IPv4Network(v, strict=False)
            return str(net)
        except Exception as e:
            raise ValueError(f"Invalid IPv4 CIDR or IP/mask: {v}") from e

    # Plain IP: infer which detected interface network it belongs to.
    try:
        ip = ipaddress.IPv4Address(v)
    except Exception as e:
        raise ValueError(f"Invalid IPv4 address: {v}") from e

    interfaces = get_local_ipv4_interfaces()
    for i in interfaces:
        net = ipaddress.IPv4Network(i.cidr, strict=False)
        if ip in net:
            return str(net)

    default_iface = get_default_local_subnet()
    if default_iface:
        raise ValueError(
            f"IP {v} does not match the detected local networks. "
            f"Please provide CIDR (e.g. 172.22.172.0/24) or use the detected subnet ({default_iface.cidr})."
        )

    raise ValueError("Could not detect local network interfaces. Provide CIDR like 10.0.0.0/24.")

