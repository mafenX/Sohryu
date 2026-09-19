"""
Local network helpers: figure out our subnet, ping-sweep it to find live
hosts, and read the OS ARP table to map IP -> MAC without needing raw
sockets / root privileges (unlike scapy-based ARP scanning).
"""

from __future__ import annotations

import ipaddress
import platform
import re
import socket
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed


def get_local_ip() -> str:
    """Return this machine's primary LAN IP (best-effort, no packets sent)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        s.close()


def guess_subnet_cidr(prefix_len: int = 24) -> str:
    """Guess our local subnet as a CIDR string, e.g. '192.168.1.0/24'."""
    local_ip = get_local_ip()
    network = ipaddress.ip_network(f"{local_ip}/{prefix_len}", strict=False)
    return str(network)


def _ping_once(ip: str, timeout: float) -> bool:
    """Send a single OS-level ping. Returns True if the host replied."""
    is_windows = platform.system().lower() == "windows"
    count_flag = "-n" if is_windows else "-c"
    timeout_flag = "-w" if is_windows else "-W"
    timeout_val = str(int(timeout * 1000)) if is_windows else str(max(1, int(timeout)))
    cmd = ["ping", count_flag, "1", timeout_flag, timeout_val, ip]
    try:
        result = subprocess.run(
            cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=timeout + 1
        )
        return result.returncode == 0
    except (subprocess.TimeoutExpired, OSError):
        return False


def ping_sweep(cidr: str, timeout: float = 1.0, max_workers: int = 64) -> list[str]:
    """Ping every host in a CIDR range concurrently. Returns list of live IPs."""
    network = ipaddress.ip_network(cidr, strict=False)
    hosts = [str(h) for h in network.hosts()]
    alive: list[str] = []
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {pool.submit(_ping_once, ip, timeout): ip for ip in hosts}
        for fut in as_completed(futures):
            ip = futures[fut]
            try:
                if fut.result():
                    alive.append(ip)
            except Exception:
                pass
    return sorted(alive, key=lambda x: ipaddress.ip_address(x))


def get_arp_table() -> dict[str, str]:
    """Read the OS ARP/neighbor table. Returns {ip: mac}."""
    table: dict[str, str] = {}
    is_windows = platform.system().lower() == "windows"
    try:
        if is_windows:
            out = subprocess.run(["arp", "-a"], capture_output=True, text=True, timeout=5).stdout
            for line in out.splitlines():
                m = re.search(r"(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F-]{17})", line)
                if m:
                    ip, mac = m.group(1), m.group(2).replace("-", ":")
                    table[ip] = mac.upper()
        else:
            # Prefer `ip neigh` (modern Linux), fall back to `arp -a`.
            try:
                out = subprocess.run(
                    ["ip", "neigh"], capture_output=True, text=True, timeout=5
                ).stdout
                for line in out.splitlines():
                    parts = line.split()
                    if len(parts) >= 5 and parts[0].count(".") == 3:
                        ip = parts[0]
                        if "lladdr" in parts:
                            mac = parts[parts.index("lladdr") + 1]
                            table[ip] = mac.upper()
            except (subprocess.TimeoutExpired, OSError, FileNotFoundError):
                pass
            if not table:
                out = subprocess.run(
                    ["arp", "-a"], capture_output=True, text=True, timeout=5
                ).stdout
                for line in out.splitlines():
                    m = re.search(
                        r"\((\d+\.\d+\.\d+\.\d+)\) at ([0-9a-fA-F:]{17})", line
                    )
                    if m:
                        table[m.group(1)] = m.group(2).upper()
    except (subprocess.TimeoutExpired, OSError, FileNotFoundError):
        pass
    return table
