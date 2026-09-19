"""
SSDP/UPnP discovery: sends an M-SEARCH multicast request to
239.255.255.250:1900 (standard SSDP address) and fetches each device's
description XML to pull friendlyName / manufacturer / modelName / deviceType.
Smart TVs, printers, media renderers (Sonos), and many hubs answer to this.
"""

from __future__ import annotations

import re
import socket
from dataclasses import dataclass

import requests

MCAST_GRP = "239.255.255.250"
MCAST_PORT = 1900

MSEARCH = (
    "M-SEARCH * HTTP/1.1\r\n"
    f"HOST: {MCAST_GRP}:{MCAST_PORT}\r\n"
    'MAN: "ssdp:discover"\r\n'
    "MX: 3\r\n"
    "ST: ssdp:all\r\n"
    "\r\n"
)


@dataclass
class SsdpDevice:
    host: str = ""
    location: str = ""
    server: str = ""
    friendly_name: str = ""
    manufacturer: str = ""
    model_name: str = ""
    device_type: str = ""


def discover_ssdp(timeout: float = 4.0) -> list[SsdpDevice]:
    devices: dict[str, SsdpDevice] = {}
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.settimeout(timeout)
    try:
        sock.sendto(MSEARCH.encode("utf-8"), (MCAST_GRP, MCAST_PORT))
        while True:
            try:
                data, addr = sock.recvfrom(65535)
            except socket.timeout:
                break
            text = data.decode("utf-8", errors="ignore")
            host = addr[0]
            location = ""
            server = ""
            for line in text.split("\r\n"):
                if line.upper().startswith("LOCATION:"):
                    location = line.split(":", 1)[1].strip()
                elif line.upper().startswith("SERVER:"):
                    server = line.split(":", 1)[1].strip()
            if host in devices:
                continue
            devices[host] = SsdpDevice(host=host, location=location, server=server)
    finally:
        sock.close()

    for dev in devices.values():
        if dev.location:
            _enrich_from_description(dev)
    return list(devices.values())


def _enrich_from_description(dev: SsdpDevice, timeout: float = 3.0) -> None:
    try:
        resp = requests.get(dev.location, timeout=timeout, verify=False)
        xml_text = resp.text
        dev.friendly_name = _tag(xml_text, "friendlyName")
        dev.manufacturer = _tag(xml_text, "manufacturer")
        dev.model_name = _tag(xml_text, "modelName")
        dev.device_type = _tag(xml_text, "deviceType")
    except requests.RequestException:
        pass


def _tag(xml_text: str, tag: str) -> str:
    m = re.search(rf"<{tag}>(.*?)</{tag}>", xml_text, re.IGNORECASE | re.DOTALL)
    return m.group(1).strip() if m else ""
