"""
ONVIF WS-Discovery: sends a standard SOAP "Probe" multicast message to
239.255.255.250:3702 (the well-known ONVIF discovery address/port) and
parses replies from ONVIF-compliant devices (IP cameras, video doorbells,
NVRs). This mirrors what tools like `onvif-discovery` / pwneye do -- it is
passive discovery, no authentication involved.
"""

from __future__ import annotations

import re
import socket
import uuid
from dataclasses import dataclass, field

MCAST_GRP = "239.255.255.250"
MCAST_PORT = 3702

PROBE_TEMPLATE = """<?xml version="1.0" encoding="UTF-8"?>
<e:Envelope xmlns:e="http://www.w3.org/2003/05/soap-envelope"
            xmlns:w="http://schemas.xmlsoap.org/ws/2004/08/addressing"
            xmlns:d="http://schemas.xmlsoap.org/ws/2005/04/discovery"
            xmlns:dn="http://www.onvif.org/ver10/network/wsdl">
  <e:Header>
    <w:MessageID>uuid:{msg_id}</w:MessageID>
    <w:To e:mustUnderstand="1">urn:schemas-xmlsoap-org:ws:2005:04:discovery</w:To>
    <w:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</w:Action>
  </e:Header>
  <e:Body>
    <d:Probe>
      <d:Types>dn:NetworkVideoTransmitter</d:Types>
    </d:Probe>
  </e:Body>
</e:Envelope>"""


@dataclass
class OnvifDevice:
    host: str = ""
    port: int = 80
    xaddrs: list[str] = field(default_factory=list)
    types: str = ""
    scopes: str = ""
    manufacturer: str = ""
    model: str = ""
    hardware: str = ""


def _extract_tag(xml_text: str, tag: str) -> str:
    m = re.search(rf"<[\w:]*{tag}[^>]*>(.*?)</[\w:]*{tag}>", xml_text, re.IGNORECASE | re.DOTALL)
    return m.group(1).strip() if m else ""


def discover_onvif(timeout: float = 4.0) -> list[OnvifDevice]:
    """Broadcast a WS-Discovery Probe and collect ONVIF device replies."""
    msg = PROBE_TEMPLATE.format(msg_id=uuid.uuid4())
    devices: dict[str, OnvifDevice] = {}

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.settimeout(timeout)
    try:
        sock.sendto(msg.encode("utf-8"), (MCAST_GRP, MCAST_PORT))
        while True:
            try:
                data, addr = sock.recvfrom(65535)
            except socket.timeout:
                break
            xml_text = data.decode("utf-8", errors="ignore")
            xaddrs_raw = _extract_tag(xml_text, "XAddrs")
            xaddrs = xaddrs_raw.split()
            if not xaddrs:
                continue
            host = addr[0]
            dev = OnvifDevice(
                host=host,
                xaddrs=xaddrs,
                types=_extract_tag(xml_text, "Types"),
                scopes=_extract_tag(xml_text, "Scopes"),
            )
            # Try to pull a port from the first XAddr (e.g. http://ip:80/...)
            m = re.search(r":(\d+)/", xaddrs[0])
            if m:
                dev.port = int(m.group(1))
            devices[host] = dev
    finally:
        sock.close()
    return list(devices.values())


GET_DEVICE_INFO_ENVELOPE = """<?xml version="1.0" encoding="UTF-8"?>
<e:Envelope xmlns:e="http://www.w3.org/2003/05/soap-envelope"
            xmlns:tds="http://www.onvif.org/ver10/device/wsdl">
  <e:Body>
    <tds:GetDeviceInformation/>
  </e:Body>
</e:Envelope>"""


def get_device_information(xaddr: str, timeout: float = 3.0) -> dict:
    """
    Call the unauthenticated ONVIF GetDeviceInformation SOAP method to pull
    Manufacturer / Model / Hardware / SerialNumber, similar to what's shown
    in the pwneye discovery output. Many devices allow this call without
    credentials (read-only device info).
    """
    import requests

    result = {"manufacturer": "", "model": "", "hardware": "", "serial": ""}
    try:
        resp = requests.post(
            xaddr,
            data=GET_DEVICE_INFO_ENVELOPE,
            headers={"Content-Type": "application/soap+xml; charset=utf-8"},
            timeout=timeout,
        )
        text = resp.text
        result["manufacturer"] = _extract_tag(text, "Manufacturer")
        result["model"] = _extract_tag(text, "Model")
        result["hardware"] = _extract_tag(text, "HardwareId")
        result["serial"] = _extract_tag(text, "SerialNumber")
    except Exception:
        pass
    return result
