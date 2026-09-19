"""
Turns the raw signals collected during discovery (open ports, HTTP banners,
ONVIF/SSDP/mDNS metadata, MAC vendor) into a device category, matching the
list the user cares about. Also flags which categories are typically
protected by an id/password login, since that's what the credential-check
command targets.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

# Category ids match the numbered menu shown by `iotscan list` / `select`.
CATEGORIES: dict[int, dict] = {
    1: {"name": "Security Camera / Video Doorbell", "has_login": True},
    2: {"name": "Smart Lock", "has_login": True},
    3: {"name": "Robot Vacuum", "has_login": True},
    4: {"name": "White Goods (Fridge / Washer / Dryer)", "has_login": True},
    5: {"name": "Smart TV", "has_login": True},
    6: {"name": "Smart Plug / Switch", "has_login": True},
    7: {"name": "Security Sensor (motion/door/window)", "has_login": False},
    8: {"name": "Smart Thermostat / AC / HVAC / HRV-ERV", "has_login": True},
    9: {"name": "Printer", "has_login": True},
    10: {"name": "Unknown IoT Device", "has_login": False},
}


@dataclass
class Device:
    ip: str = ""
    mac: str = ""
    vendor: str = ""
    open_ports: list[int] = field(default_factory=list)
    http_banners: dict[int, dict] = field(default_factory=dict)  # port -> banner info
    onvif: dict = field(default_factory=dict)
    ssdp: dict = field(default_factory=dict)
    mdns: list[str] = field(default_factory=list)
    rtsp_probes: dict[int, dict] = field(default_factory=dict)  # port -> probe_rtsp_auth() result
    category_id: int = 10
    confidence: str = "low"  # low / medium / high
    # Real, passively-observed signals (not category assumptions):
    requires_auth: bool = False  # device actually returned 401 + WWW-Authenticate
    auth_type: str = ""  # "Basic" / "Digest" / etc., if known
    two_factor_hint: bool = False  # page wording suggests 2FA -- heuristic, unverified
    form_login_hint: bool = False  # <input type="password"> seen on page -- heuristic, untested


def _text_blob(dev: Device) -> str:
    """Concatenate every textual hint we have, lowercased, for keyword matching."""
    parts = [dev.vendor]
    for b in dev.http_banners.values():
        parts += [b.get("server", ""), b.get("title", ""), b.get("realm", "")]
    if dev.onvif:
        parts += [dev.onvif.get("manufacturer", ""), dev.onvif.get("model", ""), dev.onvif.get("types", "")]
    if dev.ssdp:
        parts += [
            dev.ssdp.get("manufacturer", ""),
            dev.ssdp.get("model_name", ""),
            dev.ssdp.get("friendly_name", ""),
            dev.ssdp.get("device_type", ""),
        ]
    parts += dev.mdns
    return " ".join(p for p in parts if p).lower()


KEYWORD_RULES: list[tuple[int, list[str], str]] = [
    # (category_id, keywords, confidence)
    (1, ["camera", "doorbell", "onvif", "networkvideotransmitter", "nvr", "dvr", "rtsp",
         "hikvision", "dahua", "reolink", "ezviz", "wyze", "ring", "video doorbell"], "high"),
    (2, ["lock", "deadbolt", "august", "yale", "smartlock"], "high"),
    (3, ["vacuum", "roomba", "roborock", "ecovacs", "robot cleaner"], "high"),
    (4, ["washer", "dryer", "refrigerator", "fridge", "dishwasher", "homeconnect", "smartthinq"], "high"),
    (5, ["smarttv", "smart tv", "roku", "androidtv", "webos", "tizen", "chromecast", "googlecast"], "high"),
    (6, ["plug", "switch", "wemo", "kasa", "tapo", "smartplug", "outlet"], "medium"),
    (7, ["sensor", "motion", "door/window", "contact sensor"], "medium"),
    (8, ["thermostat", "ecobee", "nest", "hvac", "hrv", "erv", "honeywell", "climate"], "high"),
    (9, ["printer", "ipp", "hp", "canon", "epson", "cups"], "medium"),
]


def _keyword_matches(blob: str, keyword: str) -> bool:
    """
    Match `keyword` in `blob` on word boundaries when it's alphanumeric
    (so short keywords like 'erv' or 'tv' don't false-positive inside
    unrelated words such as 'server'). Multi-word phrases are matched as
    plain substrings since \\b doesn't apply cleanly to them.
    """
    if " " in keyword or "/" in keyword:
        return keyword in blob
    return re.search(rf"\b{re.escape(keyword)}\b", blob) is not None


def classify(dev: Device) -> Device:
    blob = _text_blob(dev)

    for cat_id, keywords, confidence in KEYWORD_RULES:
        if any(_keyword_matches(blob, kw) for kw in keywords):
            dev.category_id = cat_id
            dev.confidence = confidence
            return dev

    # Fall back to port/protocol heuristics if no textual match.
    if dev.onvif:
        dev.category_id, dev.confidence = 1, "high"
    elif 554 in dev.open_ports or 8554 in dev.open_ports:
        dev.category_id, dev.confidence = 1, "medium"
    elif 1883 in dev.open_ports:
        dev.category_id, dev.confidence = 6, "low"  # MQTT is common on plugs/sensors
    else:
        dev.category_id, dev.confidence = 10, "low"

    return dev


def has_login(category_id: int) -> bool:
    """
    Whether this CATEGORY typically ships with an id/password login, per a
    static reference table -- NOT a live observation of any specific device.
    Kept for reference; actual gating in the CLI uses Device.requires_auth,
    which is a real, passively-observed HTTP 401/WWW-Authenticate response.
    """
    return CATEGORIES.get(category_id, {}).get("has_login", False)


def category_name(category_id: int) -> str:
    return CATEGORIES.get(category_id, {}).get("name", "Unknown")
