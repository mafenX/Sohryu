"""
MAC OUI (vendor prefix) lookup, backed by a real, bundled vendor database
(iotscan/data/oui.txt) with ~90,000 entries sourced from IEEE registration
records, aggregated by the public "OUI-Master-Database" project (which
itself merges IEEE, Nmap, and Wireshark data). No network call is made at
runtime -- the file ships inside the package so the tool works fully
offline.

Handles all three block sizes IEEE assigns:
  - 24-bit (MA-L)  e.g. "CC:2D:21"          -> most common, exact match
  - 28-bit (MA-M)  e.g. "C8:5C:E2:70/28"    -> smaller allocations
  - 36-bit (MA-S)  e.g. "8C:1F:64:AF:A0/36" -> IAB / very small allocations
via proper bitmask comparison, not naive string prefix matching.
"""

from __future__ import annotations

import os

_DATA_PATH = os.path.join(os.path.dirname(__file__), "data", "oui.txt")

# top-24-bits (6 hex chars) -> vendor, for plain 24-bit entries
_exact24: dict[str, str] = {}
# top-24-bits (6 hex chars) -> list of (masked_value, mask, vendor), for
# the rarer 28-bit / 36-bit entries that need real bitmask comparison
_extra: dict[str, list[tuple[int, int, str]]] = {}
_loaded = False


def _load() -> None:
    global _loaded
    if _loaded:
        return
    _loaded = True
    if not os.path.exists(_DATA_PATH):
        return
    with open(_DATA_PATH, encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            try:
                oui_field, vendor = line.split("\t", 1)
            except ValueError:
                continue

            if "/" in oui_field:
                prefix_part, bits_str = oui_field.split("/", 1)
                try:
                    bits = int(bits_str)
                except ValueError:
                    continue
            else:
                prefix_part, bits = oui_field, 24

            hex_digits = prefix_part.replace(":", "").replace("-", "").upper()
            if not hex_digits:
                continue
            try:
                value = int(hex_digits, 16)
            except ValueError:
                continue

            value_padded = value << (48 - len(hex_digits) * 4)
            top24 = f"{(value_padded >> 24) & 0xFFFFFF:06X}"

            if bits == 24:
                _exact24.setdefault(top24, vendor)
            else:
                mask = ((1 << bits) - 1) << (48 - bits)
                _extra.setdefault(top24, []).append((value_padded & mask, mask, vendor))


def lookup_vendor(mac: str) -> str:
    """Return the best-effort vendor name for a MAC address, or 'Unknown'."""
    if not mac:
        return "Unknown"
    hex_digits = mac.replace(":", "").replace("-", "").upper()
    if len(hex_digits) < 6:
        return "Unknown"

    _load()
    top24 = hex_digits[0:6]

    # Check the more specific 28-bit/36-bit allocations first.
    if top24 in _extra:
        try:
            mac_int = int(hex_digits.ljust(12, "0")[:12], 16)
        except ValueError:
            mac_int = None
        if mac_int is not None:
            for masked_value, mask, vendor in _extra[top24]:
                if (mac_int & mask) == masked_value:
                    return vendor

    return _exact24.get(top24, "Unknown")
