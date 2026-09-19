"""
Persist the last `discover` run to a small JSON cache so that `list`,
`info`, and `check-creds` can reference devices by their menu number
without re-scanning the network every time.
"""

from __future__ import annotations

import json
import os
from dataclasses import asdict

CACHE_DIR = os.path.expanduser("~/.iotscan")
CACHE_FILE = os.path.join(CACHE_DIR, "devices.json")


def save_devices(devices: list) -> None:
    os.makedirs(CACHE_DIR, exist_ok=True)
    data = [asdict(d) for d in devices]
    with open(CACHE_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


def load_devices() -> list[dict]:
    if not os.path.exists(CACHE_FILE):
        return []
    with open(CACHE_FILE, "r", encoding="utf-8") as f:
        return json.load(f)
