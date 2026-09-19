"""
mDNS/Bonjour discovery via the optional `zeroconf` package. If zeroconf is
not installed, discover_mdns() simply returns an empty list instead of
crashing the whole tool -- mDNS is a nice-to-have signal, not a hard
dependency.
"""

from __future__ import annotations

from dataclasses import dataclass, field

SERVICE_TYPES = [
    "_http._tcp.local.",
    "_ipp._tcp.local.",       # printers
    "_airplay._tcp.local.",   # Apple TV / speakers
    "_googlecast._tcp.local.",  # Chromecast / Google/Android TVs
    "_hap._tcp.local.",       # HomeKit accessories (locks, sensors, plugs)
    "_spotify-connect._tcp.local.",
    "_printer._tcp.local.",
    "_rtsp._tcp.local.",      # cameras
]


@dataclass
class MdnsDevice:
    name: str = ""
    host: str = ""
    port: int = 0
    service_types: list[str] = field(default_factory=list)
    properties: dict = field(default_factory=dict)


def discover_mdns(timeout: float = 4.0) -> list[MdnsDevice]:
    try:
        from zeroconf import Zeroconf, ServiceBrowser
    except ImportError:
        return []

    import time

    found: dict[str, MdnsDevice] = {}

    class _Listener:
        def add_service(self, zc, service_type, name):
            info = zc.get_service_info(service_type, name)
            if not info:
                return
            try:
                addr = ".".join(str(b) for b in info.addresses[0]) if info.addresses else ""
            except Exception:
                addr = ""
            key = addr or name
            if key not in found:
                found[key] = MdnsDevice(name=name, host=addr, port=info.port or 0)
            if service_type not in found[key].service_types:
                found[key].service_types.append(service_type)
            if info.properties:
                found[key].properties.update(
                    {
                        (k.decode() if isinstance(k, bytes) else k): (
                            v.decode(errors="ignore") if isinstance(v, bytes) else v
                        )
                        for k, v in info.properties.items()
                    }
                )

        def update_service(self, *args, **kwargs):
            pass

        def remove_service(self, *args, **kwargs):
            pass

    zc = Zeroconf()
    listener = _Listener()
    browsers = [ServiceBrowser(zc, st, listener) for st in SERVICE_TYPES]
    try:
        time.sleep(timeout)
    finally:
        zc.close()
    return list(found.values())
