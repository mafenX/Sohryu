"""
Lightweight TCP port scanning + HTTP banner grabbing for common IoT service
ports. This is intentionally narrow-scope (a fixed, small port list) rather
than a general-purpose port scanner.
"""

from __future__ import annotations

import re
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Ports commonly exposed by consumer IoT devices.
IOT_PORTS: dict[int, str] = {
    21: "ftp",
    23: "telnet",
    80: "http",
    88: "onvif-alt/rtsp-alt",
    443: "https",
    554: "rtsp",
    1883: "mqtt",
    2323: "telnet-alt",
    5000: "http-alt (Synology/UPnP)",
    5001: "https-alt",
    8000: "http-alt (Dahua)",
    8080: "http-alt",
    8443: "https-alt",
    8554: "rtsp-alt",
    9000: "http-alt",
    37777: "dahua-proprietary",
    49152: "upnp-alt",
}


def _check_port(ip: str, port: int, timeout: float) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        try:
            return sock.connect_ex((ip, port)) == 0
        except OSError:
            return False


def scan_ports(ip: str, ports: dict[int, str] = IOT_PORTS, timeout: float = 0.6) -> list[int]:
    """Return the list of open ports (from `ports`) on `ip`."""
    open_ports: list[int] = []
    with ThreadPoolExecutor(max_workers=min(32, len(ports))) as pool:
        futures = {pool.submit(_check_port, ip, p, timeout): p for p in ports}
        for fut in as_completed(futures):
            p = futures[fut]
            try:
                if fut.result():
                    open_ports.append(p)
            except Exception:
                pass
    return sorted(open_ports)


# Substrings that suggest a login page mentions a second verification step.
# This is a PASSIVE, best-effort heuristic based on page wording only -- it
# never attempts a login, so it cannot confirm 2FA is actually enforced. A
# device can show none of these words and still have 2FA (e.g. it only
# appears after a correct password), or show them without truly requiring
# a second factor. Treat a "yes" here as "worth checking manually", not proof.
TWO_FACTOR_HINTS = [
    "two-factor", "two factor", "2fa", "verification code", "one-time password",
    "one-time code", "otp code", "authenticator app", "security code",
    "verify your identity", "enter the code sent", "enter the 6-digit code",
]

# Matches an <input type="password" ...> tag regardless of attribute order
# or quote style (e.g. type='password', type=password). Run against the
# already-lowercased page body.
_PASSWORD_INPUT_RE = re.compile(r"<input\b[^>]*\btype\s*=\s*[\"']?password[\"']?")


def grab_http_banner(ip: str, port: int, timeout: float = 2.0) -> dict:
    """
    Fetch an HTTP(S) banner: Server header, WWW-Authenticate details (which
    reveals whether the device is actually presenting a login prompt, and
    often its auth scheme/realm), page title, a passive 2FA wording
    heuristic, and a passive form-login heuristic (an <input type="password">
    field on the page). Never sends credentials.
    """
    scheme = "https" if port in (443, 8443, 5001) else "http"
    url = f"{scheme}://{ip}:{port}/"
    info = {
        "server": "",
        "realm": "",
        "auth_type": "",
        "requires_auth": False,
        "title": "",
        "status": None,
        "two_factor_hint": False,
        "form_login_hint": False,
    }
    try:
        resp = requests.get(url, timeout=timeout, verify=False, allow_redirects=True)
        info["status"] = resp.status_code
        info["server"] = resp.headers.get("Server", "")

        www_auth = resp.headers.get("WWW-Authenticate", "")
        if www_auth:
            info["realm"] = www_auth
            info["auth_type"] = www_auth.split()[0] if www_auth.split() else ""
        # A device is only counted as "login-protected" if it actually
        # challenged us for credentials (401 + WWW-Authenticate) -- not
        # just because its device category usually has a password.
        info["requires_auth"] = resp.status_code == 401 and bool(www_auth)

        body = resp.text if "text/html" in resp.headers.get("Content-Type", "") else ""
        if body:
            lower_body = body.lower()
            m = lower_body.find("<title>")
            if m != -1:
                end = lower_body.find("</title>", m)
                if end != -1:
                    info["title"] = body[m + 7 : end].strip()
            info["two_factor_hint"] = any(hint in lower_body for hint in TWO_FACTOR_HINTS)
            # PASSIVE ONLY: a <input type="password"> tag on the page means
            # this is very likely a JS/form-based login screen -- but we
            # never submit anything to it. There's no universal endpoint,
            # field names, or response format across vendors to test
            # against, so this is purely a signal for you to go check the
            # device by hand; it does not enable check-creds/bruteforce.
            info["form_login_hint"] = bool(_PASSWORD_INPUT_RE.search(lower_body))
    except requests.RequestException:
        pass
    return info
