"""
Passive RTSP authentication detection.

RTSP (RFC 2326) borrows HTTP's status-line / header style, including the
same 401 + WWW-Authenticate challenge mechanism used by Basic/Digest auth.
Many IP cameras don't expose a web UI at all, or expose one without a
login prompt, but DO require credentials to pull the actual video stream
over RTSP. Without checking RTSP separately, such a camera would never be
flagged as login-protected -- this module closes that gap.

This is passive discovery only: it sends a single DESCRIBE request (no
credentials) and reads whether the device challenges for authentication.
It never attempts a login.
"""

from __future__ import annotations

import re
import socket


def probe_rtsp_auth(ip: str, port: int = 554, timeout: float = 3.0) -> dict:
    """
    Send an unauthenticated RTSP DESCRIBE request and check whether the
    device challenges for credentials (401 + WWW-Authenticate).
    """
    result = {
        "reachable": False,
        "status": None,
        "requires_auth": False,
        "auth_type": "",
        "realm": "",
    }

    request = (
        f"DESCRIBE rtsp://{ip}:{port}/ RTSP/1.0\r\n"
        "CSeq: 1\r\n"
        "Accept: application/sdp\r\n"
        "User-Agent: iotscan\r\n"
        "\r\n"
    )

    try:
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            sock.sendall(request.encode("ascii", errors="ignore"))
            data = b""
            try:
                while b"\r\n\r\n" not in data and len(data) < 4096:
                    chunk = sock.recv(1024)
                    if not chunk:
                        break
                    data += chunk
            except socket.timeout:
                pass
    except OSError:
        return result

    text = data.decode("utf-8", errors="ignore")
    if not text:
        return result

    result["reachable"] = True

    status_line = text.split("\r\n", 1)[0]
    m_status = re.search(r"RTSP/1\.\d\s+(\d+)", status_line)
    if m_status:
        result["status"] = int(m_status.group(1))

    m_auth = re.search(r"^WWW-Authenticate:\s*(.+)$", text, re.IGNORECASE | re.MULTILINE)
    if result["status"] == 401 and m_auth:
        realm_line = m_auth.group(1).strip()
        result["requires_auth"] = True
        result["realm"] = realm_line
        result["auth_type"] = realm_line.split()[0] if realm_line.split() else ""

    return result
