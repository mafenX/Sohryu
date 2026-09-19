"""
Reference list of well-known, publicly documented DEFAULT credentials that
consumer IoT vendors ship with out of the box.

This module does NOT loop through the list on its own.
The CLI commands decide which credentials to test.

Use this only against devices you own or are authorized to test.
"""

from __future__ import annotations

import base64
import socket

import requests
import urllib3


urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# category_id -> list of (username, password) commonly used as factory defaults.
DEFAULT_CREDS: dict[int, list[tuple[str, str]]] = {
    1: [  # Security Camera / Video Doorbell
        ("admin", "admin"),
        ("admin", ""),
        ("admin", "12345"),
        ("admin", "123456"),
        ("admin", "888888"),
        ("root", "12345"),
        ("root", "vizxv"),
    ],

    2: [  # Smart Lock
        ("admin", "admin"),
        ("admin", "0000"),
        ("admin", "1234"),
    ],

    3: [  # Robot Vacuum
        ("admin", "admin"),
        ("admin", ""),
    ],

    4: [  # White Goods
        ("admin", "admin"),
        ("admin", "1234"),
    ],

    5: [  # Smart TV
        ("admin", "admin"),
        ("admin", "0000"),
    ],

    6: [  # Smart Plug / Switch
        ("admin", "admin"),
        ("admin", ""),
        ("admin", "12345678"),
    ],

    8: [  # Thermostat / HVAC
        ("admin", "admin"),
        ("admin", "1234"),
    ],

    9: [  # Printer
        ("admin", "admin"),
        ("admin", ""),
        ("admin", "printer"),
    ],
}


def candidates_for(category_id: int) -> list[tuple[str, str]]:
    return DEFAULT_CREDS.get(
        category_id,
        [("admin", "admin")]
    )


def attempt_http_login(
    ip: str,
    port: int,
    username: str,
    password: str,
    timeout: float = 4.0,
) -> dict:
    """
    Perform exactly ONE login attempt against the device's HTTP(S) interface
    using the given single credential pair.

    Tries Basic, then Digest authentication using the SAME credential pair.
    Does not loop through other credentials.
    """

    scheme = (
        "https"
        if port in (443, 8443, 5001)
        else "http"
    )

    url = f"{scheme}://{ip}:{port}/"

    result = {
        "attempted": f"{username}:{password}",
        "success": False,
        "status": None,
        "note": "",
    }

    try:
        resp = requests.get(
            url,
            auth=(username, password),
            timeout=timeout,
            verify=False,
            allow_redirects=True,
        )

        result["status"] = resp.status_code

        if resp.status_code in (200, 204):
            result["success"] = True
            return result

        if resp.status_code == 401:
            # Retry the SAME credential pair with Digest auth.
            digest_resp = requests.get(
                url,
                auth=requests.auth.HTTPDigestAuth(
                    username,
                    password,
                ),
                timeout=timeout,
                verify=False,
            )

            result["status"] = digest_resp.status_code

            result["success"] = digest_resp.status_code in (
                200,
                204,
            )

        return result

    except requests.RequestException as exc:
        result["note"] = f"connection error: {exc}"
        return result


def attempt_rtsp_login(
    ip: str,
    port: int,
    username: str,
    password: str,
    timeout: float = 4.0,
) -> dict:
    """
    Perform exactly ONE RTSP authentication test using one
    username/password pair.

    Uses RTSP DESCRIBE over a TCP socket with Basic authentication.
    Does not loop through credentials.
    """

    result = {
        "attempted": f"{username}:{password}",
        "success": False,
        "status": None,
        "note": "",
    }

    # username:password
    credentials = f"{username}:{password}"

    # Convert credentials to Base64.
    encoded = base64.b64encode(
        credentials.encode("utf-8")
    ).decode("ascii")

    # Authorization header value.
    authorization = f"Basic {encoded}"

    # Build RTSP request.
    request = (
        f"DESCRIBE rtsp://{ip}:{port}/ RTSP/1.0\r\n"
        "CSeq: 1\r\n"
        "Accept: application/sdp\r\n"
        "User-Agent: iotscan\r\n"
        f"Authorization: {authorization}\r\n"
        "\r\n"
    )

    try:
        # Create TCP connection to RTSP server.
        with socket.create_connection(
            (ip, port),
            timeout=timeout,
        ) as sock:

            sock.settimeout(timeout)

            # Send RTSP request.
            sock.sendall(
                request.encode(
                    "ascii",
                    errors="ignore",
                )
            )

            # Receive response.
            data = b""

            try:
                while (
                    b"\r\n\r\n" not in data
                    and len(data) < 4096
                ):
                    chunk = sock.recv(1024)

                    if not chunk:
                        break

                    data += chunk

            except socket.timeout:
                pass

    except OSError as exc:
        result["note"] = f"connection error: {exc}"
        return result

    # Convert received bytes into a string.
    response = data.decode(
        "ascii",
        errors="ignore",
    )

    if not response:
        result["note"] = "No RTSP response received."
        return result

    # Get the first line:
    #
    # RTSP/1.0 200 OK
    #
    # or
    #
    # RTSP/1.0 401 Unauthorized
    first_line = response.split(
        "\r\n",
        1,
    )[0]

    try:
        # Example:
        # ["RTSP/1.0", "401", "Unauthorized"]
        parts = first_line.split()

        status = int(parts[1])

    except (IndexError, ValueError):
        result["note"] = "Invalid RTSP response."
        return result

    result["status"] = status

    if status == 200:
        result["success"] = True
        result["note"] = "RTSP authentication successful."

    elif status == 401:
        result["note"] = "RTSP authentication failed."

    else:
        result["note"] = (
            f"RTSP returned status {status}."
        )

    return result
