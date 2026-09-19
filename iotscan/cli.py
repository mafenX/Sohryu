"""
Sohryu IoT Device Scanner (package: iotscan) -- a local-network IoT device
discovery & inventory tool.

Unlike a generic port scanner, Sohryu focuses on identifying *consumer IoT*
devices (cameras, doorbells, locks, vacuums, plugs, TVs, thermostats,
printers, white goods) on your LAN using ONVIF WS-Discovery, SSDP/UPnP,
optional mDNS, HTTP banner/MAC-vendor heuristics, and a passive RTSP
auth-challenge probe.

Two ways to test whether a device you own is still using a factory-default
or weak password:
  - `check-creds`: manual, one credential pair at a time, with your explicit
    confirmation before every single attempt (HTTP/HTTPS only).
  - `bruteforce` / `rtsp_bruteforce`: automated wordlist testing (HTTP/HTTPS
    or RTSP), no per-attempt confirmation -- use deliberately.

Only use the credential-testing commands against devices you own or are
explicitly authorized to test.
"""

from __future__ import annotations

import argparse
import os
import sys
import time

from . import cache, classify, creds, display, network_utils, portscan
from .mdns_probe import discover_mdns
from .onvif_probe import discover_onvif, get_device_information
from .rtsp_probe import probe_rtsp_auth
from .ssdp_probe import discover_ssdp


def cmd_discover(args: argparse.Namespace) -> None:
    subnet = args.subnet or network_utils.guess_subnet_cidr()
    display.info(f"Starting IoT discovery on {subnet}")
    display.info("Press CTRL-C to stop early")

    devices_by_ip: dict[str, classify.Device] = {}

    if not args.no_onvif:
        display.info(f"Probing ONVIF (WS-Discovery, {args.onvif_timeout}s)...")
        try:
            for od in discover_onvif(timeout=args.onvif_timeout):
                dev = devices_by_ip.setdefault(od.host, classify.Device(ip=od.host))
                info = {}
                if od.xaddrs:
                    info = get_device_information(od.xaddrs[0])
                dev.onvif = {
                    "port": od.port,
                    "xaddrs": od.xaddrs,
                    "types": od.types,
                    "scopes": od.scopes,
                    "manufacturer": info.get("manufacturer", ""),
                    "model": info.get("model", ""),
                    "hardware": info.get("hardware", ""),
                }
            display.success(f"ONVIF discovery found {sum(1 for d in devices_by_ip.values() if d.onvif)} device(s)")
        except KeyboardInterrupt:
            display.warn("ONVIF discovery stopped by user")

    if not args.no_ssdp:
        display.info(f"Probing SSDP/UPnP ({args.ssdp_timeout}s)...")
        try:
            for sd in discover_ssdp(timeout=args.ssdp_timeout):
                dev = devices_by_ip.setdefault(sd.host, classify.Device(ip=sd.host))
                dev.ssdp = {
                    "location": sd.location,
                    "server": sd.server,
                    "friendly_name": sd.friendly_name,
                    "manufacturer": sd.manufacturer,
                    "model_name": sd.model_name,
                    "device_type": sd.device_type,
                }
            display.success(f"SSDP discovery found {sum(1 for d in devices_by_ip.values() if d.ssdp)} device(s)")
        except KeyboardInterrupt:
            display.warn("SSDP discovery stopped by user")

    if not args.no_mdns:
        display.info(f"Probing mDNS ({args.mdns_timeout}s, optional)...")
        mdns_results = discover_mdns(timeout=args.mdns_timeout)
        for md in mdns_results:
            if not md.host:
                continue
            dev = devices_by_ip.setdefault(md.host, classify.Device(ip=md.host))
            dev.mdns.extend(md.service_types)
        if mdns_results:
            display.success(f"mDNS discovery found {len(mdns_results)} service(s)")

    display.info(f"Ping-sweeping {subnet} ({args.ping_timeout}s/host)...")
    alive_hosts = network_utils.ping_sweep(subnet, timeout=args.ping_timeout)
    for ip in alive_hosts:
        devices_by_ip.setdefault(ip, classify.Device(ip=ip))
    display.success(f"{len(alive_hosts)} host(s) responded to ping")

    arp_table = network_utils.get_arp_table()

    display.info(f"Port-scanning {len(devices_by_ip)} host(s) for IoT services...")
    for ip, dev in devices_by_ip.items():
        dev.mac = arp_table.get(ip, "")
        from .oui import lookup_vendor
        dev.vendor = lookup_vendor(dev.mac)
        dev.open_ports = portscan.scan_ports(ip, timeout=args.port_timeout)
        for port in dev.open_ports:
            if port in (80, 443, 8000, 8080, 8443, 5000, 5001, 9000):
                dev.http_banners[port] = portscan.grab_http_banner(ip, port)

        if dev.http_banners:
            dev.requires_auth = any(b.get("requires_auth") for b in dev.http_banners.values())
            dev.auth_type = next(
                (b["auth_type"] for b in dev.http_banners.values() if b.get("auth_type")), ""
            )
            dev.two_factor_hint = any(
                b.get("two_factor_hint") for b in dev.http_banners.values()
            )
            dev.form_login_hint = any(
                b.get("form_login_hint") for b in dev.http_banners.values()
            )

        # RTSP auth probe -- some cameras protect only the video stream
        # (RTSP), not any web UI, and would otherwise never show up as
        # login-protected. This is passive: a single unauthenticated
        # DESCRIBE request, checking for a 401 + WWW-Authenticate reply.
        for rtsp_port in (p for p in dev.open_ports if p in (554, 8554)):
            rtsp_result = probe_rtsp_auth(ip, rtsp_port)
            dev.rtsp_probes[rtsp_port] = rtsp_result
            if rtsp_result.get("requires_auth"):
                dev.requires_auth = True
                if not dev.auth_type:
                    dev.auth_type = f"RTSP {rtsp_result.get('auth_type', '')}".strip()

    for dev in devices_by_ip.values():
        classify.classify(dev)

    devices = sorted(devices_by_ip.values(), key=lambda d: d.ip)
    cache.save_devices(devices)

    display.success(f"Discovery complete. Saved {len(devices)} device(s) to cache.")
    display.print_device_list([d.__dict__ for d in devices])


def cmd_list(args: argparse.Namespace) -> None:
    devices = cache.load_devices()
    display.print_device_list(devices)


def _get_device_or_exit(index: int) -> dict:
    devices = cache.load_devices()
    if index < 1 or index > len(devices):
        display.error(f"No device #{index} in cache. Run 'iotscan list' to see valid numbers.")
        sys.exit(1)
    return devices[index - 1]


def cmd_info(args: argparse.Namespace) -> None:
    dev = _get_device_or_exit(args.id)
    display.print_device_detail(dev)


def cmd_check_creds(args: argparse.Namespace) -> None:
    dev = _get_device_or_exit(args.id)
    cat_id = dev.get("category_id", 10)

    if not dev.get("requires_auth"):
        if dev.get("form_login_hint"):
            display.warn(
                "This device's page has a password input field (JS/form-based login "
                "detected passively), but it isn't a protocol-level 401 challenge -- "
                "check-creds/bruteforce can't test it automatically since every vendor's "
                "form endpoint/field names/response format differ. Log in by hand in a "
                "browser to test it."
            )
        else:
            display.warn(
                "No login prompt was actually observed on this device "
                "(no HTTP 401 + WWW-Authenticate response during discovery). "
                "Nothing to test -- run 'iotscan discover' again if you think "
                "this is wrong, or the device may use a non-HTTP login this "
                "tool can't detect passively."
            )
        return

    if dev.get("two_factor_hint"):
        display.warn(
            "Heads up: this device's login page contains wording that suggests "
            "two-factor authentication may be involved (unverified, based on page "
            "text only). A successful password match below would not necessarily "
            "mean full account access."
        )

    http_ports = [p for p in dev.get("open_ports", []) if p in (80, 443, 8000, 8080, 8443, 5000, 5001, 9000)]
    if not http_ports:
        if dev.get("rtsp_probes") and any(r.get("requires_auth") for r in dev["rtsp_probes"].values()):
            display.error(
                "This device only challenges for auth over RTSP (video stream), not HTTP. "
                "check-creds only tests HTTP(S) logins -- for a manual single-attempt RTSP "
                "test, try 'iotscan rtsp_bruteforce' instead (or edit its wordlist to one line)."
            )
        else:
            display.error("No HTTP(S) management port found open on this device. Cannot test login.")
        return
    port = http_ports[0]

    display.print_device_detail(dev)
    print(
        "This will test ONE credential pair at a time against "
        f"http(s)://{dev['ip']}:{port}/ -- you confirm before every single attempt.\n"
        "Only do this against a device you own or are authorized to test.\n"
    )

    candidates = creds.candidates_for(cat_id)

    while True:
        print(f"Known default credentials for {classify.category_name(cat_id)}:")
        for i, (u, p) in enumerate(candidates, start=1):
            shown_p = p if p else "(blank)"
            print(f"  {i}) {u} / {shown_p}")
        print(f"  m) Enter a custom username/password manually")
        print(f"  q) Quit")

        choice = input("\nSelect an option: ").strip().lower()
        if choice == "q":
            display.info("Stopped.")
            return

        if choice == "m":
            username = input("Username: ").strip()
            password = input("Password: ").strip()
        else:
            try:
                sel = int(choice)
                username, password = candidates[sel - 1]
            except (ValueError, IndexError):
                display.error("Invalid selection.")
                continue

        confirm = input(
            f"Press Enter to attempt '{username}:{password or '(blank)'}' now, "
            "or type 'skip' to go back: "
        ).strip().lower()
        if confirm == "skip":
            continue

        display.info(f"Attempting single login: {username}:{password or '(blank)'} ...")
        result = creds.attempt_http_login(dev["ip"], port, username, password)

        if result["success"]:
            display.success(
                f"Login SUCCEEDED with '{username}:{password or '(blank)'}' "
                f"(HTTP {result['status']}). This device is using a default/weak password -- change it."
            )
            return
        elif result["note"]:
            display.error(f"Could not complete attempt: {result['note']}")
        else:
            display.warn(f"Login failed (HTTP {result['status']}) for '{username}:{password or '(blank)'}'.")

        again = input("\nTry another credential pair? [y/N]: ").strip().lower()
        if again != "y":
            display.info("Stopped.")
            return


def cmd_brute(args: argparse.Namespace) -> None:
    dev = _get_device_or_exit(args.id)

    if not dev.get("requires_auth"):
        if dev.get("form_login_hint"):
            display.error(
                "This device's page has a password input field (JS/form-based login "
                "detected passively), but not a protocol-level 401 challenge -- "
                "bruteforce can't test it automatically (every vendor's form "
                "endpoint/field names differ). Nothing to test."
            )
        else:
            display.error(
                "No login prompt was detected on this device. Nothing to test."
            )
        return

    http_ports = [
        p
        for p in dev.get("open_ports", [])
        if p in (
            80,
            443,
            8000,
            8080,
            8443,
            5000,
            5001,
            9000,
        )
    ]

    if not http_ports:
        if dev.get("rtsp_probes") and any(r.get("requires_auth") for r in dev["rtsp_probes"].values()):
            display.error(
                "This device only challenges for auth over RTSP (video stream), not HTTP. "
                "bruteforce only tests HTTP(S) logins -- use 'iotscan rtsp_bruteforce' instead."
            )
        else:
            display.error(
                "No HTTP(S) management port found open on this device."
            )
        return

    port = http_ports[0]

    if not os.path.isfile(args.wordlist):
        display.error(
            f"Wordlist not found: {args.wordlist}"
        )
        return

    username = "admin"

    display.info(
        f"Starting wordlist test for {dev['ip']}:{port}"
    )
    display.info(
        f"Username: {username}"
    )
    display.info(
        f"Wordlist: {args.wordlist}"
    )

    attempts = 0

    try:
        with open(
            args.wordlist,
            "r",
            encoding="utf-8",
            errors="ignore",
        ) as file:

            for line in file:

                password = line.strip()

                if not password:
                    continue

                attempts += 1

                print(
                    f"[{attempts}] Testing password: {password}"
                )

                result = creds.attempt_http_login(
                    dev["ip"],
                    port,
                    username,
                    password,
                )

                if result["success"]:
                    display.info(
                        f"Password found: {password}"
                    )

                    display.info(
                        f"Attempts: {attempts}"
                    )

                    return

                time.sleep(1.0)

                if attempts % 50 == 0:
                    display.info(
                        f"{attempts} passwords tested..."
                    )

    except OSError as exc:
        display.error(
            f"Could not read wordlist: {exc}"
        )
        return

    display.warn(
        f"No matching password found after {attempts} attempts."
    )


def cmd_rtsp_brute(args: argparse.Namespace) -> None:
    dev = _get_device_or_exit(args.id)

    if not dev.get("requires_auth"):
        display.error(
            "No login prompt was detected on this device. Nothing to test."
        )
        return

    rtsp_ports = [
        p
        for p in dev.get("open_ports", [])
        if p in (
            554,
            8554,
        )
    ]

    if not rtsp_ports:
        display.error("No open RTSP port (554/8554) found on this device.")
        return

    port = rtsp_ports[0]

    if not os.path.isfile(args.wordlist):
        display.error(
            f"Wordlist not found: {args.wordlist}"
        )
        return

    username = "admin"

    display.info(
        f"Starting wordlist test for {dev['ip']}:{port}"
    )
    display.info(
        f"Username: {username}"
    )
    display.info(
        f"Wordlist: {args.wordlist}"
    )

    attempts = 0

    try:
        with open(
            args.wordlist,
            "r",
            encoding="utf-8",
            errors="ignore",
        ) as file:

            for line in file:

                password = line.strip()

                if not password:
                    continue

                attempts += 1

                print(
                    f"[{attempts}] Testing password: {password}"
                )

                result = creds.attempt_rtsp_login(
                    dev["ip"],
                    port,
                    username,
                    password,
                )

                if result["success"]:
                    display.info(
                        f"Password found: {password}"
                    )

                    display.info(
                        f"Attempts: {attempts}"
                    )

                    return

                time.sleep(1.0)

                if attempts % 50 == 0:
                    display.info(
                        f"{attempts} passwords tested..."
                    )

    except OSError as exc:
        display.error(
            f"Could not read wordlist: {exc}"
        )
        return

    display.warn(
        f"No matching password found after {attempts} attempts."
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="iotscan",
        description=(
            "Sohryu IoT Device Scanner -- discover and fingerprint consumer IoT devices "
            "on your local network (cameras, doorbells, locks, vacuums, plugs, TVs, "
            "thermostats, printers, white goods), and check your own devices for "
            "factory-default or weak credentials (manual or wordlist-based, HTTP or RTSP)."
        ),
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_discover = sub.add_parser(
        "discover", help="Scan the local network and build a device inventory"
    )
    p_discover.add_argument("--subnet", help="CIDR to scan, e.g. 192.168.1.0/24 (default: auto-detect)")
    p_discover.add_argument("--ping-timeout", type=float, default=1.0, help="Ping timeout per host (s)")
    p_discover.add_argument("--port-timeout", type=float, default=0.6, help="TCP connect timeout per port (s)")
    p_discover.add_argument("--onvif-timeout", type=float, default=4.0, help="ONVIF WS-Discovery listen time (s)")
    p_discover.add_argument("--ssdp-timeout", type=float, default=4.0, help="SSDP/UPnP listen time (s)")
    p_discover.add_argument("--mdns-timeout", type=float, default=4.0, help="mDNS listen time (s)")
    p_discover.add_argument("--no-onvif", action="store_true", help="Skip ONVIF WS-Discovery")
    p_discover.add_argument("--no-ssdp", action="store_true", help="Skip SSDP/UPnP discovery")
    p_discover.add_argument("--no-mdns", action="store_true", help="Skip mDNS discovery")
    p_discover.set_defaults(func=cmd_discover)

    p_list = sub.add_parser("list", help="Show the cached device inventory from the last discover run")
    p_list.set_defaults(func=cmd_list)

    p_info = sub.add_parser("info", help="Show full details for one cached device")
    p_info.add_argument("id", type=int, help="Device number from 'iotscan list'")
    p_info.set_defaults(func=cmd_info)

    p_creds = sub.add_parser(
        "check-creds",
        help="Manually test one default-credential pair at a time against a device you own",
    )
    p_creds.add_argument("id", type=int, help="Device number from 'iotscan list'")
    p_creds.set_defaults(func=cmd_check_creds)

    p_brute = sub.add_parser(
        "bruteforce",
        help="Test a brute force against a device you own",
    )

    p_brute.add_argument(
        "id",
        type=int,
        help="Device number from 'iotscan list'",
    )

    p_brute.add_argument(
        "wordlist",
        type=str,
        help="Path to a wordlist file",
    )

    p_brute.set_defaults(func=cmd_brute)

    p_rtsp_brute = sub.add_parser(
        "rtsp_bruteforce",
        help="Test a wordlist-based RTSP login against a device you own",
    )
    p_rtsp_brute.add_argument("id", type=int, help="Device number from 'iotscan list'")
    p_rtsp_brute.add_argument("wordlist", type=str, help="Path to a wordlist file")
    p_rtsp_brute.set_defaults(func=cmd_rtsp_brute)

    return parser


def main(argv: list[str] | None = None) -> None:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        args.func(args)
    except KeyboardInterrupt:
        display.warn("\nInterrupted by user.")
        sys.exit(130)


if __name__ == "__main__":
    main()
