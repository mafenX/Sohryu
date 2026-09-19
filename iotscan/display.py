from __future__ import annotations

from colorama import Fore, Style, init as colorama_init

from . import classify

colorama_init(autoreset=True)


def info(msg: str) -> None:
    print(f"{Fore.CYAN}[info]{Style.RESET_ALL} {msg}")


def success(msg: str) -> None:
    print(f"{Fore.GREEN}[success]{Style.RESET_ALL} {msg}")


def warn(msg: str) -> None:
    print(f"{Fore.YELLOW}[warn]{Style.RESET_ALL} {msg}")


def error(msg: str) -> None:
    print(f"{Fore.RED}[error]{Style.RESET_ALL} {msg}")


def print_device_list(devices: list[dict]) -> None:
    if not devices:
        warn("No devices in cache. Run 'iotscan discover' first.")
        return
    print()
    for idx, d in enumerate(devices, start=1):
        cat = classify.category_name(d.get("category_id", 10))
        if d.get("requires_auth"):
            auth_type = d.get("auth_type") or ""
            login = f"yes ({auth_type})" if auth_type else "yes"
        elif d.get("form_login_hint"):
            login = "yes (form detected, untested)"
        else:
            login = "no / not detected"
        two_fa = "yes (heuristic)" if d.get("two_factor_hint") else "no"
        print(
            f"  {Fore.YELLOW}{idx}{Style.RESET_ALL}) "
            f"{Fore.WHITE}{Style.BRIGHT}{cat}{Style.RESET_ALL}  "
            f"({Fore.CYAN}{d.get('ip','?')}{Style.RESET_ALL}, "
            f"vendor: {d.get('vendor','Unknown')}, "
            f"login-protected: {login}, "
            f"2FA hint: {two_fa}, "
            f"confidence: {d.get('confidence','low')})"
        )
    print()


def print_device_detail(d: dict) -> None:
    print()
    print(f"{Fore.WHITE}{Style.BRIGHT}Device Detail{Style.RESET_ALL}")
    print(f"  IP:         {d.get('ip')}")
    print(f"  MAC:        {d.get('mac') or 'unknown'}")
    print(f"  Vendor:     {d.get('vendor')}")
    print(f"  Category:   {classify.category_name(d.get('category_id', 10))}")
    print(f"  Confidence: {d.get('confidence')}")
    print(f"  Open ports: {', '.join(str(p) for p in d.get('open_ports', [])) or 'none found'}")
    if d.get("requires_auth"):
        print(f"  Login:      REQUIRED -- 401 challenge observed ({d.get('auth_type') or 'unknown scheme'})")
    elif d.get("form_login_hint"):
        print(f"  Login:      form detected (password input field seen, passive heuristic, untested)")
    else:
        print(f"  Login:      not detected (no 401/WWW-Authenticate response observed)")
    if d.get("two_factor_hint"):
        print(f"  2FA hint:   page wording suggests possible 2FA (heuristic, unverified)")
    if d.get("onvif"):
        o = d["onvif"]
        print(f"  ONVIF:      manufacturer={o.get('manufacturer','?')} model={o.get('model','?')}")
    if d.get("ssdp"):
        s = d["ssdp"]
        print(f"  SSDP:       {s.get('friendly_name','?')} ({s.get('manufacturer','?')} {s.get('model_name','?')})")
    if d.get("mdns"):
        print(f"  mDNS:       {', '.join(d['mdns'])}")
    if d.get("rtsp_probes"):
        for rport, rinfo in d["rtsp_probes"].items():
            if rinfo.get("requires_auth"):
                print(f"  RTSP:port {rport} -- login REQUIRED ({rinfo.get('auth_type') or 'unknown scheme'})")
            elif rinfo.get("reachable"):
                print(f"  RTSP:port {rport} -- reachable, no auth challenge observed")
    print()
