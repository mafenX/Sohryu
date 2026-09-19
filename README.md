# Sohryu IoT Device Scanner

A terminal-based **IoT device discovery & inventory tool** for your local network.

Unlike `nmap`, which just tells you what ports are open, `Sohryu` tries to
answer *"what kind of smart device is this, and is it still using a factory
default password?"* for the consumer IoT devices on your LAN: security
cameras & video doorbells, smart locks, robot vacuums, smart plugs, security
sensors, smart TVs, thermostats/HVAC/HRV-ERV units, printers, and white
goods (fridges, washers).

## How this compares to similar tools

A few other open-source projects overlap with parts of what Sohryu does:

| Project | Focus | How Sohryu differs |
|---|---|---|
| [onvifscan](https://github.com/BrownFineSecurity/onvifscan) | ONVIF discovery + brute force | Camera-only; Sohryu adds SSDP, mDNS, RTSP, and consumer-category classification |
| [CamSniff](https://github.com/John0n1/CamSniff) | Multi-protocol camera recon (ONVIF/RTSP/HLS/WebRTC) | Much broader scope but orchestrates nmap/masscan/tshark; Sohryu is pure Python, no external tool dependency |
| [NetzwerkScan](https://github.com/Kroste/NetzwerkScan) | Discovery + default-cred checks across RTSP/HTTP/Telnet/FTP | Conceptually closest match, but a C#/.NET desktop GUI app, not a Python CLI |
| [ThopterIoT](https://github.com/MentatNOC/ThopterIoT) | ONVIF/SSDP/mDNS + OUI discovery | Discovery only, no credential testing at all |
| [IoT-SecurityChecker](https://github.com/c0mix/IoT-SecurityChecker) | masscan-based scan + brute force + exploits | Academic/exploit-focused, depends on masscan |

What's distinct about Sohryu: combining ONVIF + SSDP + mDNS + a passive RTSP
auth probe in one dependency-light Python CLI; a deliberate split between
manual, confirm-every-attempt credential testing (`check-creds`) and
automated wordlist testing (`bruteforce` / `rtsp_bruteforce`); consumer-facing
device categorization; a passive 2FA-wording heuristic; and a bundled
~90k-entry offline MAC vendor database.

## How it works

`iotscan discover` combines five signals:

1. **ONVIF WS-Discovery** — the same multicast probe protocol used by tools
   like `pwneye`/`onvif-discovery` to find IP cameras and NVRs, then reads
   Manufacturer/Model via the unauthenticated `GetDeviceInformation` call.
2. **SSDP/UPnP** — `M-SEARCH` multicast, used by smart TVs, printers, media
   renderers, and many hub-style devices, followed by fetching each
   device's UPnP description XML.
3. **mDNS/Bonjour** *(optional, requires `zeroconf`)* — catches
   HomeKit accessories, Chromecast/Android TVs, AirPlay, network printers.
4. **Ping sweep + targeted TCP port scan + HTTP banner grab** — catches
   everything else and enriches devices already found via the above.
5. **RTSP auth probe** — a single unauthenticated `DESCRIBE` request to any
   open 554/8554 port, checking for RTSP's own `401 + WWW-Authenticate`
   challenge (RTSP borrows this from HTTP). Catches cameras that only
   protect the video stream and expose no (or no login-protected) web UI.

Every discovered device is then classified into one of the categories above
using keyword/heuristic matching over vendor, MAC OUI, HTTP banners, and
ONVIF/SSDP metadata, and cached to `~/.iotscan/devices.json`.

MAC vendor lookup (`iotscan/oui.py`) is backed by a bundled, ~90,000-entry
offline database (`iotscan/data/oui.txt`, sourced from IEEE registration
records via the public [OUI-Master-Database](https://github.com/Ringmast4r/OUI-Master-Database)
project) rather than a small hand-picked list, and correctly handles IEEE's
24-bit/28-bit/36-bit allocation sizes via bitmask matching, not naive string
prefixing.

### What "login-protected" and "2FA hint" actually mean

- **login-protected** has two tiers. The strong signal is a *real, passive
  observation*: during discovery, iotscan requests each device's web port
  and marks it `yes (Basic/Digest/...)` if the device itself responded with
  `HTTP 401` plus a `WWW-Authenticate` header, or the RTSP equivalent on
  port 554/8554 (some cameras only protect the video stream, not any web
  UI). The weaker signal is `yes (form detected, untested)` — the page body
  contains a password input field but never issued a protocol-level 401,
  which usually means a JS/form-based login (see the limitations section
  below). It is not a guess based on device category — a device with
  neither signal correctly shows `no / not detected`.
- **2FA hint** is a *best-effort heuristic, not a verified fact*. iotscan
  scans the login page's HTML for wording like "verification code",
  "authenticator app", "2FA", etc. It cannot detect 2FA that only appears
  *after* a correct password (since that would require actually logging in,
  which this tool intentionally does not automate), and a page could use
  that wording without truly enforcing a second factor. Treat "yes" as "go
  check this device by hand," not as confirmed 2FA.

## Installation

```bash
git clone https://github.com/mafenX/Sohryu.git
cd Sohryu

# Recommended: use a virtual environment (avoids "externally-managed-environment"
# errors on newer Debian/Ubuntu/Kali systems where pip refuses system-wide installs)
python3 -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate

pip install -r requirements.txt
pip install -e .                # installs the `iotscan` command
# or just: python -m iotscan ...
```

Each time you come back in a new terminal, reactivate the virtual environment
first with `source venv/bin/activate` (or `venv\Scripts\activate` on Windows)
before running `iotscan`.



## Usage

```bash
iotscan --help

# 1) Discover devices on your LAN (auto-detects your subnet)
iotscan discover
iotscan discover --subnet 192.168.1.0/24
iotscan discover --no-mdns --onvif-timeout 6

# 2) List the cached inventory (numbered, like the discover output)
iotscan list

#   1) Security Camera / Video Doorbell  (192.168.1.139, vendor: Tenda, login-protected: yes (Basic), 2FA hint: no, confidence: high)
#   2) Robot Vacuum                      (192.168.1.60,  vendor: Roborock, login-protected: yes (Digest), 2FA hint: no, confidence: high)
#   3) Printer                           (192.168.1.50,  vendor: HP, login-protected: no / not detected, 2FA hint: no, confidence: medium)

# 3) Show full detail for one device (by its list number)
iotscan info 1

# 4) Manually check YOUR OWN device for a default/weak password.
#    One credential pair at a time, you confirm every single attempt.
iotscan check-creds 1
```

### `check-creds` — manual, one-attempt-at-a-time credential check

This is deliberately **not** an automated brute-forcer. Each run:

1. Shows the well-known factory-default credential pairs for that device
   category (or lets you type a custom username/password).
2. Asks you to pick **one** pair.
3. Requires you to press **Enter to confirm** before it sends that single
   login request.
4. Reports success/failure, then stops and asks whether you want to try
   another pair — nothing loops automatically.

Use this only against devices you own or are explicitly authorized to test.

### `bruteforce` / `rtsp_bruteforce` — wordlist-based login testing

Two automated commands exist for testing a full wordlist against a single
fixed username (`admin`). Unlike `check-creds`, they do not pause for
confirmation between attempts — use them deliberately, only against your own
devices, and start with a short wordlist to see how the device reacts before
running a large one (many devices lock out or rate-limit after a handful of
failed attempts):

```bash
# HTTP(S) login (web management UI)
iotscan bruteforce 1 /path/to/wordlist.txt

# RTSP login (video stream, e.g. cameras with no exposed web UI)
iotscan rtsp_bruteforce 1 /path/to/wordlist.txt
```

## Project layout

```
iotscan/
  cli.py            argparse CLI: discover / list / info / check-creds / bruteforce / rtsp_bruteforce
  network_utils.py  subnet detection, ping sweep, ARP table
  portscan.py       targeted TCP port scan + HTTP banner/auth/2FA-hint grabbing
  onvif_probe.py    ONVIF WS-Discovery + GetDeviceInformation
  ssdp_probe.py     SSDP/UPnP M-SEARCH + description XML parsing
  mdns_probe.py     optional mDNS/Bonjour discovery (needs `zeroconf`)
  rtsp_probe.py     passive RTSP auth challenge detection
  classify.py       device categories + classification heuristics
  creds.py          known default-credential reference list + single-attempt login
  cache.py          JSON persistence of the last discover run
  display.py        colored terminal output
  oui.py            offline MAC vendor lookup (bundled ~90k-entry database)
  data/oui.txt      bundled vendor database (IEEE-sourced)
```

## Troubleshooting: "everything shows Unknown IoT Device"

- **Running inside a VM?** ONVIF, SSDP, and mDNS discovery all rely on
  multicast traffic. If your VM's network adapter is set to **NAT**, that
  multicast traffic generally can't reach your real LAN. Switch it to
  **Bridged** networking so the VM gets its own address on your physical
  network, then re-run `iotscan discover`.
- **No smart devices on that subnet.** If the only hosts found are your
  router and a phone/laptop, "Unknown" is the correct answer — those
  aren't in the categories this tool targets. Try it on a network that
  actually has a camera, smart plug, etc.
- **MAC vendor still says Unknown for a device you know the brand of?**
  The bundled database is large (~90k entries) but IEEE registrations are
  never 100% complete/current, and some vendors register through a reseller
  under a different name. `iotscan info <id>` will still show any
  ONVIF/SSDP-reported manufacturer name even if the MAC lookup misses.

## Notes / limitations

- Ping sweeping and port scanning use plain sockets/OS `ping`, so no root
  privileges or `scapy`/raw-socket setup are required.
- Classification is heuristic — always double-check `iotscan info <id>`
  before trusting the category label.
- **HTML/JS form-based logins are detected passively, but not testable.**
  Protocol-level detection (`401 + WWW-Authenticate`) can't see a login that
  a device implements as a JavaScript `fetch()`/`XHR` POST to an
  app-specific endpoint — the root page still returns a plain `200 OK`. To
  catch these anyway, iotscan also scans the page body for an
  `<input type="password">` field. When only this heuristic fires (no
  protocol-level 401), a device shows as `login-protected: yes (form
  detected, untested)`. This is still just a signal to go check the device
  by hand: every vendor's form endpoint, field names, CSRF handling, and
  response format (cookie vs. JWT vs. custom header) differ, so there's no
  generic way to actually submit a login for it -- `check-creds` and
  `bruteforce` will tell you this and decline rather than attempt it.
- **RTSP-only devices are handled by a separate command.** `check-creds`
  and `bruteforce` only send HTTP(S) login attempts. If a device is flagged
  `login-protected: yes` purely from its RTSP probe (no open HTTP
  management port), those two commands will tell you so and decline —
  use `rtsp_bruteforce` for that device instead (see above).
- Only run `check-creds`/`bruteforce`/`rtsp_bruteforce` against your own equipment.
