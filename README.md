# Monitor Suite

A single Flask app that unifies three monitoring tools behind one sign-in
gate and one light-themed dashboard:

| Module | URL | What it does |
|---|---|---|
| **Web Monitor** | `/web-monitor` | Discovers subdomains for a domain (via crt.sh) and checks HTTP status, latency, and SSL certificate health for each one. |
| **Signal Monitor** | `/signal-monitor` | Scans nearby Wi-Fi networks (signal %, channel, security) and inventories devices/servers on your own local network, with history + alerts. |
| **Server Monitor** | `/server-monitor` | Public/private IP intelligence (geolocation, WHOIS, open ports, HTTP/TLS, SNMP), a server registry with continuous background monitoring, and VPN-based private-IP scanning. |

Flow: **`/` (sign in / sign up / continue as guest) → `/dashboard` (pick a
tool) → the tool itself.** Every module route is behind the login gate,
including guest sessions.

## 1. Install

```bash
python -m venv venv
source venv/bin/activate      # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

Requires Python 3.10+.

## 2. Run

```bash
python app.py
```

Open **http://127.0.0.1:5000** in your browser.

## 3. Notes on running each module for real

These tools call out to the local OS and the network, so a few things to
know when actually using them (not needed just to browse the UI):

- **Web Monitor** needs outbound internet access (it queries `crt.sh` for
  subdomains and then makes live HTTP/TLS requests to each one).
- **Signal Monitor** shells out to OS networking tools — `arp`/`ip
  neighbor`, `ping`, and platform Wi-Fi tools (`netsh` on Windows, `nmcli`
  or `iwlist` on Linux, `airport`/`networksetup` on macOS). If a tool
  isn't installed, that specific feature degrades gracefully and logs a
  warning instead of crashing — install the relevant OS package (e.g.
  `net-tools`/`iproute2` + `NetworkManager` on Linux) for full results.
  It only scans **your own** active network, never someone else's.
- **Server Monitor**'s VPN scan path (`/server-monitor` → private IP)
  needs the real `openvpn` binary installed and on `PATH`. Its SNMP
  lookups are read-only and only run if you supply a community string.
  Only point it at IPs/servers you own or are authorized to monitor.

None of this affects sign-in, the dashboard, or browsing between modules
— those work anywhere Flask runs.

## 4. Project layout

```
app.py                     # entry point: auth, dashboard, blueprint registration
auth.py                    # local JSON-file user store (sign up / sign in)
requirements.txt
data/                      # created at runtime: users.json, signalwatch_history.db, exports
templates/
  login.html               # sign in / sign up / continue as guest
  dashboard.html           # the 3-card landing page after login
  partials/navbar.html     # shared top nav included on every module page
  web_monitor.html
  signal_monitor.html
  server_monitor/console.html
  server_monitor/servers.html
modules/
  web_monitor/             # Flask blueprint + ported monitor.py (unchanged logic)
  signal_monitor/          # Flask blueprint + core.py (ported scanning engine)
  server_monitor/          # Flask blueprint + config.py + monitor/ package (unchanged logic)
```

Each module's original scanning/checking logic was carried over as-is —
only the web layer changed: the standalone per-tool servers (which each
expected to own port 5000/8000 and the URL root) were rewired into Flask
blueprints mounted at `/web-monitor`, `/signal-monitor`, and
`/server-monitor`, and every front-end `fetch()` call was repointed at
its module's new prefixed API path so nothing collides.

## 5. Accounts

Sign-up accounts are stored in `data/users.json` with hashed passwords
(Werkzeug's `generate_password_hash`). This is a lightweight local store,
not meant for multi-server/production deployment — swap in a real
database if you need that. "Continue as guest" skips account creation
entirely and just opens a session.
