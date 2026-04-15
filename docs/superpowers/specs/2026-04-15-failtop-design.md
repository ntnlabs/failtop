# failtop — Design Spec

**Date:** 2026-04-15
**Status:** Approved

## Overview

`failtop` is a single Go binary, root-required, real-time security dashboard for Linux. It renders directly to the terminal using `tcell`, polling multiple data sources concurrently via goroutines. No daemon, no background service — run it and see what's happening on your server.

**Target platforms:** Any Linux distro — Ubuntu, Debian, Mint, Fedora, RHEL, Alpine, and similar.
**Runtime requirement:** Must be run as root. Fails hard if not.
**Single binary:** No CGO, no external runtime dependencies. Drop in `/usr/local/bin/failtop` and run.

---

## Architecture

```
failtop/
├── main.go               # entry point, root check, config load, TUI start
├── config/               # config file + flag parsing (TOML)
├── ui/                   # tcell rendering engine, layout, draw loop
│   ├── layout.go         # panel geometry, resize handling
│   └── widgets/          # border, table, bar chart, scrolltext primitives
├── sources/              # one package per data source
│   ├── ufw/              # parse ufw/firewalld/iptables
│   ├── fail2ban/         # fail2ban-client socket queries
│   ├── authlog/          # tail auth log with inotify
│   ├── nic/              # /proc/net/dev polling
│   └── geo/              # MaxMind City + ASN mmdb + PTR DNS
└── state/                # shared in-memory state, goroutine-safe
```

Each `sources/` package runs a goroutine writing to a shared state struct (protected by `sync.RWMutex`). The UI draw loop reads state on a configurable tick (default 2s) and redraws affected panels. Sources write to state; UI reads state. No channels threading through the whole app.

### Startup Flow

1. Check `os.Getuid() == 0` — fail hard with clear message if not root
2. Load config: file → CLI flags → defaults
3. Probe all data sources, print detection summary to stderr before TUI starts
4. Open mmdb files if configured — warn and skip geo features if missing, do not fail
5. Launch `tcell`, start all source goroutines
6. Draw loop begins

---

## UI Layout

Built on raw `tcell` for full control over rendering. No TUI framework.

```
┌─────────────────────────────────────────────────────────────────────┐
│ failtop  eth0 ▲ 1.2MB/s ▼ 340KB/s │ pub: 1.2.3.4  local: 192.168.1.10 │
├─────────────────┬───────────────────────────────────────────────────┤
│ UFW / FAIL2BAN  │ BLOCKED IPs                                       │
│ Blocked:  1,247 │ 185.220.101.45  RU Moscow      AS1234  SSH  2m   │
│ Banned:      38 │ 103.167.34.21   CN Shanghai    AS4134  UFW  5m   │
│ Jails:        4 │ 45.155.205.233  NL Amsterdam   AS9009  SSH  7m   │
│ SSH fails:  143 │ 91.134.232.10   FR Paris       AS5410  UFW 12m   │
│ Sessions:     2 │ ...                                               │
├─────────────────┤                                                   │
│ NIC GRAPH       │                                                   │
│ ▲ ▄▆█▅▃▆▇█▄▅  │                                                   │
│ ▼ ▂▃▄▂▅▃▂▄▃▂  ├───────────────────────────────────────────────────┤
│                 │ AUTH LOG                                          │
├─────────────────│ 12:01 FAIL  root        185.220.101.45           │
│ TOP SOURCES     │ 12:00 OK    peter       publickey                 │
│ RU ████████ 34% │ 11:59 FAIL  admin       103.167.34.21            │
│ CN ██████   22% │ 11:58 BAN   fail2ban    45.155.205.233           │
│ NL ████     15% │ ...                                               │
│ US ███      11% └───────────────────────────────────────────────────┤
│ IR ██        8% │ [q]uit  [r]efresh  [↑↓] scroll IPs               │
└─────────────────┴───────────────────────────────────────────────────┘
```

### Panels

| Panel | Location | Content |
|---|---|---|
| Header bar | Full width, top | NIC name, live in/out throughput, public IP, local IP |
| Stats | Sidebar top | UFW + fail2ban counters (blocked, banned, jails, SSH fails, sessions) |
| NIC graph | Sidebar mid | Throughput sparkline using block/braille chars |
| Top sources | Sidebar bottom | Country bar chart: flag, name, heat bar, %, count |
| Blocked IPs | Main top | Scrollable table: IP, country, city, ASN/org, source (UFW/SSH/f2b), time ago |
| Auth log | Main bottom | Tailing log, color-coded: red=fail, green=accepted, yellow=ban |
| Footer | Full width, bottom | Keybinding hints |

**Key bindings:** `q` quit, `r` force refresh, `↑↓` scroll blocked IPs table.

---

## Data Sources

### Firewall (UFW / firewalld / iptables)

Auto-detected at startup in order: `ufw` → `firewalld` → `iptables`/`nftables`. Each implements a common `FirewallSource` interface. Live block events parsed from `/var/log/ufw.log` or `/var/log/kern.log` depending on what's available. Summary stats via CLI (`ufw status verbose`, `firewall-cmd --list-all`, etc.) polled every refresh cycle.

### fail2ban

Queried via `fail2ban-client status` and `fail2ban-client status <jail>` for each jail. Gives banned IP list, counts per jail. Socket path is standard across distros. Polled every refresh cycle.

### Auth Log

Auto-detected log path in order:
1. `/var/log/auth.log` (Debian/Ubuntu/Mint)
2. `/var/log/secure` (Fedora/RHEL)
3. `journalctl -f -u sshd` (fallback for journald-only systems, e.g. Alpine)

For flat file paths (1, 2): tailed in real-time using Linux `inotify` (`golang.org/x/sys/unix`), no polling delay. For the journald fallback (3): `journalctl -f` is launched as a subprocess and its stdout is read line by line.

Parsed with regex to extract: timestamp, event type (Accepted/Failed/Invalid/Ban), user, source IP, auth method.

### NIC

Read `/proc/net/dev` every second, compute delta bytes/s per interface. Auto-detects primary non-loopback interface. Public IP fetched once at startup (configurable URL or disabled). Local IP from interface addresses.

### Geo / ASN / PTR

- **GeoLite2-City.mmdb** — country, city (optional, skip if not configured)
- **GeoLite2-ASN.mmdb** — ASN number, org name (optional, skip if not configured)
- **PTR DNS** — reverse lookup fired in background goroutine per new unique IP, fills in async
- All results cached in-memory for the session
- If mmdb files are absent: columns show `-`, tool continues normally

---

## Cross-Distro Portability

| Concern | Approach |
|---|---|
| Auth log path | Probe known paths, fall back to journald |
| Firewall | Detect ufw → firewalld → iptables/nftables, use adapter pattern |
| fail2ban | Same everywhere |
| mmdb | Optional, warn if configured but missing |
| Unavailable source | Panel shows `[ source unavailable: <reason> ]`, not a crash |

---

## Configuration

**File:** `~/.config/failtop/config.toml`
**CLI flags:** override any config file value
**Precedence:** CLI flags > config file > defaults

```toml
interface        = "eth0"       # NIC to monitor (default: auto-detect)
refresh_interval = 2            # seconds
auth_log         = ""           # override auto-detected path
public_ip_url    = ""           # URL to fetch public IP (empty = use https://api.ipify.org, "off" = disable)

[mmdb]
city = "/path/to/GeoLite2-City.mmdb"
asn  = "/path/to/GeoLite2-ASN.mmdb"
```

---

## Build & Distribution

- `go build ./...` — single static binary, no CGO
- Pure Go dependencies: `tcell`, `oschwald/geoip2-golang`, `BurntSushi/toml`
- Target architectures: `linux/amd64`, `linux/arm64`
- `Makefile` with `build`, `install` (`/usr/local/bin/`), `clean` targets
- No systemd unit, no install script required

---

## Testing

- Unit tests for parsing logic in each `sources/` package: UFW log regex, auth.log parser, `/proc/net/dev` delta math, firewall auto-detection
- Sample log files in `testdata/` for each distro variant
- `ui/` package not unit tested — validated by running
- No mocking of system calls — test against real fixtures (log file samples)
