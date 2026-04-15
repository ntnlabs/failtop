# failtop

A real-time security dashboard for Linux servers, built for the terminal. Like `htop`, but for your attack surface.

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

## What it shows

| Panel | Data |
|---|---|
| Header | NIC name, live in/out throughput, public IP, local IP |
| Stats | UFW/iptables blocked count, fail2ban banned/jails, SSH fails, active sessions |
| NIC graph | Throughput sparkline (last 60 samples) |
| Top sources | Country bar chart with attack percentages |
| Blocked IPs | Scrollable table: IP, country, city, ASN/org, source (UFW/SSH/f2b), time ago |
| Auth log | Live-tailing auth log, color-coded (red=fail, green=accepted, yellow=ban) |

## Requirements

- Linux (amd64 or arm64)
- Must be run as **root**
- One of: UFW, firewalld, or iptables (auto-detected)
- Optional: fail2ban, MaxMind GeoLite2 mmdb files

## Install

```bash
git clone https://github.com/ntnlabs/failtop
cd failtop
make install        # builds and installs to /usr/local/bin/failtop
```

Or just build:

```bash
make build
sudo ./failtop
```

## Usage

```
sudo failtop [flags]

Flags:
  -interface      NIC interface to monitor (default: auto-detect)
  -refresh        Refresh interval in seconds (default: 2)
  -auth-log       Auth log path override (default: auto-detect)
  -public-ip-url  URL to fetch public IP ("off" to disable)
  -mmdb-city      Path to GeoLite2-City.mmdb
  -mmdb-asn       Path to GeoLite2-ASN.mmdb
```

Key bindings: `q` quit · `r` force refresh · `↑↓` scroll blocked IPs

## Configuration

Optional config file at `~/.config/failtop/config.toml`:

```toml
interface        = "eth0"    # NIC to monitor (default: auto-detect)
refresh_interval = 2         # seconds

[mmdb]
city = "/path/to/GeoLite2-City.mmdb"
asn  = "/path/to/GeoLite2-ASN.mmdb"
```

CLI flags override config file values.

## Geolocation (optional)

failtop uses [MaxMind GeoLite2](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data) offline databases for country, city, and ASN lookup. These are free but require registration.

Download `GeoLite2-City.mmdb` and `GeoLite2-ASN.mmdb`, then point failtop at them via config or flags. If the files are absent, the tool runs normally — geo columns just show `-`.

PTR (reverse DNS) is looked up asynchronously per new IP and fills in as results arrive.

## Cross-distro support

| Concern | Behavior |
|---|---|
| Auth log | Probes `/var/log/auth.log` → `/var/log/secure` → journald fallback |
| Firewall | Auto-detects UFW → firewalld → iptables |
| fail2ban | Standard socket path, works the same everywhere |
| Missing source | Panel shows reason, tool continues — no crash |

Tested on Ubuntu, Debian, Fedora, RHEL, Alpine, and Mint.

## Build from source

No CGO. No external runtime dependencies. Pure Go.

```bash
go build -ldflags "-s -w" -o failtop .
```

Requires Go 1.24+.

## License

See [LICENSE](LICENSE).
