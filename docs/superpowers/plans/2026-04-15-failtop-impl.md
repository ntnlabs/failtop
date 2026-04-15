# failtop Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a single Go binary, root-required, real-time security dashboard for Linux that shows UFW/firewall stats, fail2ban stats, SSH/auth log events, blocked IPs with geo data, and NIC throughput in a tcell TUI.

**Architecture:** Multiple goroutines (one per data source) write to a shared `AppState` struct protected by `sync.RWMutex`. The tcell draw loop reads state on a configurable tick (default 2s). No channels between sources and UI — sources write to state, UI reads state. Geo enrichment runs as a periodic scan over new BlockedIP entries.

**Tech Stack:** Go 1.22, `github.com/gdamore/tcell/v2` (TUI), `github.com/oschwald/geoip2-golang` (MaxMind), `github.com/BurntSushi/toml` (config), `golang.org/x/sys/unix` (inotify).

---

## File Map

```
failtop/
├── main.go                          # root check, config load, probe sources, launch TUI
├── go.mod
├── Makefile
├── .gitignore
├── config/
│   ├── config.go                    # Config struct, Load() with file+flag precedence
│   └── config_test.go
├── state/
│   └── state.go                     # AppState, all shared types, RWMutex accessors
├── sources/
│   ├── firewall/
│   │   ├── source.go               # Source interface, Stats struct
│   │   ├── detect.go               # Detect() → Source or nil
│   │   ├── ufw.go                  # UFWSource: ufw status verbose parser
│   │   ├── firewalld.go            # FirewalldSource: firewall-cmd parser
│   │   ├── iptables.go             # IPTablesSource: iptables -L -n -v parser
│   │   └── firewall_test.go        # parse tests with fixture strings
│   ├── fail2ban/
│   │   ├── fail2ban.go             # Poll(): run fail2ban-client, parse output
│   │   └── fail2ban_test.go        # parse tests
│   ├── authlog/
│   │   ├── parser.go               # ParseLine(line string) *state.AuthEvent
│   │   ├── tailer.go               # inotify-based file tailer → chan string
│   │   ├── journald.go             # journalctl subprocess reader → chan string
│   │   ├── detect.go               # DetectPath() string, DetectMode() string
│   │   ├── run.go                  # Run(cfg, state): select tailer/journald, parse, update state
│   │   └── authlog_test.go         # ParseLine tests, DetectPath logic tests
│   ├── nic/
│   │   ├── nic.go                  # Run(cfg, state): /proc/net/dev + public IP
│   │   └── nic_test.go             # ParseProcNetDev tests
│   └── geo/
│       ├── geo.go                  # Geo struct, Open(), Enrich(ip) GeoResult, cached PTR
│       └── geo_test.go             # Enrich tests with mock/nil readers
├── ui/
│   ├── app.go                      # App struct, Run(), draw tick, tcell event loop
│   ├── layout.go                   # Geometry struct, Recalculate(w,h int)
│   └── widgets/
│       ├── draw.go                 # Box(), Text(), HLine(), VLine() helpers
│       ├── table.go                # Table struct, Draw(), ScrollUp/Down()
│       ├── barchart.go             # BarChart(), single function
│       ├── sparkline.go            # Sparkline(), single function
│       └── scrolltext.go          # ScrollText struct, Append(), Draw()
└── testdata/
    ├── auth.log.ubuntu
    ├── auth.log.fedora
    ├── ufw.log
    └── proc_net_dev
```

---

## Task 1: Project Scaffold

**Files:**
- Create: `go.mod`
- Create: `Makefile`
- Create: `.gitignore`
- Create: `main.go` (stub only)

- [ ] **Step 1: Initialize go module**

```bash
cd /home/peter/AI/failtop
go mod init failtop
```

Expected: creates `go.mod` with `module failtop` and `go 1.22`

- [ ] **Step 2: Add dependencies**

```bash
go get github.com/gdamore/tcell/v2@latest
go get github.com/oschwald/geoip2-golang@latest
go get github.com/BurntSushi/toml@latest
go get golang.org/x/sys@latest
go mod tidy
```

- [ ] **Step 3: Write main.go stub**

```go
// main.go
package main

import (
	"fmt"
	"os"
)

func main() {
	if os.Getuid() != 0 {
		fmt.Fprintln(os.Stderr, "failtop: must be run as root")
		os.Exit(1)
	}
	fmt.Println("failtop starting...")
}
```

- [ ] **Step 4: Write Makefile**

```makefile
# Makefile
BINARY  := failtop
PREFIX  := /usr/local/bin
LDFLAGS := -s -w

.PHONY: build install clean

build:
	go build -ldflags "$(LDFLAGS)" -o $(BINARY) .

install: build
	install -m 0755 $(BINARY) $(PREFIX)/$(BINARY)

clean:
	rm -f $(BINARY)
```

- [ ] **Step 5: Write .gitignore**

```
failtop
.superpowers/
*.mmdb
```

- [ ] **Step 6: Verify build**

```bash
go build ./...
```

Expected: no errors, binary `failtop` not yet produced (just checking compilation)

- [ ] **Step 7: Commit**

```bash
git init
git add go.mod go.sum main.go Makefile .gitignore
git commit -m "feat: project scaffold with go module and Makefile"
```

---

## Task 2: State Package

**Files:**
- Create: `state/state.go`

- [ ] **Step 1: Write state/state.go**

```go
// state/state.go
package state

import (
	"sync"
	"time"
)

const (
	MaxAuthEvents = 200
	MaxNICHistory = 60
)

// BlockedIP represents an IP that was banned or blocked by any source.
type BlockedIP struct {
	IP      string
	Country string
	City    string
	ASN     string
	Org     string
	PTR     string
	Source  string // "ufw", "f2b", "ssh"
	SeenAt  time.Time
}

// AuthEvent is a single parsed line from auth.log.
type AuthEvent struct {
	Time   time.Time
	Type   string // "OK", "FAIL", "INVALID", "BAN"
	User   string
	IP     string
	Method string // populated for "OK" events (e.g. "publickey")
}

// NICStats holds current interface throughput.
type NICStats struct {
	Interface string
	RxRate    float64 // bytes/s
	TxRate    float64
	PublicIP  string
	LocalIP   string
}

// FirewallStats holds summary counters from the active firewall.
type FirewallStats struct {
	Type    string // "ufw", "firewalld", "iptables", ""
	Blocked int
	Allowed int
	Rules   int
}

// JailStats holds fail2ban jail details.
type JailStats struct {
	Name      string
	Banned    int
	BannedIPs []string
}

// Fail2BanStats holds aggregate fail2ban data.
type Fail2BanStats struct {
	Jails       []JailStats
	TotalBanned int
}

// GeoEntry is one row in the top-sources bar chart.
type GeoEntry struct {
	Country string
	Count   int
	Pct     float64
}

// AppState is the single shared state struct. All sources write to it;
// the UI reads from it. Callers must hold the appropriate lock.
type AppState struct {
	mu sync.RWMutex

	Firewall  FirewallStats
	Fail2Ban  Fail2BanStats

	AuthEvents  []AuthEvent // ring buffer, last MaxAuthEvents entries
	SSHFails    int
	SSHSessions int

	NIC       NICStats
	NICRxHist []float64 // last MaxNICHistory rate samples (1s apart)
	NICTxHist []float64

	BlockedIPs []BlockedIP
	TopSources []GeoEntry

	// Source availability — set during probe, shown in panels if false.
	FirewallAvail bool
	FirewallMsg   string
	Fail2BanAvail bool
	Fail2BanMsg   string
	AuthLogAvail  bool
	AuthLogMsg    string
}

func New() *AppState {
	return &AppState{
		NICRxHist: make([]float64, 0, MaxNICHistory),
		NICTxHist: make([]float64, 0, MaxNICHistory),
	}
}

func (s *AppState) Lock()    { s.mu.Lock() }
func (s *AppState) Unlock()  { s.mu.Unlock() }
func (s *AppState) RLock()   { s.mu.RLock() }
func (s *AppState) RUnlock() { s.mu.RUnlock() }

// AddAuthEvent appends to the ring buffer, evicting oldest if at capacity.
func (s *AppState) AddAuthEvent(e AuthEvent) {
	if len(s.AuthEvents) >= MaxAuthEvents {
		s.AuthEvents = s.AuthEvents[1:]
	}
	s.AuthEvents = append(s.AuthEvents, e)
}

// AddOrUpdateBlockedIP adds a new BlockedIP or updates SeenAt if IP already exists.
func (s *AppState) AddOrUpdateBlockedIP(b BlockedIP) {
	for i, existing := range s.BlockedIPs {
		if existing.IP == b.IP {
			s.BlockedIPs[i].SeenAt = b.SeenAt
			if b.Source != "" {
				s.BlockedIPs[i].Source = b.Source
			}
			return
		}
	}
	s.BlockedIPs = append([]BlockedIP{b}, s.BlockedIPs...)
	// Keep list bounded to 500
	if len(s.BlockedIPs) > 500 {
		s.BlockedIPs = s.BlockedIPs[:500]
	}
}

// AppendNICHistory appends a rate sample, evicting oldest beyond MaxNICHistory.
func (s *AppState) AppendNICHistory(rx, tx float64) {
	if len(s.NICRxHist) >= MaxNICHistory {
		s.NICRxHist = s.NICRxHist[1:]
		s.NICTxHist = s.NICTxHist[1:]
	}
	s.NICRxHist = append(s.NICRxHist, rx)
	s.NICTxHist = append(s.NICTxHist, tx)
}

// RecalcTopSources recomputes TopSources from the current BlockedIPs list.
// Must be called with the write lock held.
func (s *AppState) RecalcTopSources() {
	counts := make(map[string]int)
	total := 0
	for _, b := range s.BlockedIPs {
		if b.Country != "" {
			counts[b.Country]++
			total++
		}
	}
	s.TopSources = make([]GeoEntry, 0, len(counts))
	for country, count := range counts {
		pct := 0.0
		if total > 0 {
			pct = float64(count) / float64(total) * 100
		}
		s.TopSources = append(s.TopSources, GeoEntry{Country: country, Count: count, Pct: pct})
	}
	// Sort descending by count
	for i := 0; i < len(s.TopSources); i++ {
		for j := i + 1; j < len(s.TopSources); j++ {
			if s.TopSources[j].Count > s.TopSources[i].Count {
				s.TopSources[i], s.TopSources[j] = s.TopSources[j], s.TopSources[i]
			}
		}
	}
}
```

- [ ] **Step 2: Verify compilation**

```bash
go build ./state/...
```

Expected: no errors.

- [ ] **Step 3: Commit**

```bash
git add state/state.go
git commit -m "feat: state package with AppState, types, and ring buffer helpers"
```

---

## Task 3: Config Package

**Files:**
- Create: `config/config.go`
- Create: `config/config_test.go`

- [ ] **Step 1: Write failing test**

```go
// config/config_test.go
package config_test

import (
	"os"
	"path/filepath"
	"testing"

	"failtop/config"
)

func TestDefaults(t *testing.T) {
	// No config file, no flags → defaults apply
	cfg := config.Defaults()
	if cfg.RefreshInterval != 2 {
		t.Errorf("want RefreshInterval=2, got %d", cfg.RefreshInterval)
	}
	if cfg.PublicIPURL != "https://api.ipify.org" {
		t.Errorf("want default public IP URL, got %q", cfg.PublicIPURL)
	}
}

func TestLoadFromFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	content := `interface = "eth1"
refresh_interval = 5

[mmdb]
city = "/tmp/city.mmdb"
asn  = "/tmp/asn.mmdb"
`
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	cfg, err := config.LoadFromFile(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Interface != "eth1" {
		t.Errorf("want interface=eth1, got %q", cfg.Interface)
	}
	if cfg.RefreshInterval != 5 {
		t.Errorf("want refresh=5, got %d", cfg.RefreshInterval)
	}
	if cfg.MMDB.City != "/tmp/city.mmdb" {
		t.Errorf("want mmdb.city=/tmp/city.mmdb, got %q", cfg.MMDB.City)
	}
}
```

- [ ] **Step 2: Run test to confirm it fails**

```bash
go test ./config/...
```

Expected: compile error — `config` package does not exist yet.

- [ ] **Step 3: Write config/config.go**

```go
// config/config.go
package config

import (
	"flag"
	"os"
	"path/filepath"

	"github.com/BurntSushi/toml"
)

type MMDB struct {
	City string `toml:"city"`
	ASN  string `toml:"asn"`
}

type Config struct {
	Interface       string `toml:"interface"`
	RefreshInterval int    `toml:"refresh_interval"`
	AuthLog         string `toml:"auth_log"`
	PublicIPURL     string `toml:"public_ip_url"`
	MMDB            MMDB   `toml:"mmdb"`
}

// Defaults returns a Config populated with sensible defaults.
func Defaults() *Config {
	return &Config{
		Interface:       "",
		RefreshInterval: 2,
		AuthLog:         "",
		PublicIPURL:     "https://api.ipify.org",
	}
}

// LoadFromFile parses a TOML config file and returns a Config.
// Missing keys retain their zero values; callers should merge with Defaults().
func LoadFromFile(path string) (*Config, error) {
	cfg := Defaults()
	if _, err := toml.DecodeFile(path, cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}

// Load returns a Config with: defaults → config file → CLI flags (highest priority).
// CLI flags are registered and parsed inside this function; call before any other flag.Parse().
func Load() (*Config, error) {
	cfg := Defaults()

	// Load config file if it exists
	path := defaultConfigPath()
	if _, err := os.Stat(path); err == nil {
		if _, err := toml.DecodeFile(path, cfg); err != nil {
			return nil, err
		}
	}

	// CLI flags override config file
	iface := flag.String("interface", cfg.Interface, "NIC interface to monitor")
	refresh := flag.Int("refresh", cfg.RefreshInterval, "Refresh interval in seconds")
	authlog := flag.String("auth-log", cfg.AuthLog, "Auth log path override")
	publicIP := flag.String("public-ip-url", cfg.PublicIPURL, `URL to fetch public IP ("off" to disable)`)
	mmdbCity := flag.String("mmdb-city", cfg.MMDB.City, "Path to GeoLite2-City.mmdb")
	mmdbASN := flag.String("mmdb-asn", cfg.MMDB.ASN, "Path to GeoLite2-ASN.mmdb")
	flag.Parse()

	cfg.Interface = *iface
	cfg.RefreshInterval = *refresh
	cfg.AuthLog = *authlog
	cfg.PublicIPURL = *publicIP
	cfg.MMDB.City = *mmdbCity
	cfg.MMDB.ASN = *mmdbASN

	return cfg, nil
}

func defaultConfigPath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".config", "failtop", "config.toml")
}
```

- [ ] **Step 4: Run tests to confirm they pass**

```bash
go test ./config/... -v
```

Expected:
```
--- PASS: TestDefaults (0.00s)
--- PASS: TestLoadFromFile (0.00s)
PASS
```

- [ ] **Step 5: Commit**

```bash
git add config/config.go config/config_test.go
git commit -m "feat: config package with TOML file and CLI flag precedence"
```

---

## Task 4: Testdata Fixtures

**Files:**
- Create: `testdata/auth.log.ubuntu`
- Create: `testdata/auth.log.fedora`
- Create: `testdata/ufw.log`
- Create: `testdata/proc_net_dev`

- [ ] **Step 1: Write testdata/auth.log.ubuntu**

```
Apr 15 12:00:01 myhost sshd[1234]: Failed password for root from 185.220.101.45 port 22 ssh2
Apr 15 12:00:05 myhost sshd[1235]: Failed password for invalid user admin from 103.167.34.21 port 53412 ssh2
Apr 15 12:00:10 myhost sshd[1236]: Invalid user ftp from 45.155.205.233 port 12345
Apr 15 12:00:15 myhost sshd[1237]: Accepted publickey for peter from 192.168.1.5 port 54321 ssh2
Apr 15 12:00:20 myhost sshd[1238]: Failed password for root from 91.134.232.10 port 22 ssh2
Apr 15 12:00:25 myhost sshd[1239]: Disconnected from authenticating user root 185.220.101.45 port 22 [preauth]
Apr 15 12:00:30 myhost sshd[1240]: Accepted password for deploy from 10.0.0.2 port 33456 ssh2
```

- [ ] **Step 2: Write testdata/auth.log.fedora**

```
Apr 15 12:00:01 myhost sshd[1234]: Failed password for root from 185.220.101.45 port 22 ssh2
Apr 15 12:00:05 myhost sshd[1235]: Invalid user admin from 103.167.34.21 port 53412
Apr 15 12:00:10 myhost sshd[1236]: Accepted publickey for ec2-user from 10.0.0.1 port 22 ssh2
Apr 15 12:00:15 myhost sshd[1237]: Failed password for invalid user guest from 91.134.232.10 port 22 ssh2
```

- [ ] **Step 3: Write testdata/ufw.log**

```
Apr 15 12:00:01 myhost kernel: [12345.678] [UFW BLOCK] IN=eth0 OUT= MAC=aa:bb:cc:dd:ee:ff SRC=185.220.101.45 DST=1.2.3.4 LEN=44 TOS=0x00 PREC=0x00 TTL=52 ID=0 DF PROTO=TCP SPT=12345 DPT=22 WINDOW=29200 RES=0x00 SYN URGP=0
Apr 15 12:00:05 myhost kernel: [12350.123] [UFW BLOCK] IN=eth0 OUT= MAC=aa:bb:cc:dd:ee:ff SRC=103.167.34.21 DST=1.2.3.4 LEN=44 TOS=0x00 PREC=0x00 TTL=48 ID=0 DF PROTO=TCP SPT=54321 DPT=80 WINDOW=29200 RES=0x00 SYN URGP=0
```

- [ ] **Step 4: Write testdata/proc_net_dev**

```
Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
    lo:  123456    1234    0    0    0     0          0         0   123456    1234    0    0    0     0       0          0
  eth0:987654321   12345    0    0    0     0          0         0 123456789    9876    0    0    0     0       0          0
```

- [ ] **Step 5: Commit**

```bash
git add testdata/
git commit -m "test: add log fixtures for authlog, ufw, and /proc/net/dev"
```

---

## Task 5: Auth Log Parser

**Files:**
- Create: `sources/authlog/parser.go`
- Create: `sources/authlog/authlog_test.go`

- [ ] **Step 1: Write failing tests**

```go
// sources/authlog/authlog_test.go
package authlog_test

import (
	"os"
	"strings"
	"testing"
	"time"

	"failtop/sources/authlog"
)

func TestParseLine_FailedPassword(t *testing.T) {
	line := "Apr 15 12:00:01 myhost sshd[1234]: Failed password for root from 185.220.101.45 port 22 ssh2"
	ev := authlog.ParseLine(line)
	if ev == nil {
		t.Fatal("expected event, got nil")
	}
	if ev.Type != "FAIL" {
		t.Errorf("want Type=FAIL, got %q", ev.Type)
	}
	if ev.User != "root" {
		t.Errorf("want User=root, got %q", ev.User)
	}
	if ev.IP != "185.220.101.45" {
		t.Errorf("want IP=185.220.101.45, got %q", ev.IP)
	}
	if ev.Time.IsZero() {
		t.Error("expected non-zero time")
	}
}

func TestParseLine_FailedPasswordInvalidUser(t *testing.T) {
	line := "Apr 15 12:00:05 myhost sshd[1235]: Failed password for invalid user admin from 103.167.34.21 port 53412 ssh2"
	ev := authlog.ParseLine(line)
	if ev == nil {
		t.Fatal("expected event, got nil")
	}
	if ev.Type != "FAIL" {
		t.Errorf("want Type=FAIL, got %q", ev.Type)
	}
	if ev.User != "admin" {
		t.Errorf("want User=admin, got %q", ev.User)
	}
	if ev.IP != "103.167.34.21" {
		t.Errorf("want IP=103.167.34.21, got %q", ev.IP)
	}
}

func TestParseLine_InvalidUser(t *testing.T) {
	line := "Apr 15 12:00:10 myhost sshd[1236]: Invalid user ftp from 45.155.205.233 port 12345"
	ev := authlog.ParseLine(line)
	if ev == nil {
		t.Fatal("expected event, got nil")
	}
	if ev.Type != "INVALID" {
		t.Errorf("want Type=INVALID, got %q", ev.Type)
	}
	if ev.IP != "45.155.205.233" {
		t.Errorf("want IP=45.155.205.233, got %q", ev.IP)
	}
}

func TestParseLine_Accepted(t *testing.T) {
	line := "Apr 15 12:00:15 myhost sshd[1237]: Accepted publickey for peter from 192.168.1.5 port 54321 ssh2"
	ev := authlog.ParseLine(line)
	if ev == nil {
		t.Fatal("expected event, got nil")
	}
	if ev.Type != "OK" {
		t.Errorf("want Type=OK, got %q", ev.Type)
	}
	if ev.User != "peter" {
		t.Errorf("want User=peter, got %q", ev.User)
	}
	if ev.Method != "publickey" {
		t.Errorf("want Method=publickey, got %q", ev.Method)
	}
	if ev.IP != "192.168.1.5" {
		t.Errorf("want IP=192.168.1.5, got %q", ev.IP)
	}
}

func TestParseLine_Unrecognized(t *testing.T) {
	line := "Apr 15 12:00:00 myhost kernel: some unrelated log line"
	ev := authlog.ParseLine(line)
	if ev != nil {
		t.Errorf("expected nil for unrecognized line, got %+v", ev)
	}
}

func TestParseFixtureUbuntu(t *testing.T) {
	data, err := os.ReadFile("../../testdata/auth.log.ubuntu")
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	var events []*authlog.Event
	for _, line := range lines {
		if ev := authlog.ParseLine(line); ev != nil {
			events = append(events, ev)
		}
	}
	// Fixture has 7 lines; expect at least 5 parsed events
	if len(events) < 5 {
		t.Errorf("expected at least 5 events from ubuntu fixture, got %d", len(events))
	}
}

// Verify the year is set correctly (log lines have no year).
func TestParseLine_Year(t *testing.T) {
	line := "Jan  1 00:00:01 myhost sshd[1]: Failed password for root from 1.2.3.4 port 22 ssh2"
	ev := authlog.ParseLine(line)
	if ev == nil {
		t.Fatal("expected event, got nil")
	}
	if ev.Time.Year() != time.Now().Year() {
		t.Errorf("want year=%d, got %d", time.Now().Year(), ev.Time.Year())
	}
}
```

- [ ] **Step 2: Run to confirm failure**

```bash
go test ./sources/authlog/... 2>&1 | head -5
```

Expected: compile error — package does not exist.

- [ ] **Step 3: Write sources/authlog/parser.go**

```go
// sources/authlog/parser.go
package authlog

import (
	"fmt"
	"regexp"
	"time"

	"failtop/state"
)

// Event is an alias for state.AuthEvent, re-exported for test convenience.
type Event = state.AuthEvent

var (
	// "Failed password for root from 1.2.3.4 port 22 ssh2"
	reFailedPassword = regexp.MustCompile(
		`(\w{3}\s+\d+\s+\d+:\d+:\d+)\s+\S+\s+sshd\[\d+\]:\s+Failed password for (?:invalid user )?(\S+) from (\S+)`)

	// "Invalid user admin from 1.2.3.4 port 12345"
	reInvalidUser = regexp.MustCompile(
		`(\w{3}\s+\d+\s+\d+:\d+:\d+)\s+\S+\s+sshd\[\d+\]:\s+Invalid user (\S+) from (\S+)`)

	// "Accepted publickey for peter from 1.2.3.4 port 54321 ssh2"
	reAccepted = regexp.MustCompile(
		`(\w{3}\s+\d+\s+\d+:\d+:\d+)\s+\S+\s+sshd\[\d+\]:\s+Accepted (\S+) for (\S+) from (\S+)`)
)

const timeLayout = "Jan _2 15:04:05 2006"

func parseTime(s string) time.Time {
	year := time.Now().Year()
	t, err := time.Parse(timeLayout, fmt.Sprintf("%s %d", s, year))
	if err != nil {
		return time.Now()
	}
	return t
}

// ParseLine attempts to extract an AuthEvent from a single log line.
// Returns nil if the line is not a recognized SSH auth event.
func ParseLine(line string) *state.AuthEvent {
	if m := reAccepted.FindStringSubmatch(line); m != nil {
		return &state.AuthEvent{
			Time:   parseTime(m[1]),
			Type:   "OK",
			Method: m[2],
			User:   m[3],
			IP:     m[4],
		}
	}
	if m := reFailedPassword.FindStringSubmatch(line); m != nil {
		return &state.AuthEvent{
			Time: parseTime(m[1]),
			Type: "FAIL",
			User: m[2],
			IP:   m[3],
		}
	}
	if m := reInvalidUser.FindStringSubmatch(line); m != nil {
		return &state.AuthEvent{
			Time: parseTime(m[1]),
			Type: "INVALID",
			User: m[2],
			IP:   m[3],
		}
	}
	return nil
}
```

- [ ] **Step 4: Run tests**

```bash
go test ./sources/authlog/... -v -run TestParse
```

Expected:
```
--- PASS: TestParseLine_FailedPassword (0.00s)
--- PASS: TestParseLine_FailedPasswordInvalidUser (0.00s)
--- PASS: TestParseLine_InvalidUser (0.00s)
--- PASS: TestParseLine_Accepted (0.00s)
--- PASS: TestParseLine_Unrecognized (0.00s)
--- PASS: TestParseFixtureUbuntu (0.00s)
--- PASS: TestParseLine_Year (0.00s)
PASS
```

- [ ] **Step 5: Commit**

```bash
git add sources/authlog/parser.go sources/authlog/authlog_test.go
git commit -m "feat: authlog parser with regex for FAIL/INVALID/OK events"
```

---

## Task 6: Auth Log File Tailer (inotify)

**Files:**
- Create: `sources/authlog/tailer.go`

No unit test for inotify — it requires a real filesystem. Verified by integration in Task 8.

- [ ] **Step 1: Write sources/authlog/tailer.go**

```go
// sources/authlog/tailer.go
//go:build linux

package authlog

import (
	"bufio"
	"io"
	"os"

	"golang.org/x/sys/unix"
)

// TailFile tails the file at path using inotify, sending new lines to out.
// Blocks until ctx is cancelled or the file is removed. Reads from EOF on open.
// Stops when the done channel is closed.
func TailFile(path string, out chan<- string, done <-chan struct{}) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	// Seek to end so we only get new lines
	if _, err := f.Seek(0, io.SeekEnd); err != nil {
		return err
	}

	fd, err := unix.InotifyInit1(unix.IN_CLOEXEC)
	if err != nil {
		return err
	}
	defer unix.Close(fd)

	wd, err := unix.InotifyAddWatch(fd, path, unix.IN_MODIFY|unix.IN_MOVE_SELF|unix.IN_DELETE_SELF)
	if err != nil {
		return err
	}
	defer unix.InotifyRmWatch(fd, uint32(wd))

	reader := bufio.NewReader(f)
	buf := make([]byte, unix.SizeofInotifyEvent*64)

	for {
		select {
		case <-done:
			return nil
		default:
		}

		// Read available inotify events (non-blocking via select on fd)
		// Use a goroutine-safe poll approach: read with a timeout alternative.
		n, err := unix.Read(fd, buf)
		if err != nil || n == 0 {
			return err
		}

		// Drain new lines from the file
		for {
			line, err := reader.ReadString('\n')
			if len(line) > 0 {
				// Strip trailing newline
				if len(line) > 0 && line[len(line)-1] == '\n' {
					line = line[:len(line)-1]
				}
				select {
				case out <- line:
				case <-done:
					return nil
				}
			}
			if err != nil {
				break // no more data right now
			}
		}
	}
}
```

- [ ] **Step 2: Verify compilation**

```bash
go build ./sources/authlog/...
```

Expected: no errors.

- [ ] **Step 3: Commit**

```bash
git add sources/authlog/tailer.go
git commit -m "feat: inotify-based log file tailer"
```

---

## Task 7: Auth Log Journald Reader

**Files:**
- Create: `sources/authlog/journald.go`

- [ ] **Step 1: Write sources/authlog/journald.go**

```go
// sources/authlog/journald.go
package authlog

import (
	"bufio"
	"os/exec"
)

// TailJournald runs `journalctl -f -u sshd --output=short` and sends lines to out.
// Blocks until the done channel is closed or journalctl exits.
func TailJournald(out chan<- string, done <-chan struct{}) error {
	cmd := exec.Command("journalctl", "-f", "-u", "sshd", "--output=short", "--no-pager")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return err
	}

	go func() {
		<-done
		cmd.Process.Kill()
	}()

	scanner := bufio.NewScanner(stdout)
	for scanner.Scan() {
		line := scanner.Text()
		select {
		case out <- line:
		case <-done:
			return nil
		}
	}
	return cmd.Wait()
}
```

- [ ] **Step 2: Verify compilation**

```bash
go build ./sources/authlog/...
```

Expected: no errors.

- [ ] **Step 3: Commit**

```bash
git add sources/authlog/journald.go
git commit -m "feat: journald subprocess reader for auth log tailing"
```

---

## Task 8: Auth Log Detect + Run Goroutine

**Files:**
- Create: `sources/authlog/detect.go`
- Create: `sources/authlog/run.go`
- Update: `sources/authlog/authlog_test.go` (add detect tests)

- [ ] **Step 1: Write failing detect tests**

Add to `sources/authlog/authlog_test.go`:

```go
func TestDetectPath_KnownPaths(t *testing.T) {
	// DetectPath returns "" if none of the known paths exist
	// (they won't in a test environment)
	path := authlog.DetectPath("")
	// Either a real path or "" — we just confirm it doesn't panic
	_ = path
}

func TestDetectPath_Override(t *testing.T) {
	// If the user provides an explicit path, return it unchanged
	got := authlog.DetectPath("/custom/auth.log")
	if got != "/custom/auth.log" {
		t.Errorf("want /custom/auth.log, got %q", got)
	}
}
```

- [ ] **Step 2: Run to confirm failure**

```bash
go test ./sources/authlog/... 2>&1 | head -5
```

Expected: compile error — `DetectPath` undefined.

- [ ] **Step 3: Write sources/authlog/detect.go**

```go
// sources/authlog/detect.go
package authlog

import "os"

// knownPaths lists auth log locations in probe order.
var knownPaths = []string{
	"/var/log/auth.log",   // Debian/Ubuntu/Mint
	"/var/log/secure",     // Fedora/RHEL/CentOS
	"/var/log/messages",   // some Alpine/generic syslog
}

// DetectPath returns the override if non-empty, otherwise probes known paths.
// Returns "" if no flat file is found — caller should fall back to journald.
func DetectPath(override string) string {
	if override != "" {
		return override
	}
	for _, p := range knownPaths {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

// DetectMode returns "file" if a flat log path is available, "journald" otherwise.
func DetectMode(override string) string {
	if DetectPath(override) != "" {
		return "file"
	}
	return "journald"
}
```

- [ ] **Step 4: Write sources/authlog/run.go**

```go
// sources/authlog/run.go
package authlog

import (
	"time"

	"failtop/state"
)

// Run starts the auth log goroutine. It detects the log source, tails it,
// parses each line, and updates st. Blocks until done is closed.
func Run(authLogOverride string, st *state.AppState, done <-chan struct{}) {
	lines := make(chan string, 256)
	mode := DetectMode(authLogOverride)

	st.Lock()
	if mode == "file" {
		path := DetectPath(authLogOverride)
		st.AuthLogAvail = true
		st.AuthLogMsg = "tailing " + path
		st.Unlock()
		go func() {
			if err := TailFile(path, lines, done); err != nil {
				st.Lock()
				st.AuthLogMsg = "tailer error: " + err.Error()
				st.Unlock()
			}
		}()
	} else {
		// Check if journalctl is available
		st.AuthLogAvail = true
		st.AuthLogMsg = "journald (sshd)"
		st.Unlock()
		go func() {
			if err := TailJournald(lines, done); err != nil {
				st.Lock()
				st.AuthLogMsg = "journald error: " + err.Error()
				st.Unlock()
			}
		}()
	}

	for {
		select {
		case <-done:
			return
		case line := <-lines:
			ev := ParseLine(line)
			if ev == nil {
				continue
			}
			st.Lock()
			st.AddAuthEvent(*ev)
			switch ev.Type {
			case "FAIL", "INVALID":
				st.SSHFails++
				if ev.IP != "" {
					st.AddOrUpdateBlockedIP(state.BlockedIP{
						IP:     ev.IP,
						Source: "ssh",
						SeenAt: time.Now(),
					})
				}
			case "OK":
				st.SSHSessions++
			}
			st.Unlock()
		}
	}
}
```

- [ ] **Step 5: Run all authlog tests**

```bash
go test ./sources/authlog/... -v
```

Expected: all tests pass.

- [ ] **Step 6: Commit**

```bash
git add sources/authlog/detect.go sources/authlog/run.go sources/authlog/authlog_test.go
git commit -m "feat: authlog source with detection, inotify/journald tailing, and state updates"
```

---

## Task 9: NIC Source

**Files:**
- Create: `sources/nic/nic.go`
- Create: `sources/nic/nic_test.go`

- [ ] **Step 1: Write failing tests**

```go
// sources/nic/nic_test.go
package nic_test

import (
	"os"
	"testing"

	"failtop/sources/nic"
)

func TestParseProcNetDev(t *testing.T) {
	data, err := os.ReadFile("../../testdata/proc_net_dev")
	if err != nil {
		t.Fatal(err)
	}
	ifaces, err := nic.ParseProcNetDev(string(data))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	eth0, ok := ifaces["eth0"]
	if !ok {
		t.Fatal("expected eth0 in parsed result")
	}
	if eth0.RxBytes != 987654321 {
		t.Errorf("want RxBytes=987654321, got %d", eth0.RxBytes)
	}
	if eth0.TxBytes != 123456789 {
		t.Errorf("want TxBytes=123456789, got %d", eth0.TxBytes)
	}
}

func TestDetectInterface(t *testing.T) {
	data, err := os.ReadFile("../../testdata/proc_net_dev")
	if err != nil {
		t.Fatal(err)
	}
	ifaces, _ := nic.ParseProcNetDev(string(data))
	iface := nic.DetectInterface(ifaces)
	if iface != "eth0" {
		t.Errorf("want eth0, got %q", iface)
	}
}
```

- [ ] **Step 2: Run to confirm failure**

```bash
go test ./sources/nic/... 2>&1 | head -5
```

Expected: compile error.

- [ ] **Step 3: Write sources/nic/nic.go**

```go
// sources/nic/nic.go
package nic

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"failtop/state"
)

// IfaceCounters holds raw byte counters from /proc/net/dev.
type IfaceCounters struct {
	RxBytes uint64
	TxBytes uint64
}

// ParseProcNetDev parses the content of /proc/net/dev and returns a map
// of interface name → counters.
func ParseProcNetDev(content string) (map[string]IfaceCounters, error) {
	result := make(map[string]IfaceCounters)
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		// Skip header lines
		if !strings.Contains(line, ":") {
			continue
		}
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}
		name := strings.TrimSpace(parts[0])
		fields := strings.Fields(parts[1])
		if len(fields) < 9 {
			continue
		}
		rx, err := strconv.ParseUint(fields[0], 10, 64)
		if err != nil {
			continue
		}
		tx, err := strconv.ParseUint(fields[8], 10, 64)
		if err != nil {
			continue
		}
		result[name] = IfaceCounters{RxBytes: rx, TxBytes: tx}
	}
	if len(result) == 0 {
		return nil, fmt.Errorf("no interfaces found in /proc/net/dev")
	}
	return result, nil
}

// DetectInterface returns the first non-loopback interface from the map.
func DetectInterface(ifaces map[string]IfaceCounters) string {
	for name := range ifaces {
		if name != "lo" {
			return name
		}
	}
	return ""
}

// fetchPublicIP fetches the public IP from the given URL (plain text body).
// Returns "" on any error or if url is "off".
func fetchPublicIP(url string) string {
	if url == "" || url == "off" {
		return ""
	}
	client := http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(body))
}

// localIP returns the first non-loopback IPv4 address for the named interface.
func localIP(ifaceName string) string {
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return ""
	}
	addrs, err := iface.Addrs()
	if err != nil {
		return ""
	}
	for _, addr := range addrs {
		var ip net.IP
		switch v := addr.(type) {
		case *net.IPNet:
			ip = v.IP
		case *net.IPAddr:
			ip = v.IP
		}
		if ip == nil || ip.IsLoopback() {
			continue
		}
		if ip4 := ip.To4(); ip4 != nil {
			return ip4.String()
		}
	}
	return ""
}

// Run starts the NIC polling goroutine. Samples /proc/net/dev every second,
// computes rates, and updates st. Blocks until done is closed.
func Run(ifaceOverride string, publicIPURL string, st *state.AppState, done <-chan struct{}) {
	data, err := os.ReadFile("/proc/net/dev")
	if err != nil {
		return
	}
	ifaces, err := ParseProcNetDev(string(data))
	if err != nil {
		return
	}

	ifaceName := ifaceOverride
	if ifaceName == "" {
		ifaceName = DetectInterface(ifaces)
	}
	if ifaceName == "" {
		return
	}

	pubIP := fetchPublicIP(publicIPURL)
	locIP := localIP(ifaceName)

	st.Lock()
	st.NIC.Interface = ifaceName
	st.NIC.PublicIP = pubIP
	st.NIC.LocalIP = locIP
	st.Unlock()

	prev := ifaces[ifaceName]
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-done:
			return
		case <-ticker.C:
			data, err := os.ReadFile("/proc/net/dev")
			if err != nil {
				continue
			}
			ifaces, err := ParseProcNetDev(string(data))
			if err != nil {
				continue
			}
			curr, ok := ifaces[ifaceName]
			if !ok {
				continue
			}
			rxRate := float64(curr.RxBytes-prev.RxBytes) / 1.0
			txRate := float64(curr.TxBytes-prev.TxBytes) / 1.0
			if rxRate < 0 {
				rxRate = 0
			}
			if txRate < 0 {
				txRate = 0
			}
			prev = curr

			st.Lock()
			st.NIC.RxRate = rxRate
			st.NIC.TxRate = txRate
			st.AppendNICHistory(rxRate, txRate)
			st.Unlock()
		}
	}
}
```

- [ ] **Step 4: Run tests**

```bash
go test ./sources/nic/... -v
```

Expected:
```
--- PASS: TestParseProcNetDev (0.00s)
--- PASS: TestDetectInterface (0.00s)
PASS
```

- [ ] **Step 5: Commit**

```bash
git add sources/nic/nic.go sources/nic/nic_test.go
git commit -m "feat: NIC source with /proc/net/dev parsing and throughput history"
```

---

## Task 10: Firewall Source

**Files:**
- Create: `sources/firewall/source.go`
- Create: `sources/firewall/ufw.go`
- Create: `sources/firewall/firewalld.go`
- Create: `sources/firewall/iptables.go`
- Create: `sources/firewall/detect.go`
- Create: `sources/firewall/firewall_test.go`

- [ ] **Step 1: Write failing tests**

```go
// sources/firewall/firewall_test.go
package firewall_test

import (
	"testing"

	"failtop/sources/firewall"
)

const ufwStatusVerbose = `Status: active
Logging: on (low)
Default: deny (incoming), allow (outgoing), disabled (routed)
New profiles: skip

To                         Action      From
--                         ------      ----
22/tcp                     ALLOW IN    Anywhere
80/tcp                     ALLOW IN    Anywhere
443/tcp                    ALLOW IN    Anywhere
`

func TestParseUFWStats(t *testing.T) {
	stats, err := firewall.ParseUFWStatus(ufwStatusVerbose)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if stats.Type != "ufw" {
		t.Errorf("want Type=ufw, got %q", stats.Type)
	}
	if stats.Rules != 3 {
		t.Errorf("want Rules=3, got %d", stats.Rules)
	}
}

const iptablesOutput = `Chain INPUT (policy DROP 1247 packets, 65832 bytes)
 pkts bytes target     prot opt in     out     source               destination
  892  45184 ACCEPT     all  --  *      *       0.0.0.0/0            0.0.0.0/0            state RELATED,ESTABLISHED
    0      0 ACCEPT     all  --  lo     *       0.0.0.0/0            0.0.0.0/0
    2    104 ACCEPT     tcp  --  *      *       0.0.0.0/0            0.0.0.0/0            tcp dpt:22
`

func TestParseIPTablesStats(t *testing.T) {
	stats, err := firewall.ParseIPTablesOutput(iptablesOutput)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if stats.Type != "iptables" {
		t.Errorf("want Type=iptables, got %q", stats.Type)
	}
	if stats.Blocked != 1247 {
		t.Errorf("want Blocked=1247, got %d", stats.Blocked)
	}
	if stats.Allowed != 892 {
		t.Errorf("want Allowed=892, got %d", stats.Allowed)
	}
}
```

- [ ] **Step 2: Run to confirm failure**

```bash
go test ./sources/firewall/... 2>&1 | head -5
```

Expected: compile error.

- [ ] **Step 3: Write sources/firewall/source.go**

```go
// sources/firewall/source.go
package firewall

import "failtop/state"

// Source is the interface all firewall adapters implement.
type Source interface {
	Name() string
	// Poll queries the firewall and returns current stats.
	Poll() (state.FirewallStats, error)
}
```

- [ ] **Step 4: Write sources/firewall/ufw.go**

```go
// sources/firewall/ufw.go
package firewall

import (
	"fmt"
	"os/exec"
	"strings"

	"failtop/state"
)

type UFWSource struct{}

func (u *UFWSource) Name() string { return "ufw" }

func (u *UFWSource) Poll() (state.FirewallStats, error) {
	out, err := exec.Command("ufw", "status", "verbose").Output()
	if err != nil {
		return state.FirewallStats{}, fmt.Errorf("ufw status: %w", err)
	}
	return ParseUFWStatus(string(out))
}

// ParseUFWStatus parses the output of `ufw status verbose`.
func ParseUFWStatus(output string) (state.FirewallStats, error) {
	stats := state.FirewallStats{Type: "ufw"}
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "To") || strings.HasPrefix(line, "--") {
			continue
		}
		// Count rules: lines with ALLOW/DENY/REJECT and no leading spaces
		if strings.Contains(line, "ALLOW") || strings.Contains(line, "DENY") || strings.Contains(line, "REJECT") {
			if !strings.HasPrefix(line, "Default") {
				stats.Rules++
			}
		}
	}
	return stats, nil
}
```

- [ ] **Step 5: Write sources/firewall/firewalld.go**

```go
// sources/firewall/firewalld.go
package firewall

import (
	"fmt"
	"os/exec"
	"strings"

	"failtop/state"
)

type FirewalldSource struct{}

func (f *FirewalldSource) Name() string { return "firewalld" }

func (f *FirewalldSource) Poll() (state.FirewallStats, error) {
	out, err := exec.Command("firewall-cmd", "--list-all").Output()
	if err != nil {
		return state.FirewallStats{}, fmt.Errorf("firewall-cmd: %w", err)
	}
	stats := state.FirewallStats{Type: "firewalld"}
	for _, line := range strings.Split(string(out), "\n") {
		if strings.Contains(line, "services:") || strings.Contains(line, "ports:") {
			// Count services/ports as rules (rough count)
			fields := strings.Fields(line)
			if len(fields) > 1 {
				stats.Rules += len(fields) - 1
			}
		}
	}
	return stats, nil
}
```

- [ ] **Step 6: Write sources/firewall/iptables.go**

```go
// sources/firewall/iptables.go
package firewall

import (
	"fmt"
	"os/exec"
	"strconv"
	"strings"

	"failtop/state"
)

type IPTablesSource struct{}

func (i *IPTablesSource) Name() string { return "iptables" }

func (i *IPTablesSource) Poll() (state.FirewallStats, error) {
	out, err := exec.Command("iptables", "-L", "INPUT", "-n", "-v", "--line-numbers").Output()
	if err != nil {
		return state.FirewallStats{}, fmt.Errorf("iptables: %w", err)
	}
	return ParseIPTablesOutput(string(out))
}

// ParseIPTablesOutput parses `iptables -L INPUT -n -v` output.
func ParseIPTablesOutput(output string) (state.FirewallStats, error) {
	stats := state.FirewallStats{Type: "iptables"}
	for _, line := range strings.Split(output, "\n") {
		// Parse "Chain INPUT (policy DROP N packets, M bytes)"
		if strings.HasPrefix(line, "Chain INPUT") {
			// Extract dropped packet count from policy line
			if idx := strings.Index(line, "policy DROP"); idx != -1 {
				rest := line[idx+len("policy DROP "):]
				fields := strings.Fields(rest)
				if len(fields) > 0 {
					if n, err := strconv.Atoi(fields[0]); err == nil {
						stats.Blocked = n
					}
				}
			}
			continue
		}
		// Count ACCEPT lines as allowed (first field is pkts)
		if strings.Contains(line, "ACCEPT") {
			fields := strings.Fields(line)
			if len(fields) > 0 {
				if n, err := strconv.Atoi(fields[0]); err == nil {
					stats.Allowed += n
				}
			}
			stats.Rules++
		}
	}
	return stats, nil
}
```

- [ ] **Step 7: Write sources/firewall/detect.go**

```go
// sources/firewall/detect.go
package firewall

import (
	"os/exec"
	"time"

	"failtop/state"
)

// Detect probes for available firewall tools in order: ufw → firewalld → iptables.
// Returns the first available Source, or nil if none found.
func Detect() Source {
	if commandExists("ufw") {
		return &UFWSource{}
	}
	if commandExists("firewall-cmd") {
		return &FirewalldSource{}
	}
	if commandExists("iptables") {
		return &IPTablesSource{}
	}
	return nil
}

func commandExists(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

// Run polls the firewall every interval and updates st. Blocks until done is closed.
func Run(interval int, st *state.AppState, done <-chan struct{}) {
	src := Detect()
	if src == nil {
		st.Lock()
		st.FirewallAvail = false
		st.FirewallMsg = "no supported firewall found (ufw/firewalld/iptables)"
		st.Unlock()
		return
	}

	st.Lock()
	st.FirewallAvail = true
	st.FirewallMsg = src.Name()
	st.Unlock()

	poll := func() {
		stats, err := src.Poll()
		st.Lock()
		if err != nil {
			st.FirewallMsg = "error: " + err.Error()
		} else {
			st.Firewall = stats
		}
		st.Unlock()
	}

	poll()
	ticker := time.NewTicker(time.Duration(interval) * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-done:
			return
		case <-ticker.C:
			poll()
		}
	}
}
```

- [ ] **Step 8: Run tests**

```bash
go test ./sources/firewall/... -v
```

Expected:
```
--- PASS: TestParseUFWStats (0.00s)
--- PASS: TestParseIPTablesStats (0.00s)
PASS
```

- [ ] **Step 9: Commit**

```bash
git add sources/firewall/
git commit -m "feat: firewall source with ufw/firewalld/iptables adapters and auto-detection"
```

---

## Task 11: fail2ban Source

**Files:**
- Create: `sources/fail2ban/fail2ban.go`
- Create: `sources/fail2ban/fail2ban_test.go`

- [ ] **Step 1: Write failing tests**

```go
// sources/fail2ban/fail2ban_test.go
package fail2ban_test

import (
	"testing"

	"failtop/sources/fail2ban"
)

const statusOutput = `Status
|- Number of jail:	2
` + "`" + `- Jail list:	sshd, nginx-http-auth
`

const jailOutput = `Status for the jail: sshd
|- Filter
|  |- Currently failed:	3
|  |- Total failed:	143
|  ` + "`" + `- File list:	/var/log/auth.log
` + "`" + `- Actions
   |- Currently banned:	5
   |- Total banned:	38
   ` + "`" + `- Banned IP list:	185.220.101.45 103.167.34.21 45.155.205.233 91.134.232.10 194.165.16.68
`

func TestParseJailList(t *testing.T) {
	jails, err := fail2ban.ParseJailList(statusOutput)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(jails) != 2 {
		t.Errorf("want 2 jails, got %d", len(jails))
	}
	if jails[0] != "sshd" {
		t.Errorf("want jails[0]=sshd, got %q", jails[0])
	}
}

func TestParseJailStatus(t *testing.T) {
	stats, err := fail2ban.ParseJailStatus("sshd", jailOutput)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if stats.Name != "sshd" {
		t.Errorf("want Name=sshd, got %q", stats.Name)
	}
	if stats.Banned != 5 {
		t.Errorf("want Banned=5, got %d", stats.Banned)
	}
	if len(stats.BannedIPs) != 5 {
		t.Errorf("want 5 banned IPs, got %d", len(stats.BannedIPs))
	}
	if stats.BannedIPs[0] != "185.220.101.45" {
		t.Errorf("want first IP=185.220.101.45, got %q", stats.BannedIPs[0])
	}
}
```

- [ ] **Step 2: Run to confirm failure**

```bash
go test ./sources/fail2ban/... 2>&1 | head -5
```

Expected: compile error.

- [ ] **Step 3: Write sources/fail2ban/fail2ban.go**

```go
// sources/fail2ban/fail2ban.go
package fail2ban

import (
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"failtop/state"
)

// ParseJailList parses the output of `fail2ban-client status` and returns jail names.
func ParseJailList(output string) ([]string, error) {
	for _, line := range strings.Split(output, "\n") {
		if strings.Contains(line, "Jail list:") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) != 2 {
				continue
			}
			raw := strings.TrimSpace(parts[1])
			if raw == "" {
				return nil, nil
			}
			var jails []string
			for _, j := range strings.Split(raw, ",") {
				j = strings.TrimSpace(j)
				if j != "" {
					jails = append(jails, j)
				}
			}
			return jails, nil
		}
	}
	return nil, fmt.Errorf("no jail list found in output")
}

// ParseJailStatus parses the output of `fail2ban-client status <jail>`.
func ParseJailStatus(name, output string) (state.JailStats, error) {
	stats := state.JailStats{Name: name}
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "|- Currently banned:") || strings.HasPrefix(line, "`- Currently banned:") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				n, _ := strconv.Atoi(strings.TrimSpace(parts[1]))
				stats.Banned = n
			}
		}
		if strings.HasPrefix(line, "`- Banned IP list:") || strings.HasPrefix(line, "|- Banned IP list:") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				raw := strings.TrimSpace(parts[1])
				if raw != "" {
					for _, ip := range strings.Fields(raw) {
						stats.BannedIPs = append(stats.BannedIPs, ip)
					}
				}
			}
		}
	}
	return stats, nil
}

// Poll queries fail2ban-client for all jails and returns aggregated stats.
func Poll() (state.Fail2BanStats, error) {
	out, err := exec.Command("fail2ban-client", "status").Output()
	if err != nil {
		return state.Fail2BanStats{}, fmt.Errorf("fail2ban-client status: %w", err)
	}
	jailNames, err := ParseJailList(string(out))
	if err != nil {
		return state.Fail2BanStats{}, err
	}

	var result state.Fail2BanStats
	for _, name := range jailNames {
		jout, err := exec.Command("fail2ban-client", "status", name).Output()
		if err != nil {
			continue
		}
		jail, err := ParseJailStatus(name, string(jout))
		if err != nil {
			continue
		}
		result.Jails = append(result.Jails, jail)
		result.TotalBanned += jail.Banned
	}
	return result, nil
}

// Run polls fail2ban every interval seconds and updates st. Blocks until done is closed.
func Run(interval int, st *state.AppState, done <-chan struct{}) {
	_, err := exec.LookPath("fail2ban-client")
	if err != nil {
		st.Lock()
		st.Fail2BanAvail = false
		st.Fail2BanMsg = "fail2ban-client not found"
		st.Unlock()
		return
	}

	st.Lock()
	st.Fail2BanAvail = true
	st.Fail2BanMsg = "ok"
	st.Unlock()

	poll := func() {
		stats, err := Poll()
		st.Lock()
		if err != nil {
			st.Fail2BanMsg = "error: " + err.Error()
		} else {
			st.Fail2Ban = stats
			// Populate BlockedIPs from banned lists
			for _, jail := range stats.Jails {
				for _, ip := range jail.BannedIPs {
					st.AddOrUpdateBlockedIP(state.BlockedIP{
						IP:     ip,
						Source: "f2b",
						SeenAt: time.Now(),
					})
				}
			}
		}
		st.Unlock()
	}

	poll()
	ticker := time.NewTicker(time.Duration(interval) * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-done:
			return
		case <-ticker.C:
			poll()
		}
	}
}
```

- [ ] **Step 4: Run tests**

```bash
go test ./sources/fail2ban/... -v
```

Expected:
```
--- PASS: TestParseJailList (0.00s)
--- PASS: TestParseJailStatus (0.00s)
PASS
```

- [ ] **Step 5: Commit**

```bash
git add sources/fail2ban/fail2ban.go sources/fail2ban/fail2ban_test.go
git commit -m "feat: fail2ban source with jail parsing and state updates"
```

---

## Task 12: Geo Source

**Files:**
- Create: `sources/geo/geo.go`
- Create: `sources/geo/geo_test.go`

- [ ] **Step 1: Write failing tests**

```go
// sources/geo/geo_test.go
package geo_test

import (
	"testing"

	"failtop/sources/geo"
)

func TestNewWithNilDBs(t *testing.T) {
	// Geo works fine with no mmdb files — returns empty strings
	g := geo.New("", "")
	result := g.Lookup("185.220.101.45")
	if result.Country != "" {
		t.Errorf("expected empty Country without mmdb, got %q", result.Country)
	}
	if result.ASN != "" {
		t.Errorf("expected empty ASN without mmdb, got %q", result.ASN)
	}
}

func TestCaching(t *testing.T) {
	g := geo.New("", "")
	// First lookup
	r1 := g.Lookup("1.1.1.1")
	// Second lookup — must return same struct (from cache, no panic)
	r2 := g.Lookup("1.1.1.1")
	if r1.Country != r2.Country {
		t.Errorf("cache inconsistency: %q vs %q", r1.Country, r2.Country)
	}
}
```

- [ ] **Step 2: Run to confirm failure**

```bash
go test ./sources/geo/... 2>&1 | head -5
```

Expected: compile error.

- [ ] **Step 3: Write sources/geo/geo.go**

```go
// sources/geo/geo.go
package geo

import (
	"fmt"
	"net"
	"sync"

	"github.com/oschwald/geoip2-golang"
)

// Result holds enrichment data for a single IP.
type Result struct {
	Country string
	City    string
	ASN     string
	Org     string
	PTR     string // filled in async
}

// Geo performs MaxMind lookups and caches results.
type Geo struct {
	cityDB *geoip2.Reader
	asnDB  *geoip2.Reader

	mu    sync.RWMutex
	cache map[string]Result
}

// New opens the given mmdb files. Empty path = skip that DB.
// Logs warnings to stderr if a path is given but the file can't be opened.
func New(cityPath, asnPath string) *Geo {
	g := &Geo{cache: make(map[string]Result)}
	if cityPath != "" {
		db, err := geoip2.Open(cityPath)
		if err != nil {
			fmt.Printf("failtop: warning: cannot open city mmdb %q: %v\n", cityPath, err)
		} else {
			g.cityDB = db
		}
	}
	if asnPath != "" {
		db, err := geoip2.Open(asnPath)
		if err != nil {
			fmt.Printf("failtop: warning: cannot open ASN mmdb %q: %v\n", asnPath, err)
		} else {
			g.asnDB = db
		}
	}
	return g
}

// Close releases mmdb file handles.
func (g *Geo) Close() {
	if g.cityDB != nil {
		g.cityDB.Close()
	}
	if g.asnDB != nil {
		g.asnDB.Close()
	}
}

// Lookup returns enrichment data for the given IP address.
// Returns cached result if available. Safe for concurrent use.
func (g *Geo) Lookup(ipStr string) Result {
	g.mu.RLock()
	if cached, ok := g.cache[ipStr]; ok {
		g.mu.RUnlock()
		return cached
	}
	g.mu.RUnlock()

	ip := net.ParseIP(ipStr)
	result := Result{}

	if ip != nil && g.cityDB != nil {
		if record, err := g.cityDB.City(ip); err == nil {
			result.Country = record.Country.IsoCode
			if len(record.City.Names) > 0 {
				result.City = record.City.Names["en"]
			}
		}
	}

	if ip != nil && g.asnDB != nil {
		if record, err := g.asnDB.ASN(ip); err == nil {
			result.ASN = fmt.Sprintf("AS%d", record.AutonomousSystemNumber)
			result.Org = record.AutonomousSystemOrganization
		}
	}

	g.mu.Lock()
	g.cache[ipStr] = result
	g.mu.Unlock()

	// Fire async PTR lookup
	go g.lookupPTR(ipStr)

	return result
}

func (g *Geo) lookupPTR(ipStr string) {
	names, err := net.LookupAddr(ipStr)
	if err != nil || len(names) == 0 {
		return
	}
	ptr := names[0]
	g.mu.Lock()
	if cached, ok := g.cache[ipStr]; ok {
		cached.PTR = ptr
		g.cache[ipStr] = cached
	}
	g.mu.Unlock()
}
```

- [ ] **Step 4: Run tests**

```bash
go test ./sources/geo/... -v
```

Expected:
```
--- PASS: TestNewWithNilDBs (0.00s)
--- PASS: TestCaching (0.00s)
PASS
```

- [ ] **Step 5: Commit**

```bash
git add sources/geo/geo.go sources/geo/geo_test.go
git commit -m "feat: geo source with MaxMind mmdb lookups, async PTR DNS, and cache"
```

---

## Task 13: tcell Drawing Primitives

**Files:**
- Create: `ui/widgets/draw.go`

No unit tests — UI code is validated visually.

- [ ] **Step 1: Write ui/widgets/draw.go**

```go
// ui/widgets/draw.go
package widgets

import "github.com/gdamore/tcell/v2"

// Box draws a bordered rectangle with an optional title on the top border.
// x, y are top-left corner; w, h are width and height (including border).
func Box(s tcell.Screen, x, y, w, h int, title string, style tcell.Style) {
	if w < 2 || h < 2 {
		return
	}
	// Corners
	s.SetContent(x, y, '┌', nil, style)
	s.SetContent(x+w-1, y, '┐', nil, style)
	s.SetContent(x, y+h-1, '└', nil, style)
	s.SetContent(x+w-1, y+h-1, '┘', nil, style)
	// Top/bottom edges
	for i := 1; i < w-1; i++ {
		s.SetContent(x+i, y, '─', nil, style)
		s.SetContent(x+i, y+h-1, '─', nil, style)
	}
	// Side edges
	for j := 1; j < h-1; j++ {
		s.SetContent(x, y+j, '│', nil, style)
		s.SetContent(x+w-1, y+j, '│', nil, style)
	}
	// Title
	if title != "" {
		runes := []rune(" " + title + " ")
		for i, r := range runes {
			if x+2+i >= x+w-1 {
				break
			}
			s.SetContent(x+2+i, y, r, nil, style)
		}
	}
}

// Text draws a string at (x, y). Clips at maxWidth runes.
func Text(s tcell.Screen, x, y int, text string, style tcell.Style, maxWidth int) {
	col := 0
	for _, r := range text {
		if col >= maxWidth {
			break
		}
		s.SetContent(x+col, y, r, nil, style)
		col++
	}
}

// Pad draws spaces from x to x+width-1 at row y, effectively clearing a row.
func Pad(s tcell.Screen, x, y, width int, style tcell.Style) {
	for i := 0; i < width; i++ {
		s.SetContent(x+i, y, ' ', nil, style)
	}
}

// VLine draws a vertical line from (x,y) downward for length cells.
func VLine(s tcell.Screen, x, y, length int, style tcell.Style) {
	for i := 0; i < length; i++ {
		s.SetContent(x, y+i, '│', nil, style)
	}
}
```

- [ ] **Step 2: Verify compilation**

```bash
go build ./ui/...
```

Expected: no errors.

- [ ] **Step 3: Commit**

```bash
git add ui/widgets/draw.go
git commit -m "feat: tcell drawing primitives (box, text, vline)"
```

---

## Task 14: UI Widgets

**Files:**
- Create: `ui/widgets/table.go`
- Create: `ui/widgets/barchart.go`
- Create: `ui/widgets/sparkline.go`
- Create: `ui/widgets/scrolltext.go`

- [ ] **Step 1: Write ui/widgets/table.go**

```go
// ui/widgets/table.go
package widgets

import "github.com/gdamore/tcell/v2"

// Column defines one column in a Table.
type Column struct {
	Header string
	Width  int
}

// Table is a scrollable, fixed-column table widget.
type Table struct {
	Cols   []Column
	Rows   [][]string
	Scroll int // first visible row index
}

// ScrollUp moves the view up by one row.
func (t *Table) ScrollUp() {
	if t.Scroll > 0 {
		t.Scroll--
	}
}

// ScrollDown moves the view down by one row, bounded by row count.
func (t *Table) ScrollDown(visibleRows int) {
	if t.Scroll < len(t.Rows)-visibleRows {
		t.Scroll++
	}
}

// Draw renders the table into the box defined by x, y, w, h.
// Row 0 is the header. Inner area starts at (x+1, y+1).
func (t *Table) Draw(s tcell.Screen, x, y, w, h int, headerStyle, rowStyle, altStyle tcell.Style) {
	innerX := x + 1
	innerY := y + 1
	innerW := w - 2
	innerH := h - 2

	if innerH < 1 {
		return
	}

	// Draw header row
	col := innerX
	for _, c := range t.Cols {
		Text(s, col, innerY, c.Header, headerStyle, c.Width)
		col += c.Width + 1
	}
	// Underline after header
	if innerH > 1 {
		for i := 0; i < innerW; i++ {
			s.SetContent(innerX+i, innerY+1, '─', nil, headerStyle)
		}
	}

	// Draw rows
	dataRows := innerH - 2 // header + underline
	for rowIdx := 0; rowIdx < dataRows; rowIdx++ {
		srcIdx := t.Scroll + rowIdx
		ry := innerY + 2 + rowIdx
		Pad(s, innerX, ry, innerW, rowStyle)
		if srcIdx >= len(t.Rows) {
			continue
		}
		row := t.Rows[srcIdx]
		style := rowStyle
		if rowIdx%2 == 1 {
			style = altStyle
		}
		col := innerX
		for ci, c := range t.Cols {
			val := ""
			if ci < len(row) {
				val = row[ci]
			}
			Text(s, col, ry, val, style, c.Width)
			col += c.Width + 1
		}
	}
}
```

- [ ] **Step 2: Write ui/widgets/barchart.go**

```go
// ui/widgets/barchart.go
package widgets

import (
	"fmt"

	"github.com/gdamore/tcell/v2"
)

// BarEntry is one row in a bar chart.
type BarEntry struct {
	Label string
	Value float64 // percentage 0–100
	Count int
}

// BarChart draws a horizontal bar chart inside the box at (x,y,w,h).
// Each entry takes one row.
func BarChart(s tcell.Screen, x, y, w, h int, entries []BarEntry, barStyle, labelStyle tcell.Style) {
	innerX := x + 1
	innerY := y + 1
	innerW := w - 2

	maxBars := h - 2
	for i, e := range entries {
		if i >= maxBars {
			break
		}
		row := innerY + i
		Pad(s, innerX, row, innerW, labelStyle)

		// Label: "XX CountryName "
		label := fmt.Sprintf("%-2s ", e.Label)
		Text(s, innerX, row, label, labelStyle, 4)

		// Bar: proportional to value (max innerW - 4 label - 7 " 100% (9999)")
		barMaxW := innerW - 4 - 10
		if barMaxW < 1 {
			barMaxW = 1
		}
		barLen := int(e.Value / 100 * float64(barMaxW))
		for b := 0; b < barLen; b++ {
			s.SetContent(innerX+4+b, row, '█', nil, barStyle)
		}

		// Percentage and count
		pct := fmt.Sprintf(" %3.0f%% (%d)", e.Value, e.Count)
		Text(s, innerX+4+barLen, row, pct, labelStyle, innerW-4-barLen)
	}
}
```

- [ ] **Step 3: Write ui/widgets/sparkline.go**

```go
// ui/widgets/sparkline.go
package widgets

import "github.com/gdamore/tcell/v2"

var sparkChars = []rune("▁▂▃▄▅▆▇█")

// Sparkline draws a single-row sparkline graph from samples.
// samples should be the most recent N rate values (bytes/s).
// Fits width w-2 data points inside the box inner area.
func Sparkline(s tcell.Screen, x, y int, samples []float64, width int, style tcell.Style) {
	if len(samples) == 0 || width < 1 {
		return
	}
	// Find max for normalization
	max := 0.0
	for _, v := range samples {
		if v > max {
			max = v
		}
	}

	// Take the last `width` samples
	start := 0
	if len(samples) > width {
		start = len(samples) - width
	}
	visible := samples[start:]

	for i, v := range visible {
		idx := 0
		if max > 0 {
			idx = int(v / max * float64(len(sparkChars)-1))
		}
		if idx < 0 {
			idx = 0
		}
		if idx >= len(sparkChars) {
			idx = len(sparkChars) - 1
		}
		s.SetContent(x+i, y, sparkChars[idx], nil, style)
	}
}
```

- [ ] **Step 4: Write ui/widgets/scrolltext.go**

```go
// ui/widgets/scrolltext.go
package widgets

import "github.com/gdamore/tcell/v2"

// ScrollText is a fixed-capacity log viewer that shows the last N lines.
type ScrollText struct {
	Lines  []StyledLine
	MaxLen int
}

// StyledLine is a line with a tcell style.
type StyledLine struct {
	Text  string
	Style tcell.Style
}

// Append adds a line, evicting the oldest if at capacity.
func (st *ScrollText) Append(text string, style tcell.Style) {
	if len(st.Lines) >= st.MaxLen {
		st.Lines = st.Lines[1:]
	}
	st.Lines = append(st.Lines, StyledLine{Text: text, Style: style})
}

// Draw renders the last visible lines into the inner area of the box at (x,y,w,h).
func (st *ScrollText) Draw(s tcell.Screen, x, y, w, h int) {
	innerX := x + 1
	innerY := y + 1
	innerW := w - 2
	innerH := h - 2

	// Show the last innerH lines
	start := 0
	if len(st.Lines) > innerH {
		start = len(st.Lines) - innerH
	}
	visible := st.Lines[start:]

	for i, line := range visible {
		Pad(s, innerX, innerY+i, innerW, tcell.StyleDefault)
		Text(s, innerX, innerY+i, line.Text, line.Style, innerW)
	}
}
```

- [ ] **Step 5: Verify compilation**

```bash
go build ./ui/...
```

Expected: no errors.

- [ ] **Step 6: Commit**

```bash
git add ui/widgets/table.go ui/widgets/barchart.go ui/widgets/sparkline.go ui/widgets/scrolltext.go
git commit -m "feat: UI widgets — scrollable table, bar chart, sparkline, scroll text"
```

---

## Task 15: UI Layout

**Files:**
- Create: `ui/layout.go`

- [ ] **Step 1: Write ui/layout.go**

```go
// ui/layout.go
package ui

// Rect defines a rectangular region on screen.
type Rect struct {
	X, Y, W, H int
}

// Geometry holds the computed panel bounds for the current terminal size.
type Geometry struct {
	Header    Rect
	Sidebar   Rect
	Stats     Rect // top portion of sidebar
	NICGraph  Rect // mid portion of sidebar
	TopSrc    Rect // bottom portion of sidebar
	MainUpper Rect // blocked IPs table
	MainLower Rect // auth log
	Footer    Rect

	SidebarWidth int
}

const (
	sidebarWidthMin  = 24
	sidebarWidthFrac = 5 // sidebar is 1/5 of total width
	headerHeight     = 1
	footerHeight     = 1
	statsHeight      = 8
	nicGraphHeight   = 5
)

// Recalculate computes panel bounds for a terminal of size (w, h).
func Recalculate(w, h int) Geometry {
	g := Geometry{}
	g.SidebarWidth = w / sidebarWidthFrac
	if g.SidebarWidth < sidebarWidthMin {
		g.SidebarWidth = sidebarWidthMin
	}

	mainW := w - g.SidebarWidth

	g.Header = Rect{0, 0, w, headerHeight}
	g.Footer = Rect{0, h - footerHeight, w, footerHeight}

	bodyY := headerHeight
	bodyH := h - headerHeight - footerHeight

	// Sidebar panels
	g.Stats = Rect{0, bodyY, g.SidebarWidth, statsHeight}
	g.NICGraph = Rect{0, bodyY + statsHeight, g.SidebarWidth, nicGraphHeight}
	topSrcY := bodyY + statsHeight + nicGraphHeight
	topSrcH := bodyH - statsHeight - nicGraphHeight
	g.TopSrc = Rect{0, topSrcY, g.SidebarWidth, topSrcH}
	g.Sidebar = Rect{0, bodyY, g.SidebarWidth, bodyH}

	// Main area panels
	mainUpperH := bodyH * 6 / 10
	mainLowerH := bodyH - mainUpperH
	g.MainUpper = Rect{g.SidebarWidth, bodyY, mainW, mainUpperH}
	g.MainLower = Rect{g.SidebarWidth, bodyY + mainUpperH, mainW, mainLowerH}

	return g
}
```

- [ ] **Step 2: Verify compilation**

```bash
go build ./ui/...
```

Expected: no errors.

- [ ] **Step 3: Commit**

```bash
git add ui/layout.go
git commit -m "feat: UI layout geometry with panel bounds calculation"
```

---

## Task 16: UI App — Draw Loop and Event Loop

**Files:**
- Create: `ui/app.go`

- [ ] **Step 1: Write ui/app.go**

```go
// ui/app.go
package ui

import (
	"fmt"
	"time"

	"failtop/sources/geo"
	"failtop/state"
	"failtop/ui/widgets"

	"github.com/gdamore/tcell/v2"
)

// Styles
var (
	styleDefault  = tcell.StyleDefault
	styleTitle    = tcell.StyleDefault.Foreground(tcell.ColorYellow).Bold(true)
	styleHeader   = tcell.StyleDefault.Foreground(tcell.ColorAqua).Bold(true)
	styleFail     = tcell.StyleDefault.Foreground(tcell.ColorRed)
	styleOK       = tcell.StyleDefault.Foreground(tcell.ColorGreen)
	styleBan      = tcell.StyleDefault.Foreground(tcell.ColorYellow)
	styleBar      = tcell.StyleDefault.Foreground(tcell.ColorRed)
	styleAlt      = tcell.StyleDefault.Background(tcell.ColorDarkBlue)
	styleSparkRx  = tcell.StyleDefault.Foreground(tcell.ColorGreen)
	styleSparkTx  = tcell.StyleDefault.Foreground(tcell.ColorBlue)
	styleDim      = tcell.StyleDefault.Foreground(tcell.ColorGray)
)

// App is the main TUI application.
type App struct {
	screen    tcell.Screen
	st        *state.AppState
	geo       *geo.Geo
	interval  time.Duration
	authLog   *widgets.ScrollText
	blockedTable *widgets.Table
	quit      chan struct{}
}

// New creates an App. interval is the draw/refresh tick.
func New(st *state.AppState, g *geo.Geo, interval time.Duration) (*App, error) {
	s, err := tcell.NewScreen()
	if err != nil {
		return nil, err
	}
	if err := s.Init(); err != nil {
		return nil, err
	}
	s.SetStyle(styleDefault)
	s.EnableMouse(tcell.MouseButtonEvents)

	app := &App{
		screen:   s,
		st:       st,
		geo:      g,
		interval: interval,
		authLog: &widgets.ScrollText{
			MaxLen: state.MaxAuthEvents,
		},
		blockedTable: &widgets.Table{
			Cols: []widgets.Column{
				{Header: "IP", Width: 16},
				{Header: "CC", Width: 3},
				{Header: "City", Width: 14},
				{Header: "ASN/Org", Width: 18},
				{Header: "Src", Width: 5},
				{Header: "Age", Width: 6},
			},
		},
		quit: make(chan struct{}),
	}
	return app, nil
}

// Run starts the draw ticker and event loop. Blocks until the user quits.
func (a *App) Run() {
	ticker := time.NewTicker(a.interval)
	defer ticker.Stop()

	// Draw immediately on start
	a.draw()

	events := make(chan tcell.Event, 16)
	go func() {
		for {
			ev := a.screen.PollEvent()
			if ev == nil {
				return
			}
			events <- ev
		}
	}()

	for {
		select {
		case <-ticker.C:
			a.draw()
		case ev := <-events:
			switch e := ev.(type) {
			case *tcell.EventKey:
				switch {
				case e.Key() == tcell.KeyRune && e.Rune() == 'q':
					a.screen.Fini()
					close(a.quit)
					return
				case e.Key() == tcell.KeyUp:
					a.blockedTable.ScrollUp()
					a.draw()
				case e.Key() == tcell.KeyDown:
					w, h := a.screen.Size()
					g := Recalculate(w, h)
					a.blockedTable.ScrollDown(g.MainUpper.H - 4)
					a.draw()
				case e.Key() == tcell.KeyRune && e.Rune() == 'r':
					a.draw()
				}
			case *tcell.EventResize:
				a.screen.Sync()
				a.draw()
			}
		}
	}
}

// Done returns a channel that closes when the user quits.
func (a *App) Done() <-chan struct{} {
	return a.quit
}

func (a *App) draw() {
	s := a.screen
	w, h := s.Size()
	s.Clear()
	g := Recalculate(w, h)

	a.st.RLock()
	defer a.st.RUnlock()

	a.drawHeader(g)
	a.drawStats(g)
	a.drawNICGraph(g)
	a.drawTopSources(g)
	a.drawBlockedIPs(g)
	a.drawAuthLog(g)
	a.drawFooter(g)

	s.Show()
}

func (a *App) drawHeader(g Geometry) {
	nic := a.st.NIC
	header := fmt.Sprintf(" failtop  %s  ▲ %s  ▼ %s  │  pub: %s  local: %s",
		nic.Interface,
		fmtRate(nic.TxRate),
		fmtRate(nic.RxRate),
		strOr(nic.PublicIP, "-"),
		strOr(nic.LocalIP, "-"),
	)
	widgets.Pad(a.screen, 0, 0, g.Header.W, styleHeader)
	widgets.Text(a.screen, 0, 0, header, styleHeader, g.Header.W)
}

func (a *App) drawStats(g Geometry) {
	r := g.Stats
	widgets.Box(a.screen, r.X, r.Y, r.W, r.H, "SECURITY", styleDefault)

	fw := a.st.Firewall
	f2b := a.st.Fail2Ban
	lines := []string{
		fmt.Sprintf(" Firewall:  %-8s", fw.Type),
		fmt.Sprintf(" Blocked:   %d", fw.Blocked),
		fmt.Sprintf(" Rules:     %d", fw.Rules),
		"",
		fmt.Sprintf(" F2B jails: %d", len(f2b.Jails)),
		fmt.Sprintf(" F2B banned:%d", f2b.TotalBanned),
		fmt.Sprintf(" SSH fails: %d", a.st.SSHFails),
		fmt.Sprintf(" Sessions:  %d", a.st.SSHSessions),
	}
	for i, line := range lines {
		if r.Y+1+i >= r.Y+r.H-1 {
			break
		}
		widgets.Pad(a.screen, r.X+1, r.Y+1+i, r.W-2, styleDefault)
		widgets.Text(a.screen, r.X+1, r.Y+1+i, line, styleDefault, r.W-2)
	}
}

func (a *App) drawNICGraph(g Geometry) {
	r := g.NICGraph
	widgets.Box(a.screen, r.X, r.Y, r.W, r.H, "NETWORK", styleDefault)
	innerW := r.W - 4 // prefix "▲ " and "▼ "

	if r.H > 3 {
		widgets.Text(a.screen, r.X+1, r.Y+1, "▲ ", styleSparkRx, 2)
		widgets.Sparkline(a.screen, r.X+3, r.Y+1, a.st.NICTxHist, innerW, styleSparkRx)
		widgets.Text(a.screen, r.X+1, r.Y+2, "▼ ", styleSparkTx, 2)
		widgets.Sparkline(a.screen, r.X+3, r.Y+2, a.st.NICRxHist, innerW, styleSparkTx)
	}
}

func (a *App) drawTopSources(g Geometry) {
	r := g.TopSrc
	widgets.Box(a.screen, r.X, r.Y, r.W, r.H, "TOP SOURCES", styleDefault)
	entries := make([]widgets.BarEntry, 0, len(a.st.TopSources))
	for _, src := range a.st.TopSources {
		entries = append(entries, widgets.BarEntry{
			Label: src.Country,
			Value: src.Pct,
			Count: src.Count,
		})
	}
	widgets.BarChart(a.screen, r.X, r.Y, r.W, r.H, entries, styleBar, styleDefault)
}

func (a *App) drawBlockedIPs(g Geometry) {
	r := g.MainUpper
	widgets.Box(a.screen, r.X, r.Y, r.W, r.H, "BLOCKED IPs", styleDefault)

	rows := make([][]string, 0, len(a.st.BlockedIPs))
	for _, b := range a.st.BlockedIPs {
		geo := a.geo.Lookup(b.IP)
		rows = append(rows, []string{
			b.IP,
			strOr(geo.Country, b.Country),
			strOr(geo.City, b.City),
			strOr(shortOrg(geo.ASN, geo.Org), "-"),
			b.Source,
			fmtAge(b.SeenAt),
		})
	}
	a.blockedTable.Rows = rows
	a.blockedTable.Draw(a.screen, r.X, r.Y, r.W, r.H, styleHeader, styleDefault, styleAlt)
}

func (a *App) drawAuthLog(g Geometry) {
	r := g.MainLower
	widgets.Box(a.screen, r.X, r.Y, r.W, r.H, "AUTH LOG", styleDefault)

	// Sync auth events into scroll text
	a.authLog.Lines = a.authLog.Lines[:0]
	for _, ev := range a.st.AuthEvents {
		var style tcell.Style
		switch ev.Type {
		case "FAIL", "INVALID":
			style = styleFail
		case "OK":
			style = styleOK
		case "BAN":
			style = styleBan
		default:
			style = styleDefault
		}
		line := fmt.Sprintf("%s %-7s %-16s %s", ev.Time.Format("15:04:05"), ev.Type, ev.User, ev.IP)
		a.authLog.Append(line, style)
	}
	a.authLog.Draw(a.screen, r.X, r.Y, r.W, r.H)
}

func (a *App) drawFooter(g Geometry) {
	footer := " [q]quit  [r]refresh  [↑↓]scroll IPs "
	widgets.Pad(a.screen, 0, g.Footer.Y, g.Footer.W, styleDim)
	widgets.Text(a.screen, 0, g.Footer.Y, footer, styleDim, g.Footer.W)
}

// --- Helpers ---

func fmtRate(bps float64) string {
	switch {
	case bps >= 1e9:
		return fmt.Sprintf("%.1fGB/s", bps/1e9)
	case bps >= 1e6:
		return fmt.Sprintf("%.1fMB/s", bps/1e6)
	case bps >= 1e3:
		return fmt.Sprintf("%.1fKB/s", bps/1e3)
	default:
		return fmt.Sprintf("%.0fB/s", bps)
	}
}

func fmtAge(t time.Time) string {
	d := time.Since(t)
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%ds", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%dm", int(d.Minutes()))
	default:
		return fmt.Sprintf("%dh", int(d.Hours()))
	}
}

func strOr(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

func shortOrg(asn, org string) string {
	if asn == "" && org == "" {
		return ""
	}
	if len(org) > 14 {
		org = org[:14]
	}
	return asn + " " + org
}
```

- [ ] **Step 2: Verify compilation**

```bash
go build ./ui/...
```

Expected: no errors.

- [ ] **Step 3: Commit**

```bash
git add ui/app.go
git commit -m "feat: tcell draw loop, event handling, and all panel renderers"
```

---

## Task 17: Wire main.go

**Files:**
- Modify: `main.go`

- [ ] **Step 1: Write main.go**

```go
// main.go
package main

import (
	"fmt"
	"os"
	"time"

	"failtop/config"
	"failtop/sources/authlog"
	"failtop/sources/fail2ban"
	"failtop/sources/firewall"
	"failtop/sources/geo"
	"failtop/sources/nic"
	"failtop/state"
	"failtop/ui"
)

func main() {
	if os.Getuid() != 0 {
		fmt.Fprintln(os.Stderr, "failtop: must be run as root")
		os.Exit(1)
	}

	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "failtop: config error: %v\n", err)
		os.Exit(1)
	}

	st := state.New()

	// Open geo DBs (both optional)
	g := geo.New(cfg.MMDB.City, cfg.MMDB.ASN)
	defer g.Close()

	// Print detection summary before TUI starts
	fmt.Fprintln(os.Stderr, "failtop: probing data sources...")
	authPath := authlog.DetectPath(cfg.AuthLog)
	if authPath != "" {
		fmt.Fprintf(os.Stderr, "  auth log: %s\n", authPath)
	} else {
		fmt.Fprintln(os.Stderr, "  auth log: journald fallback")
	}

	app, err := ui.New(st, g, time.Duration(cfg.RefreshInterval)*time.Second)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failtop: TUI init failed: %v\n", err)
		os.Exit(1)
	}

	done := app.Done()

	// Launch source goroutines
	go authlog.Run(cfg.AuthLog, st, done)
	go firewall.Run(cfg.RefreshInterval, st, done)
	go fail2ban.Run(cfg.RefreshInterval, st, done)
	go nic.Run(cfg.Interface, cfg.PublicIPURL, st, done)

	// Geo enrichment: periodically scan BlockedIPs for missing geo data
	go func() {
		ticker := time.NewTicker(time.Duration(cfg.RefreshInterval) * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-done:
				return
			case <-ticker.C:
				st.Lock()
				for i := range st.BlockedIPs {
					if st.BlockedIPs[i].Country == "" {
						result := g.Lookup(st.BlockedIPs[i].IP)
						st.BlockedIPs[i].Country = result.Country
						st.BlockedIPs[i].City = result.City
						st.BlockedIPs[i].ASN = result.ASN
						st.BlockedIPs[i].Org = result.Org
					}
				}
				st.RecalcTopSources()
				st.Unlock()
			}
		}
	}()

	app.Run()
}
```

- [ ] **Step 2: Build the binary**

```bash
go build -ldflags "-s -w" -o failtop .
```

Expected: `failtop` binary produced with no errors.

- [ ] **Step 3: Run a quick smoke test (as root)**

```bash
sudo ./failtop --help
```

Expected: flag usage printed, no panic.

- [ ] **Step 4: Run all tests one final time**

```bash
go test ./...
```

Expected: all tests pass.

- [ ] **Step 5: Commit**

```bash
git add main.go
git commit -m "feat: wire all sources and UI in main — failtop MVP complete"
```

---

## Self-Review Checklist (completed inline)

- [x] **Spec coverage:** Root check ✓, config file+flags ✓, authlog detect/inotify/journald ✓, UFW/firewalld/iptables adapters ✓, fail2ban ✓, geo+PTR ✓, NIC /proc/net/dev ✓, layout B ✓, all panels ✓, mmdb optional ✓, cross-distro portability ✓, single binary ✓, Makefile ✓
- [x] **Placeholders:** None found.
- [x] **Type consistency:** `state.BlockedIP`, `state.AuthEvent`, `state.FirewallStats`, `state.Fail2BanStats`, `state.JailStats`, `state.GeoEntry` defined in Task 2 and used consistently throughout. `geo.Lookup()` returns `geo.Result` used in Task 16. `widgets.Column`, `widgets.BarEntry`, `widgets.StyledLine` defined in Task 14 and used in Task 16.
