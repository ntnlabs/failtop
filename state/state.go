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

// AuthEvent is a single parsed line from auth.log or apache access log.
type AuthEvent struct {
	Time   time.Time
	Type   string // "OK", "FAIL", "INVALID", "BAN", "SCAN", "404", "500", ...
	User   string
	IP     string
	Method string // auth method for SSH ("publickey"), status code for HTTP
	Source string // "ssh", "web"
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

	BlockedIPs         []BlockedIP
	TopSources         []GeoEntry
	BlockRate          float64          // new unique IPs per minute
	newBlocksSinceCalc int              // counter reset each minute
	seenIPs            map[string]struct{} // all IPs ever seen, prevents re-counting evicted IPs

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
		seenIPs:   make(map[string]struct{}),
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
	if _, seen := s.seenIPs[b.IP]; !seen {
		s.seenIPs[b.IP] = struct{}{}
		s.newBlocksSinceCalc++
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

// UpdateBlockRate snapshots newBlocksSinceCalc into BlockRate (blocks/min) and resets the counter.
// Must be called with the write lock held.
func (s *AppState) UpdateBlockRate() {
	s.BlockRate = float64(s.newBlocksSinceCalc)
	s.newBlocksSinceCalc = 0
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
