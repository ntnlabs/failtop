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
// Prints warning to stdout if a path is given but file can't be opened.
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
