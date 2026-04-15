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
