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
	if fw := firewall.Detect(); fw != nil {
		fmt.Fprintf(os.Stderr, "  firewall: %s\n", fw.Name())
	} else {
		fmt.Fprintln(os.Stderr, "  firewall: none detected")
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

	// Geo enrichment: periodically scan BlockedIPs for missing geo data.
	// Lookups happen outside the lock to avoid blocking the UI render path.
	go func() {
		ticker := time.NewTicker(time.Duration(cfg.RefreshInterval) * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-done:
				return
			case <-ticker.C:
				st.RLock()
				type pending struct {
					idx int
					ip  string
				}
				var work []pending
				for i, b := range st.BlockedIPs {
					if b.Country == "" {
						work = append(work, pending{i, b.IP})
					}
				}
				st.RUnlock()

				if len(work) == 0 {
					continue
				}

				type result struct {
					idx int
					r   geo.Result
				}
				results := make([]result, 0, len(work))
				for _, w := range work {
					results = append(results, result{w.idx, g.Lookup(w.ip)})
				}

				st.Lock()
				for _, res := range results {
					if res.idx < len(st.BlockedIPs) {
						st.BlockedIPs[res.idx].Country = res.r.Country
						st.BlockedIPs[res.idx].City = res.r.City
						st.BlockedIPs[res.idx].ASN = res.r.ASN
						st.BlockedIPs[res.idx].Org = res.r.Org
					}
				}
				st.RecalcTopSources()
				st.Unlock()
			}
		}
	}()

	app.Run()
}
