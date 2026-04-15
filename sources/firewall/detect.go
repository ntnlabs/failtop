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

// Run polls the firewall every interval seconds and updates st. Blocks until done is closed.
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
