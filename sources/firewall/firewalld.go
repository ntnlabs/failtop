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
			fields := strings.Fields(line)
			if len(fields) > 1 {
				stats.Rules += len(fields) - 1
			}
		}
	}
	return stats, nil
}
