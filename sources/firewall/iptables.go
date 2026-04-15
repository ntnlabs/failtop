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
		if strings.HasPrefix(line, "Chain INPUT") {
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
