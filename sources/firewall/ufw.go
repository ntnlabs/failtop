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
		if strings.Contains(line, "ALLOW") || strings.Contains(line, "DENY") || strings.Contains(line, "REJECT") {
			if !strings.HasPrefix(line, "Default") {
				stats.Rules++
			}
		}
	}
	return stats, nil
}
