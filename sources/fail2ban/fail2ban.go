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
