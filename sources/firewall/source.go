// sources/firewall/source.go
package firewall

import "failtop/state"

// Source is the interface all firewall adapters implement.
type Source interface {
	Name() string
	// Poll queries the firewall and returns current stats.
	Poll() (state.FirewallStats, error)
}
