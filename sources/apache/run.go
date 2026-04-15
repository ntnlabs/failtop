//go:build linux

// sources/apache/run.go
package apache

import (
	"failtop/sources/authlog"
	"failtop/state"
)

// Run detects Apache log files and tails them, feeding filtered events into state.
// Blocks until done is closed.
func Run(st *state.AppState, done <-chan struct{}) {
	paths := DetectLogFiles()
	if len(paths) == 0 {
		return
	}

	lines := make(chan string, 100)
	for _, p := range paths {
		path := p
		go func() {
			_ = authlog.TailFile(path, lines, done)
		}()
	}

	for {
		select {
		case <-done:
			return
		case line := <-lines:
			ev := ParseLine(line)
			if ev == nil {
				continue
			}
			ev.Source = "web"
			st.AddAuthEvent(*ev)
			if ev.IP != "" {
				st.AddOrUpdateBlockedIP(state.BlockedIP{
					IP:     ev.IP,
					Source: "web",
					SeenAt: ev.Time,
				})
			}
		}
	}
}
