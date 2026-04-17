// sources/authlog/run.go
package authlog

import (
	"time"

	"failtop/state"
)

// Run starts the auth log goroutine. It detects the log source, tails it,
// parses each line, and updates st. Blocks until done is closed.
func Run(authLogOverride string, st *state.AppState, done <-chan struct{}) {
	lines := make(chan string, 256)
	mode := DetectMode(authLogOverride)

	st.Lock()
	if mode == "file" {
		path := DetectPath(authLogOverride)
		st.AuthLogAvail = true
		st.AuthLogMsg = "tailing " + path
		st.Unlock()
		go func() {
			if err := TailFile(path, lines, done); err != nil {
				st.Lock()
				st.AuthLogMsg = "tailer error: " + err.Error()
				st.Unlock()
			}
		}()
	} else {
		st.AuthLogAvail = true
		st.AuthLogMsg = "journald (sshd)"
		st.Unlock()
		go func() {
			if err := TailJournald(lines, done); err != nil {
				st.Lock()
				st.AuthLogMsg = "journald error: " + err.Error()
				st.Unlock()
			}
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
			ev.Source = "ssh"
			st.Lock()
			st.AddAuthEvent(*ev)
			switch ev.Type {
			case "FAIL", "INVALID":
				st.SSHFails++
				if ev.IP != "" {
					st.AddOrUpdateBlockedIP(state.BlockedIP{
						IP:     ev.IP,
						Source: "ssh",
						SeenAt: time.Now(),
					})
				}
			case "OK":
				st.SSHSessions++
			case "BYE":
				if st.SSHSessions > 0 {
					st.SSHSessions--
				}
			}
			st.Unlock()
		}
	}
}
