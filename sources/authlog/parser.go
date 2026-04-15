// sources/authlog/parser.go
package authlog

import (
	"fmt"
	"regexp"
	"time"

	"failtop/state"
)

// Event is an alias for state.AuthEvent, re-exported for test convenience.
type Event = state.AuthEvent

var (
	// "Failed password for root from 1.2.3.4 port 22 ssh2"
	// "Failed password for invalid user admin from 1.2.3.4 port 53412 ssh2"
	reFailedPassword = regexp.MustCompile(
		`(\w{3}\s+\d+\s+\d+:\d+:\d+)\s+\S+\s+sshd\[\d+\]:\s+Failed password for (?:invalid user )?(\S+) from (\S+)`)

	// "Invalid user admin from 1.2.3.4 port 12345"
	reInvalidUser = regexp.MustCompile(
		`(\w{3}\s+\d+\s+\d+:\d+:\d+)\s+\S+\s+sshd\[\d+\]:\s+Invalid user (\S+) from (\S+)`)

	// "Accepted publickey for peter from 1.2.3.4 port 54321 ssh2"
	reAccepted = regexp.MustCompile(
		`(\w{3}\s+\d+\s+\d+:\d+:\d+)\s+\S+\s+sshd\[\d+\]:\s+Accepted (\S+) for (\S+) from (\S+)`)
)

const timeLayout = "Jan _2 15:04:05 2006"

func parseTime(s string) time.Time {
	year := time.Now().Year()
	t, err := time.Parse(timeLayout, fmt.Sprintf("%s %d", s, year))
	if err != nil {
		return time.Now()
	}
	return t
}

// ParseLine attempts to extract an AuthEvent from a single log line.
// Returns nil if the line is not a recognized SSH auth event.
func ParseLine(line string) *state.AuthEvent {
	if m := reAccepted.FindStringSubmatch(line); m != nil {
		return &state.AuthEvent{
			Time:   parseTime(m[1]),
			Type:   "OK",
			Method: m[2],
			User:   m[3],
			IP:     m[4],
		}
	}
	if m := reFailedPassword.FindStringSubmatch(line); m != nil {
		return &state.AuthEvent{
			Time: parseTime(m[1]),
			Type: "FAIL",
			User: m[2],
			IP:   m[3],
		}
	}
	if m := reInvalidUser.FindStringSubmatch(line); m != nil {
		return &state.AuthEvent{
			Time: parseTime(m[1]),
			Type: "INVALID",
			User: m[2],
			IP:   m[3],
		}
	}
	return nil
}
