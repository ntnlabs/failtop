// sources/apache/parser.go
package apache

import (
	"regexp"
	"strings"
	"time"

	"failtop/state"
)

// Combined Log Format:
// IP - - [15/Apr/2026:12:01:23 +0000] "GET /path HTTP/1.1" 404 1234 "ref" "ua"
var reApache = regexp.MustCompile(
	`^(\S+) \S+ \S+ \[([^\]]+)\] "(\S+) (\S+) [^"]*" (\d{3}) `,
)

var suspiciousPaths = []string{
	"/wp-admin", "/wp-login", "/wordpress",
	"/.env", "/.git", "/.ssh",
	"/phpmyadmin", "/pma", "/myadmin",
	"/admin", "/administrator",
	"/shell", "/cmd", "/exec",
	"/../", "%2e%2e", "%252e",
	"/etc/passwd", "/proc/self",
	"/.htaccess", "/xmlrpc",
}

// ParseLine parses a Combined Log Format line and returns an AuthEvent if the
// line should be shown (4xx, 5xx, or suspicious path). Returns nil otherwise.
func ParseLine(line string) *state.AuthEvent {
	m := reApache.FindStringSubmatch(line)
	if m == nil {
		return nil
	}
	ip := m[1]
	t, _ := time.Parse("02/Jan/2006:15:04:05 -0700", m[2])
	if t.IsZero() {
		t = time.Now()
	}
	path := m[4]
	status := m[5]

	lower := strings.ToLower(path)
	isSuspicious := false
	for _, s := range suspiciousPaths {
		if strings.Contains(lower, s) {
			isSuspicious = true
			break
		}
	}

	var evType string
	switch {
	case isSuspicious:
		evType = "SCAN"
	case status[0] == '5':
		evType = status
	case status[0] == '4':
		evType = status
	default:
		return nil
	}

	return &state.AuthEvent{
		Time:   t,
		Type:   evType,
		User:   path,
		IP:     ip,
		Method: status,
	}
}
