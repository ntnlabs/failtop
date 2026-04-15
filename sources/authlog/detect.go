// sources/authlog/detect.go
package authlog

import "os"

// knownPaths lists auth log locations in probe order.
var knownPaths = []string{
	"/var/log/auth.log",  // Debian/Ubuntu/Mint
	"/var/log/secure",    // Fedora/RHEL/CentOS
	"/var/log/messages",  // some Alpine/generic syslog
}

// DetectPath returns the override if non-empty, otherwise probes known paths.
// Returns "" if no flat file is found — caller should fall back to journald.
func DetectPath(override string) string {
	if override != "" {
		return override
	}
	for _, p := range knownPaths {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

// DetectMode returns "file" if a flat log path is available, "journald" otherwise.
func DetectMode(override string) string {
	if DetectPath(override) != "" {
		return "file"
	}
	return "journald"
}
