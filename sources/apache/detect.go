// sources/apache/detect.go
package apache

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
)

var configDirs = []string{
	"/etc/apache2/sites-enabled",
	"/etc/httpd/conf.d",
	"/etc/apache2/conf-enabled",
}

var logDirs = []string{
	"/var/log/apache2",
	"/var/log/httpd",
}

// DetectLogFiles returns a deduplicated list of Apache access log file paths.
// First tries parsing Apache config files for CustomLog directives,
// then falls back to globbing known log directories.
func DetectLogFiles() []string {
	paths := fromConfig()
	if len(paths) > 0 {
		return paths
	}
	return fromGlob()
}

func fromConfig() []string {
	seen := map[string]bool{}
	var result []string
	for _, dir := range configDirs {
		matches, _ := filepath.Glob(filepath.Join(dir, "*.conf"))
		for _, conf := range matches {
			for _, p := range parseCustomLogs(conf) {
				if !seen[p] {
					seen[p] = true
					result = append(result, p)
				}
			}
		}
	}
	return result
}

func parseCustomLogs(path string) []string {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	var paths []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		if !strings.EqualFold(fields[0], "customlog") {
			continue
		}
		if len(fields) >= 2 && strings.HasPrefix(fields[1], "/") {
			paths = append(paths, fields[1])
		}
	}
	return paths
}

func fromGlob() []string {
	var result []string
	for _, dir := range logDirs {
		matches, _ := filepath.Glob(filepath.Join(dir, "*access*.log"))
		result = append(result, matches...)
	}
	return result
}
