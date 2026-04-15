// sources/apache/apache_test.go
package apache_test

import (
	"testing"

	"failtop/sources/apache"
)

func TestParseLineScan(t *testing.T) {
	line := `185.220.101.45 - - [15/Apr/2026:12:01:23 +0000] "GET /wp-admin HTTP/1.1" 200 1234 "-" "Mozilla/5.0"`
	ev := apache.ParseLine(line)
	if ev == nil {
		t.Fatal("expected event, got nil")
	}
	if ev.Type != "SCAN" {
		t.Errorf("want Type=SCAN, got %q", ev.Type)
	}
	if ev.IP != "185.220.101.45" {
		t.Errorf("want IP=185.220.101.45, got %q", ev.IP)
	}
	if ev.User != "/wp-admin" {
		t.Errorf("want User=/wp-admin, got %q", ev.User)
	}
}

func TestParseLine4xx(t *testing.T) {
	line := `103.167.34.21 - - [15/Apr/2026:12:02:00 +0000] "GET /missing HTTP/1.1" 404 512 "-" "-"`
	ev := apache.ParseLine(line)
	if ev == nil {
		t.Fatal("expected event, got nil")
	}
	if ev.Type != "404" {
		t.Errorf("want Type=404, got %q", ev.Type)
	}
}

func TestParseLine5xx(t *testing.T) {
	line := `10.0.0.1 - - [15/Apr/2026:12:03:00 +0000] "GET /api HTTP/1.1" 500 0 "-" "-"`
	ev := apache.ParseLine(line)
	if ev == nil {
		t.Fatal("expected event, got nil")
	}
	if ev.Type != "500" {
		t.Errorf("want Type=500, got %q", ev.Type)
	}
}

func TestParseLineNormal(t *testing.T) {
	line := `10.0.0.1 - - [15/Apr/2026:12:04:00 +0000] "GET / HTTP/1.1" 200 1024 "-" "-"`
	ev := apache.ParseLine(line)
	if ev != nil {
		t.Errorf("expected nil for normal 200 request, got %+v", ev)
	}
}

func TestParseLineInvalid(t *testing.T) {
	ev := apache.ParseLine("not a log line")
	if ev != nil {
		t.Errorf("expected nil for invalid line, got %+v", ev)
	}
}
