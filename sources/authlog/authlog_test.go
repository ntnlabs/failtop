// sources/authlog/authlog_test.go
package authlog_test

import (
	"os"
	"strings"
	"testing"
	"time"

	"failtop/sources/authlog"
)

func TestParseLine_FailedPassword(t *testing.T) {
	line := "Apr 15 12:00:01 myhost sshd[1234]: Failed password for root from 185.220.101.45 port 22 ssh2"
	ev := authlog.ParseLine(line)
	if ev == nil {
		t.Fatal("expected event, got nil")
	}
	if ev.Type != "FAIL" {
		t.Errorf("want Type=FAIL, got %q", ev.Type)
	}
	if ev.User != "root" {
		t.Errorf("want User=root, got %q", ev.User)
	}
	if ev.IP != "185.220.101.45" {
		t.Errorf("want IP=185.220.101.45, got %q", ev.IP)
	}
	if ev.Time.IsZero() {
		t.Error("expected non-zero time")
	}
}

func TestParseLine_FailedPasswordInvalidUser(t *testing.T) {
	line := "Apr 15 12:00:05 myhost sshd[1235]: Failed password for invalid user admin from 103.167.34.21 port 53412 ssh2"
	ev := authlog.ParseLine(line)
	if ev == nil {
		t.Fatal("expected event, got nil")
	}
	if ev.Type != "FAIL" {
		t.Errorf("want Type=FAIL, got %q", ev.Type)
	}
	if ev.User != "admin" {
		t.Errorf("want User=admin, got %q", ev.User)
	}
	if ev.IP != "103.167.34.21" {
		t.Errorf("want IP=103.167.34.21, got %q", ev.IP)
	}
}

func TestParseLine_InvalidUser(t *testing.T) {
	line := "Apr 15 12:00:10 myhost sshd[1236]: Invalid user ftp from 45.155.205.233 port 12345"
	ev := authlog.ParseLine(line)
	if ev == nil {
		t.Fatal("expected event, got nil")
	}
	if ev.Type != "INVALID" {
		t.Errorf("want Type=INVALID, got %q", ev.Type)
	}
	if ev.IP != "45.155.205.233" {
		t.Errorf("want IP=45.155.205.233, got %q", ev.IP)
	}
}

func TestParseLine_Accepted(t *testing.T) {
	line := "Apr 15 12:00:15 myhost sshd[1237]: Accepted publickey for peter from 192.168.1.5 port 54321 ssh2"
	ev := authlog.ParseLine(line)
	if ev == nil {
		t.Fatal("expected event, got nil")
	}
	if ev.Type != "OK" {
		t.Errorf("want Type=OK, got %q", ev.Type)
	}
	if ev.User != "peter" {
		t.Errorf("want User=peter, got %q", ev.User)
	}
	if ev.Method != "publickey" {
		t.Errorf("want Method=publickey, got %q", ev.Method)
	}
	if ev.IP != "192.168.1.5" {
		t.Errorf("want IP=192.168.1.5, got %q", ev.IP)
	}
}

func TestParseLine_Unrecognized(t *testing.T) {
	line := "Apr 15 12:00:00 myhost kernel: some unrelated log line"
	ev := authlog.ParseLine(line)
	if ev != nil {
		t.Errorf("expected nil for unrecognized line, got %+v", ev)
	}
}

func TestParseFixtureUbuntu(t *testing.T) {
	data, err := os.ReadFile("../../testdata/auth.log.ubuntu")
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	var events []*authlog.Event
	for _, line := range lines {
		if ev := authlog.ParseLine(line); ev != nil {
			events = append(events, ev)
		}
	}
	if len(events) < 5 {
		t.Errorf("expected at least 5 events from ubuntu fixture, got %d", len(events))
	}
}

func TestParseLine_Year(t *testing.T) {
	line := "Jan  1 00:00:01 myhost sshd[1]: Failed password for root from 1.2.3.4 port 22 ssh2"
	ev := authlog.ParseLine(line)
	if ev == nil {
		t.Fatal("expected event, got nil")
	}
	if ev.Time.Year() != time.Now().Year() {
		t.Errorf("want year=%d, got %d", time.Now().Year(), ev.Time.Year())
	}
}
