// sources/fail2ban/fail2ban_test.go
package fail2ban_test

import (
	"testing"

	"failtop/sources/fail2ban"
)

const statusOutput = `Status
|- Number of jail:	2
` + "`" + `- Jail list:	sshd, nginx-http-auth
`

const jailOutput = `Status for the jail: sshd
|- Filter
|  |- Currently failed:	3
|  |- Total failed:	143
|  ` + "`" + `- File list:	/var/log/auth.log
` + "`" + `- Actions
   |- Currently banned:	5
   |- Total banned:	38
   ` + "`" + `- Banned IP list:	185.220.101.45 103.167.34.21 45.155.205.233 91.134.232.10 194.165.16.68
`

func TestParseJailList(t *testing.T) {
	jails, err := fail2ban.ParseJailList(statusOutput)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(jails) != 2 {
		t.Errorf("want 2 jails, got %d", len(jails))
	}
	if jails[0] != "sshd" {
		t.Errorf("want jails[0]=sshd, got %q", jails[0])
	}
}

func TestParseJailStatus(t *testing.T) {
	stats, err := fail2ban.ParseJailStatus("sshd", jailOutput)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if stats.Name != "sshd" {
		t.Errorf("want Name=sshd, got %q", stats.Name)
	}
	if stats.Banned != 5 {
		t.Errorf("want Banned=5, got %d", stats.Banned)
	}
	if len(stats.BannedIPs) != 5 {
		t.Errorf("want 5 banned IPs, got %d", len(stats.BannedIPs))
	}
	if stats.BannedIPs[0] != "185.220.101.45" {
		t.Errorf("want first IP=185.220.101.45, got %q", stats.BannedIPs[0])
	}
}
