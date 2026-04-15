// sources/firewall/firewall_test.go
package firewall_test

import (
	"testing"

	"failtop/sources/firewall"
)

const ufwStatusVerbose = `Status: active
Logging: on (low)
Default: deny (incoming), allow (outgoing), disabled (routed)
New profiles: skip

To                         Action      From
--                         ------      ----
22/tcp                     ALLOW IN    Anywhere
80/tcp                     ALLOW IN    Anywhere
443/tcp                    ALLOW IN    Anywhere
185.220.101.45             DENY IN     Anywhere
103.167.34.21              DENY IN     Anywhere
45.155.205.233             REJECT IN   Anywhere
`

func TestParseUFWStats(t *testing.T) {
	stats, err := firewall.ParseUFWStatus(ufwStatusVerbose)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if stats.Type != "ufw" {
		t.Errorf("want Type=ufw, got %q", stats.Type)
	}
	if stats.Rules != 3 {
		t.Errorf("want Rules=3, got %d", stats.Rules)
	}
	if stats.Blocked != 3 {
		t.Errorf("want Blocked=3, got %d", stats.Blocked)
	}
}

const iptablesOutput = `Chain INPUT (policy DROP 1247 packets, 65832 bytes)
 pkts bytes target     prot opt in     out     source               destination
  892  45184 ACCEPT     all  --  *      *       0.0.0.0/0            0.0.0.0/0            state RELATED,ESTABLISHED
    0      0 ACCEPT     all  --  lo     *       0.0.0.0/0            0.0.0.0/0
    2    104 ACCEPT     tcp  --  *      *       0.0.0.0/0            0.0.0.0/0            tcp dpt:22
`

func TestParseIPTablesStats(t *testing.T) {
	stats, err := firewall.ParseIPTablesOutput(iptablesOutput)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if stats.Type != "iptables" {
		t.Errorf("want Type=iptables, got %q", stats.Type)
	}
	if stats.Blocked != 1247 {
		t.Errorf("want Blocked=1247, got %d", stats.Blocked)
	}
	if stats.Allowed != 894 {
		t.Errorf("want Allowed=894, got %d", stats.Allowed)
	}
}
