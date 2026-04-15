package nic_test

import (
	"os"
	"testing"

	"failtop/sources/nic"
)

func TestParseProcNetDev(t *testing.T) {
	data, err := os.ReadFile("../../testdata/proc_net_dev")
	if err != nil {
		t.Fatal(err)
	}
	ifaces, err := nic.ParseProcNetDev(string(data))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	eth0, ok := ifaces["eth0"]
	if !ok {
		t.Fatal("expected eth0 in parsed result")
	}
	if eth0.RxBytes != 987654321 {
		t.Errorf("want RxBytes=987654321, got %d", eth0.RxBytes)
	}
	if eth0.TxBytes != 123456789 {
		t.Errorf("want TxBytes=123456789, got %d", eth0.TxBytes)
	}
}

func TestDetectInterface(t *testing.T) {
	data, err := os.ReadFile("../../testdata/proc_net_dev")
	if err != nil {
		t.Fatal(err)
	}
	ifaces, _ := nic.ParseProcNetDev(string(data))
	iface := nic.DetectInterface(ifaces)
	if iface != "eth0" {
		t.Errorf("want eth0, got %q", iface)
	}
}
