package config_test

import (
	"os"
	"path/filepath"
	"testing"

	"failtop/config"
)

func TestDefaults(t *testing.T) {
	cfg := config.Defaults()
	if cfg.RefreshInterval != 2 {
		t.Errorf("want RefreshInterval=2, got %d", cfg.RefreshInterval)
	}
	if cfg.PublicIPURL != "https://ifconfig.me/ip" {
		t.Errorf("want default public IP URL, got %q", cfg.PublicIPURL)
	}
}

func TestLoadFromFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	content := `interface = "eth1"
refresh_interval = 5

[mmdb]
city = "/tmp/city.mmdb"
asn  = "/tmp/asn.mmdb"
`
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	cfg, err := config.LoadFromFile(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Interface != "eth1" {
		t.Errorf("want interface=eth1, got %q", cfg.Interface)
	}
	if cfg.RefreshInterval != 5 {
		t.Errorf("want refresh=5, got %d", cfg.RefreshInterval)
	}
	if cfg.MMDB.City != "/tmp/city.mmdb" {
		t.Errorf("want mmdb.city=/tmp/city.mmdb, got %q", cfg.MMDB.City)
	}
}
