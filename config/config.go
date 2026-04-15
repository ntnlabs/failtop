// config/config.go
package config

import (
	"flag"
	"os"
	"path/filepath"

	"github.com/BurntSushi/toml"
)

type MMDB struct {
	City string `toml:"city"`
	ASN  string `toml:"asn"`
}

type Config struct {
	Interface       string `toml:"interface"`
	RefreshInterval int    `toml:"refresh_interval"`
	AuthLog         string `toml:"auth_log"`
	PublicIPURL     string `toml:"public_ip_url"`
	MMDB            MMDB   `toml:"mmdb"`
}

// Defaults returns a Config populated with sensible defaults.
func Defaults() *Config {
	return &Config{
		Interface:       "",
		RefreshInterval: 2,
		AuthLog:         "",
		PublicIPURL:     "https://checkip.amazonaws.com",
	}
}

// LoadFromFile parses a TOML config file and returns a Config.
// Missing keys retain their zero values; callers should merge with Defaults().
func LoadFromFile(path string) (*Config, error) {
	cfg := Defaults()
	if _, err := toml.DecodeFile(path, cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}

// Load returns a Config with: defaults → config file → CLI flags (highest priority).
// CLI flags are registered and parsed inside this function; call before any other flag.Parse().
func Load() (*Config, error) {
	cfg := Defaults()

	// Load config file if it exists
	path := defaultConfigPath()
	if _, err := os.Stat(path); err == nil {
		if _, err := toml.DecodeFile(path, cfg); err != nil {
			return nil, err
		}
	}

	// CLI flags override config file
	iface := flag.String("interface", cfg.Interface, "NIC interface to monitor")
	refresh := flag.Int("refresh", cfg.RefreshInterval, "Refresh interval in seconds")
	authlog := flag.String("auth-log", cfg.AuthLog, "Auth log path override")
	publicIP := flag.String("public-ip-url", cfg.PublicIPURL, `URL to fetch public IP ("off" to disable)`)
	mmdbCity := flag.String("mmdb-city", cfg.MMDB.City, "Path to GeoLite2-City.mmdb")
	mmdbASN := flag.String("mmdb-asn", cfg.MMDB.ASN, "Path to GeoLite2-ASN.mmdb")
	flag.Parse()

	cfg.Interface = *iface
	cfg.RefreshInterval = *refresh
	cfg.AuthLog = *authlog
	cfg.PublicIPURL = *publicIP
	cfg.MMDB.City = *mmdbCity
	cfg.MMDB.ASN = *mmdbASN

	return cfg, nil
}

func defaultConfigPath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".config", "failtop", "config.toml")
}
