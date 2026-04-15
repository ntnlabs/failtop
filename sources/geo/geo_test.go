package geo_test

import (
	"testing"

	"failtop/sources/geo"
)

func TestNewWithNilDBs(t *testing.T) {
	// Geo works fine with no mmdb files — returns empty strings
	g := geo.New("", "")
	result := g.Lookup("185.220.101.45")
	if result.Country != "" {
		t.Errorf("expected empty Country without mmdb, got %q", result.Country)
	}
	if result.ASN != "" {
		t.Errorf("expected empty ASN without mmdb, got %q", result.ASN)
	}
}

func TestCaching(t *testing.T) {
	g := geo.New("", "")
	// First lookup
	r1 := g.Lookup("1.1.1.1")
	// Second lookup — must return same struct (from cache, no panic)
	r2 := g.Lookup("1.1.1.1")
	if r1.Country != r2.Country {
		t.Errorf("cache inconsistency: %q vs %q", r1.Country, r2.Country)
	}
}
