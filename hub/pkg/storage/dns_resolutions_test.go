package storage

import (
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The point of the table: turn an address back into the name it was looked up
// under.
func TestResolutionNamesAnAddress(t *testing.T) {
	store := openStore(t, filepath.Join(t.TempDir(), "res.db"))
	now := time.Now().UTC()

	accepted, rejected, err := store.RecordDNSResolutions([]DNSResolution{
		{Domain: "firmware.nest.com", IP: "10.9.9.9", At: now},
	}, now)
	if err != nil {
		t.Fatalf("recording: %v", err)
	}
	if accepted != 1 || rejected != 0 {
		t.Fatalf("expected the answer kept, got %d/%d", accepted, rejected)
	}
	if got := store.NameForIP("10.9.9.9"); got != "firmware.nest.com" {
		t.Fatalf("address was not named: %q", got)
	}
}

// dnsmasq puts outcomes in the value position for answers carrying no address.
// Those are not names and must never become rows.
func TestResolutionRejectsNonAnswers(t *testing.T) {
	store := openStore(t, filepath.Join(t.TempDir(), "res.db"))
	now := time.Now().UTC()

	_, rejected, err := store.RecordDNSResolutions([]DNSResolution{
		{Domain: "NXDOMAIN", IP: "10.9.9.1", At: now},
		{Domain: "NODATA-IPv6", IP: "10.9.9.2", At: now},
		{Domain: "no-dots", IP: "10.9.9.3", At: now},
		{Domain: "good.example.com", IP: "not-an-address", At: now},
		{Domain: "real.example.com", IP: "10.9.9.4", At: now},
	}, now)
	if err != nil {
		t.Fatalf("recording: %v", err)
	}
	if rejected != 4 {
		t.Fatalf("expected four rejects, got %d", rejected)
	}
	if store.NameForIP("10.9.9.1") != "" || store.NameForIP("10.9.9.2") != "" {
		t.Fatalf("an outcome was stored as a name")
	}
	if store.NameForIP("10.9.9.4") != "real.example.com" {
		t.Fatalf("the valid answer was lost")
	}
}

// A name is chosen by whoever asked for it, so it is attacker-controlled.
func TestResolutionDomainIsBounded(t *testing.T) {
	store := openStore(t, filepath.Join(t.TempDir(), "res.db"))
	now := time.Now().UTC()
	_, rejected, err := store.RecordDNSResolutions([]DNSResolution{
		{Domain: strings.Repeat("a", 300) + ".com", IP: "10.9.9.5", At: now},
		{Domain: "bad\x00name.com", IP: "10.9.9.6", At: now},
	}, now)
	if err != nil {
		t.Fatalf("recording: %v", err)
	}
	if rejected != 2 {
		t.Fatalf("an oversized or control-character name survived: %d rejected", rejected)
	}
}

// Case and a trailing dot are the same name; storing both would split the row
// and make the hit count lie.
func TestResolutionFoldsSpelling(t *testing.T) {
	store := openStore(t, filepath.Join(t.TempDir(), "res.db"))
	now := time.Now().UTC()
	if _, _, err := store.RecordDNSResolutions([]DNSResolution{
		{Domain: "API.Example.COM.", IP: "10.9.9.7", At: now},
		{Domain: "api.example.com", IP: "10.9.9.7", At: now},
	}, now); err != nil {
		t.Fatalf("recording: %v", err)
	}
	names, err := store.LookupNamesForIP("10.9.9.7", 10)
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if len(names) != 1 {
		t.Fatalf("one name spelled two ways became %d rows: %+v", len(names), names)
	}
	if names[0].Hits != 2 {
		t.Fatalf("hits did not accumulate: %d", names[0].Hits)
	}
}

// A CDN address serves many names; the most recent is the one most likely to
// explain the connection being judged now.
func TestResolutionPrefersMostRecentName(t *testing.T) {
	store := openStore(t, filepath.Join(t.TempDir(), "res.db"))
	now := time.Now().UTC()
	if _, _, err := store.RecordDNSResolutions([]DNSResolution{
		{Domain: "old.example.com", IP: "10.9.9.8", At: now.Add(-2 * time.Hour)},
		{Domain: "new.example.com", IP: "10.9.9.8", At: now},
	}, now); err != nil {
		t.Fatalf("recording: %v", err)
	}
	if got := store.NameForIP("10.9.9.8"); got != "new.example.com" {
		t.Fatalf("expected the most recent name, got %q", got)
	}
}

// Naming a page of alerts must not be a query per row.
func TestResolutionBatchLookup(t *testing.T) {
	store := openStore(t, filepath.Join(t.TempDir(), "res.db"))
	now := time.Now().UTC()
	if _, _, err := store.RecordDNSResolutions([]DNSResolution{
		{Domain: "one.example.com", IP: "10.9.9.11", At: now},
		{Domain: "two.example.com", IP: "10.9.9.12", At: now},
	}, now); err != nil {
		t.Fatalf("recording: %v", err)
	}
	got, err := store.NamesForIPs([]string{"10.9.9.11", "10.9.9.12", "10.9.9.13", "rubbish"})
	if err != nil {
		t.Fatalf("batch lookup: %v", err)
	}
	if got["10.9.9.11"] != "one.example.com" || got["10.9.9.12"] != "two.example.com" {
		t.Fatalf("batch lookup wrong: %v", got)
	}
	if _, ok := got["10.9.9.13"]; ok {
		t.Fatalf("an unknown address was given a name: %v", got)
	}
}

// Bindings go stale; a table nobody prunes is a disk-full incident waiting.
func TestResolutionsArePruned(t *testing.T) {
	store := openStore(t, filepath.Join(t.TempDir(), "res.db"))
	old := time.Now().UTC().Add(-72 * time.Hour)
	if _, _, err := store.RecordDNSResolutions([]DNSResolution{
		{Domain: "stale.example.com", IP: "10.9.9.20", At: old},
	}, old); err != nil {
		t.Fatalf("recording: %v", err)
	}
	n, err := store.PruneOldDNSResolutions(24 * time.Hour)
	if err != nil {
		t.Fatalf("pruning: %v", err)
	}
	if n != 1 {
		t.Fatalf("expected the stale binding pruned, removed %d", n)
	}
}
