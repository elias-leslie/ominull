package storage

import (
	"path/filepath"
	"testing"
	"time"
)

func TestRouterDailyAggregatesArePrunedAfterRetention(t *testing.T) {
	store := openStore(t, filepath.Join(t.TempDir(), "daily.db"))
	old := time.Now().UTC().Add(-RouterDailyRetention - 48*time.Hour)
	recent := time.Now().UTC()
	for _, at := range []time.Time{old, recent} {
		if err := store.RecordDNSDomainCounts("gw", at, []DNSDomainCount{{ClientIP: "10.0.0.36", Domain: "example.com", Queries: 3}}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := store.PruneOldData(DefaultRetention()); err != nil {
		t.Fatal(err)
	}
	if n, _ := store.DNSDomainQueries(old, "gw", "10.0.0.36", "example.com"); n != 0 {
		t.Fatalf("aggregate past retention survived: %d", n)
	}
	if n, _ := store.DNSDomainQueries(recent, "gw", "10.0.0.36", "example.com"); n != 3 {
		t.Fatalf("recent aggregate = %d, want 3", n)
	}
}
