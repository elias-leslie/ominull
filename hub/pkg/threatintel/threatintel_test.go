package threatintel

import (
	"context"
	"errors"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"ominull/hub/pkg/storage"
)

func TestThreatIntelManager(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test_ti.db")

	store, err := storage.New(dbPath)
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}

	mgr := New(store)
	// The feeds are served from a fixture, never fetched: one answers with a
	// list to parse, the other is unreachable and must fall back to the
	// built-in baseline. The test used to wait out a live five-second timeout.
	mgr.httpClient = &http.Client{Transport: feedFixture{
		"feodotracker.abuse.ch": "# Feodo fixture\n203.0.113.7\n\n203.0.113.8 # trailing note\n",
	}}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := mgr.SyncAllFeeds(ctx); err != nil {
		t.Fatalf("SyncAllFeeds failed: %v", err)
	}
	for _, ip := range []string{"203.0.113.7", "203.0.113.8"} {
		if ioc, found := mgr.CheckThreat(ip); !found || ioc.Source != "feodo" {
			t.Fatalf("fixture indicator %s = %+v %v, want a feodo match", ip, ioc, found)
		}
	}
	if _, found := mgr.CheckThreat(mgr.getBuiltinEmergingThreatsBaseline()[0].Value); !found {
		t.Fatal("an unreachable feed did not fall back to its built-in baseline")
	}

	// Verify indicators loaded into fast lookup cache
	iocs, err := store.ListIOCs(100)
	if err != nil {
		t.Fatalf("ListIOCs failed: %v", err)
	}
	if len(iocs) == 0 {
		t.Fatalf("expected active IOCs to be loaded into database")
	}

	// Verify threat lookup against a known indicator from the list
	testIOC := iocs[0]
	matchedIOC, found := mgr.CheckThreat(testIOC.Value)
	if !found {
		t.Fatalf("expected %s to be found in TI cache", testIOC.Value)
	}
	if matchedIOC.Value != testIOC.Value {
		t.Errorf("matched IOC value mismatch: got %s, want %s", matchedIOC.Value, testIOC.Value)
	}

	// Verify clean IP is not flagged
	_, foundClean := mgr.CheckThreat("8.8.8.8")
	if foundClean {
		t.Fatalf("8.8.8.8 should not be in threat feed")
	}

	// Verify Offline GeoIP and ASN Resolution
	geoGoogle := ResolveGeoIP("8.8.8.8")
	if geoGoogle.Country != "US" || geoGoogle.ASN != "AS15169" {
		t.Errorf("unexpected GeoIP for 8.8.8.8: %+v", geoGoogle)
	}

	// 1.1.1.1 is anycast, announced from every Cloudflare edge at once. The
	// table used to answer AU/Sydney for it because APNIC registers the block
	// in that region; which continent a packet to it actually lands on is not
	// knowable offline, so the assertion is on the owner, which is.
	geoCF := ResolveGeoIP("1.1.1.1")
	if geoCF.ASN != "AS13335" || geoCF.Org != "Cloudflare, Inc." {
		t.Errorf("unexpected GeoIP for 1.1.1.1: %+v", geoCF)
	}

	geoLocal := ResolveGeoIP("192.168.1.1")
	if geoLocal.Country != "LOCAL" || geoLocal.ASN != "AS-PRIVATE" {
		t.Errorf("unexpected GeoIP for private IP: %+v", geoLocal)
	}
}

// feedFixture answers feed requests by host; any other host is unreachable.
type feedFixture map[string]string

func (f feedFixture) RoundTrip(r *http.Request) (*http.Response, error) {
	body, ok := f[r.URL.Host]
	if !ok {
		return nil, errors.New("fixture: feed unreachable")
	}
	return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(body)), Header: http.Header{}, Request: r}, nil
}
