package server

import (
	"strings"
	"testing"
	"time"

	"ominull/hub/pkg/storage"
	"ominull/hub/pkg/threatintel"
)

func TestJudgeDomainFeeds(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC()
	recent, old := now.Add(-2*time.Hour), now.Add(-48*time.Hour)
	feeds := []storage.DomainIntelFeed{{Name: "a"}, {Name: "b"}}
	stale := 24 * time.Hour
	good := func(name string) threatintel.DomainFeedStatus {
		return threatintel.DomainFeedStatus{Name: name, Domains: 10, FetchedAt: &recent}
	}
	cases := []struct {
		name     string
		feeds    []storage.DomainIntelFeed
		statuses []threatintel.DomainFeedStatus
		severity int
		want     string
	}{
		{"none set up", nil, nil, ocsfSevInformational, "No bad-domain lists"},
		{"all loaded", feeds, []threatintel.DomainFeedStatus{good("a"), good("b")}, ocsfSevInformational, "2 bad-domain lists loaded, 20 names"},
		{"first fetch not done", feeds, []threatintel.DomainFeedStatus{good("a")}, ocsfSevInformational, "still loading"},
		{"one failed fetch is weather", feeds, []threatintel.DomainFeedStatus{good("a"), {Name: "b", Domains: 10, FetchedAt: &recent, Error: "HTTP 503"}},
			ocsfSevInformational, "using its last good copy: b"},
		{"no key", feeds, []threatintel.DomainFeedStatus{{Name: "a", Error: "no key", NeedsKey: true}, {Name: "b", Error: "no key", NeedsKey: true}},
			ocsfSevLow, "abuse.ch key"},
		{"failing past the line", feeds, []threatintel.DomainFeedStatus{good("a"), {Name: "b", Domains: 10, FetchedAt: &old, Error: "HTTP 503"}},
			ocsfSevMedium, "b (HTTP 503)"},
		{"never loaded", feeds, []threatintel.DomainFeedStatus{good("a"), {Name: "b", Error: "the list held no names"}},
			ocsfSevMedium, "the list held no names"},
		{"a real failure outranks a missing key", feeds, []threatintel.DomainFeedStatus{{Name: "a", Error: "no key", NeedsKey: true}, {Name: "b", Error: "HTTP 500"}},
			ocsfSevMedium, "b (HTTP 500)"},
	}
	for _, c := range cases {
		severity, status, message := judgeDomainFeeds(c.feeds, c.statuses, now, stale)
		if severity != c.severity || !strings.Contains(message, c.want) {
			t.Errorf("%s: severity %d, message %q", c.name, severity, message)
		}
		if raised := severity > ocsfSevInformational; raised != (status == ocsfStatusNew) {
			t.Errorf("%s: severity %d with status %d", c.name, severity, status)
		}
	}
}

func TestUnmatchedEndpointFinding(t *testing.T) {
	t.Parallel()
	srv, store := setupTestServer(t)
	defer store.Close()
	now := time.Now().UTC()
	yes := true
	endpoint := func(id, host, os, status string, seen time.Time) {
		t.Helper()
		if err := store.UpsertEndpoint(storage.Endpoint{ID: id, TenantID: "t-01", Hostname: host, OS: os, Status: status, LastSeenAt: seen}); err != nil {
			t.Fatal(err)
		}
	}
	endpoint("known", "known.lan", "Linux", "online", now)
	endpoint("laptop", "LAPTOP-1", "Windows 11", "online", now)
	endpoint("gone", "gone", "Linux", "retired", now)
	// An old row of a re-enrolled host is not a second machine.
	endpoint("known-old", "known", "Linux", "offline", now.Add(-time.Hour))

	f, err := srv.unmatchedEndpointFinding(now)
	if err != nil {
		t.Fatal(err)
	}
	if f.SeverityID != ocsfSevInformational || !strings.Contains(f.Message, "Not checked") {
		t.Fatalf("no list from Aico yet: %+v", f)
	}
	if err := store.SaveAicoFleet([]storage.AicoMachine{{Machine: "known", Up: &yes, Reports: true}}, now); err != nil {
		t.Fatal(err)
	}
	if f, err = srv.unmatchedEndpointFinding(now); err != nil {
		t.Fatal(err)
	}
	if f.SeverityID != ocsfSevInformational || !strings.Contains(f.Message, "1 Windows agent is outside") {
		t.Fatalf("only Windows outside: %+v", f)
	}
	endpoint("renamed", "renamed-host", "Linux", "online", now)
	if f, err = srv.unmatchedEndpointFinding(now); err != nil {
		t.Fatal(err)
	}
	if f.SeverityID != ocsfSevLow || f.StatusID != ocsfStatusNew || strings.Contains(f.Message, "renamed") {
		t.Fatalf("a Linux agent outside: %+v", f)
	}
	if got := f.Unmapped["endpoints"].([]string); len(got) != 1 || got[0] != "renamed" {
		t.Fatalf("named endpoints: %v", got)
	}
	if err := store.SaveAicoFleet([]storage.AicoMachine{{Machine: "known", Up: &yes, Reports: true}}, now.Add(-24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if f, err = srv.unmatchedEndpointFinding(now); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(f.Message, "Not checked") {
		t.Fatalf("a stale list is not evidence: %+v", f)
	}
}
