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
	failing := func(name string, fetched, since *time.Time, err string, needsKey bool) threatintel.DomainFeedStatus {
		return threatintel.DomainFeedStatus{Name: name, Domains: 10, FetchedAt: fetched, FailingSince: since, Error: err, NeedsKey: needsKey}
	}
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
		{"one failed fetch is weather", feeds, []threatintel.DomainFeedStatus{good("a"), failing("b", &recent, &recent, "HTTP 503", false)},
			ocsfSevInformational, "using its last good copy: b"},
		// A last good fetch long ago says nothing about how long it has been failing.
		{"a first failure after a long good run is weather", feeds, []threatintel.DomainFeedStatus{good("a"), failing("b", &old, &recent, "HTTP 503", false)},
			ocsfSevInformational, "using its last good copy: b"},
		{"a first fetch failing right after a restart is weather", feeds, []threatintel.DomainFeedStatus{good("a"), failing("b", nil, &recent, "HTTP 503", false)},
			ocsfSevInformational, "aren't checked; retrying: b"},
		{"no key", feeds, []threatintel.DomainFeedStatus{failing("a", nil, &old, "no key", true), failing("b", nil, &old, "no key", true)},
			ocsfSevLow, "abuse.ch key"},
		{"a key lost after a good fetch still has its copy", feeds, []threatintel.DomainFeedStatus{good("a"), failing("b", &recent, &recent, "no key", true)},
			ocsfSevInformational, "using its last good copy: b"},
		{"a key lost long ago is a failing list", feeds, []threatintel.DomainFeedStatus{good("a"), failing("b", &old, &old, "no key", true)},
			ocsfSevMedium, "over 24 h: b"},
		{"failing past the line", feeds, []threatintel.DomainFeedStatus{good("a"), failing("b", &old, &old, "HTTP 503", false)},
			ocsfSevMedium, "over 24 h: b"},
		{"never loaded past the line", feeds, []threatintel.DomainFeedStatus{good("a"), failing("b", nil, &old, "the list held no names", false)},
			ocsfSevMedium, "over 24 h: b"},
		{"a real failure outranks a missing key", feeds, []threatintel.DomainFeedStatus{failing("a", nil, &old, "no key", true), failing("b", nil, &old, "HTTP 500", false)},
			ocsfSevMedium, "over 24 h: b"},
	}
	for _, c := range cases {
		severity, status, message := judgeDomainFeeds(c.feeds, c.statuses, now, stale)
		if severity != c.severity || !strings.Contains(message, c.want) {
			t.Errorf("%s: severity %d, message %q", c.name, severity, message)
		}
		if strings.Contains(message, "HTTP") || strings.Contains(message, "held no names") {
			t.Errorf("%s: a fetch error reached the message: %q", c.name, message)
		}
		if raised := severity > ocsfSevInformational; raised != (status == ocsfStatusNew) {
			t.Errorf("%s: severity %d with status %d", c.name, severity, status)
		}
	}
}

// A restart forgets a list's failures in memory; the count of how long it has failed
// carries on, so a hub restarted daily still says when a list stays down.
func TestDomainFeedFailureCountSurvivesARestart(t *testing.T) {
	t.Parallel()
	srv, store := setupTestServer(t)
	defer store.Close()
	now := time.Now().UTC().Truncate(time.Second)
	first, restarted := now.Add(-30*time.Hour), now.Add(-time.Hour)
	failing := func(since time.Time) []threatintel.DomainFeedStatus {
		return []threatintel.DomainFeedStatus{{Name: "b", Error: "HTTP 503", FailingSince: &since}}
	}
	feeds := []storage.DomainIntelFeed{{Name: "b"}}
	if got := srv.domainFeedFailures(feeds, failing(first), first); !got[0].FailingSince.Equal(first) {
		t.Fatalf("first failure: %v", got[0].FailingSince)
	}
	// A hub just started judges before its first fetch.
	srv.domainFeedFailures(feeds, nil, restarted)
	got := srv.domainFeedFailures(feeds, failing(restarted), now)
	if !got[0].FailingSince.Equal(first) {
		t.Fatalf("a restart restarted the count: %v", got[0].FailingSince)
	}
	if severity, _, _ := judgeDomainFeeds(feeds, got, now, 24*time.Hour); severity != ocsfSevMedium {
		t.Fatalf("a list down for 30 h across a restart graded %d", severity)
	}
	fetched := now
	if good := srv.domainFeedFailures(feeds, []threatintel.DomainFeedStatus{{Name: "b", FetchedAt: &fetched}}, now); good[0].FailingSince != nil {
		t.Fatalf("a good fetch kept a failure time: %+v", good[0])
	}
	if got := srv.domainFeedFailures(feeds, failing(now), now); !got[0].FailingSince.Equal(now) {
		t.Fatalf("a good fetch didn't end the count: %v", got[0].FailingSince)
	}
	srv.domainFeedFailures(feeds, failing(first), now)
	srv.domainFeedFailures(nil, nil, now)
	if got := srv.domainFeedFailures(feeds, failing(now), now); !got[0].FailingSince.Equal(now) {
		t.Fatalf("a list taken out of the tuning kept its count: %v", got[0].FailingSince)
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
