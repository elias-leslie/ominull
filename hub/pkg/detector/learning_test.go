package detector

import (
	"testing"
	"time"

	"ominull/hub/pkg/storage"
)

// A window does not switch the detectors off. The finding is written in full -
// with its severity, its technique and its evidence - and only its visibility
// changes, because the host that was already compromised when its baseline
// period opened is the one host whose findings must not quietly vanish.
func TestFindingsInsideALearningWindowAreHeldNotLost(t *testing.T) {
	engine, store := noiseEngine(t)
	if err := store.UpsertEndpoint(storage.Endpoint{
		ID: "linux-01", TenantID: "default", LocationID: "loc-home", Hostname: "linux-01",
		OS: "Linux", RoleTag: "workstation", Status: "online",
		LastSeenAt: time.Now().UTC(), CreatedAt: time.Now().UTC().Add(-30 * 24 * time.Hour),
	}); err != nil {
		t.Fatalf("seeding the endpoint: %v", err)
	}
	if _, err := store.CreateLearningWindow(storage.LearningWindow{
		TenantID: "default", ScopeType: storage.LearningScopeEndpoint, ScopeID: "linux-01", StartedBy: "test",
	}); err != nil {
		t.Fatalf("opening the window: %v", err)
	}

	now := time.Now().UTC()
	for i := 0; i < 40; i++ {
		bytes := int64(1500)
		if i == 39 {
			bytes = 90 * 1024 * 1024
		}
		engine.Evaluate(storage.Event{
			TenantID: "default", EndpointID: "linux-01", Timestamp: now.Add(time.Duration(i) * time.Second),
			Action: "PERMIT", Direction: "OUTBOUND",
			DstIP: "203.0.113.9", DstPort: 443, BytesOut: bytes,
			ProcessPath: "/usr/bin/curl",
		})
	}

	spikes := anomaliesOfType(t, store, "BANDWIDTH_SPIKE")
	if len(spikes) == 0 {
		t.Fatal("the detector was silenced by the window rather than held")
	}
	for _, a := range spikes {
		if a.HeldReason != storage.HeldLearning {
			t.Fatalf("a finding raised inside a learning window was not held: %+v", a)
		}
		if a.Severity == "" || a.Title == "" || a.Technique == "" {
			t.Fatalf("a held finding lost its detail: %+v", a)
		}
	}

	open, err := store.CountAnomalyAlerts("default", true)
	if err != nil {
		t.Fatalf("counting: %v", err)
	}
	if open != 0 {
		t.Fatalf("held findings were counted as open work: %d", open)
	}
}

// The observations a proposal is argued from are the point of the window, and
// they have to name a program and a counterparty. An unnamed network never
// becomes a pair, because a proposal has to say who it would vouch for.
func TestAWindowRecordsWhatItSaw(t *testing.T) {
	engine, store := noiseEngine(t)
	if err := store.UpsertEndpoint(storage.Endpoint{
		ID: "linux-02", TenantID: "default", LocationID: "loc-home", Hostname: "linux-02",
		OS: "Linux", RoleTag: "workstation", Status: "online",
		LastSeenAt: time.Now().UTC(), CreatedAt: time.Now().UTC().Add(-30 * 24 * time.Hour),
	}); err != nil {
		t.Fatalf("seeding the endpoint: %v", err)
	}
	window, err := store.CreateLearningWindow(storage.LearningWindow{
		TenantID: "default", ScopeType: storage.LearningScopeEndpoint, ScopeID: "linux-02", StartedBy: "test",
	})
	if err != nil {
		t.Fatalf("opening the window: %v", err)
	}

	now := time.Now().UTC()
	for i := 0; i < 5; i++ {
		engine.Evaluate(storage.Event{
			TenantID: "default", EndpointID: "linux-02", Timestamp: now.Add(time.Duration(i) * time.Minute),
			Action: "PERMIT", Direction: "OUTBOUND",
			DstIP: "1.1.1.1", DstPort: 443, BytesOut: 900,
			ProcessPath: "/usr/bin/curl",
		})
	}
	engine.flushLearning()

	obs, err := store.ListLearningObservations(window.ID, "")
	if err != nil {
		t.Fatalf("listing observations: %v", err)
	}
	seen := map[string]int64{}
	for _, o := range obs {
		seen[o.Kind+":"+o.Key] += o.Count
	}
	if seen[storage.LearnProcess+":curl"] != 5 {
		t.Fatalf("the program was not counted: %v", seen)
	}
	if seen[storage.LearnPort+":443"] != 5 {
		t.Fatalf("the port was not counted: %v", seen)
	}
	pairs := 0
	for key := range seen {
		if len(key) > len(storage.LearnPair) && key[:len(storage.LearnPair)] == storage.LearnPair {
			pairs++
		}
	}
	if pairs > 1 {
		t.Fatalf("one conversation produced %d pairs: %v", pairs, seen)
	}
}

// An endpoint outside every window is judged normally. Learning mode that
// leaked across scopes would silence a fleet by accident.
func TestAnEndpointOutsideAWindowIsStillJudged(t *testing.T) {
	engine, store := noiseEngine(t)
	for _, id := range []string{"linux-03", "linux-04"} {
		if err := store.UpsertEndpoint(storage.Endpoint{
			ID: id, TenantID: "default", LocationID: "loc-home", Hostname: id,
			OS: "Linux", RoleTag: "workstation", Status: "online",
			LastSeenAt: time.Now().UTC(), CreatedAt: time.Now().UTC().Add(-30 * 24 * time.Hour),
		}); err != nil {
			t.Fatalf("seeding %s: %v", id, err)
		}
	}
	if _, err := store.CreateLearningWindow(storage.LearningWindow{
		TenantID: "default", ScopeType: storage.LearningScopeEndpoint, ScopeID: "linux-03", StartedBy: "test",
	}); err != nil {
		t.Fatalf("opening the window: %v", err)
	}

	now := time.Now().UTC()
	for i := 0; i < 40; i++ {
		bytes := int64(1500)
		if i == 39 {
			bytes = 90 * 1024 * 1024
		}
		engine.Evaluate(storage.Event{
			TenantID: "default", EndpointID: "linux-04", Timestamp: now.Add(time.Duration(i) * time.Second),
			Action: "PERMIT", Direction: "OUTBOUND",
			DstIP: "203.0.113.10", DstPort: 443, BytesOut: bytes,
			ProcessPath: "/usr/bin/curl",
		})
	}

	spikes := anomaliesOfType(t, store, "BANDWIDTH_SPIKE")
	if len(spikes) == 0 {
		t.Fatal("an endpoint outside every window raised nothing")
	}
	for _, a := range spikes {
		if a.HeldReason != "" {
			t.Fatalf("a window over another host held this finding: %+v", a)
		}
	}
}

// Rented compute never becomes a pair, at either door. The tuning refuses to
// enforce such a pair, so recording one would only produce a proposal that
// looks like protection and is not.
func TestRentedComputeNeverBecomesALearnedPair(t *testing.T) {
	engine, store := noiseEngine(t)
	if err := store.UpsertEndpoint(storage.Endpoint{
		ID: "linux-05", TenantID: "default", LocationID: "loc-home", Hostname: "linux-05",
		OS: "Linux", RoleTag: "workstation", Status: "online",
		LastSeenAt: time.Now().UTC(), CreatedAt: time.Now().UTC().Add(-30 * 24 * time.Hour),
	}); err != nil {
		t.Fatalf("seeding: %v", err)
	}
	window, err := store.CreateLearningWindow(storage.LearningWindow{
		TenantID: "default", ScopeType: storage.LearningScopeEndpoint, ScopeID: "linux-05", StartedBy: "test",
	})
	if err != nil {
		t.Fatalf("opening: %v", err)
	}

	now := time.Now().UTC()
	ep, _ := store.GetEndpoint("linux-05")
	for i := 0; i < 5; i++ {
		engine.observeForLearning(storage.Event{
			TenantID: "default", EndpointID: "linux-05", Direction: "OUTBOUND",
			DstIP: "203.0.113.44", DstPort: 443, ProcessPath: "/usr/bin/python3.13",
		}, *ep, "Rented cloud, listed by Someone", storage.TenancyHosting, 14, now)
	}
	engine.flushLearning()

	obs, err := store.ListLearningObservations(window.ID, storage.LearnPair)
	if err != nil {
		t.Fatalf("listing: %v", err)
	}
	if len(obs) != 0 {
		t.Fatalf("rented compute was recorded as a vouchable pair: %+v", obs)
	}

	// The program itself is still counted - what it talked to is what is
	// refused, not that it ran.
	procs, err := store.ListLearningObservations(window.ID, storage.LearnProcess)
	if err != nil {
		t.Fatalf("listing: %v", err)
	}
	if len(procs) != 1 || procs[0].Count != 5 {
		t.Fatalf("the program was not counted: %+v", procs)
	}
}
