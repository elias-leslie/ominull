package detector

import (
	"testing"
	"time"

	"ominull/hub/pkg/storage"
	"ominull/hub/pkg/threatintel"
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
	// The program by its path and the network by its AS number: the forms a
	// proposal is applied in.
	if seen[storage.LearnProcess+":/usr/bin/curl"] != 5 || seen[storage.LearnPair+":/usr/bin/curl@as13335"] != 5 {
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
		}, *ep, threatintel.GeoRecord{ASN: "AS64500", Org: "Rented cloud, listed by Someone", Tenancy: storage.TenancyHosting}, 14, now)
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

// A path the agent could not match to the file that runs names no program, so
// learning records neither the program nor a pair for it: a proposal argued
// from it would vouch for whatever was bind-mounted over that path. What the
// estate did - the hour, the port, the network - is still counted.
func TestAPathMismatchIsNeverLearnedAsAProgram(t *testing.T) {
	engine, store := noiseEngine(t)
	if err := store.UpsertEndpoint(storage.Endpoint{
		ID: "linux-06", TenantID: "default", LocationID: "loc-home", Hostname: "linux-06",
		OS: "Linux", RoleTag: "workstation", Status: "online",
		LastSeenAt: time.Now().UTC(), CreatedAt: time.Now().UTC().Add(-30 * 24 * time.Hour),
	}); err != nil {
		t.Fatalf("seeding: %v", err)
	}
	window, err := store.CreateLearningWindow(storage.LearningWindow{
		TenantID: "default", ScopeType: storage.LearningScopeEndpoint, ScopeID: "linux-06", StartedBy: "test",
	})
	if err != nil {
		t.Fatalf("opening: %v", err)
	}

	now := time.Now().UTC()
	ep, _ := store.GetEndpoint("linux-06")
	for i := 0; i < 5; i++ {
		engine.observeForLearning(storage.Event{
			TenantID: "default", EndpointID: "linux-06", Direction: "OUTBOUND",
			DstIP: "1.1.1.1", DstPort: 443, ProcessPath: "/opt/google/chrome/chrome", AttributionStatus: pathMismatch,
		}, *ep, threatintel.GeoRecord{ASN: "AS13335", Org: "Cloudflare, Inc.", Tenancy: storage.TenancySharedCDN}, 14, now)
	}
	engine.flushLearning()

	obs, err := store.ListLearningObservations(window.ID, "")
	if err != nil {
		t.Fatalf("listing: %v", err)
	}
	seen := map[string]int64{}
	for _, o := range obs {
		if o.Kind == storage.LearnProcess || o.Kind == storage.LearnPair {
			t.Fatalf("a path_mismatch process was learned as %s %q", o.Kind, o.Key)
		}
		seen[o.Kind+":"+o.Key] += o.Count
	}
	if seen[storage.LearnPort+":443"] != 5 || seen[storage.LearnOwner+":as13335"] != 5 || seen[storage.LearnHour+":14"] != 5 {
		t.Fatalf("the conversation itself was not counted: %v", seen)
	}
}

// A window over the whole estate holds behavioural findings only. A
// threat-list match and a sensitive-port egress are floors: they page inside
// a window as they do outside it, so even an approved window cannot hide them.
func TestALearningWindowNeverHoldsTheFloor(t *testing.T) {
	engine, store := noiseEngine(t)
	if err := store.UpsertEndpoint(storage.Endpoint{
		ID: "linux-03", TenantID: "default", LocationID: "loc-home", Hostname: "linux-03",
		OS: "Linux", RoleTag: "workstation", Status: "online",
		LastSeenAt: time.Now().UTC(), CreatedAt: time.Now().UTC().Add(-30 * 24 * time.Hour),
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.CreateLearningWindow(storage.LearningWindow{
		TenantID: "default", ScopeType: storage.LearningScopeTenant, StartedBy: "test",
	}); err != nil {
		t.Fatal(err)
	}
	if _, learning := store.LearningWindowFor(storage.Endpoint{ID: "linux-03", TenantID: "default"}); !learning {
		t.Fatal("the estate-wide window does not cover the host")
	}
	now := time.Now().UTC()
	flow := func(dst string, port uint16, ioc *storage.IOC) storage.Event {
		return storage.Event{TenantID: "default", EndpointID: "linux-03", Timestamp: now, Action: "PERMIT",
			Direction: "OUTBOUND", DstIP: dst, DstPort: port, BytesOut: 800, ProcessPath: "/usr/bin/curl", ThreatMatch: ioc}
	}
	engine.Evaluate(flow("185.220.101.5", 443, &storage.IOC{Value: "185.220.101.5", Source: "test-feed", ThreatType: "c2", Confidence: 100, Active: true}))
	engine.Evaluate(flow("159.65.0.10", 445, nil))
	for _, kind := range []string{"THREAT_INTEL_MATCH", "SENSITIVE_PORT_EGRESS"} {
		got := anomaliesOfType(t, store, kind)
		if len(got) != 1 || got[0].HeldReason != "" {
			t.Fatalf("%s inside a learning window = %+v, want one finding that pages", kind, got)
		}
	}
	for kind := range learningHolds {
		if TierFor(kind) == storage.TierHunt {
			t.Fatalf("%s is a hunt lead and is held as one already", kind)
		}
	}
}
