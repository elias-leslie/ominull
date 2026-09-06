package storage

import (
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func seedEndpoint(t *testing.T, s *Store, id, tenant, location, role string) {
	t.Helper()
	if err := s.UpsertEndpoint(Endpoint{
		ID:         id,
		TenantID:   tenant,
		LocationID: location,
		Hostname:   id,
		OS:         "Linux",
		RoleTag:    role,
		Status:     "online",
		LastSeenAt: time.Now().UTC(),
		CreatedAt:  time.Now().UTC().Add(-30 * 24 * time.Hour),
	}); err != nil {
		t.Fatalf("seeding endpoint %s: %v", id, err)
	}
}

func openLearningWindow(t *testing.T, s *Store, scopeType, scopeID string) LearningWindow {
	t.Helper()
	w, err := s.CreateLearningWindow(LearningWindow{
		TenantID:  "default",
		ScopeType: scopeType,
		ScopeID:   scopeID,
		StartedBy: "tester",
	})
	if err != nil {
		t.Fatalf("opening a %s window: %v", scopeType, err)
	}
	return w
}

// A window opened over a location has to cover the endpoints in it. Scoping
// only to a single host would make learning mode useless for the case it
// exists for - a whole site being brought under management at once.
func TestALocationWindowCoversItsEndpoints(t *testing.T) {
	store := openStore(t, filepath.Join(t.TempDir(), "learning.db"))
	seedEndpoint(t, store, "ep-here", "default", "loc-home", "workstation")
	seedEndpoint(t, store, "ep-elsewhere", "default", "loc-office", "workstation")

	openLearningWindow(t, store, LearningScopeLocation, "loc-home")

	here, _ := store.GetEndpoint("ep-here")
	if _, learning := store.LearningWindowFor(*here); !learning {
		t.Fatal("an endpoint at the window's location is not learning")
	}
	elsewhere, _ := store.GetEndpoint("ep-elsewhere")
	if _, learning := store.LearningWindowFor(*elsewhere); learning {
		t.Fatal("an endpoint at another location was swept into the window")
	}
}

// The narrowest window wins, so observations from a host with its own window
// land there rather than in an estate-wide one opened around it.
func TestTheNarrowestWindowOwnsTheEndpoint(t *testing.T) {
	store := openStore(t, filepath.Join(t.TempDir(), "learning.db"))
	seedEndpoint(t, store, "ep-1", "default", "loc-home", "workstation")

	openLearningWindow(t, store, LearningScopeTenant, "default")
	narrow := openLearningWindow(t, store, LearningScopeEndpoint, "ep-1")

	ep, _ := store.GetEndpoint("ep-1")
	got, learning := store.LearningWindowFor(*ep)
	if !learning {
		t.Fatal("the endpoint is not learning at all")
	}
	if got.ID != narrow.ID {
		t.Fatalf("the estate-wide window claimed the endpoint: got %s, want %s", got.ID, narrow.ID)
	}
}

// A window that has been closed, or whose end has simply passed, stops holding
// findings at once. A hub that was down when a window ended must not resume
// holding when it comes back.
func TestAFinishedWindowStopsHolding(t *testing.T) {
	store := openStore(t, filepath.Join(t.TempDir(), "learning.db"))
	seedEndpoint(t, store, "ep-1", "default", "loc-home", "workstation")
	w := openLearningWindow(t, store, LearningScopeEndpoint, "ep-1")

	ep, _ := store.GetEndpoint("ep-1")
	if _, learning := store.LearningWindowFor(*ep); !learning {
		t.Fatal("a fresh window is not holding")
	}
	if err := store.CloseLearningWindow(w.ID, LearningCompleted); err != nil {
		t.Fatalf("closing: %v", err)
	}
	if _, learning := store.LearningWindowFor(*ep); learning {
		t.Fatal("a closed window is still holding")
	}

	past := w
	past.Status = LearningActive
	past.EndsAt = time.Now().UTC().Add(-time.Minute)
	if past.Open(time.Now().UTC()) {
		t.Fatal("a window whose end has passed still reads as open")
	}
}

// A held finding is recorded in full and stays out of every count that
// describes outstanding work, and it is one filter away.
func TestHeldFindingsAreKeptButNotRaised(t *testing.T) {
	store := openStore(t, filepath.Join(t.TempDir(), "learning.db"))
	seedAnomaly(t, store, "open-1", "HIGH", false)
	if err := store.CreateAnomalyAlert(AnomalyAlert{
		ID:          "held-1",
		TenantID:    "default",
		EndpointID:  "ep-1",
		AnomalyType: "C2_BEACONING",
		Severity:    "CRITICAL",
		Title:       "held finding",
		HeldReason:  HeldLearning,
		Timestamp:   time.Now().UTC(),
	}); err != nil {
		t.Fatalf("seeding the held finding: %v", err)
	}

	count, err := store.CountAnomalyAlerts("default", true)
	if err != nil {
		t.Fatalf("counting: %v", err)
	}
	if count != 1 {
		t.Fatalf("the open count included a held finding: got %d, want 1", count)
	}

	page, total, err := store.QueryAnomalyAlerts("default", 50, 0, true, "", "", "", HeldExclude)
	if err != nil {
		t.Fatalf("querying: %v", err)
	}
	if total != 1 || len(page) != 1 || page[0].ID != "open-1" {
		t.Fatalf("the default view showed a held finding: %d rows, total %d", len(page), total)
	}

	held, heldTotal, err := store.QueryAnomalyAlerts("default", 50, 0, true, "", "", "", HeldOnly)
	if err != nil {
		t.Fatalf("querying held: %v", err)
	}
	if heldTotal != 1 || len(held) != 1 || held[0].ID != "held-1" {
		t.Fatalf("the Held filter did not return the held finding: %d rows", len(held))
	}
	if held[0].HeldReason != HeldLearning || held[0].Severity != "CRITICAL" {
		t.Fatalf("the held finding lost its detail: %+v", held[0])
	}

	// The dashboard reads the same rows as the alert page.
	summary, err := store.GetAnalyticsSummary("default")
	if err != nil {
		t.Fatalf("summary: %v", err)
	}
	sum := int64(0)
	for _, n := range summary.SeverityCounts {
		sum += int64(n)
	}
	if sum != count {
		t.Fatalf("the severity chart counted held findings: %d against %d open", sum, count)
	}
}

// A proposal has to carry the argument for itself: how much evidence, how many
// machines, and how those machines break down by role.
func TestProposalsCarryTheirCorroboration(t *testing.T) {
	store := openStore(t, filepath.Join(t.TempDir(), "learning.db"))
	seedEndpoint(t, store, "ep-1", "default", "loc-home", "workstation")
	seedEndpoint(t, store, "ep-2", "default", "loc-home", "workstation")
	seedEndpoint(t, store, "ep-3", "default", "loc-home", "server")
	w := openLearningWindow(t, store, LearningScopeLocation, "loc-home")

	now := time.Now().UTC()
	obs := []LearningObservation{}
	for _, ep := range []string{"ep-1", "ep-2", "ep-3"} {
		obs = append(obs,
			LearningObservation{WindowID: w.ID, EndpointID: ep, Kind: LearnPair, Key: "backup-agent@acme storage", Count: 400, FirstSeen: now, LastSeen: now},
			LearningObservation{WindowID: w.ID, EndpointID: ep, Kind: LearnProcess, Key: "backup-agent", Count: 400, FirstSeen: now, LastSeen: now},
		)
	}
	obs = append(obs,
		LearningObservation{WindowID: w.ID, EndpointID: "ep-1", Kind: LearnPair, Key: "oddity@somebody else", Count: 3, FirstSeen: now, LastSeen: now},
		LearningObservation{WindowID: w.ID, EndpointID: "ep-1", Kind: LearnProcess, Key: "oddity", Count: 3, FirstSeen: now, LastSeen: now},
	)
	if err := store.RecordLearningObservations(obs); err != nil {
		t.Fatalf("recording observations: %v", err)
	}

	proposals, err := store.ComputeLearningProposals(w.ID)
	if err != nil {
		t.Fatalf("computing proposals: %v", err)
	}

	var wide, narrow *LearningProposal
	for i := range proposals {
		switch proposals[i].Subject {
		case "backup-agent@acme storage":
			wide = &proposals[i]
		case "oddity@somebody else":
			narrow = &proposals[i]
		}
	}
	if wide == nil || narrow == nil {
		t.Fatalf("expected both pair proposals, got %d: %+v", len(proposals), proposals)
	}
	if wide.Endpoints != 3 || wide.Evidence != 1200 {
		t.Fatalf("the corroborated pair lost its evidence: %d endpoints, %d observations", wide.Endpoints, wide.Evidence)
	}
	if wide.Roles["workstation"] != 2 || wide.Roles["server"] != 1 {
		t.Fatalf("the role breakdown is wrong: %v", wide.Roles)
	}
	if narrow.Endpoints != 1 {
		t.Fatalf("the single-host pair claims corroboration: %d", narrow.Endpoints)
	}
	if !(wide.Corroboration > narrow.Corroboration) {
		t.Fatalf("one machine argued as strongly as three: %.2f against %.2f", narrow.Corroboration, wide.Corroboration)
	}
	if proposals[0].Subject != "backup-agent@acme storage" {
		t.Fatalf("the best-argued proposal is not first: %s", proposals[0].Subject)
	}
	// A pair whose counterparty nobody named must never become a proposal, and
	// the accumulator must not invent one.
	for _, p := range proposals {
		if strings.Contains(p.Subject, "@unattributed") {
			t.Fatalf("an unnamed network was proposed for silence: %s", p.Subject)
		}
	}
}

// The quiet-hours reading is the longest run of hours in which nothing
// happened. An estate that never went quiet has no window to propose.
func TestQuietHoursAreOnlyProposedWhenTheEstateSlept(t *testing.T) {
	store := openStore(t, filepath.Join(t.TempDir(), "learning.db"))
	seedEndpoint(t, store, "ep-1", "default", "loc-home", "workstation")
	w := openLearningWindow(t, store, LearningScopeEndpoint, "ep-1")

	now := time.Now().UTC()
	obs := []LearningObservation{}
	// Awake 07:00-22:59, asleep 23:00-06:59.
	for h := 7; h <= 22; h++ {
		obs = append(obs, LearningObservation{
			WindowID: w.ID, EndpointID: "ep-1", Kind: LearnHour,
			Key: fmt.Sprintf("%d", h), Count: 100, FirstSeen: now, LastSeen: now,
		})
	}
	if err := store.RecordLearningObservations(obs); err != nil {
		t.Fatalf("recording: %v", err)
	}

	proposals, err := store.ComputeLearningProposals(w.ID)
	if err != nil {
		t.Fatalf("computing: %v", err)
	}
	var hours *LearningProposal
	for i := range proposals {
		if proposals[i].Kind == ProposeOffHours {
			hours = &proposals[i]
		}
	}
	if hours == nil {
		t.Fatal("no quiet-hours proposal from an estate that slept eight hours")
	}
	if hours.Subject != "23:00-07:00" {
		t.Fatalf("the quiet window was read wrong: %s", hours.Subject)
	}

	// An estate busy around the clock proposes nothing.
	busy := openLearningWindow(t, store, LearningScopeTenant, "default")
	all := []LearningObservation{}
	for h := 0; h < 24; h++ {
		all = append(all, LearningObservation{
			WindowID: busy.ID, EndpointID: "ep-1", Kind: LearnHour,
			Key: fmt.Sprintf("%d", h), Count: 10, FirstSeen: now, LastSeen: now,
		})
	}
	if err := store.RecordLearningObservations(all); err != nil {
		t.Fatalf("recording: %v", err)
	}
	busyProposals, err := store.ComputeLearningProposals(busy.ID)
	if err != nil {
		t.Fatalf("computing: %v", err)
	}
	for _, p := range busyProposals {
		if p.Kind == ProposeOffHours {
			t.Fatalf("an estate that never went quiet proposed quiet hours: %s", p.Subject)
		}
	}
}

// Observations accumulate rather than overwrite: a window is a total, not a
// snapshot of the last flush.
func TestObservationsAccumulate(t *testing.T) {
	store := openStore(t, filepath.Join(t.TempDir(), "learning.db"))
	seedEndpoint(t, store, "ep-1", "default", "loc-home", "workstation")
	w := openLearningWindow(t, store, LearningScopeEndpoint, "ep-1")

	first := time.Now().UTC().Add(-time.Hour)
	last := time.Now().UTC()
	for _, at := range []time.Time{first, last} {
		if err := store.RecordLearningObservations([]LearningObservation{{
			WindowID: w.ID, EndpointID: "ep-1", Kind: LearnPair, Key: "curl@acme",
			Count: 5, FirstSeen: at, LastSeen: at,
		}}); err != nil {
			t.Fatalf("recording: %v", err)
		}
	}

	obs, err := store.ListLearningObservations(w.ID, LearnPair)
	if err != nil {
		t.Fatalf("listing: %v", err)
	}
	if len(obs) != 1 {
		t.Fatalf("expected one accumulated row, got %d", len(obs))
	}
	if obs[0].Count != 10 {
		t.Fatalf("counts did not accumulate: %d", obs[0].Count)
	}
	if obs[0].LastSeen.Before(last.Add(-time.Second)) {
		t.Fatalf("the last-seen time went backwards: %s", obs[0].LastSeen)
	}
}

// A window that only caught one busy hour has not watched a day, and must not
// be allowed to declare the other twenty-three off-hours. This is the shape a
// short live window takes, and the arithmetic alone would happily propose it.
func TestOneBusyHourProposesNoOffHours(t *testing.T) {
	store := openStore(t, filepath.Join(t.TempDir(), "learning.db"))
	seedEndpoint(t, store, "ep-1", "default", "loc-home", "workstation")
	w := openLearningWindow(t, store, LearningScopeEndpoint, "ep-1")

	now := time.Now().UTC()
	if err := store.RecordLearningObservations([]LearningObservation{{
		WindowID: w.ID, EndpointID: "ep-1", Kind: LearnHour,
		Key: "19", Count: 40, FirstSeen: now, LastSeen: now,
	}}); err != nil {
		t.Fatalf("recording: %v", err)
	}

	proposals, err := store.ComputeLearningProposals(w.ID)
	if err != nil {
		t.Fatalf("computing: %v", err)
	}
	for _, p := range proposals {
		if p.Kind == ProposeOffHours {
			t.Fatalf("one observed hour proposed an off-hours window: %s", p.Subject)
		}
	}
}
