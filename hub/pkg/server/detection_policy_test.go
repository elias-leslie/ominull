package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"ominull/hub/pkg/storage"
)

// policyPost sends one detection-policy write with the admin key, once, with
// no owner standing by: what an agent holding the key gets.
func policyPost(srv *Server, method, path, body, approval string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-API-Key", "mock_admin_token")
	if approval != "" {
		r.Header.Set(approvalHeader, approval)
	}
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, r)
	return w
}

type pendingApproval struct {
	ApprovalID string   `json:"approval_id"`
	Action     string   `json:"action"`
	Summary    string   `json:"summary"`
	Loosens    []string `json:"loosens"`
	Targets    []string `json:"targets"`
}

func mustPend(t *testing.T, w *httptest.ResponseRecorder) pendingApproval {
	t.Helper()
	if w.Code != http.StatusAccepted {
		t.Fatalf("want 202 (waits for the owner), got %d %s", w.Code, w.Body.String())
	}
	var p pendingApproval
	if err := json.Unmarshal(w.Body.Bytes(), &p); err != nil || p.ApprovalID == "" {
		t.Fatalf("202 without an approval: %s", w.Body.String())
	}
	return p
}

func policyNotes(t *testing.T, store *storage.Store) []storage.AuditEntry {
	t.Helper()
	page, err := store.AuditHistory("", 100, "", storage.AuditFilter{Action: policyChangedAudit})
	if err != nil {
		t.Fatal(err)
	}
	return page.Entries
}

// Every field the tuning row saves says which way loosens, so a field added
// later cannot slip through as "no change".
func TestEveryTuningFieldKnowsWhichWayLoosens(t *testing.T) {
	typ := reflect.TypeOf(storage.DetectionTuning{})
	for i := 0; i < typ.NumField(); i++ {
		name := strings.Split(typ.Field(i).Tag.Get("json"), ",")[0]
		if _, ok := tuningDirections[name]; !ok {
			t.Errorf("tuning field %q has no direction in tuningDirections", name)
		}
	}
}

func TestTuningChangesAreJudgedFieldByField(t *testing.T) {
	base := storage.DefaultDetectionTuning()
	base.QuietOrgs = []string{"as15169", "as8075"}
	base.KnownWorkloads = []storage.KnownWorkload{{Workload: "/usr/bin/gh", Owner: "as36459", Reason: "cli", ExpiresAt: testExpiry}}
	cases := []struct {
		name   string
		change func(*storage.DetectionTuning)
		want   []string
	}{
		{"nothing", func(*storage.DetectionTuning) {}, nil},
		{"beacon off", func(t *storage.DetectionTuning) { t.BeaconOn = false }, []string{"beacon_enabled"}},
		{"raised threshold", func(t *storage.DetectionTuning) { t.BeaconScore = 0.95 }, []string{"beacon_score_threshold"}},
		{"lowered threshold", func(t *storage.DetectionTuning) { t.BeaconScore = 0.6 }, nil},
		{"narrower beacon band", func(t *storage.DetectionTuning) { t.BeaconMaxInterval = 600 }, []string{"beacon_max_interval_seconds"}},
		{"longer learning period", func(t *storage.DetectionTuning) { t.WarmupHours = 48 }, []string{"warmup_hours"}},
		{"removed quiet network", func(t *storage.DetectionTuning) { t.QuietOrgs = []string{"as15169"} }, nil},
		{"added quiet network", func(t *storage.DetectionTuning) { t.QuietOrgs = append(t.QuietOrgs, "as16509") }, []string{"quiet_orgs"}},
		// Same length, different contents: one entry swapped for another.
		{"equal-length swap", func(t *storage.DetectionTuning) { t.QuietOrgs = []string{"as15169", "as16509"} }, []string{"quiet_orgs"}},
		{"rented workload", func(t *storage.DetectionTuning) {
			t.KnownWorkloads = []storage.KnownWorkload{{Workload: "/usr/bin/gh", Owner: "*", Reason: "cli", ExpiresAt: testExpiry, IncludeRented: true}}
		}, []string{"known_workloads"}},
		{"removed workload", func(t *storage.DetectionTuning) { t.KnownWorkloads = nil }, nil},
		{"workload expiry extended", func(t *storage.DetectionTuning) {
			t.KnownWorkloads = []storage.KnownWorkload{{Workload: "/usr/bin/gh", Owner: "as36459", Reason: "cli", ExpiresAt: testExpiry.Add(time.Hour)}}
		}, []string{"known_workloads"}},
		{"workload expiry shortened", func(t *storage.DetectionTuning) {
			t.KnownWorkloads = []storage.KnownWorkload{{Workload: "/usr/bin/gh", Owner: "as36459", Reason: "cli", ExpiresAt: testExpiry.Add(-time.Hour)}}
		}, nil},
		{"workload reason reworded", func(t *storage.DetectionTuning) {
			t.KnownWorkloads = []storage.KnownWorkload{{Workload: "/usr/bin/gh", Owner: "as36459", Reason: "GitHub CLI", ExpiresAt: testExpiry}}
		}, nil},
		{"mixed", func(t *storage.DetectionTuning) { t.BeaconScore = 0.6; t.FirstSeenOn = false }, []string{"first_seen_enabled"}},
		{"agent runtime removed", func(t *storage.DetectionTuning) { t.AgentRuntimes = t.AgentRuntimes[1:] }, []string{"agent_runtimes"}},
		{"agent-heavy by observation", func(t *storage.DetectionTuning) { t.AgentHeavyObserved = !t.AgentHeavyObserved }, nil},
		{"vendor prefix added", func(t *storage.DetectionTuning) {
			t.AgentRuntimeVendors[0].Prefixes = append(t.AgentRuntimeVendors[0].Prefixes, "198.51.100.0/24")
		}, []string{"agent_runtime_vendors"}},
		{"vendor domain added", func(t *storage.DetectionTuning) {
			t.AgentRuntimeVendors[1].Domains = append(t.AgentRuntimeVendors[1].Domains, "example.com")
		}, []string{"agent_runtime_vendors"}},
		{"vendor for a new runtime", func(t *storage.DetectionTuning) {
			t.AgentRuntimeVendors = append(t.AgentRuntimeVendors, storage.AgentRuntimeVendor{Runtime: "ollama", Vendor: "Ollama", Domains: []string{"ollama.com"}})
		}, []string{"agent_runtime_vendors"}},
		{"vendor renamed", func(t *storage.DetectionTuning) { t.AgentRuntimeVendors[0].Vendor = "Someone" }, []string{"agent_runtime_vendors"}},
		{"vendor prefix removed", func(t *storage.DetectionTuning) {
			t.AgentRuntimeVendors[0].Prefixes = t.AgentRuntimeVendors[0].Prefixes[1:]
		}, nil},
		{"vendor domain removed", func(t *storage.DetectionTuning) {
			t.AgentRuntimeVendors[1].Domains = t.AgentRuntimeVendors[1].Domains[1:]
		}, nil},
		{"vendor removed", func(t *storage.DetectionTuning) { t.AgentRuntimeVendors = t.AgentRuntimeVendors[1:] }, nil},
		{"wider window", func(t *storage.DetectionTuning) { t.OffHoursStart = 21 }, nil},
		{"shorter window", func(t *storage.DetectionTuning) { t.OffHoursStart = 23 }, []string{"off_hours_window"}},
		{"moved window", func(t *storage.DetectionTuning) { t.OffHoursStart, t.OffHoursEnd = 23, 6 }, []string{"off_hours_window"}},
		{"other zone", func(t *storage.DetectionTuning) { t.OffHoursZone = "UTC" }, []string{"off_hours_window"}},
	}
	for _, c := range cases {
		after := base
		after.QuietOrgs = append([]string(nil), base.QuietOrgs...)
		after.AgentRuntimes = append(after.AgentRuntimes[:0:0], base.AgentRuntimes...)
		after.AgentRuntimeVendors = nil
		for _, v := range base.AgentRuntimeVendors {
			v.Domains = append([]string(nil), v.Domains...)
			v.Prefixes = append([]string(nil), v.Prefixes...)
			after.AgentRuntimeVendors = append(after.AgentRuntimeVendors, v)
		}
		c.change(&after)
		after, err := storage.PrepareDetectionTuning(after)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		got := tuningLoosens(base, after)
		if strings.Join(got, ",") != strings.Join(c.want, ",") {
			t.Errorf("%s: loosens %v, want %v", c.name, got, c.want)
		}
	}
	if base.AgentHeavyObserved {
		off := base
		off.AgentHeavyObserved = false
		if got := tuningLoosens(off, base); len(got) != 1 {
			t.Errorf("counting agent-heavy hosts by observation mutes more: %v", got)
		}
	}
}

// A reset tightens only when every entry it brings back is one already saved.
func TestAResetLoosensWhenItBringsQuietEntriesBack(t *testing.T) {
	shipped := storage.DefaultDetectionTuning()
	tighter := shipped
	tighter.QuietClients = shipped.QuietClients[1:]
	if got := tuningLoosens(tighter, shipped); strings.Join(got, ",") != "quiet_clients" {
		t.Fatalf("reset re-adding a removed client: %v", got)
	}
	looser := shipped
	looser.QuietOrgs = append(append([]string(nil), shipped.QuietOrgs...), "as64500")
	looser.BeaconOn = false
	if got := tuningLoosens(looser, shipped); len(got) != 0 {
		t.Fatalf("reset from a looser row should only tighten: %v", got)
	}
}

// The admin key, which every agent can read, cannot loosen detection: the
// save waits for the owner and nothing changes until they approve.
func TestALooseningSaveWaitsForTheOwner(t *testing.T) {
	t.Parallel()
	srv, store := setupTestServer(t)
	defer store.Close()
	body := `{"beacon_enabled":false,"quiet_orgs":["as714","as8075","as15169","as13335","as16509","as20940","as54113","as64500"]}`
	p := mustPend(t, policyPost(srv, http.MethodPost, "/api/v1/detection/tuning", body, ""))
	if p.Action != "Loosen detection tuning" || !strings.Contains(p.Summary, "beacon_enabled true -> false") || !strings.Contains(p.Summary, "quiet_orgs +as64500") {
		t.Fatalf("the owner would not see the change: %+v", p)
	}
	if strings.Join(p.Loosens, ",") != "beacon_enabled,quiet_orgs" || len(p.Targets) != 1 || p.Targets[0] != "detection:tuning" {
		t.Fatalf("pending approval = %+v", p)
	}
	if got := store.GetDetectionTuning(); !got.BeaconOn || len(got.QuietOrgs) != 7 {
		t.Fatal("a loosening save applied before the owner approved it")
	}
	// Repeating it with an approval nobody granted changes nothing.
	if w := policyPost(srv, http.MethodPost, "/api/v1/detection/tuning", body, p.ApprovalID); w.Code != http.StatusForbidden {
		t.Fatalf("unapproved retry = %d %s", w.Code, w.Body.String())
	}
	// PUT and case-variant keys go through the same gate.
	mustPend(t, policyPost(srv, http.MethodPut, "/api/v1/detection/tuning", `{"Beacon_Enabled":false}`, ""))
	if !store.GetDetectionTuning().BeaconOn {
		t.Fatal("a case-variant key slipped past the gate")
	}

	ownerOf(t, srv).approve(t, p.ApprovalID)
	if w := policyPost(srv, http.MethodPost, "/api/v1/detection/tuning", body, p.ApprovalID); w.Code != http.StatusOK {
		t.Fatalf("approved save = %d %s", w.Code, w.Body.String())
	}
	if got := store.GetDetectionTuning(); got.BeaconOn || len(got.QuietOrgs) != 8 {
		t.Fatal("the approved save did not apply")
	}
	notes := policyNotes(t, store)
	if len(notes) != 1 || !strings.Contains(notes[0].Details, "loosened (beacon_enabled, quiet_orgs) with owner approval "+p.ApprovalID) ||
		!strings.Contains(notes[0].Details, "credential api-key (unverified)") {
		t.Fatalf("notes = %+v", notes)
	}
	// An approval is spent once.
	if w := policyPost(srv, http.MethodPost, "/api/v1/detection/tuning", `{"beacon_enabled":false,"warmup_hours":72}`, p.ApprovalID); w.Code != http.StatusForbidden {
		t.Fatalf("spent approval reused = %d", w.Code)
	}
}

// An approval covers the change the owner saw and nothing else.
func TestAnApprovalCannotCarryADifferentChange(t *testing.T) {
	t.Parallel()
	srv, store := setupTestServer(t)
	defer store.Close()
	p := mustPend(t, policyPost(srv, http.MethodPost, "/api/v1/detection/tuning", `{"warmup_hours":48}`, ""))
	ownerOf(t, srv).approve(t, p.ApprovalID)
	if w := policyPost(srv, http.MethodPost, "/api/v1/detection/tuning", `{"beacon_enabled":false}`, p.ApprovalID); w.Code != http.StatusForbidden {
		t.Fatalf("another change under the approval = %d %s", w.Code, w.Body.String())
	}
	if !store.GetDetectionTuning().BeaconOn {
		t.Fatal("beacon detection was switched off under an approval for something else")
	}
}

// The digest binds the policy as it was when the owner was asked: once that
// policy has moved, the approval is refused rather than applied over it.
func TestAStaleApprovalIsRefused(t *testing.T) {
	t.Parallel()
	srv, store := setupTestServer(t)
	defer store.Close()
	p := mustPend(t, policyPost(srv, http.MethodPost, "/api/v1/detection/tuning", `{"warmup_hours":48}`, ""))
	ownerOf(t, srv).approve(t, p.ApprovalID)
	// Meanwhile a tightening save lands, which needs nobody.
	if w := policyPost(srv, http.MethodPost, "/api/v1/detection/tuning", `{"beacon_score_threshold":0.7}`, ""); w.Code != http.StatusOK {
		t.Fatalf("tightening save = %d %s", w.Code, w.Body.String())
	}
	w := policyPost(srv, http.MethodPost, "/api/v1/detection/tuning", `{"warmup_hours":48}`, p.ApprovalID)
	if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "ask again") {
		t.Fatalf("stale approval = %d %s", w.Code, w.Body.String())
	}
	if store.GetDetectionTuning().WarmupHours != 24 {
		t.Fatal("a stale approval applied")
	}
}

// Tightening applies at once and leaves a note naming the credential.
func TestATighteningSaveAppliesWithANote(t *testing.T) {
	t.Parallel()
	srv, store := setupTestServer(t)
	defer store.Close()
	w := policyPost(srv, http.MethodPost, "/api/v1/detection/tuning", `{"beacon_score_threshold":0.7,"warmup_hours":12}`, "")
	if w.Code != http.StatusOK {
		t.Fatalf("tightening save = %d %s", w.Code, w.Body.String())
	}
	if got := store.GetDetectionTuning(); got.BeaconScore != 0.7 || got.WarmupHours != 12 {
		t.Fatal("the tightening save did not apply")
	}
	notes := policyNotes(t, store)
	if len(notes) != 1 || !strings.HasPrefix(notes[0].Details, "tightened detection tuning save") || !strings.Contains(notes[0].Details, "credential api-key (unverified)") {
		t.Fatalf("notes = %+v", notes)
	}
	// A save that changes nothing leaves no note.
	if w := policyPost(srv, http.MethodPost, "/api/v1/detection/tuning", `{}`, ""); w.Code != http.StatusOK {
		t.Fatalf("empty save = %d", w.Code)
	}
	if len(policyNotes(t, store)) != 1 {
		t.Fatal("a save with no change left a note")
	}
}

// Silence is part of the floor: no save switches it off, tap or not.
func TestSilenceDetectionCannotBeSwitchedOff(t *testing.T) {
	t.Parallel()
	srv, store := setupTestServer(t)
	defer store.Close()
	w := policyPost(srv, http.MethodPost, "/api/v1/detection/tuning", `{"silence_enabled":false}`, "")
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "floor") {
		t.Fatalf("silence off = %d %s", w.Code, w.Body.String())
	}
	if !store.GetDetectionTuning().SilenceOn {
		t.Fatal("silence detection is off")
	}
}

// Concurrent saves are serialised: each patch lands over the one before it,
// so none of them is lost.
func TestConcurrentSavesAreNotLost(t *testing.T) {
	t.Parallel()
	srv, store := setupTestServer(t)
	defer store.Close()
	bodies := []string{`{"beacon_score_threshold":0.7}`, `{"warmup_hours":6}`, `{"beacon_cooldown_minutes":10}`, `{"first_seen_cooldown_minutes":10}`, `{"bandwidth_cooldown_minutes":2}`, `{"silence_after_minutes":10}`}
	var wg sync.WaitGroup
	for _, b := range bodies {
		wg.Add(1)
		go func(b string) {
			defer wg.Done()
			if w := policyPost(srv, http.MethodPost, "/api/v1/detection/tuning", b, ""); w.Code != http.StatusOK {
				t.Errorf("%s = %d %s", b, w.Code, w.Body.String())
			}
		}(b)
	}
	wg.Wait()
	got := store.GetDetectionTuning()
	if got.BeaconScore != 0.7 || got.WarmupHours != 6 || got.BeaconCooldownMin != 10 || got.FirstSeenCooldown != 10 || got.BandwidthCooldown != 2 || got.SilenceAfterMinutes != 10 {
		t.Fatalf("a concurrent save was lost: %+v", got)
	}
}

// Restoring the shipped values waits for the owner when it brings back quiet
// entries someone removed, and applies at once when it only tightens.
func TestResetIsJudgedLikeAnySave(t *testing.T) {
	t.Parallel()
	srv, store := setupTestServer(t)
	defer store.Close()
	tu := storage.DefaultDetectionTuning()
	tu.QuietClients = tu.QuietClients[1:]
	if _, err := store.SaveDetectionTuning(tu, "test"); err != nil {
		t.Fatal(err)
	}
	p := mustPend(t, policyPost(srv, http.MethodDelete, "/api/v1/detection/tuning", "", ""))
	if p.Action != "Restore shipped detection tuning" || !strings.Contains(p.Summary, "quiet_clients +") {
		t.Fatalf("reset approval = %+v", p)
	}
	ownerOf(t, srv).approve(t, p.ApprovalID)
	if w := policyPost(srv, http.MethodDelete, "/api/v1/detection/tuning", "", p.ApprovalID); w.Code != http.StatusOK {
		t.Fatalf("approved reset = %d %s", w.Code, w.Body.String())
	}

	tu = storage.DefaultDetectionTuning()
	tu.BeaconOn = false
	if _, err := store.SaveDetectionTuning(tu, "test"); err != nil {
		t.Fatal(err)
	}
	if w := policyPost(srv, http.MethodDelete, "/api/v1/detection/tuning", "", ""); w.Code != http.StatusOK {
		t.Fatalf("tightening reset = %d %s", w.Code, w.Body.String())
	}
	if !store.GetDetectionTuning().BeaconOn {
		t.Fatal("the tightening reset did not apply")
	}
}

// "Expected" on a finding writes a quiet pair, which loosens: the finding is
// acknowledged only once the owner has approved.
func TestMarkingExpectedWaitsForTheOwner(t *testing.T) {
	t.Parallel()
	srv, store := setupTestServer(t)
	defer store.Close()
	seedFinding(t, store, "f-wait", "/opt/acme/backup-agent", `{"destination_asn":"AS64500","destination_tenancy":"isp"}`)
	body := `{"id":"f-wait"}`
	p := mustPend(t, policyPost(srv, http.MethodPost, "/api/v1/detection/tuning/suppress", body, ""))
	if p.Action != "Mark a conversation expected" || !strings.Contains(p.Summary, "quiet_pairs +/opt/acme/backup-agent@as64500") {
		t.Fatalf("expected approval = %+v", p)
	}
	if a, _ := store.GetAnomalyAlert("f-wait"); a.Acknowledged || len(store.GetDetectionTuning().QuietPairs) != 0 {
		t.Fatal("the pair or the acknowledgement landed before the owner approved")
	}
	ownerOf(t, srv).approve(t, p.ApprovalID)
	if w := policyPost(srv, http.MethodPost, "/api/v1/detection/tuning/suppress", body, p.ApprovalID); w.Code != http.StatusOK {
		t.Fatalf("approved = %d %s", w.Code, w.Body.String())
	}
	if a, _ := store.GetAnomalyAlert("f-wait"); !a.Acknowledged || len(store.GetDetectionTuning().QuietPairs) != 1 {
		t.Fatal("the approved pair did not land")
	}
}

// Learning proposals loosen through the same gate.
func TestApplyingLearningProposalsWaitsForTheOwner(t *testing.T) {
	t.Parallel()
	srv, store := setupTestServer(t)
	defer store.Close()
	seedLearningEndpoint(t, store, "ep-1", "workstation")
	seedLearningEndpoint(t, store, "ep-2", "workstation")
	win, err := store.CreateLearningWindow(storage.LearningWindow{
		TenantID: "default", ScopeType: storage.LearningScopeLocation, ScopeID: "loc-home", StartedBy: "test",
	})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	var obs []storage.LearningObservation
	for _, ep := range []string{"ep-1", "ep-2"} {
		obs = append(obs, storage.LearningObservation{WindowID: win.ID, EndpointID: ep, Kind: storage.LearnPair,
			Key: "/opt/acme/backup-agent@as64500", Count: 200, FirstSeen: now, LastSeen: now})
	}
	if err := store.RecordLearningObservations(obs); err != nil {
		t.Fatal(err)
	}
	proposals, err := store.ComputeLearningProposals(win.ID)
	if err != nil || len(proposals) == 0 {
		t.Fatalf("proposals: %v %v", proposals, err)
	}
	body := `{"window":"` + win.ID + `","ids":["` + proposals[0].ID + `"]}`
	p := mustPend(t, policyPost(srv, http.MethodPost, "/api/v1/learning/proposals/apply", body, ""))
	if p.Action != "Apply learning proposals" || !strings.Contains(p.Summary, "quiet_pairs +/opt/acme/backup-agent@as64500") {
		t.Fatalf("learning approval = %+v", p)
	}
	if len(store.GetDetectionTuning().QuietPairs) != 0 {
		t.Fatal("a proposal applied before the owner approved it")
	}
}

// Exclusions: a create and turning one on loosen and wait; turning one off
// and deleting one tighten, apply at once and are noted.
func TestExclusionWritesAreJudged(t *testing.T) {
	t.Parallel()
	srv, store := setupTestServer(t)
	defer store.Close()
	expires := time.Now().UTC().Add(24 * time.Hour).Format(time.RFC3339)
	body := `{"name":"bridge","process_path":"/usr/bin/docker-proxy","dst_ip_range":"172.18.0.0/16","port":7070,"protocol":"tcp","reason":"bridge","expires_at":"` + expires + `"}`
	p := mustPend(t, policyPost(srv, http.MethodPost, "/api/v1/exclusions", body, ""))
	if p.Action != "Add a detection exclusion" || !strings.Contains(p.Summary, "process_path /usr/bin/docker-proxy") || p.Targets[0] != "exclusion:new" {
		t.Fatalf("exclusion approval = %+v", p)
	}
	if list, _ := store.ListExclusions(""); len(list) != 0 {
		t.Fatal("the exclusion was created before the owner approved")
	}
	ownerOf(t, srv).approve(t, p.ApprovalID)
	w := policyPost(srv, http.MethodPost, "/api/v1/exclusions", body, p.ApprovalID)
	if w.Code != http.StatusCreated {
		t.Fatalf("approved create = %d %s", w.Code, w.Body.String())
	}
	var ex storage.Exclusion
	_ = json.Unmarshal(w.Body.Bytes(), &ex)

	if w := policyPost(srv, http.MethodPost, "/api/v1/exclusions/toggle", `{"id":"`+ex.ID+`","active":false}`, ""); w.Code != http.StatusOK {
		t.Fatalf("toggle off = %d %s", w.Code, w.Body.String())
	}
	p = mustPend(t, policyPost(srv, http.MethodPost, "/api/v1/exclusions/toggle", `{"id":"`+ex.ID+`","active":true}`, ""))
	if p.Action != "Turn a detection exclusion on" || p.Targets[0] != "exclusion:"+ex.ID {
		t.Fatalf("toggle approval = %+v", p)
	}
	if got, _ := store.GetExclusion(ex.ID); got.Active {
		t.Fatal("the exclusion came back on before the owner approved")
	}
	// Saving over the id (a renewal) loosens too.
	mustPend(t, policyPost(srv, http.MethodPost, "/api/v1/exclusions", strings.Replace(body, `{"name"`, `{"id":"`+ex.ID+`","name"`, 1), ""))

	if w := policyPost(srv, http.MethodDelete, "/api/v1/exclusions?id="+ex.ID, "", ""); w.Code != http.StatusOK {
		t.Fatalf("delete = %d %s", w.Code, w.Body.String())
	}
	notes := policyNotes(t, store)
	var kinds []string
	for _, n := range notes {
		kinds = append(kinds, strings.SplitN(n.Details, ":", 2)[0])
	}
	want := "tightened exclusion delete,tightened exclusion disable,loosened (exclusion) with owner approval " + mustApprovalOf(t, notes) + " exclusion create"
	if strings.Join(kinds, ",") != want {
		t.Fatalf("notes = %v, want %s", kinds, want)
	}
}

func mustApprovalOf(t *testing.T, notes []storage.AuditEntry) string {
	t.Helper()
	for _, n := range notes {
		if i := strings.Index(n.Details, "owner approval "); i >= 0 {
			return strings.Fields(n.Details[i+len("owner approval "):])[0]
		}
	}
	t.Fatal("no approved change in the notes")
	return ""
}

// Without the response authority there is nobody to ask: loosening is
// refused, tightening still applies.
func TestWithoutTheAuthorityLooseningIsRefused(t *testing.T) {
	t.Parallel()
	srv, store := setupTestServer(t)
	defer store.Close()
	srv.SetResponseAuth(nil)
	if w := policyPost(srv, http.MethodPost, "/api/v1/detection/tuning", `{"beacon_enabled":false}`, ""); w.Code != http.StatusServiceUnavailable {
		t.Fatalf("loosening without an authority = %d %s", w.Code, w.Body.String())
	}
	if w := policyPost(srv, http.MethodPost, "/api/v1/detection/tuning", `{"warmup_hours":1}`, ""); w.Code != http.StatusOK {
		t.Fatalf("tightening without an authority = %d %s", w.Code, w.Body.String())
	}
	if got := store.GetDetectionTuning(); !got.BeaconOn || got.WarmupHours != 1 {
		t.Fatal("wrong outcome")
	}
}

// The Nightshift feed carries the day's changes as a note, and an unsound
// tuning row as a critical finding.
func TestTheFeedReportsPolicyChangesAndAnUnsoundRow(t *testing.T) {
	t.Parallel()
	srv, store := setupTestServer(t)
	defer store.Close()
	find := func(uid string) feedFinding {
		t.Helper()
		findings, err := srv.detectionPolicySection(time.Now().UTC())
		if err != nil {
			t.Fatal(err)
		}
		for _, f := range findings {
			if f.FindingInfo["uid"] == uid {
				return f
			}
		}
		t.Fatalf("no %s finding", uid)
		return feedFinding{}
	}
	if f := find("ominull.detection.changes"); f.StatusID != ocsfStatusResolved {
		t.Fatalf("quiet day = %+v", f)
	}
	if w := policyPost(srv, http.MethodPost, "/api/v1/detection/tuning", `{"warmup_hours":12}`, ""); w.Code != http.StatusOK {
		t.Fatal(w.Body.String())
	}
	f := find("ominull.detection.changes")
	changes, _ := f.Unmapped["changes"].([]map[string]any)
	if f.SeverityID != ocsfSevInformational || f.StatusID != ocsfStatusNew || len(changes) != 1 ||
		!strings.Contains(changes[0]["change"].(string), "credential api-key (unverified)") {
		t.Fatalf("change note = %+v", f)
	}
	if f := find("ominull.detection.invalid"); f.SeverityID != ocsfSevInformational || f.StatusID != ocsfStatusResolved {
		t.Fatalf("sound row = %+v", f)
	}

	for _, settings := range []string{`{"beacon_enabled":`, `{"known_workloads":[{"workload":"python3 *","owner":"*","reason":"x"}]}`} {
		if _, err := store.DB().Exec(`UPDATE detection_tuning SET settings = ? WHERE id = 1`, settings); err != nil {
			t.Fatal(err)
		}
		f = find("ominull.detection.invalid")
		if f.SeverityID != ocsfSevCritical || f.StatusID != ocsfStatusNew || f.Unmapped["problem"] == "" {
			t.Fatalf("unsound row %s = %+v", settings, f)
		}
	}
}

// A save that pads a loosening with tightening edits cannot hide it: the
// tightening half is saved at once, and the owner is asked about the
// loosening alone, which the summary shows in full.
func TestAMixedSaveIsAskedAboutOnlyItsLoosening(t *testing.T) {
	t.Parallel()
	srv, store := setupTestServer(t)
	defer store.Close()
	shipped := tuningFields(storage.DefaultDetectionTuning())
	body := map[string]any{}
	for _, k := range []string{"admin_fanout_max_hosts", "agent_baseline_days", "agent_upload_floor_mb", "bandwidth_cooldown_minutes",
		"bandwidth_min_samples", "beacon_cooldown_minutes", "beacon_min_samples", "beacon_min_span_minutes",
		"first_seen_cooldown_minutes", "warmup_hours"} {
		body[k] = shipped[k].(float64) - 1
	}
	body["quiet_processes"] = append(append([]any(nil), shipped["quiet_processes"].([]any)...), "/usr/bin/curl")
	raw, _ := json.Marshal(body)
	w := policyPost(srv, http.MethodPost, "/api/v1/detection/tuning", string(raw), "")
	p := mustPend(t, w)
	if strings.Join(p.Loosens, ",") != "quiet_processes" || !strings.Contains(p.Summary, "quiet_processes +/usr/bin/curl") ||
		strings.Contains(p.Summary, "admin_fanout_max_hosts") || strings.Contains(p.Summary, " more") {
		t.Fatalf("the owner would not see the loosening on its own: %+v", p)
	}
	if !strings.Contains(w.Body.String(), `"tightened_now"`) {
		t.Fatalf("the 202 does not say what was already saved: %s", w.Body.String())
	}
	got := store.GetDetectionTuning()
	if float64(got.WarmupHours) != shipped["warmup_hours"].(float64)-1 {
		t.Fatal("the tightening half was not saved")
	}
	for _, q := range got.QuietProcesses {
		if q == "/usr/bin/curl" {
			t.Fatal("the loosening applied before the owner approved it")
		}
	}
	// The caller repeats the same request under the approval, as the console does.
	ownerOf(t, srv).approve(t, p.ApprovalID)
	if w := policyPost(srv, http.MethodPost, "/api/v1/detection/tuning", string(raw), p.ApprovalID); w.Code != http.StatusOK {
		t.Fatalf("approved retry = %d %s", w.Code, w.Body.String())
	}
	got = store.GetDetectionTuning()
	if !strings.Contains(strings.Join(got.QuietProcesses, "\n")+"\n", "/usr/bin/curl\n") {
		t.Fatalf("the approved loosening did not apply: %v", got.QuietProcesses)
	}
	notes := policyNotes(t, store)
	if len(notes) != 2 {
		t.Fatalf("want a tightened note and a loosened note, got %+v", notes)
	}

	// A list that loses entries and gains one loses them now; the owner is
	// asked only about the one it gains.
	orgs := got.QuietOrgs
	if len(orgs) < 2 {
		t.Fatalf("need shipped quiet orgs: %v", orgs)
	}
	swap, _ := json.Marshal(map[string]any{"quiet_orgs": []string{orgs[0], "as64500"}})
	p = mustPend(t, policyPost(srv, http.MethodPost, "/api/v1/detection/tuning", string(swap), ""))
	if p.Summary != "floor drill: blinds no floor rule; quiet_orgs +as64500" {
		t.Fatalf("swap summary %q", p.Summary)
	}
	if len(store.GetDetectionTuning().QuietOrgs) != 1 {
		t.Fatal("the dropped quiet networks were not dropped at once")
	}
}

// A loosening too large to show the owner in full is refused, not cut short.
func TestALooseningTooLargeToShowIsRefused(t *testing.T) {
	t.Parallel()
	srv, store := setupTestServer(t)
	defer store.Close()
	orgs := append([]string(nil), store.GetDetectionTuning().QuietOrgs...)
	for i := 0; i < 60; i++ {
		orgs = append(orgs, "as"+strings.Repeat("6", 4)+string(rune('0'+i%10))+string(rune('0'+i/10)))
	}
	raw, _ := json.Marshal(map[string]any{"quiet_orgs": orgs})
	w := policyPost(srv, http.MethodPost, "/api/v1/detection/tuning", string(raw), "")
	if w.Code != http.StatusUnprocessableEntity || !strings.Contains(w.Body.String(), "smaller changes") {
		t.Fatalf("oversized loosening = %d %s", w.Code, w.Body.String())
	}
	if len(store.GetDetectionTuning().QuietOrgs) == len(orgs) {
		t.Fatal("the oversized loosening applied")
	}
}

// Presence and retirement decide whether the silence floor reports a host,
// so watching one less closely waits for the owner like any loosening.
func TestParkingOrRetiringAHostWaitsForTheOwner(t *testing.T) {
	t.Parallel()
	srv, store := setupTestServer(t)
	defer store.Close()
	now := time.Now().UTC()
	if err := store.UpsertEndpoint(storage.Endpoint{ID: "srv-1", TenantID: "t-01", Hostname: "web", Status: "online", LastSeenAt: now}); err != nil {
		t.Fatal(err)
	}
	if err := store.SetEndpointIsolation("srv-1", true, nil); err != nil {
		t.Fatal(err)
	}
	watched := func() bool {
		ep, err := store.GetEndpoint("srv-1")
		if err != nil || ep == nil {
			t.Fatalf("endpoint: %v", err)
		}
		_, on := ep.QuietAllowance(time.Hour)
		return on && ep.Status != "retired"
	}

	park := `{"endpoint_id":"srv-1","presence":"parked","reason":"off between tests"}`
	p := mustPend(t, policyPost(srv, http.MethodPost, "/api/v1/endpoints/presence", park, ""))
	if p.Action != "Expect a host to go quiet" || p.Targets[0] != "endpoint:srv-1" ||
		p.Summary != "host srv-1 (web); presence always_on -> parked; reason off between tests" {
		t.Fatalf("park approval = %+v", p)
	}
	if !watched() {
		t.Fatal("the host stopped being watched before the owner approved")
	}
	// Another reason, or an approval nobody granted, changes nothing.
	if w := policyPost(srv, http.MethodPost, "/api/v1/endpoints/presence", park, p.ApprovalID); w.Code != http.StatusForbidden || !watched() {
		t.Fatalf("unapproved park = %d %s", w.Code, w.Body.String())
	}
	ownerOf(t, srv).approve(t, p.ApprovalID)
	if w := policyPost(srv, http.MethodPost, "/api/v1/endpoints/presence", strings.Replace(park, "between tests", "for good", 1), p.ApprovalID); w.Code != http.StatusForbidden || !watched() {
		t.Fatalf("park under another reason = %d %s", w.Code, w.Body.String())
	}
	if w := policyPost(srv, http.MethodPost, "/api/v1/endpoints/presence", park, p.ApprovalID); w.Code != http.StatusOK || watched() {
		t.Fatalf("approved park = %d %s", w.Code, w.Body.String())
	}
	// Watching it closely again needs nobody, and is noted.
	if w := policyPost(srv, http.MethodPost, "/api/v1/endpoints/presence", `{"endpoint_id":"srv-1","presence":"always_on"}`, ""); w.Code != http.StatusOK || !watched() {
		t.Fatalf("always on = %d %s", w.Code, w.Body.String())
	}

	retire := `{"endpoint_id":"srv-1","reason":"decommissioned"}`
	p = mustPend(t, policyPost(srv, http.MethodPost, "/api/v1/endpoints/retire", retire, ""))
	if p.Action != "Retire a host" || p.Summary != "host srv-1 (web); isolated true -> false; status active -> retired; reason decommissioned" {
		t.Fatalf("retire approval = %+v", p)
	}
	if ep, _ := store.GetEndpoint("srv-1"); ep.Status == "retired" || !ep.IsIsolated {
		t.Fatal("the host was retired, or its isolation lifted, before the owner approved")
	}
	ownerOf(t, srv).approve(t, p.ApprovalID)
	if w := policyPost(srv, http.MethodPost, "/api/v1/endpoints/retire", retire, p.ApprovalID); w.Code != http.StatusOK || watched() {
		t.Fatalf("approved retire = %d %s", w.Code, w.Body.String())
	}
	// Retiring a host already retired changes nothing and needs nobody.
	if w := policyPost(srv, http.MethodPost, "/api/v1/endpoints/retire", retire, ""); w.Code != http.StatusOK {
		t.Fatalf("retire again = %d %s", w.Code, w.Body.String())
	}
	var kinds []string
	for _, n := range policyNotes(t, store) {
		kinds = append(kinds, strings.SplitN(n.Details, ":", 2)[0])
	}
	if len(kinds) != 3 || !strings.HasPrefix(kinds[0], "loosened (retire) with owner approval") || kinds[1] != "tightened endpoint watch presence" ||
		!strings.HasPrefix(kinds[2], "loosened (presence) with owner approval") {
		t.Fatalf("notes = %v", kinds)
	}
}

// Opening a learning window holds the behavioural findings of every host it
// covers, so with the admin key alone it only asks. An estate-wide window
// says so in words, the approval binds its scope and length, and closing it
// needs nobody.
func TestOpeningALearningWindowWaitsForTheOwner(t *testing.T) {
	t.Parallel()
	srv, store := setupTestServer(t)
	defer store.Close()
	if err := store.UpsertEndpoint(storage.Endpoint{ID: "ep-1", TenantID: "default", Hostname: "web", Status: "online", LastSeenAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	learning := func() bool {
		_, on := store.LearningWindowFor(storage.Endpoint{ID: "ep-1", TenantID: "default"})
		return on
	}

	estate := `{"scope_type":"tenant","days":90}`
	p := mustPend(t, policyPost(srv, http.MethodPost, "/api/v1/learning/windows", estate, ""))
	if p.Action != "Open a learning window" || len(p.Targets) != 1 || p.Targets[0] != "learning:tenant:" ||
		p.Summary != "every host in every tenant for 90 days; holds beacon, volume and agent egress findings" {
		t.Fatalf("estate window approval = %+v", p)
	}
	if learning() {
		t.Fatal("the window opened before the owner approved")
	}
	if w := policyPost(srv, http.MethodPost, "/api/v1/learning/windows", estate, p.ApprovalID); w.Code != http.StatusForbidden || learning() {
		t.Fatalf("ungranted approval = %d %s", w.Code, w.Body.String())
	}
	ownerOf(t, srv).approve(t, p.ApprovalID)
	// The approval is for this window: not a longer one, not another scope.
	for _, other := range []string{`{"scope_type":"tenant","days":89}`, `{"scope_type":"tenant","scope_id":"t-02","days":90}`} {
		if w := policyPost(srv, http.MethodPost, "/api/v1/learning/windows", other, p.ApprovalID); w.Code != http.StatusForbidden || learning() {
			t.Fatalf("approval spent on %s = %d %s", other, w.Code, w.Body.String())
		}
	}
	w := policyPost(srv, http.MethodPost, "/api/v1/learning/windows", estate, p.ApprovalID)
	if w.Code != http.StatusOK || !learning() {
		t.Fatalf("approved window = %d %s", w.Code, w.Body.String())
	}
	var opened struct {
		Window storage.LearningWindow `json:"window"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &opened)
	if d := time.Until(opened.Window.EndsAt); d < 89*24*time.Hour || d > 90*24*time.Hour {
		t.Fatalf("window ends in %v, want 90 days", d)
	}

	// One host for two hours names the host; a note is a label.
	p = mustPend(t, policyPost(srv, http.MethodPost, "/api/v1/learning/windows", `{"scope_type":"endpoint","scope_id":"ep-1","hours":2,"note":"new host"}`, ""))
	if p.Targets[0] != "learning:endpoint:ep-1" || p.Summary != "endpoint ep-1 (web) for 2 hours; holds beacon, volume and agent egress findings; note new host" {
		t.Fatalf("host window approval = %+v", p)
	}
	if w := policyPost(srv, http.MethodPost, "/api/v1/learning/windows", `{"scope_type":"location","days":7}`, ""); w.Code != http.StatusBadRequest {
		t.Fatalf("a location window naming no location = %d %s", w.Code, w.Body.String())
	}

	if w := policyPost(srv, http.MethodPost, "/api/v1/learning/windows/close", `{"id":"`+opened.Window.ID+`"}`, ""); w.Code != http.StatusOK || learning() {
		t.Fatalf("close = %d %s", w.Code, w.Body.String())
	}
	var kinds []string
	for _, n := range policyNotes(t, store) {
		kinds = append(kinds, strings.SplitN(n.Details, ":", 2)[0])
	}
	if len(kinds) != 2 || kinds[0] != "tightened learning window close" ||
		!strings.HasPrefix(kinds[1], "loosened (learning_window) with owner approval") {
		t.Fatalf("notes = %v", kinds)
	}
}

// Acknowledging or deleting findings hides them from the feed's open counts,
// so the detection-policy note counts every one, and a tenant key cannot reach
// another tenant's finding by id.
func TestAcknowledgedAndDeletedFindingsShowOnTheFeedNote(t *testing.T) {
	t.Parallel()
	srv, store := setupTestServer(t)
	defer store.Close()
	now := time.Now().UTC()
	for _, tn := range []storage.Tenant{{ID: "t-alpha", Name: "Alpha", APIKey: "key-alpha", CreatedAt: now}, {ID: "t-beta", Name: "Beta", APIKey: "key-beta", CreatedAt: now}} {
		if err := store.CreateTenant(tn); err != nil {
			t.Fatal(err)
		}
	}
	for _, a := range []storage.AnomalyAlert{
		{ID: "a1", TenantID: "t-alpha", AnomalyType: "C2_BEACONING", Severity: "HIGH"},
		{ID: "b1", TenantID: "t-beta", AnomalyType: "THREAT_INTEL_MATCH", Severity: "CRITICAL"},
		{ID: "b2", TenantID: "t-beta", AnomalyType: "NOVEL_DESTINATION", Severity: "MEDIUM"},
	} {
		a.Hostname, a.Title, a.Timestamp = "h", "x", now
		if err := store.CreateAnomalyAlert(a); err != nil {
			t.Fatal(err)
		}
	}
	post := func(key, path, body string) map[string]any {
		t.Helper()
		r := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
		r.Header.Set("X-API-Key", key)
		w := httptest.NewRecorder()
		srv.Handler().ServeHTTP(w, r)
		if w.Code != http.StatusOK {
			t.Fatalf("%s %s = %d %s", path, body, w.Code, w.Body.String())
		}
		var out map[string]any
		_ = json.Unmarshal(w.Body.Bytes(), &out)
		return out
	}
	note := func() feedFinding {
		t.Helper()
		findings, err := srv.detectionPolicySection(time.Now().UTC())
		if err != nil {
			t.Fatal(err)
		}
		for _, f := range findings {
			if f.FindingInfo["uid"] == "ominull.detection.changes" {
				return f
			}
		}
		t.Fatal("no detection policy note")
		return feedFinding{}
	}
	acked := func(id string) bool {
		a, err := store.GetAnomalyAlert(id)
		if err != nil {
			t.Fatal(err)
		}
		return a.Acknowledged
	}

	// Another tenant's finding by id is out of reach, and nothing is noted.
	if out := post("key-alpha", "/api/v1/anomalies/acknowledge", `{"ids":["b1"]}`); out["acknowledged"] != float64(0) || acked("b1") {
		t.Fatalf("tenant alpha acknowledged beta's finding: %v", out)
	}
	if f := note(); f.StatusID != ocsfStatusResolved {
		t.Fatalf("nothing was acknowledged yet the note says %+v", f)
	}
	if out := post("mock_admin_token", "/api/v1/anomalies/acknowledge", `{"ids":["a1","b1"]}`); out["acknowledged"] != float64(2) {
		t.Fatalf("admin acknowledge = %v", out)
	}
	f := note()
	dismissed, _ := f.Unmapped["dismissed"].([]map[string]any)
	if f.StatusID != ocsfStatusNew || len(dismissed) != 1 ||
		!strings.Contains(f.Message, "2 findings acknowledged (2 HIGH or CRITICAL)") ||
		!strings.Contains(dismissed[0]["change"].(string), "C2_BEACONING, THREAT_INTEL_MATCH") ||
		!strings.Contains(dismissed[0]["change"].(string), "credential api-key (unverified)") {
		t.Fatalf("note after acknowledging = %+v", f)
	}
	// A repeat acknowledges nothing new and adds nothing; all, then clear, are counted.
	post("mock_admin_token", "/api/v1/anomalies/acknowledge", `{"id":"a1"}`)
	if out := post("mock_admin_token", "/api/v1/anomalies/acknowledge", `{"all":true}`); out["acknowledged"] != float64(1) {
		t.Fatalf("acknowledge all = %v", out)
	}
	if out := post("mock_admin_token", "/api/v1/anomalies/clear", `{}`); out["deleted"] != float64(3) {
		t.Fatalf("clear = %v", out)
	}
	f = note()
	dismissed, _ = f.Unmapped["dismissed"].([]map[string]any)
	if len(dismissed) != 3 || f.Message != "3 findings acknowledged (2 HIGH or CRITICAL) and 3 acknowledged findings deleted in the last 24 h" {
		t.Fatalf("note after clearing = %q %v", f.Message, dismissed)
	}
}

func feedNote(t *testing.T, srv *Server, uid string) feedFinding {
	t.Helper()
	findings, err := srv.detectionPolicySection(time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range findings {
		if f.FindingInfo["uid"] == uid {
			return f
		}
	}
	t.Fatalf("no %s note", uid)
	return feedFinding{}
}

// The note counts every acknowledgement in the window, not one page of them,
// so a HIGH acknowledgement followed by many small ones is still counted and
// still listed.
func TestEveryDismissalInTheWindowIsCounted(t *testing.T) {
	t.Parallel()
	srv, store := setupTestServer(t)
	defer store.Close()
	now := time.Now().UTC()
	seed := func(id, typ, sev string) {
		if err := store.CreateAnomalyAlert(storage.AnomalyAlert{ID: id, TenantID: "default", AnomalyType: typ, Severity: sev,
			Hostname: "h", Title: "x", Timestamp: now}); err != nil {
			t.Fatal(err)
		}
	}
	ack := func(id string) {
		t.Helper()
		r := httptest.NewRequest(http.MethodPost, "/api/v1/anomalies/acknowledge", strings.NewReader(`{"id":"`+id+`"}`))
		r.Header.Set("X-API-Key", "mock_admin_token")
		w := httptest.NewRecorder()
		srv.Handler().ServeHTTP(w, r)
		if w.Code != http.StatusOK {
			t.Fatalf("acknowledge %s = %d %s", id, w.Code, w.Body.String())
		}
	}
	seed("crit", "THREAT_INTEL_MATCH", "CRITICAL")
	ack("crit")
	for i := 0; i < 60; i++ {
		id := fmt.Sprintf("low-%02d", i)
		seed(id, "NOVEL_DESTINATION", "LOW")
		ack(id)
	}
	f := feedNote(t, srv, "ominull.detection.changes")
	if !strings.HasPrefix(f.Message, "61 findings acknowledged (1 HIGH or CRITICAL)") {
		t.Fatalf("note = %q", f.Message)
	}
	dismissed, _ := f.Unmapped["dismissed"].([]map[string]any)
	listed := false
	for _, d := range dismissed {
		listed = listed || strings.Contains(d["change"].(string), "THREAT_INTEL_MATCH")
	}
	if !listed || len(dismissed) != feedDismissedListShown || f.Unmapped["dismissed_omitted"] != 61-feedDismissedListShown {
		t.Fatalf("listed the CRITICAL row = %v, %d rows, %v omitted", listed, len(dismissed), f.Unmapped["dismissed_omitted"])
	}
}

// A failed acknowledgement rolls back, so it writes no FINDINGS_ACKNOWLEDGED
// row and the feed note does not count or list a dismissal that never happened.
func TestAFailedAcknowledgementIsNotNoted(t *testing.T) {
	t.Parallel()
	srv, store := setupTestServer(t)
	defer store.Close()
	for _, id := range []string{"f1", "f2"} {
		if err := store.CreateAnomalyAlert(storage.AnomalyAlert{ID: id, TenantID: "default", AnomalyType: "C2_BEACONING",
			Severity: "HIGH", Hostname: "h", Title: "x", Timestamp: time.Now().UTC()}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := store.DB().Exec(`CREATE TRIGGER reject_f2_ack BEFORE UPDATE ON anomaly_alerts WHEN OLD.id = 'f2'
		BEGIN SELECT RAISE(ABORT, 'rejected test acknowledgement'); END`); err != nil {
		t.Fatal(err)
	}
	for _, body := range []string{`{"ids":["f1","f2"]}`, `{"all":true}`} {
		if w := adminPost(srv, "/api/v1/anomalies/acknowledge", body, ""); w.Code != http.StatusInternalServerError {
			t.Fatalf("%s: rejected acknowledgement = %d %s", body, w.Code, w.Body.String())
		}
	}
	page, err := store.AuditHistory("", 100, "", storage.AuditFilter{Action: findingsAcknowledgedAudit})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Entries) != 0 {
		t.Fatalf("a rolled-back acknowledgement was recorded: %+v", page.Entries)
	}
	if f := feedNote(t, srv, "ominull.detection.changes"); f.StatusID != ocsfStatusResolved {
		t.Fatalf("nothing was acknowledged yet the note says %+v", f)
	}
}

// A vendor range is approved by the owner, refused when it is not one
// maker's own address space, and a save that drops a range and adds another
// drops it at once and asks only about the one it adds.
func TestVendorRangesAreJudgedAsPolicy(t *testing.T) {
	t.Parallel()
	srv, store := setupTestServer(t)
	defer store.Close()
	post := func(vendors []storage.AgentRuntimeVendor, approval string) *httptest.ResponseRecorder {
		raw, _ := json.Marshal(map[string]any{"agent_runtime_vendors": vendors})
		return policyPost(srv, http.MethodPost, "/api/v1/detection/tuning", string(raw), approval)
	}
	shipped := storage.DefaultDetectionTuning().AgentRuntimeVendors
	for name, prefix := range map[string]string{"cloudflare": "104.16.0.0/16", "malformed": "160.79.104/23", "over-broad": "160.0.0.0/8"} {
		v := append([]storage.AgentRuntimeVendor(nil), shipped...)
		v[0].Prefixes = []string{prefix}
		if w := post(v, ""); w.Code != http.StatusBadRequest {
			t.Fatalf("%s prefix %s = %d %s, want 400", name, prefix, w.Code, w.Body.String())
		}
	}
	v := append([]storage.AgentRuntimeVendor(nil), shipped...)
	v[0].Prefixes = []string{"160.79.104.0/23", "198.51.100.0/24"}
	p := mustPend(t, post(v, ""))
	if strings.Join(p.Loosens, ",") != "agent_runtime_vendors" {
		t.Fatalf("loosens %v", p.Loosens)
	}
	if !reflect.DeepEqual(store.GetDetectionTuning().AgentRuntimeVendors[0].Prefixes, []string{"160.79.104.0/23"}) {
		t.Fatalf("the tightening half was not saved first: %+v", store.GetDetectionTuning().AgentRuntimeVendors[0])
	}
	ownerOf(t, srv).approve(t, p.ApprovalID)
	if w := post(v, p.ApprovalID); w.Code != http.StatusOK {
		t.Fatalf("approved save = %d %s", w.Code, w.Body.String())
	}
	got := store.GetDetectionTuning()
	if !got.InRuntimeVendorRange("claude", netip.MustParseAddr("198.51.100.9")) || got.InRuntimeVendorRange("claude", netip.MustParseAddr("2607:6bc0::1")) {
		t.Fatalf("saved vendors %+v", got.AgentRuntimeVendors)
	}
}

// A known workload needs an expiry in the future when it is added, moving one
// later waits for the owner while moving another earlier applies at once, and
// the feed note names expired entries and a saved row weaker than the floor.
func TestKnownWorkloadExpiryAndTheFloorAreJudgedAndShown(t *testing.T) {
	t.Parallel()
	srv, store := setupTestServer(t)
	defer store.Close()
	for _, body := range []string{
		`{"known_workloads":[{"workload":"/usr/bin/gh","owner":"as36459","reason":"cli"}]}`,
		`{"known_workloads":[{"workload":"/usr/bin/gh","owner":"as36459","reason":"cli","expires_at":"2020-01-01T00:00:00Z"}]}`,
	} {
		if w := policyPost(srv, http.MethodPost, "/api/v1/detection/tuning", body, ""); w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "expires_at") {
			t.Fatalf("%s = %d %s", body, w.Code, w.Body.String())
		}
	}

	until := time.Now().UTC().Add(30 * 24 * time.Hour).Truncate(time.Second)
	saved := storage.DefaultDetectionTuning()
	saved.KnownWorkloads = []storage.KnownWorkload{
		{Workload: "/usr/bin/gh", Owner: "as36459", Reason: "cli", ExpiresAt: until},
		{Workload: "/usr/bin/ssh", Owner: "as36459", Reason: "git", ExpiresAt: until},
	}
	if _, err := store.SaveDetectionTuning(saved, "test"); err != nil {
		t.Fatal(err)
	}
	body := fmt.Sprintf(`{"known_workloads":[{"workload":"/usr/bin/gh","owner":"as36459","reason":"cli","expires_at":%q},{"workload":"/usr/bin/ssh","owner":"as36459","reason":"git","expires_at":%q}]}`,
		until.Add(-time.Hour).Format(time.RFC3339), until.Add(time.Hour).Format(time.RFC3339))
	p := mustPend(t, policyPost(srv, http.MethodPost, "/api/v1/detection/tuning", body, ""))
	if strings.Join(p.Loosens, ",") != "known_workloads" {
		t.Fatalf("an extended expiry should wait for the owner: %+v", p)
	}
	got := store.GetDetectionTuning().KnownWorkloads
	if len(got) != 2 || !got[0].ExpiresAt.Equal(until.Add(-time.Hour)) || !got[1].ExpiresAt.Equal(until) {
		t.Fatalf("the shortened expiry should apply at once and the extended one wait: %+v", got)
	}

	// A row saved weaker than the floor, holding an expired workload.
	row := `{"silence_enabled":true,"silence_after_minutes":60,"bandwidth_enabled":true,"known_workloads":[{"workload":"/usr/bin/gh","owner":"as36459","reason":"cli","expires_at":"2020-01-01T00:00:00Z"}]}`
	if _, err := store.DB().Exec(`UPDATE detection_tuning SET settings = ? WHERE id = 1`, row); err != nil {
		t.Fatal(err)
	}
	findings, err := srv.detectionPolicySection(time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range findings {
		if f.FindingInfo["uid"] == "ominull.detection.invalid" && f.SeverityID != ocsfSevInformational {
			t.Fatalf("an expired workload or a value past the floor is not an unsound row: %+v", f)
		}
		if f.FindingInfo["uid"] != "ominull.detection.changes" {
			continue
		}
		clamped, _ := f.Unmapped["floor_clamped"].([]string)
		expired, _ := f.Unmapped["known_workloads_expired"].([]string)
		if f.StatusID != ocsfStatusNew || len(clamped) != 1 || !strings.Contains(clamped[0], "silence_after_minutes 60") ||
			len(expired) != 1 || !strings.Contains(f.Message, "detection floor") {
			t.Fatalf("feed note = %+v", f)
		}
		return
	}
	t.Fatal("no detection policy note")
}

// A loosening change waiting for the owner carries the floor drill run against
// the policy it would save, so the owner sees what it blinds before tapping:
// an exclusion over an internet range blinds the 10 MB burst, a container
// network over the LAN blinds the lateral sweeps; a case already blinded is
// not counted again. The approved retry runs the same drill and applies;
// nothing changes before the tap.
func TestTheOwnerSeesWhatALooseningChangeWouldBlind(t *testing.T) {
	t.Parallel()
	srv, store := setupTestServer(t)
	defer store.Close()
	expires := time.Now().UTC().Add(24 * time.Hour).Format(time.RFC3339)
	body := `{"name":"uploads","dst_ip_range":"203.0.113.0/24","reason":"backup target","expires_at":"` + expires + `"}`
	w := policyPost(srv, http.MethodPost, "/api/v1/exclusions", body, "")
	p := mustPend(t, w)
	if !strings.HasPrefix(p.Summary, "BLINDS 1 FLOOR CASE: bandwidth burst; ") || !strings.Contains(w.Body.String(), `"drill_blinds":["bandwidth burst"]`) {
		t.Fatalf("exclusion approval = %q %s", p.Summary, w.Body.String())
	}
	ownerOf(t, srv).approve(t, p.ApprovalID)
	if w := policyPost(srv, http.MethodPost, "/api/v1/exclusions", body, p.ApprovalID); w.Code != http.StatusCreated {
		t.Fatalf("approved create = %d %s", w.Code, w.Body.String())
	}

	p = mustPend(t, policyPost(srv, http.MethodPost, "/api/v1/detection/tuning", `{"container_cidrs":["192.168.250.0/24"]}`, ""))
	// The burst the live exclusion already blinds is not this change's; the
	// quiet processes' lateral sweeps are.
	if !strings.HasPrefix(p.Summary, "BLINDS 12 FLOOR CASES: lateral sweep, agent ssh fan-out reaching a floor port and 10 more; container_cidrs +192.168.250.0/24") {
		t.Fatalf("tuning approval = %q", p.Summary)
	}
	if len(store.GetDetectionTuning().ContainerCIDRs) != 0 {
		t.Fatal("the container network applied before the owner approved it")
	}
}
