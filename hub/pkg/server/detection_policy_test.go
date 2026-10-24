package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"reflect"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"ominull/hub/pkg/storage"
)

// policyPost sends one detection-policy write with the admin key, once: what
// an agent holding the key gets. The approval argument is unused (the hub signs
// a loosening itself); callers pass "".
func policyPost(srv *Server, method, path, body, _ string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-API-Key", "mock_admin_token")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, r)
	return w
}

// signedChange is the newest ACTION_AUTHORIZED row of a detection-policy
// change: what the authority signed, in its own words.
type signedChange struct {
	ID      string
	Target  string
	Loosens []string
	Summary string
}

var signedChangeRow = regexp.MustCompile(`^detection policy change loosening (.*) \(authorization (\S+)\): (.*)$`)

// mustSign asserts the request finished at once with status code (no round
// trip) and returns the authorization it left in the audit.
func mustSign(t *testing.T, store *storage.Store, w *httptest.ResponseRecorder, code int) signedChange {
	t.Helper()
	if w.Code != code {
		t.Fatalf("want %d on the first request, got %d %s", code, w.Code, w.Body.String())
	}
	rows := authorizedAudit(t, store)
	if len(rows) == 0 {
		t.Fatalf("no ACTION_AUTHORIZED row after %d %s", w.Code, w.Body.String())
	}
	m := signedChangeRow.FindStringSubmatch(rows[0].Details)
	if m == nil {
		t.Fatalf("newest ACTION_AUTHORIZED row is not a policy change: %+v", rows[0])
	}
	return signedChange{ID: m[2], Target: rows[0].Resource, Loosens: strings.Split(m[1], ", "), Summary: m[3]}
}

// noteKinds is the first half (before the colon) of each policy note.
func noteKinds(notes []storage.AuditEntry) []string {
	var kinds []string
	for _, n := range notes {
		kinds = append(kinds, strings.SplitN(n.Details, ":", 2)[0])
	}
	return kinds
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

// The admin key, which every agent can read, can loosen detection, but the
// authority signs each loosening first and the audit says what was signed:
// the first request applies it, with no round trip.
func TestALooseningSaveIsSignedAtOnce(t *testing.T) {
	t.Parallel()
	srv, store := setupTestServer(t)
	defer store.Close()
	body := `{"beacon_enabled":false,"quiet_orgs":["as714","as8075","as15169","as13335","as16509","as20940","as54113","as64500"]}`
	a := mustSign(t, store, policyPost(srv, http.MethodPost, "/api/v1/detection/tuning", body, ""), http.StatusOK)
	if !strings.Contains(a.Summary, "beacon_enabled true -> false") || !strings.Contains(a.Summary, "quiet_orgs +as64500") {
		t.Fatalf("the audit does not show the change: %+v", a)
	}
	if strings.Join(a.Loosens, ",") != "beacon_enabled,quiet_orgs" || a.Target != "detection:tuning" {
		t.Fatalf("authorization = %+v", a)
	}
	if got := store.GetDetectionTuning(); got.BeaconOn || len(got.QuietOrgs) != 8 {
		t.Fatal("the signed save did not apply")
	}
	notes := policyNotes(t, store)
	if len(notes) != 1 || !strings.Contains(notes[0].Details, "loosened (beacon_enabled, quiet_orgs) with authorization "+a.ID) ||
		!strings.Contains(notes[0].Details, "credential api-key (unverified)") {
		t.Fatalf("notes = %+v", notes)
	}
}

// PUT and case-variant keys go through the same gate: the loosening is
// recognised, signed and audited like any other.
func TestACaseVariantKeyIsStillJudgedALoosening(t *testing.T) {
	t.Parallel()
	srv, store := setupTestServer(t)
	defer store.Close()
	a := mustSign(t, store, policyPost(srv, http.MethodPut, "/api/v1/detection/tuning", `{"Beacon_Enabled":false}`, ""), http.StatusOK)
	if strings.Join(a.Loosens, ",") != "beacon_enabled" || store.GetDetectionTuning().BeaconOn {
		t.Fatalf("case-variant key: %+v beacon on=%v", a, store.GetDetectionTuning().BeaconOn)
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

// Restoring the shipped values is signed when it brings back quiet entries
// someone removed, and applies plainly when it only tightens.
func TestResetIsJudgedLikeAnySave(t *testing.T) {
	t.Parallel()
	srv, store := setupTestServer(t)
	defer store.Close()
	tu := storage.DefaultDetectionTuning()
	tu.QuietClients = tu.QuietClients[1:]
	if _, err := store.SaveDetectionTuning(tu, "test"); err != nil {
		t.Fatal(err)
	}
	a := mustSign(t, store, policyPost(srv, http.MethodDelete, "/api/v1/detection/tuning", "", ""), http.StatusOK)
	if !strings.Contains(a.Summary, "quiet_clients +") || len(store.GetDetectionTuning().QuietClients) != len(storage.DefaultDetectionTuning().QuietClients) {
		t.Fatalf("reset authorization = %+v", a)
	}

	n := len(authorizedAudit(t, store))
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
	if got := len(authorizedAudit(t, store)); got != n {
		t.Fatalf("a tightening reset was sent to the authority (%d -> %d rows)", n, got)
	}
}

// "Expected" on a finding writes a quiet pair, which loosens: the pair and the
// acknowledgement land on the first request, with the pair in the audit.
func TestMarkingExpectedIsSignedAtOnce(t *testing.T) {
	t.Parallel()
	srv, store := setupTestServer(t)
	defer store.Close()
	seedFinding(t, store, "f-wait", "/opt/acme/backup-agent", `{"destination_asn":"AS64500","destination_tenancy":"isp"}`)
	a := mustSign(t, store, policyPost(srv, http.MethodPost, "/api/v1/detection/tuning/suppress", `{"id":"f-wait"}`, ""), http.StatusOK)
	if !strings.Contains(a.Summary, "quiet_pairs +/opt/acme/backup-agent@as64500") {
		t.Fatalf("authorization = %+v", a)
	}
	if al, _ := store.GetAnomalyAlert("f-wait"); !al.Acknowledged || len(store.GetDetectionTuning().QuietPairs) != 1 {
		t.Fatal("the pair did not land")
	}
}

// Learning proposals loosen through the same gate and apply on the first request.
func TestApplyingLearningProposalsIsSignedAtOnce(t *testing.T) {
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
	a := mustSign(t, store, policyPost(srv, http.MethodPost, "/api/v1/learning/proposals/apply", body, ""), http.StatusOK)
	if !strings.Contains(a.Summary, "quiet_pairs +/opt/acme/backup-agent@as64500") {
		t.Fatalf("authorization = %+v", a)
	}
	if len(store.GetDetectionTuning().QuietPairs) == 0 {
		t.Fatal("the proposal did not apply")
	}
}

// Exclusions: a create and turning one on loosen and are signed; turning one
// off and deleting one tighten, apply at once and are noted.
func TestExclusionWritesAreJudged(t *testing.T) {
	t.Parallel()
	srv, store := setupTestServer(t)
	defer store.Close()
	expires := time.Now().UTC().Add(24 * time.Hour).Format(time.RFC3339)
	body := `{"name":"bridge","process_path":"/usr/bin/docker-proxy","dst_ip_range":"172.18.0.0/16","port":7070,"protocol":"tcp","reason":"bridge","expires_at":"` + expires + `"}`
	w := policyPost(srv, http.MethodPost, "/api/v1/exclusions", body, "")
	a := mustSign(t, store, w, http.StatusCreated)
	if !strings.Contains(a.Summary, "process_path /usr/bin/docker-proxy") || a.Target != "exclusion:new" {
		t.Fatalf("exclusion authorization = %+v", a)
	}
	var ex storage.Exclusion
	_ = json.Unmarshal(w.Body.Bytes(), &ex)
	if got, err := store.GetExclusion(ex.ID); err != nil || !got.Active {
		t.Fatalf("the exclusion was not created: %v %+v", err, got)
	}

	if w := policyPost(srv, http.MethodPost, "/api/v1/exclusions/toggle", `{"id":"`+ex.ID+`","active":false}`, ""); w.Code != http.StatusOK {
		t.Fatalf("toggle off = %d %s", w.Code, w.Body.String())
	}
	a = mustSign(t, store, policyPost(srv, http.MethodPost, "/api/v1/exclusions/toggle", `{"id":"`+ex.ID+`","active":true}`, ""), http.StatusOK)
	if a.Target != "exclusion:"+ex.ID {
		t.Fatalf("toggle authorization = %+v", a)
	}
	if got, _ := store.GetExclusion(ex.ID); !got.Active {
		t.Fatal("the exclusion did not come back on")
	}
	// Saving over the id (a renewal) loosens too.
	mustSign(t, store, policyPost(srv, http.MethodPost, "/api/v1/exclusions", strings.Replace(body, `{"name"`, `{"id":"`+ex.ID+`","name"`, 1), ""), http.StatusCreated)

	if w := policyPost(srv, http.MethodDelete, "/api/v1/exclusions?id="+ex.ID, "", ""); w.Code != http.StatusOK {
		t.Fatalf("delete = %d %s", w.Code, w.Body.String())
	}
	kinds := noteKinds(policyNotes(t, store))
	if len(kinds) != 5 || kinds[0] != "tightened exclusion delete" || !strings.HasPrefix(kinds[1], "loosened (exclusion) with authorization ") ||
		!strings.HasPrefix(kinds[2], "loosened (exclusion) with authorization ") || kinds[3] != "tightened exclusion disable" ||
		!strings.HasPrefix(kinds[4], "loosened (exclusion) with authorization ") {
		t.Fatalf("notes = %v", kinds)
	}
}

// Without the response authority nothing can sign a loosening: it is
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
// authority signs the loosening alone, and the audit shows it in full. Both
// halves apply on the first request.
func TestAMixedSaveIsSignedOnlyForItsLoosening(t *testing.T) {
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
	a := mustSign(t, store, policyPost(srv, http.MethodPost, "/api/v1/detection/tuning", string(raw), ""), http.StatusOK)
	if strings.Join(a.Loosens, ",") != "quiet_processes" || !strings.Contains(a.Summary, "quiet_processes +/usr/bin/curl") ||
		strings.Contains(a.Summary, "admin_fanout_max_hosts") || strings.Contains(a.Summary, " more") {
		t.Fatalf("the loosening is not shown on its own: %+v", a)
	}
	got := store.GetDetectionTuning()
	if float64(got.WarmupHours) != shipped["warmup_hours"].(float64)-1 {
		t.Fatal("the tightening half was not saved")
	}
	if !strings.Contains(strings.Join(got.QuietProcesses, "\n")+"\n", "/usr/bin/curl\n") {
		t.Fatalf("the loosening did not apply: %v", got.QuietProcesses)
	}
	notes := policyNotes(t, store)
	if len(notes) != 2 {
		t.Fatalf("want a tightened note and a loosened note, got %+v", notes)
	}

	// A list that loses entries and gains one loses them now; the authority
	// signs only the one it gains.
	orgs := got.QuietOrgs
	if len(orgs) < 2 {
		t.Fatalf("need shipped quiet orgs: %v", orgs)
	}
	swap, _ := json.Marshal(map[string]any{"quiet_orgs": []string{orgs[0], "as64500"}})
	a = mustSign(t, store, policyPost(srv, http.MethodPost, "/api/v1/detection/tuning", string(swap), ""), http.StatusOK)
	if a.Summary != "floor drill: blinds no floor case (the 10 MB burst yields to exclusions and quiet processes); quiet_orgs +as64500" {
		t.Fatalf("swap summary %q", a.Summary)
	}
	if got := store.GetDetectionTuning().QuietOrgs; len(got) != 2 || got[0] != orgs[0] || got[1] != "as64500" {
		t.Fatalf("quiet networks after the swap: %v", got)
	}
}

// Presence and retirement decide whether the silence floor reports a host, so
// watching one less closely is a loosening the authority signs, on the first
// request.
func TestParkingOrRetiringAHostIsSignedAtOnce(t *testing.T) {
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
	if !watched() {
		t.Fatal("the host starts unwatched")
	}
	a := mustSign(t, store, policyPost(srv, http.MethodPost, "/api/v1/endpoints/presence", park, ""), http.StatusOK)
	if a.Target != "endpoint:srv-1" || a.Summary != "host srv-1 (web); presence always_on -> parked; reason off between tests" || watched() {
		t.Fatalf("park authorization = %+v watched=%v", a, watched())
	}
	// Watching it closely again needs no signature, and is noted.
	n := len(authorizedAudit(t, store))
	if w := policyPost(srv, http.MethodPost, "/api/v1/endpoints/presence", `{"endpoint_id":"srv-1","presence":"always_on"}`, ""); w.Code != http.StatusOK || !watched() {
		t.Fatalf("always on = %d %s", w.Code, w.Body.String())
	}
	if got := len(authorizedAudit(t, store)); got != n {
		t.Fatalf("watching a host closely was sent to the authority (%d -> %d rows)", n, got)
	}

	retire := `{"endpoint_id":"srv-1","reason":"decommissioned"}`
	a = mustSign(t, store, policyPost(srv, http.MethodPost, "/api/v1/endpoints/retire", retire, ""), http.StatusOK)
	if a.Summary != "host srv-1 (web); isolated true -> false; status active -> retired; reason decommissioned" || watched() {
		t.Fatalf("retire authorization = %+v watched=%v", a, watched())
	}
	if ep, _ := store.GetEndpoint("srv-1"); ep.Status != "retired" || ep.IsIsolated {
		t.Fatalf("the host was not retired and released: %+v", ep)
	}
	// Retiring a host already retired changes nothing and signs nothing.
	n = len(authorizedAudit(t, store))
	if w := policyPost(srv, http.MethodPost, "/api/v1/endpoints/retire", retire, ""); w.Code != http.StatusOK || len(authorizedAudit(t, store)) != n {
		t.Fatalf("retire again = %d %s", w.Code, w.Body.String())
	}
	kinds := noteKinds(policyNotes(t, store))
	if len(kinds) != 3 || !strings.HasPrefix(kinds[0], "loosened (retire) with authorization") || kinds[1] != "tightened endpoint watch presence" ||
		!strings.HasPrefix(kinds[2], "loosened (presence) with authorization") {
		t.Fatalf("notes = %v", kinds)
	}
}

// Opening a learning window holds the behavioural findings of every host it
// covers, so the authority signs it, and an estate-wide window says so in
// words. Closing it needs no signature.
func TestOpeningALearningWindowIsSignedAtOnce(t *testing.T) {
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
	open := func(body string) (signedChange, storage.LearningWindow) {
		t.Helper()
		w := policyPost(srv, http.MethodPost, "/api/v1/learning/windows", body, "")
		a := mustSign(t, store, w, http.StatusOK)
		var opened struct {
			Window storage.LearningWindow `json:"window"`
		}
		_ = json.Unmarshal(w.Body.Bytes(), &opened)
		return a, opened.Window
	}

	a, estate := open(`{"scope_type":"tenant","days":90}`)
	if a.Target != "learning:tenant:" ||
		a.Summary != "every host in every tenant for 90 days; holds beacon, volume and agent egress findings" {
		t.Fatalf("estate window authorization = %+v", a)
	}
	if !learning() {
		t.Fatal("the window did not open")
	}
	if d := time.Until(estate.EndsAt); d < 89*24*time.Hour || d > 90*24*time.Hour {
		t.Fatalf("window ends in %v, want 90 days", d)
	}

	// One host for two hours names the host; a note is a label.
	a, host := open(`{"scope_type":"endpoint","scope_id":"ep-1","hours":2,"note":"new host"}`)
	if a.Target != "learning:endpoint:ep-1" || a.Summary != "endpoint ep-1 (web) for 2 hours; holds beacon, volume and agent egress findings; note new host" {
		t.Fatalf("host window authorization = %+v", a)
	}
	n := len(authorizedAudit(t, store))
	if w := policyPost(srv, http.MethodPost, "/api/v1/learning/windows", `{"scope_type":"location","days":7}`, ""); w.Code != http.StatusBadRequest || len(authorizedAudit(t, store)) != n {
		t.Fatalf("a location window naming no location = %d %s", w.Code, w.Body.String())
	}

	for _, id := range []string{estate.ID, host.ID} {
		if w := policyPost(srv, http.MethodPost, "/api/v1/learning/windows/close", `{"id":"`+id+`"}`, ""); w.Code != http.StatusOK {
			t.Fatalf("close = %d %s", w.Code, w.Body.String())
		}
	}
	if learning() {
		t.Fatal("a window is still open after both were closed")
	}
	kinds := noteKinds(policyNotes(t, store))
	if len(kinds) != 4 || kinds[0] != "tightened learning window close" || kinds[1] != "tightened learning window close" ||
		!strings.HasPrefix(kinds[2], "loosened (learning_window) with authorization") || !strings.HasPrefix(kinds[3], "loosened (learning_window) with authorization") {
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

// A vendor range is signed by the authority, refused when it is not one
// maker's own address space, and a save that drops a range and adds another
// drops it and signs only the one it adds.
func TestVendorRangesAreJudgedAsPolicy(t *testing.T) {
	t.Parallel()
	srv, store := setupTestServer(t)
	defer store.Close()
	post := func(vendors []storage.AgentRuntimeVendor) *httptest.ResponseRecorder {
		raw, _ := json.Marshal(map[string]any{"agent_runtime_vendors": vendors})
		return policyPost(srv, http.MethodPost, "/api/v1/detection/tuning", string(raw), "")
	}
	shipped := storage.DefaultDetectionTuning().AgentRuntimeVendors
	for name, prefix := range map[string]string{"cloudflare": "104.16.0.0/16", "malformed": "160.79.104/23", "over-broad": "160.0.0.0/8"} {
		v := append([]storage.AgentRuntimeVendor(nil), shipped...)
		v[0].Prefixes = []string{prefix}
		if w := post(v); w.Code != http.StatusBadRequest {
			t.Fatalf("%s prefix %s = %d %s, want 400", name, prefix, w.Code, w.Body.String())
		}
	}
	if n := len(authorizedAudit(t, store)); n != 0 {
		t.Fatalf("a refused range reached the authority: %d rows", n)
	}
	v := append([]storage.AgentRuntimeVendor(nil), shipped...)
	v[0].Prefixes = []string{"160.79.104.0/23", "198.51.100.0/24"}
	a := mustSign(t, store, post(v), http.StatusOK)
	if strings.Join(a.Loosens, ",") != "agent_runtime_vendors" {
		t.Fatalf("loosens %v", a.Loosens)
	}
	got := store.GetDetectionTuning()
	if !got.InRuntimeVendorRange("claude", netip.MustParseAddr("198.51.100.9")) || got.InRuntimeVendorRange("claude", netip.MustParseAddr("2607:6bc0::1")) {
		t.Fatalf("saved vendors %+v", got.AgentRuntimeVendors)
	}
}

// A known workload needs an expiry in the future when it is added, moving one
// later is signed while moving another earlier applies plainly, and
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
	a := mustSign(t, store, policyPost(srv, http.MethodPost, "/api/v1/detection/tuning", body, ""), http.StatusOK)
	if strings.Join(a.Loosens, ",") != "known_workloads" {
		t.Fatalf("an extended expiry should be signed: %+v", a)
	}
	got := store.GetDetectionTuning().KnownWorkloads
	if len(got) != 2 || !got[0].ExpiresAt.Equal(until.Add(-time.Hour)) || !got[1].ExpiresAt.Equal(until.Add(time.Hour)) {
		t.Fatalf("both expiries should apply on the first request: %+v", got)
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

// A loosening change carries the floor drill run against the policy it would
// save into what the authority signs, so the audit shows what it blinds: an
// exclusion over an internet range blinds the 10 MB burst, a container
// network over the LAN blinds the lateral sweeps; a case already blinded is
// not counted again.
func TestTheAuthorizationRecordsWhatALooseningChangeWouldBlind(t *testing.T) {
	t.Parallel()
	srv, store := setupTestServer(t)
	defer store.Close()
	expires := time.Now().UTC().Add(24 * time.Hour).Format(time.RFC3339)
	body := `{"name":"uploads","dst_ip_range":"203.0.113.0/24","reason":"backup target","expires_at":"` + expires + `"}`
	a := mustSign(t, store, policyPost(srv, http.MethodPost, "/api/v1/exclusions", body, ""), http.StatusCreated)
	if !strings.HasPrefix(a.Summary, "BLINDS 1 FLOOR CASE: bandwidth burst; ") {
		t.Fatalf("exclusion authorization = %q", a.Summary)
	}

	a = mustSign(t, store, policyPost(srv, http.MethodPost, "/api/v1/detection/tuning", `{"container_cidrs":["192.168.250.0/24"]}`, ""), http.StatusOK)
	// The burst the live exclusion already blinds is not this change's; the
	// quiet processes' lateral sweeps are.
	if !strings.HasPrefix(a.Summary, "BLINDS 12 FLOOR CASES: lateral sweep, agent ssh fan-out reaching a floor port and 10 more; container_cidrs +192.168.250.0/24") {
		t.Fatalf("tuning authorization = %q", a.Summary)
	}
	if len(store.GetDetectionTuning().ContainerCIDRs) != 1 {
		t.Fatal("the container network did not apply")
	}
}

// A floor case that raises today and is missing from the proposed run counts
// as blinded: removing the agent runtime an exclusion's program is drops that
// program's resolver-bypass case.
func TestADrillCaseTheChangeDropsCountsAsBlinded(t *testing.T) {
	t.Parallel()
	srv, store := setupTestServer(t)
	defer store.Close()
	now := time.Now().UTC()
	if err := store.CreateExclusion(storage.Exclusion{ID: "ex-agy", TenantID: "default", Scope: "global", Name: "assistant",
		ProcessPath: "/usr/local/bin/agy", Reason: "test", Active: true, CreatedAt: now, ExpiresAt: now.Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	tu := store.GetDetectionTuning()
	var kept []storage.AgentRuntime
	for _, rt := range tu.AgentRuntimes {
		if rt.Path != "agy" {
			kept = append(kept, rt)
		}
	}
	if len(kept) == len(tu.AgentRuntimes) {
		t.Fatal("need agy among the shipped agent runtimes")
	}
	raw, _ := json.Marshal(map[string]any{"agent_runtimes": kept})
	a := mustSign(t, store, policyPost(srv, http.MethodPost, "/api/v1/detection/tuning", string(raw), ""), http.StatusOK)
	if !strings.HasPrefix(a.Summary, "BLINDS 1 FLOOR CASE: resolver bypass under exclusion ex-agy") {
		t.Fatalf("summary %q", a.Summary)
	}
}
