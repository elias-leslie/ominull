package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"regexp"
	"slices"
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

// withRule changes one of the tuning's rules by id.
func withRule(id string, edit func(*storage.ExpectedRule)) func(*storage.DetectionTuning) {
	return func(t *storage.DetectionTuning) {
		for i := range t.ExpectedRules {
			if t.ExpectedRules[i].ID == id {
				edit(&t.ExpectedRules[i])
				return
			}
		}
		panic("no rule " + id)
	}
}

func cloneTuning(t storage.DetectionTuning) storage.DetectionTuning {
	raw, _ := json.Marshal(t)
	var out storage.DetectionTuning
	_ = json.Unmarshal(raw, &out)
	return out
}

func TestTuningChangesAreJudgedFieldByField(t *testing.T) {
	base := storage.DefaultDetectionTuning()
	base.ExpectedRules = append(base.ExpectedRules, storage.ExpectedRule{ID: "gh", Reason: "cli", Workload: "/usr/bin/gh", Networks: []string{"as36459"},
		Findings: []string{storage.KindNovelDestination, storage.KindNovelProcess}, ExpiresAt: testExpiry})
	base = cloneTuning(base)
	curl := storage.ExpectedRule{ID: "curl", Reason: "r", Programs: []storage.ExpectedProgram{{Path: "/usr/bin/curl"}}, Networks: []string{"as15169"}}
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
		{"added rule", func(t *storage.DetectionTuning) { t.ExpectedRules = append(t.ExpectedRules, curl) }, []string{"expected_rules"}},
		{"removed rule", func(t *storage.DetectionTuning) { t.ExpectedRules = t.ExpectedRules[1:] }, nil},
		// Same length, different contents: one rule swapped for another.
		{"equal-length swap", func(t *storage.DetectionTuning) { t.ExpectedRules[len(t.ExpectedRules)-1] = curl }, []string{"expected_rules"}},
		{"rented workload", withRule("gh", func(r *storage.ExpectedRule) { r.Tenancy = storage.ExpectedTenancyAny }), []string{"expected_rules"}},
		{"vendor-only workload", withRule("gh", func(r *storage.ExpectedRule) { r.Tenancy = storage.ExpectedTenancyVendor }), nil},
		{"workload expiry extended", withRule("gh", func(r *storage.ExpectedRule) { r.ExpiresAt = testExpiry.Add(time.Hour) }), []string{"expected_rules"}},
		{"workload expiry shortened", withRule("gh", func(r *storage.ExpectedRule) { r.ExpiresAt = testExpiry.Add(-time.Hour) }), nil},
		{"rule reason reworded", withRule("gh", func(r *storage.ExpectedRule) { r.Reason = "GitHub CLI" }), nil},
		{"rule renamed", withRule("gh", func(r *storage.ExpectedRule) { r.Name = "GitHub" }), nil},
		{"another network", withRule("gh", func(r *storage.ExpectedRule) { r.Networks = append(r.Networks, "as16509") }), []string{"expected_rules"}},
		{"network replaced", withRule("gh", func(r *storage.ExpectedRule) { r.Networks = []string{"as16509"} }), []string{"expected_rules"}},
		{"network dropped", withRule("gh", func(r *storage.ExpectedRule) { r.Networks = nil }), []string{"expected_rules"}},
		{"another finding kind", withRule("gh", func(r *storage.ExpectedRule) { r.Findings = append(r.Findings, storage.KindBeacon) }), []string{"expected_rules"}},
		{"fewer finding kinds", withRule("gh", func(r *storage.ExpectedRule) { r.Findings = r.Findings[:1] }), nil},
		{"every finding kind", withRule("gh", func(r *storage.ExpectedRule) { r.Findings = nil }), []string{"expected_rules"}},
		{"narrowed to a host", withRule("gh", func(r *storage.ExpectedRule) { r.Hosts = []string{"ws-1"} }), nil},
		{"another host", withRule("curl-host", func(r *storage.ExpectedRule) { r.Hosts = append(r.Hosts, "ws-2") }), []string{"expected_rules"}},
		{"host restriction lifted", withRule("curl-host", func(r *storage.ExpectedRule) { r.Hosts = nil }), []string{"expected_rules"}},
		{"narrowed to a port", withRule("gh", func(r *storage.ExpectedRule) { r.Port = 443 }), nil},
		{"port lifted", withRule("curl-host", func(r *storage.ExpectedRule) { r.Port = 0 }), []string{"expected_rules"}},
		{"another port", withRule("curl-host", func(r *storage.ExpectedRule) { r.Port = 8443 }), []string{"expected_rules"}},
		{"another program", withRule("curl-host", func(r *storage.ExpectedRule) {
			r.Programs = append(r.Programs, storage.ExpectedProgram{Path: "/usr/bin/wget"})
		}), []string{"expected_rules"}},
		{"program account lifted", withRule("curl-host", func(r *storage.ExpectedRule) { r.Programs[0].RunAs = "" }), []string{"expected_rules"}},
		{"program pinned to a build", withRule("curl-host", func(r *storage.ExpectedRule) { r.Programs[0].SHA256 = strings.Repeat("ab", 32) }), nil},
		{"exception removed", withRule("curl-host", func(r *storage.ExpectedRule) { r.ExceptDomains = nil }), []string{"expected_rules"}},
		{"exception added", withRule("curl-host", func(r *storage.ExpectedRule) { r.ExceptDomains = append(r.ExceptDomains, "www.googleapis.com") }), nil},
		{"domains lifted", withRule("curl-host", func(r *storage.ExpectedRule) { r.Domains = nil }), []string{"expected_rules"}},
		{"later expiry", withRule("curl-host", func(r *storage.ExpectedRule) { r.ExpiresAt = testExpiry.Add(48 * time.Hour) }), []string{"expected_rules"}},
		{"expiry lifted", withRule("curl-host", func(r *storage.ExpectedRule) { r.ExpiresAt = time.Time{} }), []string{"expected_rules"}},
		{"expiry added", withRule("gh-open", func(r *storage.ExpectedRule) { r.ExpiresAt = testExpiry }), nil},
		{"vendor prefix added", withRule("vendor-claude", func(r *storage.ExpectedRule) { r.Prefixes = append(r.Prefixes, "198.51.100.0/24") }), []string{"expected_rules"}},
		{"vendor domain added", withRule("vendor-claude", func(r *storage.ExpectedRule) { r.Domains = append(r.Domains, "example.com") }), []string{"expected_rules"}},
		{"vendor prefix removed", withRule("vendor-claude", func(r *storage.ExpectedRule) { r.Prefixes = r.Prefixes[1:] }), nil},
		{"vendor domain removed", withRule("vendor-claude", func(r *storage.ExpectedRule) { r.Domains = r.Domains[1:] }), nil},
		{"vendor removed", func(t *storage.DetectionTuning) {
			t.ExpectedRules = slices.DeleteFunc(t.ExpectedRules, func(r storage.ExpectedRule) bool { return r.ID == "vendor-claude" })
		}, nil},
		{"vendor network added", withRule("vendor-antigravity", func(r *storage.ExpectedRule) { r.Networks = append(r.Networks, "as396982") }), []string{"expected_rules"}},
		{"vendor exclusion removed", withRule("vendor-antigravity", func(r *storage.ExpectedRule) { r.ExceptDomains = r.ExceptDomains[1:] }), []string{"expected_rules"}},
		{"vendor exclusion added", withRule("vendor-antigravity", func(r *storage.ExpectedRule) { r.ExceptDomains = append(r.ExceptDomains, "www.googleapis.com") }), nil},
		{"mixed", func(t *storage.DetectionTuning) { t.BeaconScore = 0.6; t.BandwidthOn = false }, []string{"bandwidth_enabled"}},
		{"agent runtime removed", func(t *storage.DetectionTuning) { t.AgentRuntimes = t.AgentRuntimes[1:] }, []string{"agent_runtimes"}},
		{"agent-heavy by observation", func(t *storage.DetectionTuning) { t.AgentHeavyObserved = !t.AgentHeavyObserved }, nil},
		{"wider window", func(t *storage.DetectionTuning) { t.OffHoursStart = 21 }, nil},
		{"shorter window", func(t *storage.DetectionTuning) { t.OffHoursStart = 23 }, []string{"off_hours_window"}},
		{"moved window", func(t *storage.DetectionTuning) { t.OffHoursStart, t.OffHoursEnd = 23, 6 }, []string{"off_hours_window"}},
		{"other zone", func(t *storage.DetectionTuning) { t.OffHoursZone = "UTC" }, []string{"off_hours_window"}},
		{"lab network added", func(t *storage.DetectionTuning) { t.LabCIDRs = []string{"10.20.0.0/24"} }, []string{"lab_cidrs"}},
		{"browser added", func(t *storage.DetectionTuning) { t.BeaconBrowsers = append(t.BeaconBrowsers, "lynx") }, []string{"beacon_browsers"}},
		{"browser removed", func(t *storage.DetectionTuning) { t.BeaconBrowsers = t.BeaconBrowsers[1:] }, nil},
		{"longer beacon span", func(t *storage.DetectionTuning) { t.BeaconPageSpanMin = 45 }, []string{"beacon_page_span_min"}},
	}
	// Two more rules to narrow and widen: one with every restriction, one
	// open-ended.
	base.ExpectedRules = append(base.ExpectedRules,
		storage.ExpectedRule{ID: "curl-host", Reason: "r", Findings: []string{storage.KindBandwidthSpike}, Hosts: []string{"ws-1"},
			Programs: []storage.ExpectedProgram{{Path: "/usr/bin/curl", RunAs: "root"}}, Domains: []string{"googleapis.com"},
			ExceptDomains: []string{"storage.googleapis.com"}, Prefixes: []string{"142.250.0.0/16"}, Port: 443, ExpiresAt: testExpiry},
		storage.ExpectedRule{ID: "gh-open", Reason: "r", Programs: []storage.ExpectedProgram{{Path: "/usr/bin/gh"}}, Networks: []string{"as36459"}})
	base, err := storage.PrepareDetectionTuning(cloneTuning(base))
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range cases {
		after := cloneTuning(base)
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
	// Taking a network out of a zone loosens too: its lab hosts lose the
	// lab escape page, its servers the always-on page.
	zoned := base
	zoned.LabCIDRs, zoned.InfraCIDRs = []string{"10.20.0.0/24"}, []string{"10.0.0.1/32"}
	if got := tuningLoosens(zoned, base); strings.Join(got, ",") != "infra_cidrs,lab_cidrs" {
		t.Errorf("zones removed: loosens %v", got)
	}
	if base.AgentHeavyObserved {
		off := base
		off.AgentHeavyObserved = false
		if got := tuningLoosens(off, base); len(got) != 1 {
			t.Errorf("counting agent-heavy hosts by observation mutes more: %v", got)
		}
	}
}

// A reset tightens only when every rule it brings back is one already saved.
func TestAResetLoosensWhenItBringsExpectedRulesBack(t *testing.T) {
	shipped := storage.DefaultDetectionTuning()
	tighter := cloneTuning(shipped)
	tighter.ExpectedRules = tighter.ExpectedRules[1:]
	if got := tuningLoosens(tighter, shipped); strings.Join(got, ",") != "expected_rules" {
		t.Fatalf("reset re-adding a removed rule: %v", got)
	}
	looser := cloneTuning(shipped)
	looser.ExpectedRules = append(looser.ExpectedRules, storage.ExpectedRule{ID: "extra", Reason: "r", Programs: []storage.ExpectedProgram{{Path: "/usr/bin/curl"}}})
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
	rules := append(storage.DefaultDetectionTuning().ExpectedRules, storage.ExpectedRule{ID: "extra-curl", Reason: "r",
		Programs: []storage.ExpectedProgram{{Path: "/usr/bin/curl"}}, Networks: []string{"as64500"}})
	raw, _ := json.Marshal(map[string]any{"beacon_enabled": false, "expected_rules": rules})
	a := mustSign(t, store, policyPost(srv, http.MethodPost, "/api/v1/detection/tuning", string(raw), ""), http.StatusOK)
	if !strings.Contains(a.Summary, "beacon_enabled true -> false") || !strings.Contains(a.Summary, "id=extra-curl") {
		t.Fatalf("the audit does not show the change: %+v", a)
	}
	if strings.Join(a.Loosens, ",") != "beacon_enabled,expected_rules" || a.Target != "detection:tuning" {
		t.Fatalf("authorization = %+v", a)
	}
	if got := store.GetDetectionTuning(); got.BeaconOn || len(got.ExpectedRules) != len(rules) {
		t.Fatal("the signed save did not apply")
	}
	notes := policyNotes(t, store)
	if len(notes) != 1 || !strings.Contains(notes[0].Details, "loosened (beacon_enabled, expected_rules) with authorization "+a.ID) ||
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
	bodies := []string{`{"beacon_score_threshold":0.7}`, `{"warmup_hours":6}`, `{"beacon_cooldown_minutes":10}`, `{"bandwidth_cooldown_minutes":2}`, `{"silence_after_minutes":10}`}
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
	if got.BeaconScore != 0.7 || got.WarmupHours != 6 || got.BeaconCooldownMin != 10 || got.BandwidthCooldown != 2 || got.SilenceAfterMinutes != 10 {
		t.Fatalf("a concurrent save was lost: %+v", got)
	}
}

// Restoring the shipped values is signed when it brings back rules
// someone removed, and applies plainly when it only tightens.
func TestResetIsJudgedLikeAnySave(t *testing.T) {
	t.Parallel()
	srv, store := setupTestServer(t)
	defer store.Close()
	tu := storage.DefaultDetectionTuning()
	tu.ExpectedRules = tu.ExpectedRules[1:]
	if _, err := store.SaveDetectionTuning(tu, "test"); err != nil {
		t.Fatal(err)
	}
	a := mustSign(t, store, policyPost(srv, http.MethodDelete, "/api/v1/detection/tuning", "", ""), http.StatusOK)
	if !strings.Contains(a.Summary, "expected_rules +{") || len(store.GetDetectionTuning().ExpectedRules) != len(storage.DefaultDetectionTuning().ExpectedRules) {
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

// "Expected" on a finding writes an expected rule, which loosens: the rule and
// the acknowledgement land on the first request, with the rule in the audit.
func TestMarkingExpectedIsSignedAtOnce(t *testing.T) {
	t.Parallel()
	srv, store := setupTestServer(t)
	defer store.Close()
	seedFinding(t, store, "f-wait", "/opt/acme/backup-agent", `{"destination_asn":"AS64500","destination_tenancy":"isp"}`)
	a := mustSign(t, store, policyPost(srv, http.MethodPost, "/api/v1/detection/expected/mark", `{"id":"f-wait"}`, ""), http.StatusOK)
	if !strings.Contains(a.Summary, "id=marked-backup-agent-") || strings.Join(a.Loosens, ",") != "expected_rules" {
		t.Fatalf("authorization = %+v", a)
	}
	if al, _ := store.GetAnomalyAlert("f-wait"); !al.Acknowledged || len(markedRules(store)) != 1 {
		t.Fatal("the rule did not land")
	}
}

// Saving a rule through the rule endpoint: a new rule, a widened one and a
// renewal are signed; narrowing one and deleting one tighten, apply at once
// and are noted.
func TestExpectedRuleWritesAreJudged(t *testing.T) {
	t.Parallel()
	srv, store := setupTestServer(t)
	defer store.Close()
	expires := time.Now().UTC().Add(24 * time.Hour).Format(time.RFC3339)
	body := `{"id":"bridge","name":"bridge","reason":"bridge","programs":[{"path":"/usr/bin/docker-proxy"}],"prefixes":["172.18.0.0/16"],"port":7070,"protocol":"tcp","expires_at":"` + expires + `"}`
	a := mustSign(t, store, policyPost(srv, http.MethodPost, "/api/v1/detection/expected", body, ""), http.StatusOK)
	if !strings.Contains(a.Summary, "id=bridge") || a.Target != "detection:tuning" {
		t.Fatalf("rule authorization = %+v", a)
	}
	if _, ok := store.GetDetectionTuning().RuleByID("bridge"); !ok {
		t.Fatal("the rule was not created")
	}

	// Narrowing it to one host applies at once.
	narrow := strings.Replace(body, `"port":7070`, `"port":7070,"hosts":["ws-1"]`, 1)
	if w := policyPost(srv, http.MethodPost, "/api/v1/detection/expected", narrow, ""); w.Code != http.StatusOK {
		t.Fatalf("narrowing = %d %s", w.Code, w.Body.String())
	}
	// Opening it up again is signed.
	a = mustSign(t, store, policyPost(srv, http.MethodPost, "/api/v1/detection/expected", body, ""), http.StatusOK)
	if strings.Join(a.Loosens, ",") != "expected_rules" {
		t.Fatalf("widening authorization = %+v", a)
	}
	if got, _ := store.GetDetectionTuning().RuleByID("bridge"); len(got.Hosts) != 0 {
		t.Fatal("the rule did not widen")
	}
	// A renewal loosens too.
	later := time.Now().UTC().Add(48 * time.Hour).Format(time.RFC3339)
	mustSign(t, store, policyPost(srv, http.MethodPost, "/api/v1/detection/expected", strings.Replace(body, expires, later, 1), ""), http.StatusOK)

	if w := policyPost(srv, http.MethodDelete, "/api/v1/detection/expected?id=bridge", "", ""); w.Code != http.StatusOK {
		t.Fatalf("delete = %d %s", w.Code, w.Body.String())
	}
	kinds := noteKinds(policyNotes(t, store))
	if len(kinds) != 5 || kinds[0] != "tightened detection tuning rule_delete" || !strings.HasPrefix(kinds[1], "loosened (expected_rules) with authorization ") ||
		!strings.HasPrefix(kinds[2], "loosened (expected_rules) with authorization ") || kinds[3] != "tightened detection tuning rule_save" ||
		!strings.HasPrefix(kinds[4], "loosened (expected_rules) with authorization ") {
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

// The Aico push carries the day's changes as a note, and an unsound
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

	for _, settings := range []string{`{"beacon_enabled":`, `{"expected_rules":[{"id":"x","reason":"x","workload":"python3 *","networks":["*"],"expires_at":"2099-01-01T00:00:00Z"}]}`} {
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
	for _, k := range []string{"agent_baseline_days", "agent_upload_floor_mb", "bandwidth_cooldown_minutes",
		"beacon_cooldown_minutes", "beacon_min_samples", "beacon_min_span_minutes",
		"warmup_hours"} {
		body[k] = shipped[k].(float64) - 1
	}
	rules := append(storage.DefaultDetectionTuning().ExpectedRules, storage.ExpectedRule{ID: "extra-curl", Reason: "r",
		Programs: []storage.ExpectedProgram{{Path: "/usr/bin/curl"}}, Networks: []string{"as64500"}})
	body["expected_rules"] = rules
	raw, _ := json.Marshal(body)
	a := mustSign(t, store, policyPost(srv, http.MethodPost, "/api/v1/detection/tuning", string(raw), ""), http.StatusOK)
	if strings.Join(a.Loosens, ",") != "expected_rules" || !strings.Contains(a.Summary, "id=extra-curl") ||
		strings.Contains(a.Summary, "warmup_hours") || strings.Contains(a.Summary, " more") {
		t.Fatalf("the loosening is not shown on its own: %+v", a)
	}
	got := store.GetDetectionTuning()
	if float64(got.WarmupHours) != shipped["warmup_hours"].(float64)-1 {
		t.Fatal("the tightening half was not saved")
	}
	if _, ok := got.RuleByID("extra-curl"); !ok {
		t.Fatalf("the loosening did not apply: %d rules", len(got.ExpectedRules))
	}
	notes := policyNotes(t, store)
	if len(notes) != 2 {
		t.Fatalf("want a tightened note and a loosened note, got %+v", notes)
	}

	// A list that loses rules and gains one loses them now; the authority
	// signs only the one it gains.
	if len(got.ExpectedRules) < 3 {
		t.Fatalf("need shipped rules: %d", len(got.ExpectedRules))
	}
	swap, _ := json.Marshal(map[string]any{"expected_rules": []storage.ExpectedRule{got.ExpectedRules[0],
		{ID: "other-curl", Reason: "r", Programs: []storage.ExpectedProgram{{Path: "/usr/bin/curl"}}, Networks: []string{"as64501"}}}})
	a = mustSign(t, store, policyPost(srv, http.MethodPost, "/api/v1/detection/tuning", string(swap), ""), http.StatusOK)
	if !strings.Contains(a.Summary, "id=other-curl") || strings.Contains(a.Summary, "extra-curl") {
		t.Fatalf("swap summary %q", a.Summary)
	}
	if got := store.GetDetectionTuning().ExpectedRules; len(got) != 2 || got[0].ID != storage.DefaultDetectionTuning().ExpectedRules[0].ID || got[1].ID != "other-curl" {
		t.Fatalf("rules after the swap: %v", got)
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

// A maker's range is signed by the authority, refused when it is not one
// maker's own address space, and a save that drops a range and adds another
// drops it and signs only the one it adds.
func TestVendorRangesAreJudgedAsPolicy(t *testing.T) {
	t.Parallel()
	srv, store := setupTestServer(t)
	defer store.Close()
	post := func(prefixes ...string) *httptest.ResponseRecorder {
		rules := storage.DefaultDetectionTuning().ExpectedRules
		for i := range rules {
			if rules[i].ID == "vendor-claude" {
				rules[i].Prefixes = prefixes
			}
		}
		raw, _ := json.Marshal(map[string]any{"expected_rules": rules})
		return policyPost(srv, http.MethodPost, "/api/v1/detection/tuning", string(raw), "")
	}
	for name, prefix := range map[string]string{"cloudflare": "104.16.0.0/16", "malformed": "160.79.104/23", "over-broad": "160.0.0.0/8"} {
		if w := post(prefix); w.Code != http.StatusBadRequest {
			t.Fatalf("%s prefix %s = %d %s, want 400", name, prefix, w.Code, w.Body.String())
		}
	}
	if n := len(authorizedAudit(t, store)); n != 0 {
		t.Fatalf("a refused range reached the authority: %d rows", n)
	}
	a := mustSign(t, store, post("160.79.104.0/23", "198.51.100.0/24"), http.StatusOK)
	if strings.Join(a.Loosens, ",") != "expected_rules" {
		t.Fatalf("loosens %v", a.Loosens)
	}
	got := store.GetDetectionTuning()
	claude := storage.ExpectCtx{Kind: storage.KindBandwidthSpike, Host: "ws", Path: "/home/u/.local/share/claude/versions/2.1.5", User: "u",
		DstIP: "198.51.100.9", Domain: "api.anthropic.com", Port: 443, Direction: "OUTBOUND"}
	if !expects(got, claude) {
		t.Fatalf("the added range is not honoured: %+v", got.ExpectedRules)
	}
	claude.DstIP = "2607:6bc0::1"
	if expects(got, claude) {
		t.Fatal("a range the save dropped still counts")
	}
}

// A workload rule needs an expiry in the future when it is added, moving one
// later is signed while moving another earlier applies plainly, and the feed
// note names expired rules and a saved row weaker than the floor.
func TestWorkloadRuleExpiryAndTheFloorAreJudgedAndShown(t *testing.T) {
	t.Parallel()
	srv, store := setupTestServer(t)
	defer store.Close()
	for _, body := range []string{
		`{"id":"gh","workload":"/usr/bin/gh","networks":["as36459"],"reason":"cli"}`,
		`{"id":"gh","workload":"/usr/bin/gh","networks":["as36459"],"reason":"cli","expires_at":"2020-01-01T00:00:00Z"}`,
		`{"id":"gh","workload":"/usr/bin/gh","networks":["as36459"],"reason":"cli","expires_at":"2099-01-01T00:00:00Z"}`,
	} {
		if w := policyPost(srv, http.MethodPost, "/api/v1/detection/expected", body, ""); w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "expires_at") {
			t.Fatalf("%s = %d %s", body, w.Code, w.Body.String())
		}
	}

	until := time.Now().UTC().Add(30 * 24 * time.Hour).Truncate(time.Second)
	saved := storage.DefaultDetectionTuning()
	saved.ExpectedRules = append(saved.ExpectedRules,
		storage.ExpectedRule{ID: "gh", Workload: "/usr/bin/gh", Networks: []string{"as36459"}, Reason: "cli", ExpiresAt: until},
		storage.ExpectedRule{ID: "ssh", Workload: "/usr/bin/ssh", Networks: []string{"as36459"}, Reason: "git", ExpiresAt: until})
	if _, err := store.SaveDetectionTuning(saved, "test"); err != nil {
		t.Fatal(err)
	}
	rules := store.GetDetectionTuning().ExpectedRules
	for i := range rules {
		switch rules[i].ID {
		case "gh":
			rules[i].ExpiresAt = until.Add(-time.Hour)
		case "ssh":
			rules[i].ExpiresAt = until.Add(time.Hour)
		}
	}
	raw, _ := json.Marshal(map[string]any{"expected_rules": rules})
	a := mustSign(t, store, policyPost(srv, http.MethodPost, "/api/v1/detection/tuning", string(raw), ""), http.StatusOK)
	if strings.Join(a.Loosens, ",") != "expected_rules" {
		t.Fatalf("an extended expiry should be signed: %+v", a)
	}
	gh, _ := store.GetDetectionTuning().RuleByID("gh")
	ssh, _ := store.GetDetectionTuning().RuleByID("ssh")
	if !gh.ExpiresAt.Equal(until.Add(-time.Hour)) || !ssh.ExpiresAt.Equal(until.Add(time.Hour)) {
		t.Fatalf("both expiries should apply on the first request: %v %v", gh.ExpiresAt, ssh.ExpiresAt)
	}

	// A row saved weaker than the floor, holding an expired workload rule.
	row := `{"silence_enabled":true,"silence_after_minutes":60,"bandwidth_enabled":true,"expected_rules":[{"id":"gh","workload":"/usr/bin/gh","networks":["as36459"],"reason":"cli","expires_at":"2020-01-01T00:00:00Z"}]}`
	if _, err := store.DB().Exec(`UPDATE detection_tuning SET settings = ? WHERE id = 1`, row); err != nil {
		t.Fatal(err)
	}
	findings, err := srv.detectionPolicySection(time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range findings {
		if f.FindingInfo["uid"] == "ominull.detection.invalid" && f.SeverityID != ocsfSevInformational {
			t.Fatalf("an expired rule or a value past the floor is not an unsound row: %+v", f)
		}
		if f.FindingInfo["uid"] != "ominull.detection.changes" {
			continue
		}
		clamped, _ := f.Unmapped["floor_clamped"].([]string)
		expired, _ := f.Unmapped["expected_rules_expired"].([]string)
		if f.StatusID != ocsfStatusNew || len(clamped) != 1 || !strings.Contains(clamped[0], "silence_after_minutes 60") ||
			len(expired) != 1 || !strings.Contains(f.Message, "detection floor") {
			t.Fatalf("feed note = %+v", f)
		}
		return
	}
	t.Fatal("no detection policy note")
}

// A loosening change carries the floor drill run against the policy it would
// save into what the authority signs, so the audit shows what it blinds: a
// rule over an internet range blinds the 10 MB burst and the rare beacon, a
// container network over the LAN blinds the lateral sweeps and the lab escape;
// a case already blinded is not counted again.
func TestTheAuthorizationRecordsWhatALooseningChangeWouldBlind(t *testing.T) {
	t.Parallel()
	srv, store := setupTestServer(t)
	defer store.Close()
	body := `{"id":"uploads","name":"uploads","prefixes":["203.0.113.0/24"],"reason":"backup target"}`
	a := mustSign(t, store, policyPost(srv, http.MethodPost, "/api/v1/detection/expected", body, ""), http.StatusOK)
	if !strings.HasPrefix(a.Summary, "BLINDS 1 FLOOR CASE: rare beacon; ") {
		t.Fatalf("rule authorization = %q", a.Summary)
	}

	a = mustSign(t, store, policyPost(srv, http.MethodPost, "/api/v1/detection/tuning", `{"container_cidrs":["192.168.250.0/24"]}`, ""), http.StatusOK)
	// The beacon the saved rule already blinds is not this change's; the
	// lateral sweeps and the lab escape are.
	if !strings.HasPrefix(a.Summary, "BLINDS ") || !strings.Contains(a.Summary, "lateral sweep, lab escape") ||
		strings.Contains(a.Summary, "rare beacon") || !strings.HasSuffix(a.Summary, "container_cidrs +192.168.250.0/24") {
		t.Fatalf("tuning authorization = %q", a.Summary)
	}
	if len(store.GetDetectionTuning().ContainerCIDRs) != 1 {
		t.Fatal("the container network did not apply")
	}
}

// A floor case that raises today and is missing from the proposed run counts
// as blinded: removing the agent runtime a rule's program is drops that
// program's resolver-bypass case.
func TestADrillCaseTheChangeDropsCountsAsBlinded(t *testing.T) {
	t.Parallel()
	srv, store := setupTestServer(t)
	defer store.Close()
	tu := store.GetDetectionTuning()
	tu.ExpectedRules = append(tu.ExpectedRules, storage.ExpectedRule{ID: "assistant", Name: "assistant", Reason: "test",
		Programs: []storage.ExpectedProgram{{Path: "/usr/local/bin/agy"}}, Hosts: []string{"ws-1"}})
	if _, err := store.SaveDetectionTuning(tu, "test"); err != nil {
		t.Fatal(err)
	}
	tu = store.GetDetectionTuning()
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
	if !strings.HasPrefix(a.Summary, "BLINDS 1 FLOOR CASE: resolver bypass under rule assistant") {
		t.Fatalf("summary %q", a.Summary)
	}
}
