package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"ominull/hub/pkg/storage"
)

// markFinding presses "mark as expected" on a finding through the API.
func markFinding(t *testing.T, srv *Server, id string) (int, map[string]interface{}) {
	t.Helper()
	return markWith(t, srv, `{"id":"`+id+`"}`, "mock_admin_token")
}

func markWith(t *testing.T, srv *Server, body, key string) (int, map[string]interface{}) {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, "/api/v1/detection/expected/mark", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-API-Key", key)
	w := serveAuthorized(t, srv.Handler(), r)
	out := map[string]interface{}{}
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	return w.Code, out
}

func seedFinding(t *testing.T, store *storage.Store, id, process, evidence string) {
	t.Helper()
	seedFindingOf(t, store, id, "C2_BEACONING", process, evidence)
}

func seedFindingOf(t *testing.T, store *storage.Store, id, kind, process, evidence string) {
	t.Helper()
	if err := store.CreateAnomalyAlert(storage.AnomalyAlert{
		ID:          id,
		TenantID:    "default",
		EndpointID:  "ep-1",
		Hostname:    "workstation",
		AnomalyType: kind,
		Technique:   "T1071.001",
		Severity:    "MEDIUM",
		Title:       "Periodic beaconing",
		Description: "a conversation",
		Evidence:    evidence,
		ProcessPath: process,
		DstIP:       "10.0.0.9",
		DstPort:     443,
		Timestamp:   time.Now().UTC(),
	}); err != nil {
		t.Fatalf("seeding the finding: %v", err)
	}
}

func markedRules(store *storage.Store) []storage.ExpectedRule {
	var out []storage.ExpectedRule
	for _, r := range store.GetDetectionTuning().ExpectedRules {
		if strings.HasPrefix(r.ID, "marked-") {
			out = append(out, r)
		}
	}
	return out
}

func expects(tuning storage.DetectionTuning, c storage.ExpectCtx) bool {
	_, ok := tuning.Expected(c)
	return ok
}

// The loop the console did not have: say "expected" on a finding, and a narrow
// rule is written that would have made it expected.
func TestMarkingAFindingExpectedWritesANarrowRule(t *testing.T) {
	t.Parallel()
	srv, store := setupTestServer(t)
	seedFinding(t, store, "f-1", `C:\Program Files\Acme\backup-agent.exe`, `{"destination_owner":"Acme Vendor","destination_asn":"AS64500","destination_tenancy":"vendor"}`)

	code, body := markFinding(t, srv, "f-1")
	if code != http.StatusOK || body["added"] != true {
		t.Fatalf("mark: %d %v", code, body)
	}
	rules := markedRules(store)
	if len(rules) != 1 {
		t.Fatalf("rules written = %+v", rules)
	}
	r := rules[0]
	if len(r.Findings) != 1 || r.Findings[0] != storage.KindBeacon || len(r.Hosts) != 1 || r.Hosts[0] != "ep-1" ||
		len(r.Programs) != 1 || r.Programs[0].Path != "c:/program files/acme/backup-agent.exe" || len(r.Networks) != 1 || r.Networks[0] != "as64500" {
		t.Fatalf("the rule is not the narrow one: %+v", r)
	}

	tuning := store.GetDetectionTuning()
	ctx := storage.ExpectCtx{Kind: storage.KindBeacon, Host: "ep-1", Path: `C:\Program Files\Acme\backup-agent.exe`,
		ASN: "AS64500", Org: "Acme Vendor", Tenancy: storage.TenancyVendor, Direction: "OUTBOUND"}
	if !expects(tuning, ctx) {
		t.Fatal("the rule was not written into the tuning, so the same finding raises again tomorrow")
	}
	// Marking one program talking to that owner must not cover every program
	// talking to it, a copy of it somewhere else, another host, another kind
	// of finding or another network.
	for name, mutate := range map[string]func(*storage.ExpectCtx){
		"another program":   func(c *storage.ExpectCtx) { c.Path = "/usr/bin/curl" },
		"a copy elsewhere":  func(c *storage.ExpectCtx) { c.Path = `C:\Users\Public\backup-agent.exe` },
		"another host":      func(c *storage.ExpectCtx) { c.Host = "ep-2" },
		"another finding":   func(c *storage.ExpectCtx) { c.Kind = storage.KindNovelProcess },
		"another network":   func(c *storage.ExpectCtx) { c.ASN, c.Org = "AS13335", "Cloudflare, Inc." },
		"rented compute":    func(c *storage.ExpectCtx) { c.Tenancy = storage.TenancyHosting },
		"the cloud storage": func(c *storage.ExpectCtx) { c.Kind = storage.KindCloudStorage },
	} {
		c := ctx
		mutate(&c)
		if expects(tuning, c) {
			t.Errorf("the rule also covers %s", name)
		}
	}

	found, err := store.GetAnomalyAlert("f-1")
	if err != nil {
		t.Fatalf("reading the finding back: %v", err)
	}
	if !found.Acknowledged {
		t.Error("the finding that was just explained is still sitting in the open list")
	}
	page, err := store.AuditHistory("", 20, "", storage.AuditFilter{Action: "EXPECTED_RULE_MARKED"})
	if err != nil || len(page.Entries) != 1 {
		t.Fatalf("audit rows for the mark = %v %v", page.Entries, err)
	}
}

// A program that updates itself lands in a new versioned folder every release.
// Marking it expected names the folder with the release number left open and
// the account that ran it, so it stays expected after its next update and for
// nobody else.
func TestASelfUpdatingProgramInAHomeFolderStaysExpectedAfterItUpdates(t *testing.T) {
	t.Parallel()
	srv, store := setupTestServer(t)
	seedFindingOf(t, store, "f-agy", "NOVEL_DESTINATION", "/home/me/.local/share/agy/versions/1.4.2/agy",
		`{"destination_asn":"AS15169","destination_owner":"Google LLC","destination_tenancy":"vendor","user_identity":"me"}`)

	code, body := markFinding(t, srv, "f-agy")
	if code != http.StatusOK {
		t.Fatalf("mark: %d %v", code, body)
	}
	rules := markedRules(store)
	if len(rules) != 1 || rules[0].Programs[0].Path != "/home/me/.local/share/agy/versions/*/agy" || rules[0].Programs[0].RunAs != "me" || rules[0].Programs[0].SHA256 != "" {
		t.Fatalf("rules = %+v", rules)
	}
	// Only the marked rule is judged: the shipped rule for agy's own maker
	// would cover some of these on its own.
	tuning := store.GetDetectionTuning()
	tuning.ExpectedRules = rules
	ctx := storage.ExpectCtx{Kind: storage.KindNovelDestination, Host: "ep-1", Path: "/home/me/.local/share/agy/versions/1.5.0/agy", User: "me",
		ASN: "AS15169", Org: "Google LLC", Tenancy: storage.TenancyVendor, Direction: "OUTBOUND"}
	if !expects(tuning, ctx) {
		t.Fatal("the updated release is no longer expected")
	}
	for name, mutate := range map[string]func(*storage.ExpectCtx){
		"another account":     func(c *storage.ExpectCtx) { c.User = "mallory" },
		"no account read":     func(c *storage.ExpectCtx) { c.User = "" },
		"another folder":      func(c *storage.ExpectCtx) { c.Path = "/home/me/Downloads/agy" },
		"a deeper look-alike": func(c *storage.ExpectCtx) { c.Path = "/home/me/.local/share/agy/versions/1.5.0/x/agy" },
	} {
		c := ctx
		mutate(&c)
		if expects(tuning, c) {
			t.Errorf("the rule also covers %s", name)
		}
	}
}

// A system component runs as root: the rule is bound to the system's own
// accounts, not to a name.
func TestAProgramRunningAsRootIsMarkedForTheSystemAccount(t *testing.T) {
	t.Parallel()
	srv, store := setupTestServer(t)
	seedFindingOf(t, store, "f-sys", "NOVEL_DESTINATION", "/usr/lib/example/updater",
		`{"destination_asn":"AS15169","destination_tenancy":"vendor","user_identity":"root"}`)
	if code, body := markFinding(t, srv, "f-sys"); code != http.StatusOK {
		t.Fatalf("mark: %d %v", code, body)
	}
	rules := markedRules(store)
	if len(rules) != 1 || rules[0].Programs[0].RunAs != "system" {
		t.Fatalf("rules = %+v", rules)
	}
}

// Rented compute is where an implant hides behind a reputable-sounding name.
// It is barred in the rules, and it has to be barred at the door as well, or
// the button becomes the way to write the entry the rules refuse.
func TestRentedComputeCannotBeMarkedExpected(t *testing.T) {
	t.Parallel()
	srv, store := setupTestServer(t)
	seedFinding(t, store, "f-2", "/usr/bin/python3.13", `{"destination_owner":"Some Cloud (customer)","destination_tenancy":"hosting"}`)

	code, body := markFinding(t, srv, "f-2")
	if code != http.StatusBadRequest {
		t.Fatalf("rented compute was accepted: %d %v", code, body)
	}
	if len(markedRules(store)) != 0 {
		t.Fatal("a rule was written for a destination on rented compute")
	}
	found, _ := store.GetAnomalyAlert("f-2")
	if found.Acknowledged {
		t.Error("a refused mark still cleared the finding")
	}
}

// "unknown" is what an agent sends when nothing owns the socket. There is no
// program there to vouch for.
func TestAnUnattributedProcessCannotBeMarkedExpected(t *testing.T) {
	t.Parallel()
	srv, store := setupTestServer(t)
	seedFinding(t, store, "f-3", "unknown", `{"destination_owner":"Acme Vendor","destination_tenancy":"vendor"}`)

	code, _ := markFinding(t, srv, "f-3")
	if code != http.StatusBadRequest {
		t.Fatalf("an unattributed process was vouched for: %d", code)
	}
	if len(markedRules(store)) != 0 {
		t.Fatal("a rule was written with no program on one side of it")
	}
}

// An address nobody can name is not a counterparty, and covering one would
// cover whatever answers on it next.
func TestAnUnnamedNetworkCannotBeMarkedExpected(t *testing.T) {
	t.Parallel()
	srv, store := setupTestServer(t)
	seedFinding(t, store, "f-4", "/usr/bin/curl", `{"attribution_status":"authoritative"}`)

	code, _ := markFinding(t, srv, "f-4")
	if code != http.StatusBadRequest {
		t.Fatalf("an unnamed network was covered: %d", code)
	}
	if len(markedRules(store)) != 0 {
		t.Fatal("a rule was written for an unnamed network")
	}
}

// What the floor raises, and what is never marked from a click, is refused
// with its reason and nothing is written.
func TestFloorFindingsAndStorageUploadsCannotBeMarkedExpected(t *testing.T) {
	t.Parallel()
	srv, store := setupTestServer(t)
	ev := `{"destination_owner":"Acme Vendor","destination_asn":"AS64500","destination_tenancy":"vendor"}`
	for i, kind := range []string{
		"THREAT_INTEL_MATCH", "SENSITIVE_PORT_EGRESS", "PORT_SCAN_RECON", "DECOY_TOUCHED", "LAB_ESCAPE", "RESOLVER_BYPASS", "ENDPOINT_SILENT",
		"CLOUD_STORAGE_EGRESS", "LATERAL_PORT_SWEEP",
	} {
		id := "floor-" + string(rune('a'+i))
		seedFindingOf(t, store, id, kind, "/usr/bin/backup-agent", ev)
		if code, body := markFinding(t, srv, id); code != http.StatusBadRequest {
			t.Errorf("%s was marked expected: %d %v", kind, code, body)
		}
		if found, _ := store.GetAnomalyAlert(id); found.Acknowledged {
			t.Errorf("a refused mark of %s still cleared it", kind)
		}
	}
	if len(markedRules(store)) != 0 {
		t.Fatalf("rules were written for floor findings: %+v", markedRules(store))
	}
}

// Loosening a detector is an administrator's decision, like every other write
// to the rules.
func TestMarkingExpectedIsAnAdministratorAction(t *testing.T) {
	t.Parallel()
	srv, store := setupTestServer(t)
	seedFinding(t, store, "f-5", "/usr/bin/backup-agent", `{"destination_owner":"Acme Vendor","destination_tenancy":"vendor"}`)

	code, _ := markWith(t, srv, `{"id":"f-5"}`, "mock_tenant_token")
	if code == http.StatusOK {
		t.Fatalf("a tenant credential covered a detector: %d", code)
	}
	if len(markedRules(store)) != 0 {
		t.Fatal("a rule was written without administrator authority")
	}
}

// Pressing it twice is not an error, and does not write the rule twice.
func TestMarkingExpectedTwiceIsIdempotent(t *testing.T) {
	t.Parallel()
	srv, store := setupTestServer(t)
	seedFinding(t, store, "f-6", "/usr/bin/backup-agent", `{"destination_owner":"Acme Vendor","destination_tenancy":"vendor"}`)
	seedFinding(t, store, "f-7", "/usr/bin/backup-agent", `{"destination_owner":"Acme Vendor","destination_tenancy":"vendor"}`)

	if code, _ := markFinding(t, srv, "f-6"); code != http.StatusOK {
		t.Fatalf("first mark: %d", code)
	}
	code, body := markFinding(t, srv, "f-7")
	if code != http.StatusOK {
		t.Fatalf("second mark: %d %v", code, body)
	}
	if body["added"] != false {
		t.Error("the second press claimed to have added the rule again")
	}
	if n := len(markedRules(store)); n != 1 {
		t.Fatalf("the rule is in the tuning %d times", n)
	}
	found, _ := store.GetAnomalyAlert("f-7")
	if !found.Acknowledged {
		t.Error("the second finding was left open")
	}
	// The second press only dismisses a finding, so it is recorded like any
	// acknowledgement and the Nightshift feed counts it.
	page, err := store.AuditHistory("", 10, "", storage.AuditFilter{Action: findingsAcknowledgedAudit})
	if err != nil || len(page.Entries) != 2 {
		t.Fatalf("acknowledgements recorded = %v %v, want one per press", page.Entries, err)
	}
	note := feedNote(t, srv, "ominull.detection.changes")
	if !strings.Contains(note.Message, "2 findings acknowledged") {
		t.Fatalf("feed note = %q", note.Message)
	}
}

// A finding whose agent saw a different file running than the one at the
// reported path names a program by a path it did not run, so it vouches for
// nothing.
func TestAPathMismatchCannotBeMarkedExpected(t *testing.T) {
	t.Parallel()
	srv, store := setupTestServer(t)
	seedFinding(t, store, "f-10", "/usr/bin/backup-agent", `{"destination_owner":"Acme Vendor","destination_asn":"AS64500","destination_tenancy":"vendor","attribution_status":"path_mismatch"}`)

	if code, body := markFinding(t, srv, "f-10"); code != http.StatusBadRequest {
		t.Fatalf("a path mismatch was vouched for: %d %v", code, body)
	}
	if found, _ := store.GetAnomalyAlert("f-10"); found.Acknowledged || len(markedRules(store)) != 0 {
		t.Fatal("a path mismatch was dismissed or written as a rule")
	}
}

// A finding whose program is known only by its name - an agent that could not
// read the executable path - has no installed program to vouch for, and a name
// is something any program can take.
func TestAProgramKnownOnlyByNameCannotBeMarkedExpected(t *testing.T) {
	t.Parallel()
	srv, store := setupTestServer(t)
	seedFinding(t, store, "f-9", "rclone", `{"destination_owner":"Google LLC","destination_asn":"AS15169","destination_tenancy":"vendor"}`)

	if code, body := markFinding(t, srv, "f-9"); code != http.StatusBadRequest {
		t.Fatalf("a bare program name was vouched for: %d %v", code, body)
	}
	if len(markedRules(store)) != 0 {
		t.Fatal("a rule was written for a program named only by its name")
	}
}

// Without an AS number in the evidence the rule names the network exactly as
// it was resolved, never a fragment of it.
func TestAnUnnumberedOwnerIsWrittenExactly(t *testing.T) {
	t.Parallel()
	srv, store := setupTestServer(t)
	seedFinding(t, store, "f-10", "/usr/bin/backup-agent", `{"destination_owner":"Acme Vendor","destination_tenancy":"vendor"}`)

	code, body := markFinding(t, srv, "f-10")
	rules := markedRules(store)
	if code != http.StatusOK || len(rules) != 1 || len(rules[0].Networks) != 1 || rules[0].Networks[0] != "acme vendor" {
		t.Fatalf("mark: %d %v %+v", code, body, rules)
	}
	c := storage.ExpectCtx{Kind: storage.KindBeacon, Host: "ep-1", Path: "/usr/bin/backup-agent", Org: "Acme Vendor Cloud (customer range)", Tenancy: storage.TenancyVendor}
	if expects(store.GetDetectionTuning(), c) {
		t.Fatal("an exact owner matched a longer name that contains it")
	}
}

// A program in a folder every account can write to is covered by the build the
// finding saw: /tmp/rclone by path alone is whatever was copied there last.
// Without a recorded hash there is nothing to vouch for.
func TestAProgramInASharedFolderIsMarkedExpectedByItsBuild(t *testing.T) {
	t.Parallel()
	srv, store := setupTestServer(t)
	sha := strings.Repeat("ab", 32)
	seedFinding(t, store, "f-11", "/tmp/rclone",
		`{"destination_asn":"AS15169","destination_tenancy":"vendor","executable_sha256":"`+strings.ToUpper(sha)+`"}`)
	code, body := markFinding(t, srv, "f-11")
	rules := markedRules(store)
	if code != http.StatusOK || len(rules) != 1 || rules[0].Programs[0].SHA256 != sha {
		t.Fatalf("mark: %d %v %+v", code, body, rules)
	}
	tuning := store.GetDetectionTuning()
	ctx := storage.ExpectCtx{Kind: storage.KindBeacon, Host: "ep-1", Path: "/tmp/rclone", SHA: sha, ASN: "AS15169", Org: "Google LLC", Tenancy: storage.TenancyVendor}
	if !expects(tuning, ctx) {
		t.Fatal("the build the finding saw is not expected")
	}
	ctx.SHA = strings.Repeat("cd", 32)
	if expects(tuning, ctx) {
		t.Fatal("another build at the same path is expected")
	}

	seedFinding(t, store, "f-12", "/tmp/rclone", `{"destination_asn":"AS15169","destination_tenancy":"vendor"}`)
	if code, body := markFinding(t, srv, "f-12"); code != http.StatusBadRequest {
		t.Fatalf("an unhashed program in /tmp was vouched for: %d %v", code, body)
	}
	if n := len(markedRules(store)); n != 1 {
		t.Fatalf("rules = %d, want only the pinned one", n)
	}
}

// The options: every host, and a lifetime.
func TestMarkingExpectedCanSpanHostsAndExpire(t *testing.T) {
	t.Parallel()
	srv, store := setupTestServer(t)
	seedFinding(t, store, "f-13", "/usr/bin/backup-agent", `{"destination_owner":"Acme Vendor","destination_asn":"AS64500","destination_tenancy":"vendor"}`)
	code, body := markWith(t, srv, `{"id":"f-13","all_hosts":true,"days":30,"reason":"nightly backup"}`, "mock_admin_token")
	rules := markedRules(store)
	if code != http.StatusOK || len(rules) != 1 {
		t.Fatalf("mark: %d %v", code, body)
	}
	r := rules[0]
	if len(r.Hosts) != 0 || r.Reason != "nightly backup" || r.ExpiresAt.Before(time.Now().Add(29*24*time.Hour)) || r.ExpiresAt.After(time.Now().Add(31*24*time.Hour)) {
		t.Fatalf("rule = %+v", r)
	}
}

// The rule API: list, save, replace, delete; an unsound rule is refused and
// nothing is saved; a non-administrator changes nothing.
func TestTheExpectedRuleAPIListsSavesAndDeletes(t *testing.T) {
	t.Parallel()
	srv, store := setupTestServer(t)
	call := func(method, path, body, key string) (int, map[string]interface{}) {
		t.Helper()
		var r *http.Request
		if body == "" {
			r = httptest.NewRequest(method, path, nil)
		} else {
			r = httptest.NewRequest(method, path, strings.NewReader(body))
			r.Header.Set("Content-Type", "application/json")
		}
		r.Header.Set("X-API-Key", key)
		w := serveAuthorized(t, srv.Handler(), r)
		out := map[string]interface{}{}
		_ = json.Unmarshal(w.Body.Bytes(), &out)
		return w.Code, out
	}
	code, out := call(http.MethodGet, "/api/v1/detection/expected", "", "mock_admin_token")
	rules, _ := out["rules"].([]interface{})
	if code != http.StatusOK || len(rules) != len(store.GetDetectionTuning().ExpectedRules) || len(rules) == 0 {
		t.Fatalf("list: %d %v", code, out)
	}
	if kinds, _ := out["findings"].([]interface{}); len(kinds) == 0 {
		t.Fatalf("the list does not say which findings a rule can name: %v", out)
	}

	rule := `{"id":"backup","name":"Offsite backup","reason":"restic through rclone","findings":["BANDWIDTH_SPIKE"],"hosts":["ws-1"],` +
		`"programs":[{"path":"/usr/local/bin/rclone"}],"prefixes":["172.217.0.0/16"],"port":443,"protocol":"tcp"}`
	before := len(store.GetDetectionTuning().ExpectedRules)
	if code, out := call(http.MethodPost, "/api/v1/detection/expected", rule, "mock_tenant_token"); code == http.StatusOK {
		t.Fatalf("a tenant key saved a rule: %v", out)
	}
	if code, out := call(http.MethodPost, "/api/v1/detection/expected", rule, "mock_admin_token"); code != http.StatusOK {
		t.Fatalf("save: %d %v", code, out)
	}
	if got, ok := store.GetDetectionTuning().RuleByID("backup"); !ok || got.Port != 443 || len(store.GetDetectionTuning().ExpectedRules) != before+1 {
		t.Fatalf("the rule was not saved: %+v", got)
	}
	// Saving the same id replaces it.
	if code, out := call(http.MethodPost, "/api/v1/detection/expected", strings.Replace(rule, `"port":443`, `"port":8443`, 1), "mock_admin_token"); code != http.StatusOK {
		t.Fatalf("replace: %d %v", code, out)
	}
	if got, _ := store.GetDetectionTuning().RuleByID("backup"); got.Port != 8443 || len(store.GetDetectionTuning().ExpectedRules) != before+1 {
		t.Fatalf("the rule was not replaced: %+v", got)
	}

	for name, bad := range map[string]string{
		"no reason":              `{"id":"x","programs":[{"path":"/usr/bin/curl"}]}`,
		"a program by name":      `{"id":"x","reason":"r","programs":[{"path":"curl"}]}`,
		"nothing to match":       `{"id":"x","reason":"r"}`,
		"a floor finding":        `{"id":"x","reason":"r","findings":["THREAT_INTEL_MATCH"],"programs":[{"path":"/usr/bin/curl"}]}`,
		"a domain without a net": `{"id":"x","reason":"r","domains":["googleapis.com"]}`,
	} {
		if code, out := call(http.MethodPost, "/api/v1/detection/expected", bad, "mock_admin_token"); code != http.StatusBadRequest {
			t.Errorf("%s was saved: %d %v", name, code, out)
		}
	}

	if code, _ := call(http.MethodDelete, "/api/v1/detection/expected?id=nothing", "", "mock_admin_token"); code != http.StatusNotFound {
		t.Fatalf("deleting a rule that is not there = %d", code)
	}
	if code, out := call(http.MethodDelete, "/api/v1/detection/expected?id=backup", "", "mock_admin_token"); code != http.StatusOK {
		t.Fatalf("delete: %d %v", code, out)
	}
	if _, ok := store.GetDetectionTuning().RuleByID("backup"); ok {
		t.Fatal("the rule is still there")
	}
}
