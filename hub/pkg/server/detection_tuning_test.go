package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func tuningBody(t *testing.T, srv *Server, method, body string) (int, map[string]interface{}) {
	t.Helper()
	var r *http.Request
	if body == "" {
		r = httptest.NewRequest(method, "/api/v1/detection/tuning", nil)
	} else {
		r = httptest.NewRequest(method, "/api/v1/detection/tuning", strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
	}
	r.Header.Set("X-API-Key", "mock_admin_token")
	// A loosening save waits for the owner; the test owner approves it.
	w := serveAuthorized(t, srv.Handler(), r)
	out := map[string]interface{}{}
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	return w.Code, out
}

// A hub nobody has tuned still answers with the shipped numbers, so the console
// never has to guess them.
func TestAnUntunedHubReportsTheShippedThresholds(t *testing.T) {
	t.Parallel()
	srv, _ := setupTestServer(t)
	code, body := tuningBody(t, srv, http.MethodGet, "")
	if code != http.StatusOK {
		t.Fatalf("GET tuning: %d", code)
	}
	tun, _ := body["tuning"].(map[string]interface{})
	if tun == nil {
		t.Fatal("no tuning in the response")
	}
	if tun["beacon_min_samples"].(float64) < 6 {
		t.Errorf("beacon sample floor is %v; the loose rule is back", tun["beacon_min_samples"])
	}
	if _, ok := body["defaults"]; !ok {
		t.Error("the shipped defaults are not sent, so the console cannot show what changed")
	}
	if body["window"] == "" {
		t.Error("the off-hours window is not described")
	}
}

// The numbers are the operator's, and they survive a round trip.
func TestASavedThresholdComesBack(t *testing.T) {
	t.Parallel()
	srv, _ := setupTestServer(t)
	code, body := tuningBody(t, srv, http.MethodPost,
		`{"beacon_score_threshold":0.93,"off_hours_start":23,"off_hours_end":4,"off_hours_zone":"UTC","warmup_hours":48}`)
	if code != http.StatusOK {
		t.Fatalf("POST tuning: %d %v", code, body)
	}
	_, got := tuningBody(t, srv, http.MethodGet, "")
	tun := got["tuning"].(map[string]interface{})
	if tun["beacon_score_threshold"].(float64) != 0.93 {
		t.Errorf("threshold did not persist: %v", tun["beacon_score_threshold"])
	}
	if tun["warmup_hours"].(float64) != 48 {
		t.Errorf("learning period did not persist: %v", tun["warmup_hours"])
	}
	if got["window"] != "23:00-04:00 UTC" {
		t.Errorf("window reads %q", got["window"])
	}
}

// Anything a form can send, a form will eventually send. A zero sample count
// would make every pair of packets a beacon.
func TestNonsenseThresholdsAreClamped(t *testing.T) {
	t.Parallel()
	srv, _ := setupTestServer(t)
	code, body := tuningBody(t, srv, http.MethodPost,
		`{"beacon_min_samples":0,"beacon_score_threshold":9,"beacon_cooldown_minutes":-5,"warmup_hours":100000}`)
	if code != http.StatusOK {
		t.Fatalf("POST: %d %v", code, body)
	}
	tun := body["tuning"].(map[string]interface{})
	if tun["beacon_min_samples"].(float64) < 6 {
		t.Errorf("sample floor accepted as %v", tun["beacon_min_samples"])
	}
	if s := tun["beacon_score_threshold"].(float64); s <= 0 || s > 1 {
		t.Errorf("threshold accepted as %v", s)
	}
	if tun["warmup_hours"].(float64) > 720 {
		t.Errorf("learning period accepted as %v", tun["warmup_hours"])
	}
}

// Restoring the shipped numbers has to be one action, not a form to retype.
func TestTheShippedThresholdsCanBeRestored(t *testing.T) {
	t.Parallel()
	srv, _ := setupTestServer(t)
	tuningBody(t, srv, http.MethodPost, `{"beacon_score_threshold":0.20,"beacon_enabled":false}`)
	code, body := tuningBody(t, srv, http.MethodDelete, "")
	if code != http.StatusOK {
		t.Fatalf("DELETE tuning: %d", code)
	}
	tun := body["tuning"].(map[string]interface{})
	if tun["beacon_score_threshold"].(float64) != 0.80 {
		t.Errorf("reset left the threshold at %v", tun["beacon_score_threshold"])
	}
	if tun["beacon_enabled"] != true {
		t.Error("reset left the beacon detector switched off")
	}
}

// A save names only what it changes. Adding one rule through the API once
// decoded the rest of the body onto zero values and switched beacon,
// first-seen, bandwidth and silence detection off and emptied the lists.
func TestAPartialSaveKeepsEverythingItLeavesOut(t *testing.T) {
	t.Parallel()
	srv, _ := setupTestServer(t)
	until := time.Now().Add(30 * 24 * time.Hour).UTC().Format(time.RFC3339)
	if code, body := tuningBody(t, srv, http.MethodPost, `{"warmup_hours":48,"lab_cidrs":["10.20.0.0/24"],
		"expected_rules":[{"id":"gh","workload":"/usr/bin/gh","networks":["as36459"],"reason":"cli","expires_at":"`+until+`"},
		{"id":"ssh","workload":"/usr/bin/ssh","networks":["as36459"],"reason":"git","expires_at":"`+until+`"}]}`); code != http.StatusOK {
		t.Fatalf("first save: %d %v", code, body)
	}
	code, body := tuningBody(t, srv, http.MethodPost, `{"expected_rules":[{"id":"curl","workload":"/usr/bin/curl","networks":["as54113"],"reason":"x","expires_at":"`+until+`"}]}`)
	if code != http.StatusOK {
		t.Fatalf("partial save: %d %v", code, body)
	}
	tun := body["tuning"].(map[string]interface{})
	for _, k := range []string{"beacon_enabled", "first_seen_enabled", "bandwidth_enabled", "silence_enabled", "off_hours_enabled", "agent_egress_enabled"} {
		if tun[k] != true {
			t.Errorf("%s = %v after a save that did not name it", k, tun[k])
		}
	}
	if tun["warmup_hours"].(float64) != 48 || len(tun["agent_runtimes"].([]interface{})) == 0 || len(tun["lab_cidrs"].([]interface{})) != 1 {
		t.Errorf("unnamed values were reset: warmup %v, runtimes %v, lab %v", tun["warmup_hours"], tun["agent_runtimes"], tun["lab_cidrs"])
	}
	rules := tun["expected_rules"].([]interface{})
	if len(rules) != 1 || rules[0].(map[string]interface{})["id"] != "curl" || rules[0].(map[string]interface{})["tenancy"] == "any" {
		t.Errorf("a named list replaces the saved one exactly: %v", rules)
	}
	if code, _ := tuningBody(t, srv, http.MethodPost, `{"beacon_enabled":false}`); code != http.StatusOK {
		t.Fatal("explicit false")
	}
	_, got := tuningBody(t, srv, http.MethodGet, "")
	if g := got["tuning"].(map[string]interface{}); g["beacon_enabled"] != false || g["silence_enabled"] != true {
		t.Errorf("an explicit false is kept and nothing else moves: %v %v", g["beacon_enabled"], g["silence_enabled"])
	}
}

// Through the API, a list expected rules replaced is refused with a pointer to
// the rules, and an expected rule that would be read more widely than it is
// written is refused with the reason; nothing is saved.
func TestASaveNamingARetiredListOrAnUnsoundRuleIsRefused(t *testing.T) {
	t.Parallel()
	srv, store := setupTestServer(t)
	before := len(store.GetDetectionTuning().ExpectedRules)
	for _, body := range []string{
		`{"quiet_processes":["/usr/bin/svchost.exe"]}`,
		`{"quiet_clients":["/opt/google/chrome/chrome"]}`,
		`{"quiet_orgs":["amazon"]}`,
		`{"quiet_pairs":["/usr/bin/rclone@google"]}`,
		`{"known_workloads":[]}`,
		`{"agent_runtime_vendors":[]}`,
		`{"admin_fanout_sources":["ws"]}`,
		`{"expected_rules":[{"id":"a","reason":"r","programs":[{"path":"chrome"}]}]}`,
		`{"expected_rules":[{"id":"b","reason":"r","domains":["googleapis.com"]}]}`,
		`{"expected_rules":[{"id":"c","programs":[{"path":"/usr/bin/curl"}]}]}`,
	} {
		code, out := tuningBody(t, srv, http.MethodPost, body)
		if code != http.StatusBadRequest {
			t.Errorf("%s: %d %v", body, code, out)
		}
	}
	if got := len(store.GetDetectionTuning().ExpectedRules); got != before {
		t.Fatalf("a refused save changed the rules: %d, was %d", got, before)
	}
}
