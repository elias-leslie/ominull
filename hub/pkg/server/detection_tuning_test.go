package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
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
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, r)
	out := map[string]interface{}{}
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	return w.Code, out
}

// A hub nobody has tuned still answers with the shipped numbers, so the console
// never has to guess them.
func TestAnUntunedHubReportsTheShippedThresholds(t *testing.T) {
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
	srv, _ := setupTestServer(t)
	_, body := tuningBody(t, srv, http.MethodPost,
		`{"beacon_min_samples":0,"beacon_score_threshold":9,"beacon_cooldown_minutes":-5,"warmup_hours":100000}`)
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
