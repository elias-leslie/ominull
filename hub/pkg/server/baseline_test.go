package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"ominull/hub/pkg/storage"
)

// Isolation is the one control here with no way back if it is wrong. These tests
// are about the gate in front of it: what the hub refuses to do, and what it
// still allows so the refusal does not become an obstacle in an incident.

func seedBaselineEndpoint(t *testing.T, store *storage.Store, id string) {
	t.Helper()
	seedEndpoint(t, store, id, "Linux", "1.7.11")
}

// reportReady makes an endpoint look like a healthy agent that has just checked
// in, using the resolvers given.
func reportReady(t *testing.T, store *storage.Store, id string, resolvers ...string) {
	t.Helper()
	obs := []storage.ObservedService{}
	for _, rs := range resolvers {
		obs = append(obs, storage.ObservedService{Service: "dns", Destination: rs, Source: "resolv.conf"})
	}
	if err := store.SetEndpointObservations(id, obs, storage.Readiness{
		EnforcementEngine: "ok",
		HubLiteral:        "10.0.0.57",
		AddressOrigin:     "dhcp",
	}); err != nil {
		t.Fatalf("recording observations for %s: %v", id, err)
	}
}

func savePolicy(t *testing.T, store *storage.Store, name string, rules ...storage.BaselineRule) {
	t.Helper()
	p := &storage.BaselinePolicy{Name: name, Scope: "global", Enabled: true, Rules: rules}
	if err := store.SaveBaselinePolicy(p); err != nil {
		t.Fatalf("saving policy %s: %v", name, err)
	}
}

func postJSON(t *testing.T, srv *Server, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest("POST", path, strings.NewReader(body))
	req.Header.Set("X-API-Key", "mock_admin_token")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	return w
}

// TestIsolateIsRefusedWhenTheBaselineDoesNotCoverWhatTheHostUses is the whole
// point of the policy. The host resolves against 10.0.0.1; the baseline permits
// only 10.0.0.2. Isolating it would leave DNS pointed at an address the floor
// drops, and the symptom would appear minutes later as "the network is broken".
func TestIsolateIsRefusedWhenTheBaselineDoesNotCoverWhatTheHostUses(t *testing.T) {
	srv, store := setupTestServer(t)
	defer store.Close()

	seedBaselineEndpoint(t, store, "ep-1")
	reportReady(t, store, "ep-1", "10.0.0.1")
	savePolicy(t, store, "Corp", storage.BaselineRule{Service: "dns", Destination: "10.0.0.2"})

	w := postJSON(t, srv, "/api/v1/endpoints/isolate", `{"endpoint_id":"ep-1"}`)
	if w.Code != http.StatusConflict {
		t.Fatalf("isolate returned %d, want 409: %s", w.Code, w.Body.String())
	}

	var out map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("decoding the refusal: %v", err)
	}
	if !strings.Contains(fmt.Sprint(out["error"]), "10.0.0.1") {
		t.Errorf("the refusal does not name the uncovered destination: %v", out["error"])
	}
	uncovered, _ := out["uncovered"].([]interface{})
	if len(uncovered) != 1 {
		t.Errorf("uncovered lists %d entries, want 1: %v", len(uncovered), out["uncovered"])
	}

	// A refused order must not have been carried out.
	isolated, _, err := store.GetEndpointIsolation("ep-1")
	if err != nil {
		t.Fatalf("reading isolation state: %v", err)
	}
	if isolated {
		t.Errorf("the endpoint was isolated despite the refusal")
	}
}

// TestIsolateSucceedsOnceTheBaselineCoversTheHost guards the gate from being
// widened into one that refuses everything.
func TestIsolateSucceedsOnceTheBaselineCoversTheHost(t *testing.T) {
	srv, store := setupTestServer(t)
	defer store.Close()

	seedBaselineEndpoint(t, store, "ep-1")
	reportReady(t, store, "ep-1", "10.0.0.1")
	savePolicy(t, store, "Corp", storage.BaselineRule{Service: "dns", Destination: "10.0.0.1"})

	w := postJSON(t, srv, "/api/v1/endpoints/isolate", `{"endpoint_id":"ep-1"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("isolate returned %d, want 200: %s", w.Code, w.Body.String())
	}
	isolated, _, _ := store.GetEndpointIsolation("ep-1")
	if !isolated {
		t.Errorf("the endpoint was not isolated")
	}
}

// TestForceOverridesTheGateAndIsAudited. An operator containing a host that is
// actively compromised must not be held up by a policy gap or a stale probe. The
// override exists, and it is a different action in the log.
func TestForceOverridesTheGateAndIsAudited(t *testing.T) {
	srv, store := setupTestServer(t)
	defer store.Close()

	seedBaselineEndpoint(t, store, "ep-1")
	reportReady(t, store, "ep-1", "10.0.0.1")

	w := postJSON(t, srv, "/api/v1/endpoints/isolate", `{"endpoint_id":"ep-1","force":true}`)
	if w.Code != http.StatusOK {
		t.Fatalf("a forced isolate returned %d, want 200: %s", w.Code, w.Body.String())
	}
	isolated, _, _ := store.GetEndpointIsolation("ep-1")
	if !isolated {
		t.Fatalf("a forced isolate did not isolate the endpoint")
	}

	logs, err := store.ListAuditLogs("", 50)
	if err != nil {
		t.Fatalf("reading the audit log: %v", err)
	}
	var forced *storage.AuditEntry
	for i := range logs {
		if logs[i].Action == "ISOLATE_HOST_FORCED" {
			forced = &logs[i]
		}
	}
	if forced == nil {
		t.Fatalf("an override was not recorded as its own action; the log has %d entries", len(logs))
	}
	if !strings.Contains(forced.Details, "10.0.0.1") {
		t.Errorf("the override record does not say what was overridden: %q", forced.Details)
	}
}

// TestAnEndpointOnAnOlderAgentIsStillIsolated. An agent that has never reported
// readiness is an agent that also does not honour the baseline - both arrive in
// the same release - so it is still running the permissive built-in floor and
// isolating it is exactly as safe as it was before this policy existed.
// Refusing here would have taken the Isolate button away from the entire fleet
// for the length of a rollout. It is recorded as its own action so the state is
// visible rather than assumed.
func TestAnEndpointOnAnOlderAgentIsStillIsolated(t *testing.T) {
	srv, store := setupTestServer(t)
	defer store.Close()

	seedBaselineEndpoint(t, store, "ep-quiet")

	w := postJSON(t, srv, "/api/v1/endpoints/isolate", `{"endpoint_id":"ep-quiet"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("isolate returned %d, want 200: %s", w.Code, w.Body.String())
	}
	isolated, _, _ := store.GetEndpointIsolation("ep-quiet")
	if !isolated {
		t.Fatalf("the endpoint was not isolated")
	}

	logs, err := store.ListAuditLogs("", 50)
	if err != nil {
		t.Fatalf("reading the audit log: %v", err)
	}
	found := false
	for _, e := range logs {
		if e.Action == "ISOLATE_HOST_UNVERIFIED" {
			found = true
		}
	}
	if !found {
		t.Errorf("isolating an unverifiable endpoint was not recorded as its own action")
	}
}

// TestAStaleReadinessReportIsRefused. The report describes a host as it was; a
// sufficiently old one describes a host that may no longer exist in that state.
// Tested against the predicate directly rather than through the store, because
// the store stamps the report time itself - there is deliberately no way for a
// caller, or an endpoint, to claim its answer is fresher than it is.
func TestAStaleReadinessReportIsRefused(t *testing.T) {
	srv, store := setupTestServer(t)
	defer store.Close()

	fresh := storage.BaselineResolution{
		ReadinessReported: true,
		Readiness: storage.Readiness{
			EnforcementEngine: "ok",
			HubLiteral:        "10.0.0.57",
			ReportedAt:        time.Now().UTC(),
		},
	}
	if ok, why, _ := srv.isolationReadiness(fresh); !ok {
		t.Fatalf("a fresh, passing report was refused: %s", why)
	}

	stale := fresh
	stale.Readiness.ReportedAt = time.Now().UTC().Add(-2 * readinessStaleAfter)
	ok, why, _ := srv.isolationReadiness(stale)
	if ok {
		t.Fatalf("a report %s old was accepted", 2*readinessStaleAfter)
	}
	if !strings.Contains(why, "old") {
		t.Errorf("the refusal does not mention staleness: %q", why)
	}
}

// TestAnAgentThatCannotEnforceIsNotIsolated. An agent whose firewall engine will
// not open cannot apply the permits either - so the isolation it is being asked
// for would be a default-deny with nothing underneath it.
func TestAnAgentThatCannotEnforceIsNotIsolated(t *testing.T) {
	srv, store := setupTestServer(t)
	defer store.Close()

	seedBaselineEndpoint(t, store, "ep-1")
	if err := store.SetEndpointObservations("ep-1", nil, storage.Readiness{
		EnforcementEngine: "iptables is not installed",
		HubLiteral:        "10.0.0.57",
	}); err != nil {
		t.Fatalf("recording observations: %v", err)
	}

	w := postJSON(t, srv, "/api/v1/endpoints/isolate", `{"endpoint_id":"ep-1"}`)
	if w.Code != http.StatusConflict {
		t.Fatalf("isolate returned %d, want 409: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "iptables is not installed") {
		t.Errorf("the refusal does not carry the agent's own reason: %s", w.Body.String())
	}
}

// TestAHostWithNoHubLiteralIsNotIsolated. The pinhole is the only way back. An
// agent that cannot reduce its hub to an address cannot write it.
func TestAHostWithNoHubLiteralIsNotIsolated(t *testing.T) {
	srv, store := setupTestServer(t)
	defer store.Close()

	seedBaselineEndpoint(t, store, "ep-1")
	if err := store.SetEndpointObservations("ep-1", nil, storage.Readiness{EnforcementEngine: "ok"}); err != nil {
		t.Fatalf("recording observations: %v", err)
	}

	w := postJSON(t, srv, "/api/v1/endpoints/isolate", `{"endpoint_id":"ep-1"}`)
	if w.Code != http.StatusConflict {
		t.Fatalf("isolate returned %d, want 409: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "hub_literal") {
		t.Errorf("the refusal does not name the missing check: %s", w.Body.String())
	}
}

// TestOneUnreadyHostStopsTheWholeBulkIsolate. Isolating nine of ten and
// reporting nine is how an operator comes to believe a host is contained when it
// is not - and the tenth is the one the hub predicted it could not get back.
func TestOneUnreadyHostStopsTheWholeBulkIsolate(t *testing.T) {
	srv, store := setupTestServer(t)
	defer store.Close()

	seedBaselineEndpoint(t, store, "ep-ok")
	seedBaselineEndpoint(t, store, "ep-bad")
	reportReady(t, store, "ep-ok", "10.0.0.1")
	// ep-bad resolves against a server no policy permits.
	reportReady(t, store, "ep-bad", "10.0.0.9")
	savePolicy(t, store, "Corp", storage.BaselineRule{Service: "dns", Destination: "10.0.0.1"})

	w := postJSON(t, srv, "/api/v1/endpoints/isolate-bulk", `{"scope":"all"}`)
	if w.Code != http.StatusConflict {
		t.Fatalf("bulk isolate returned %d, want 409: %s", w.Code, w.Body.String())
	}
	for _, id := range []string{"ep-ok", "ep-bad"} {
		isolated, _, _ := store.GetEndpointIsolation(id)
		if isolated {
			t.Errorf("%s was isolated even though the batch was refused", id)
		}
	}
}

// TestUnisolateIsNeverGated. The gate stands in front of cutting a host off, not
// in front of putting it back. A refusal here would mean a policy mistake could
// strand a host that is already isolated.
func TestUnisolateIsNeverGated(t *testing.T) {
	srv, store := setupTestServer(t)
	defer store.Close()

	seedBaselineEndpoint(t, store, "ep-1")
	if err := store.SetEndpointIsolation("ep-1", true, nil); err != nil {
		t.Fatalf("pre-isolating: %v", err)
	}

	w := postJSON(t, srv, "/api/v1/endpoints/unisolate", `{"endpoint_id":"ep-1"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("unisolate returned %d, want 200: %s", w.Code, w.Body.String())
	}
	isolated, _, _ := store.GetEndpointIsolation("ep-1")
	if isolated {
		t.Errorf("the endpoint is still isolated after a release")
	}
}
