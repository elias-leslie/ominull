package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"ominull/hub/pkg/storage"
)

func agentSessionRequest(t *testing.T, srv *Server, method, key, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, "/api/v1/traffic/agent-sessions", strings.NewReader(body))
	req.Header.Set("X-API-Key", key)
	w := httptest.NewRecorder()
	srv.authMiddleware(srv.handleAgentSessions).ServeHTTP(w, req)
	return w
}

func TestAgentSessionNamesAreSavedAndListed(t *testing.T) {
	t.Parallel()
	srv, _ := setupTestServer(t)
	w := agentSessionRequest(t, srv, http.MethodPost, srv.adminKey, `{"sessions":[{"window":"ab12cd34","name":"Lane 3g","tool":"claude","project":"ominull"},{"window":"NOT HEX","name":"x"},{"window":"ef56","name":""}]}`)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"saved":1`) {
		t.Fatalf("post: %d %s", w.Code, w.Body.String())
	}
	w = agentSessionRequest(t, srv, http.MethodGet, srv.adminKey, "")
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "Lane 3g") || strings.Contains(w.Body.String(), "NOT HEX") {
		t.Fatalf("get: %d %s", w.Code, w.Body.String())
	}
}

// Blocks go only to a lab machine the policy names, only while it enforces.
func TestAgentSessionBlocksReachOnlyLabMachines(t *testing.T) {
	t.Parallel()
	srv, store := setupTestServer(t)
	for _, ep := range []storage.Endpoint{
		{ID: "lab-1", TenantID: "default", Hostname: "lab", IP: "10.20.0.9", Status: "online"},
		{ID: "work-1", TenantID: "default", Hostname: "work", IP: "10.0.0.9", Status: "online"},
	} {
		if err := store.UpsertEndpoint(ep); err != nil {
			t.Fatal(err)
		}
	}
	code, body := tuningBody(t, srv, http.MethodPost, `{"lab_cidrs":["10.20.0.0/24"]}`)
	if code != http.StatusOK {
		t.Fatalf("lab range: %d %v", code, body)
	}
	policy := func(endpoint string) string {
		return `{"agent_egress_policy":{"mode":"enforce","block_endpoints":["` + endpoint + `"],"rules":[{"id":"b","action":"block","cidrs":["203.0.113.0/24"]}]}}`
	}
	if code, body := tuningBody(t, srv, http.MethodPost, policy("work-1")); code != http.StatusBadRequest || !strings.Contains(body["error"].(string), "lab") {
		t.Fatalf("a non-lab machine must be refused: %d %v", code, body)
	}
	if code, body := tuningBody(t, srv, http.MethodPost, policy("nobody")); code != http.StatusBadRequest {
		t.Fatalf("an unknown machine must be refused: %d %v", code, body)
	}
	if code, body := tuningBody(t, srv, http.MethodPost, policy("lab-1")); code != http.StatusOK {
		t.Fatalf("lab machine: %d %v", code, body)
	}
	if got := srv.agentSessionBlocks("lab-1"); len(got) != 1 || got[0] != "*|*|203.0.113.0/24|0" {
		t.Fatalf("lab blocks: %v", got)
	}
	if got := srv.agentSessionBlocks("work-1"); got != nil {
		t.Fatalf("another machine holds nothing: %v", got)
	}
	if code, body := tuningBody(t, srv, http.MethodPost, `{"agent_egress_policy":{"mode":"observe","block_endpoints":["lab-1"],"rules":[{"id":"b","action":"block","cidrs":["203.0.113.0/24"]}]}}`); code != http.StatusOK {
		t.Fatalf("observe: %d %v", code, body)
	}
	if got := srv.agentSessionBlocks("lab-1"); got != nil {
		t.Fatalf("observing holds nothing: %v", got)
	}
}

// The lab check holds beyond the save: a machine that leaves the lab stops
// receiving blocks, without stopping unrelated edits.
func TestAgentSessionBlocksFollowTheMachineOutOfTheLab(t *testing.T) {
	t.Parallel()
	srv, store := setupTestServer(t)
	lab := storage.Endpoint{ID: "lab-1", TenantID: "default", Hostname: "lab", IP: "10.20.0.9", Status: "online", RoleTag: "lab"}
	if err := store.UpsertEndpoint(lab); err != nil {
		t.Fatal(err)
	}
	if code, body := tuningBody(t, srv, http.MethodPost, `{"agent_egress_policy":{"mode":"enforce","block_endpoints":["lab-1"],"rules":[{"id":"b","action":"block","cidrs":["203.0.113.0/24"]}]}}`); code != http.StatusOK {
		t.Fatalf("save: %d %v", code, body)
	}
	if got := srv.agentSessionBlocks("lab-1"); len(got) != 1 {
		t.Fatalf("lab blocks: %v", got)
	}
	lab.RoleTag = "agent"
	if err := store.UpsertEndpoint(lab); err != nil {
		t.Fatal(err)
	}
	if got := srv.agentSessionBlocks("lab-1"); got != nil {
		t.Fatalf("a machine that left the lab must hold nothing: %v", got)
	}
	if code, body := tuningBody(t, srv, http.MethodPost, `{"beacon_cooldown_minutes":31}`); code != http.StatusOK {
		t.Fatalf("an unrelated save must still work: %d %v", code, body)
	}
	if code, body := tuningBody(t, srv, http.MethodPost, `{"agent_egress_policy":{"mode":"observe"}}`); code != http.StatusBadRequest {
		// Changing the mode asks again, and it still names a machine that left.
		t.Fatalf("a change of mode with a non-lab machine named: %d %v", code, body)
	}
}

// The ways round the lab check.
func TestEgressBlockGuardCannotBeTalkedRound(t *testing.T) {
	t.Parallel()
	srv, store := setupTestServer(t)
	for _, ep := range []storage.Endpoint{
		{ID: "tagged", TenantID: "default", Hostname: "tagged", IP: "10.20.0.8", Status: "online", RoleTag: "agent"},
		{ID: "work-1", TenantID: "default", Hostname: "work", IP: "10.0.0.9", Status: "online"},
		{ID: "lab-2", TenantID: "default", Hostname: "lab-host", IP: "10.20.0.7", Status: "online", RoleTag: "lab"},
	} {
		if err := store.UpsertEndpoint(ep); err != nil {
			t.Fatal(err)
		}
	}
	if code, body := tuningBody(t, srv, http.MethodPost, `{"lab_cidrs":["10.20.0.0/24"]}`); code != http.StatusOK {
		t.Fatalf("lab range: %d %v", code, body)
	}
	policy := func(id, extra string) string {
		return `{` + extra + `"agent_egress_policy":{"mode":"enforce","block_endpoints":["` + id + `"],"rules":[{"id":"b","action":"block","cidrs":["203.0.113.0/24"]}]}}`
	}
	if code, body := tuningBody(t, srv, http.MethodPost, policy("tagged", "")); code != http.StatusBadRequest {
		t.Fatalf("an explicit role beats a lab address: %d %v", code, body)
	}
	if code, body := tuningBody(t, srv, http.MethodPost, policy("work-1", `"lab_cidrs":["10.0.0.0/24"],`)); code != http.StatusBadRequest {
		t.Fatalf("one save can't name a machine and call it lab: %d %v", code, body)
	}
	if code, body := tuningBody(t, srv, http.MethodPost, policy("lab-host", "")); code != http.StatusBadRequest {
		t.Fatalf("a hostname is not an id, and would hold nothing: %d %v", code, body)
	}
}

// Naming one thing in the policy leaves the rest of it alone.
func TestEgressPolicyPatchKeepsWhatItDoesNotName(t *testing.T) {
	t.Parallel()
	srv, store := setupTestServer(t)
	if err := store.UpsertEndpoint(storage.Endpoint{ID: "lab-1", TenantID: "default", Hostname: "lab", IP: "10.20.0.9", Status: "online", RoleTag: "lab"}); err != nil {
		t.Fatal(err)
	}
	if code, body := tuningBody(t, srv, http.MethodPost, `{"agent_egress_policy":{"block_endpoints":["lab-1"],"rules":[{"id":"a","action":"flag"},{"id":"c","action":"allow"}]}}`); code != http.StatusOK {
		t.Fatalf("save: %d %v", code, body)
	}
	if code, body := tuningBody(t, srv, http.MethodPost, `{"agent_egress_policy":{"mode":"enforce"}}`); code != http.StatusOK {
		t.Fatalf("mode: %d %v", code, body)
	}
	p := store.GetDetectionTuning().AgentEgressPolicy
	if p.Mode != storage.EgressEnforce || len(p.Rules) != 2 || len(p.BlockEndpoints) != 1 {
		t.Fatalf("policy after a mode change: %+v", p)
	}
	if code, body := tuningBody(t, srv, http.MethodPost, `{"agent_egress_policy":{"rules":[{"id":"c","action":"allow"}]}}`); code != http.StatusOK {
		t.Fatalf("rules: %d %v", code, body)
	}
	if p := store.GetDetectionTuning().AgentEgressPolicy; len(p.Rules) != 1 || p.Rules[0].ID != "c" {
		t.Fatalf("a named list replaces the old one: %+v", p)
	}
}
