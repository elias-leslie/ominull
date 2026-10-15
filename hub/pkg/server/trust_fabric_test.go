package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"ominull/hub/pkg/storage"
	"ominull/hub/pkg/trustfabric"
)

func trustRequest(t *testing.T, srv *Server, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("X-API-Key", "mock_admin_token")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	return w
}

func auditActions(t *testing.T, store *storage.Store, action string) []storage.AuditEntry {
	t.Helper()
	all, err := store.ListAuditLogs("", 500)
	if err != nil {
		t.Fatal(err)
	}
	var out []storage.AuditEntry
	for _, a := range all {
		if a.Action == action {
			out = append(out, a)
		}
	}
	return out
}

func TestTrustFabricIsolationModes(t *testing.T) {
	t.Parallel()
	srv, store := setupTestServer(t)
	defer store.Close()
	seedEndpointRow(t, store, storage.Endpoint{ID: "pos-04", LocationID: "store-12", RoleTag: "pos", ResponseCapabilities: `{"isolate":true}`})
	reportReady(t, store, "pos-04")

	for _, body := range []string{
		`{"scope_type":"site","scope_id":"store-12","kind":"ip","value":"198.51.100.25","action":"allow","justification":"payments"}`,
		`{"scope_type":"group","scope_id":"pos","kind":"cidr","value":"203.0.113.0/28","action":"allow"}`,
		`{"scope_type":"provider","kind":"ip","value":"198.51.100.99","action":"allow"}`,
		`{"scope_type":"site","scope_id":"store-12","kind":"ip","value":"198.51.100.99","action":"deny"}`,
	} {
		if w := trustRequest(t, srv, http.MethodPost, "/api/v1/trust/rules", body); w.Code != http.StatusCreated {
			t.Fatalf("create %s: %d %s", body, w.Code, w.Body.String())
		}
	}
	if w := trustRequest(t, srv, http.MethodPost, "/api/v1/trust/rules", `{"scope_type":"provider","kind":"cidr","value":"0.0.0.0/0","action":"allow"}`); w.Code != http.StatusBadRequest {
		t.Fatalf("whole-family allow: %d", w.Code)
	}

	w := trustRequest(t, srv, http.MethodGet, "/api/v1/trust/effective?endpoint_id=pos-04&addr=198.51.100.99", "")
	var eff struct {
		Policy   fabricPolicy         `json:"policy"`
		Decision trustfabric.Decision `json:"decision"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &eff); err != nil || w.Code != http.StatusOK {
		t.Fatalf("effective: %d %s", w.Code, w.Body.String())
	}
	if strings.Join(eff.Policy.Enforced, ",") != "198.51.100.25" || strings.Join(eff.Policy.NotEnforced, ",") != "203.0.113.0/28" {
		t.Fatalf("policy %+v", eff.Policy)
	}
	if eff.Decision.Action != trustfabric.Deny || eff.Decision.Scope != trustfabric.ScopeSite {
		t.Fatalf("decision %+v", eff.Decision)
	}

	// Full isolation takes no exceptions.
	if w := postJSON(t, srv, "/api/v1/endpoints/isolate", `{"endpoint_id":"pos-04","mode":"full","allow_ips":["10.0.0.9"]}`); w.Code != http.StatusBadRequest {
		t.Fatalf("full with allow_ips: %d %s", w.Code, w.Body.String())
	}
	if w := postJSON(t, srv, "/api/v1/endpoints/isolate", `{"endpoint_id":"pos-04","mode":"partial"}`); w.Code != http.StatusBadRequest {
		t.Fatalf("unknown mode: %d", w.Code)
	}

	// Selective isolation carries the fabric's enforceable addresses plus the
	// request's own.
	if w := postJSON(t, srv, "/api/v1/endpoints/isolate", `{"endpoint_id":"pos-04","mode":"selective","allow_ips":["10.0.0.9"]}`); w.Code != http.StatusOK {
		t.Fatalf("selective: %d %s", w.Code, w.Body.String())
	}
	iso, allow, err := store.GetEndpointIsolation("pos-04")
	if err != nil || !iso || strings.Join(allow, ",") != "10.0.0.9,198.51.100.25" {
		t.Fatalf("isolation %v %v %v", iso, allow, err)
	}
	recs, _ := store.IsolatedEndpoints()
	if len(recs) != 1 || recs[0].ID == "" || recs[0].Mode != isolationModeSelective {
		t.Fatalf("isolation record %+v", recs)
	}
	isolationID := recs[0].ID
	snaps := auditActions(t, store, "ISOLATION_FABRIC_SNAPSHOT")
	if len(snaps) != 1 || !strings.Contains(snaps[0].Details, isolationID) || !strings.Contains(snaps[0].Details, "203.0.113.0/28") {
		t.Fatalf("snapshot %+v", snaps)
	}

	// An endpoint allow rule written during the isolation expires in four
	// hours, is recorded against the isolation and does not widen it.
	w = trustRequest(t, srv, http.MethodPost, "/api/v1/trust/rules", `{"scope_type":"endpoint","scope_id":"pos-04","kind":"ip","value":"192.0.2.7","action":"allow"}`)
	var created trustfabric.Rule
	if err := json.Unmarshal(w.Body.Bytes(), &created); err != nil || w.Code != http.StatusCreated {
		t.Fatalf("mid-isolation rule: %d %s", w.Code, w.Body.String())
	}
	if created.ExpiresAt == nil || created.ExpiresAt.Sub(time.Now()) > isolatedRuleTTL || created.ExpiresAt.Sub(time.Now()) < isolatedRuleTTL-time.Minute {
		t.Fatalf("expires_at %v", created.ExpiresAt)
	}
	during := auditActions(t, store, "TRUST_RULE_DURING_ISOLATION")
	if len(during) != 1 || during[0].Resource != "pos-04" || !strings.Contains(during[0].Details, isolationID) {
		t.Fatalf("during %+v", during)
	}
	if _, allow, _ := store.GetEndpointIsolation("pos-04"); strings.Contains(strings.Join(allow, ","), "192.0.2.7") {
		t.Fatal("a rule change widened an isolation in force")
	}
	if w := trustRequest(t, srv, http.MethodDelete, "/api/v1/trust/rules?id="+created.ID, ""); w.Code != http.StatusOK {
		t.Fatalf("delete: %d", w.Code)
	}
	if n := len(auditActions(t, store, "TRUST_RULE_DURING_ISOLATION")); n != 2 {
		t.Fatalf("delete during isolation recorded %d times in all", n)
	}

	// Release clears the isolation id; the next isolation (mode omitted, no
	// list) is full and gets a new id.
	if w := postJSON(t, srv, "/api/v1/endpoints/unisolate", `{"endpoint_id":"pos-04"}`); w.Code != http.StatusOK {
		t.Fatalf("unisolate: %d %s", w.Code, w.Body.String())
	}
	if recs, _ := store.IsolatedEndpoints(); len(recs) != 0 {
		t.Fatalf("still isolated %+v", recs)
	}
	if w := postJSON(t, srv, "/api/v1/endpoints/isolate", `{"endpoint_id":"pos-04"}`); w.Code != http.StatusOK {
		t.Fatalf("isolate: %d %s", w.Code, w.Body.String())
	}
	recs, _ = store.IsolatedEndpoints()
	if len(recs) != 1 || recs[0].ID == isolationID || recs[0].Mode != isolationModeFull || len(recs[0].AllowIPs) != 0 {
		t.Fatalf("second isolation %+v", recs)
	}
}

func TestTrustRulesNeedAdmin(t *testing.T) {
	t.Parallel()
	srv, store := setupTestServer(t)
	defer store.Close()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/trust/rules", nil)
	req.Header.Set("X-API-Key", "mock_tenant_token")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	if w.Code == http.StatusOK {
		t.Fatalf("tenant credential read trust rules: %d", w.Code)
	}
}

// A rule changed while the owner is deciding does not void the approval: the
// expansion approved is the one enforced.
func TestSelectiveIsolationPinnedToApproval(t *testing.T) {
	t.Parallel()
	srv, store := setupTestServer(t)
	defer store.Close()
	seedEndpointRow(t, store, storage.Endpoint{ID: "pos-05", ResponseCapabilities: `{"isolate":true}`})
	reportReady(t, store, "pos-05")
	if _, err := store.CreateTrustRule(trustfabric.Rule{ScopeType: "endpoint", ScopeID: "pos-05", Kind: "ip", Value: "198.51.100.25", Action: "allow"}); err != nil {
		t.Fatal(err)
	}
	h := srv.Handler()
	body := `{"endpoint_id":"pos-05","mode":"selective"}`
	ask := func(approvalID string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/endpoints/isolate", strings.NewReader(body))
		req.Header.Set("X-API-Key", "mock_admin_token")
		if approvalID != "" {
			req.Header.Set(approvalHeader, approvalID)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		return w
	}
	pendingID := func(w *httptest.ResponseRecorder) string {
		var p struct {
			ApprovalID string `json:"approval_id"`
		}
		if w.Code != http.StatusAccepted || json.Unmarshal(w.Body.Bytes(), &p) != nil || p.ApprovalID == "" {
			t.Fatalf("want 202 with an approval id: %d %s", w.Code, w.Body.String())
		}
		return p.ApprovalID
	}

	id := pendingID(ask(""))
	if _, err := store.CreateTrustRule(trustfabric.Rule{ScopeType: "provider", Kind: "ip", Value: "192.0.2.7", Action: "allow"}); err != nil {
		t.Fatal(err)
	}
	ownerOf(t, srv).approve(t, id)
	if w := ask(id); w.Code != http.StatusOK {
		t.Fatalf("approved isolation refused after a rule change: %d %s", w.Code, w.Body.String())
	}
	if _, allow, _ := store.GetEndpointIsolation("pos-05"); strings.Join(allow, ",") != "198.51.100.25" {
		t.Fatalf("enforced %v, want what was approved", allow)
	}

	// Without the pin (a hub restart) a changed fabric fails closed.
	if w := postJSON(t, srv, "/api/v1/endpoints/unisolate", `{"endpoint_id":"pos-05"}`); w.Code != http.StatusOK {
		t.Fatalf("unisolate: %d", w.Code)
	}
	id = pendingID(ask(""))
	srv.fabricPins.mu.Lock()
	srv.fabricPins.pins = nil
	srv.fabricPins.mu.Unlock()
	if _, err := store.CreateTrustRule(trustfabric.Rule{ScopeType: "provider", Kind: "ip", Value: "192.0.2.8", Action: "allow"}); err != nil {
		t.Fatal(err)
	}
	ownerOf(t, srv).approve(t, id)
	if w := ask(id); w.Code != http.StatusForbidden {
		t.Fatalf("unpinned changed expansion: %d %s", w.Code, w.Body.String())
	}
	if iso, _, _ := store.GetEndpointIsolation("pos-05"); iso {
		t.Fatal("isolated with a list nobody approved")
	}
}
