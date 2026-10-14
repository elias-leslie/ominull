package server

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"ominull/hub/pkg/responseauth"
	"ominull/hub/pkg/storage"
)

func adminPost(srv *Server, path, body string, approval string) *httptest.ResponseRecorder {
	req := httptest.NewRequest("POST", path, strings.NewReader(body))
	req.Header.Set("X-API-Key", "mock_admin_token")
	if approval != "" {
		req.Header.Set(approvalHeader, approval)
	}
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	return w
}

func pendingID(t *testing.T, w *httptest.ResponseRecorder) string {
	t.Helper()
	if w.Code != http.StatusAccepted {
		t.Fatalf("want 202 approval requested, got %d: %s", w.Code, w.Body.String())
	}
	var p struct {
		ApprovalID string `json:"approval_id"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &p)
	return p.ApprovalID
}

func isolated(t *testing.T, store *storage.Store, id string) bool {
	t.Helper()
	ep, err := store.GetEndpoint(id)
	if err != nil || ep == nil {
		t.Fatalf("endpoint %s: %v", id, err)
	}
	return ep.IsIsolated
}

func seedPlain(t *testing.T, store *storage.Store, ids ...string) {
	t.Helper()
	for _, id := range ids {
		if err := store.UpsertEndpoint(storage.Endpoint{ID: id, TenantID: "default", Hostname: "host-" + id, OS: "test", Status: "online"}); err != nil {
			t.Fatal(err)
		}
	}
}

// The admin key alone cannot isolate: it gets an approval request, a forged
// or mismatched approval is refused, and a real one works once.
func TestIsolateNeedsTheOwnersApproval(t *testing.T) {
	t.Parallel()
	srv, store := setupTestServer(t)
	defer store.Close()
	seedPlain(t, store, "ep-a", "ep-b")
	owner := ownerOf(t, srv)

	body := `{"endpoint_id":"ep-a","force":true}`
	id := pendingID(t, adminPost(srv, "/api/v1/endpoints/isolate", body, ""))
	if isolated(t, store, "ep-a") {
		t.Fatal("isolated before the owner approved")
	}
	if w := adminPost(srv, "/api/v1/endpoints/isolate", body, id); w.Code != http.StatusForbidden {
		t.Fatalf("pending approval used: %d %s", w.Code, w.Body.String())
	}
	if w := adminPost(srv, "/api/v1/endpoints/isolate", body, "ffffffffffffffffffffffffffffffff"); w.Code != http.StatusForbidden {
		t.Fatalf("forged approval id: %d", w.Code)
	}
	owner.approve(t, id)
	// The approval covers ep-a only.
	if w := adminPost(srv, "/api/v1/endpoints/isolate", `{"endpoint_id":"ep-b","force":true}`, id); w.Code != http.StatusForbidden {
		t.Fatalf("approval for ep-a isolated ep-b: %d", w.Code)
	}
	if isolated(t, store, "ep-b") {
		t.Fatal("ep-b isolated under ep-a's approval")
	}
	// A mismatch must not burn it? It does: the authority refused without consuming.
	if w := adminPost(srv, "/api/v1/endpoints/isolate", body, id); w.Code != http.StatusOK {
		t.Fatalf("approved isolate: %d %s", w.Code, w.Body.String())
	}
	if !isolated(t, store, "ep-a") {
		t.Fatal("not isolated after an approved request")
	}
	if w := adminPost(srv, "/api/v1/endpoints/isolate", body, id); w.Code != http.StatusForbidden {
		t.Fatalf("approval reused: %d", w.Code)
	}
	// Release is gated the same way.
	rel := `{"endpoint_id":"ep-a"}`
	rid := pendingID(t, adminPost(srv, "/api/v1/endpoints/unisolate", rel, ""))
	if !isolated(t, store, "ep-a") {
		t.Fatal("released without approval")
	}
	owner.approve(t, rid)
	if w := adminPost(srv, "/api/v1/endpoints/unisolate", rel, rid); w.Code != http.StatusOK || isolated(t, store, "ep-a") {
		t.Fatalf("approved release: %d", w.Code)
	}
	logs, _ := store.ListAuditLogs("", 500)
	seen := map[string]bool{}
	for _, l := range logs {
		seen[l.Action] = true
	}
	for _, a := range []string{"OWNER_APPROVAL_REQUESTED", "OWNER_APPROVAL_REFUSED", "OWNER_APPROVAL_USED", "ISOLATE_HOST", "UNISOLATE_HOST"} {
		if !seen[a] {
			t.Errorf("audit lacks %s", a)
		}
	}
}

// A bulk approval binds the target set it showed the owner: if the scope
// resolves to different hosts by the time it is used, it is refused.
func TestBulkApprovalBindsItsTargets(t *testing.T) {
	t.Parallel()
	srv, store := setupTestServer(t)
	defer store.Close()
	seedPlain(t, store, "ep-1", "ep-2")
	body := `{"scope":"all","force":true}`
	id := pendingID(t, adminPost(srv, "/api/v1/endpoints/isolate-bulk", body, ""))
	ownerOf(t, srv).approve(t, id)
	seedPlain(t, store, "ep-3")
	if w := adminPost(srv, "/api/v1/endpoints/isolate-bulk", body, id); w.Code != http.StatusForbidden {
		t.Fatalf("drifted target set accepted: %d %s", w.Code, w.Body.String())
	}
	for _, ep := range []string{"ep-1", "ep-2", "ep-3"} {
		if isolated(t, store, ep) {
			t.Fatalf("%s isolated by a refused bulk request", ep)
		}
	}
}

func TestAgentUpdateNeedsTheOwnersApproval(t *testing.T) {
	t.Parallel()
	srv, store := setupTestServer(t)
	defer store.Close()
	seedPlain(t, store, "ep-1")
	pendingID(t, adminPost(srv, "/api/v1/agents/update", `{"all":true,"version":"1.1.0"}`, ""))
	if v, _ := store.GetSetting("desired_agent_version"); v == "1.1.0" {
		t.Fatal("desired version set without approval")
	}
}

func TestOwnerApprovalUnavailableWithoutPinnedApprover(t *testing.T) {
	t.Parallel()
	srv, store := setupTestServer(t)
	defer store.Close()
	seedPlain(t, store, "ep-1")
	ownerOf(t, srv).auth.SetApproversPath(filepath.Join(t.TempDir(), "none.json"))
	w := adminPost(srv, "/api/v1/endpoints/isolate", `{"endpoint_id":"ep-1","force":true}`, "")
	if w.Code != http.StatusServiceUnavailable || isolated(t, store, "ep-1") {
		t.Fatalf("no approver pinned: %d %s", w.Code, w.Body.String())
	}
}

// The relay carries the authority's signed statement out and the owner's
// assertion back. Its key cannot read anything else, and the admin key
// cannot use the relay.
func TestApprovalRelay(t *testing.T) {
	t.Parallel()
	srv, store := setupTestServer(t)
	defer store.Close()
	seedPlain(t, store, "ep-1")
	owner := ownerOf(t, srv)

	issue := adminPost(srv, "/api/v1/integrations/nightshift/approval-key", ``, "")
	var k struct {
		Key string `json:"key"`
	}
	_ = json.Unmarshal(issue.Body.Bytes(), &k)
	if issue.Code != 200 || !strings.HasPrefix(k.Key, "nsa_") {
		t.Fatalf("issue relay key: %d %s", issue.Code, issue.Body.String())
	}
	relay := func(method, path, body, key string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		if key != "" {
			req.Header.Set("X-API-Key", key)
		}
		w := httptest.NewRecorder()
		srv.Handler().ServeHTTP(w, req)
		return w
	}
	if w := relay("GET", "/api/v1/integrations/nightshift/approvals", "", "mock_admin_token"); w.Code != http.StatusUnauthorized {
		t.Fatalf("admin key on the relay: %d", w.Code)
	}
	if w := relay("GET", "/api/v1/endpoints", "", k.Key); w.Code != http.StatusUnauthorized {
		t.Fatalf("relay key read the fleet: %d", w.Code)
	}

	// Long-poll wakes when an approval is requested.
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() { done <- relay("GET", "/api/v1/integrations/nightshift/approvals?wait=10", "", k.Key) }()
	time.Sleep(100 * time.Millisecond)
	start := time.Now()
	id := pendingID(t, adminPost(srv, "/api/v1/endpoints/isolate", `{"endpoint_id":"ep-1","force":true}`, ""))
	w := <-done
	if time.Since(start) > 3*time.Second {
		t.Fatalf("long-poll did not wake promptly: %v", time.Since(start))
	}
	var list struct {
		Approvals []responseauth.ApprovalView `json:"approvals"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &list)
	if len(list.Approvals) != 1 || list.Approvals[0].ID != id || list.Approvals[0].Signature == "" {
		t.Fatalf("relay list: %s", w.Body.String())
	}
	stmt, _ := base64.StdEncoding.DecodeString(list.Approvals[0].Statement)
	if !strings.Contains(string(stmt), `"action":"Isolate host"`) {
		t.Fatalf("statement: %s", stmt)
	}
	// Known ids do not wake the poll.
	if w := relay("GET", "/api/v1/integrations/nightshift/approvals?wait=1&known="+id, "", k.Key); w.Code != 200 {
		t.Fatalf("known poll: %d", w.Code)
	}

	// A garbage assertion is rejected and leaves it pending.
	bad, _ := json.Marshal(responseauth.ApprovalAnswer{ID: id, Decision: "approve", Assertion: &responseauth.ApprovalAssertion{CredentialID: owner.approver.CredentialID, AuthenticatorData: "AA", ClientDataJSON: "AA", Signature: "AA"}})
	if w := relay("POST", "/api/v1/integrations/nightshift/approvals/answer", string(bad), k.Key); w.Code == 200 {
		t.Fatal("garbage assertion approved")
	}
	good, _ := json.Marshal(responseauth.ApprovalAnswer{ID: id, Decision: "approve", Assertion: owner.approver.Assert(list.Approvals[0].Challenge, "approve")})
	if w := relay("POST", "/api/v1/integrations/nightshift/approvals/answer", string(good), k.Key); w.Code != 200 {
		t.Fatalf("good assertion: %d %s", w.Code, w.Body.String())
	}
	// The requester sees it approved.
	st := httptest.NewRequest("GET", "/api/v1/approvals?id="+id, nil)
	st.Header.Set("X-API-Key", "mock_admin_token")
	sw := httptest.NewRecorder()
	srv.Handler().ServeHTTP(sw, st)
	if !strings.Contains(sw.Body.String(), `"state":"approved"`) {
		t.Fatalf("status: %s", sw.Body.String())
	}
	if w := adminPost(srv, "/api/v1/endpoints/isolate", `{"endpoint_id":"ep-1","force":true}`, id); w.Code != 200 || !isolated(t, store, "ep-1") {
		t.Fatalf("approved via relay: %d", w.Code)
	}
}

func TestBulkIsolationNeedsAnExplicitScope(t *testing.T) {
	t.Parallel()
	srv, store := setupTestServer(t)
	defer store.Close()
	seedPlain(t, store, "ep-1", "ep-2")
	for _, body := range []string{`{"endpoint_ids":["ep-1"],"force":true}`, `{"scope":"ids","ids":[],"force":true}`, `{"scope":"everything","force":true}`} {
		for _, route := range []string{"/api/v1/endpoints/isolate-bulk", "/api/v1/endpoints/unisolate-bulk"} {
			if w := adminPost(srv, route, body, ""); w.Code != http.StatusBadRequest {
				t.Fatalf("%s %s: want 400, got %d %s", route, body, w.Code, w.Body.String())
			}
		}
	}
	if targets, err := store.BulkIsolationTargets("", "unknown", ""); err != nil || len(targets) != 0 {
		t.Fatalf("an unknown scope matched %v (%v)", targets, err)
	}
}
