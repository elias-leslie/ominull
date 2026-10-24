package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"ominull/hub/pkg/responseauth"
	"ominull/hub/pkg/storage"
)

func auditCounts(t *testing.T, store *storage.Store) map[string]int {
	t.Helper()
	page, err := store.AuditHistory("", 500, "", storage.AuditFilter{})
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]int{}
	for _, e := range page.Entries {
		out[e.Action]++
	}
	return out
}

// A former ask path: the isolation is signed by the authority and runs on the
// first request. Nothing answers 202, nothing is left pending, and the audit
// says authorized, not "approval requested".
func TestIsolationIsAuthorizedOnTheFirstRequest(t *testing.T) {
	t.Parallel()
	srv, store := setupTestServer(t)
	defer store.Close()
	seedPlain(t, store, "ep-1")

	w := adminPost(srv, "/api/v1/endpoints/isolate", `{"endpoint_id":"ep-1","force":true}`, "")
	if w.Code != http.StatusOK {
		t.Fatalf("want 200 at once, got %d %s", w.Code, w.Body.String())
	}
	if !isolated(t, store, "ep-1") {
		t.Fatal("the isolation did not run")
	}
	actions := auditCounts(t, store)
	if actions["ACTION_AUTHORIZED"] != 1 || actions["ACTION_REFUSED"] != 0 {
		t.Fatalf("audit: %v", actions)
	}
	for a := range actions {
		if strings.HasPrefix(a, "OWNER_APPROVAL_") {
			t.Fatalf("an approval row was written: %s", a)
		}
	}
	// Releasing the isolation was an always-ask action: it runs at once too.
	if w := adminPost(srv, "/api/v1/endpoints/unisolate", `{"endpoint_id":"ep-1"}`, ""); w.Code != http.StatusOK {
		t.Fatalf("release: %d %s", w.Code, w.Body.String())
	}
	if isolated(t, store, "ep-1") {
		t.Fatal("the release did not run")
	}
}

// The handler runs under the id of the authorization the authority just made;
// a caller's own X-Approval-ID is dropped, and the grants reach the handler.
func TestAuthorizedHandlerSeesTheAuthorityNotTheCaller(t *testing.T) {
	t.Parallel()
	srv, store := setupTestServer(t)
	defer store.Close()
	var gotID string
	var granted int
	h := srv.authorized(func(w http.ResponseWriter, r *http.Request, body []byte) (*actionPlan, bool) {
		return &actionPlan{Kind: responseauth.ActionKindIsolation, Action: "Isolate host", Summary: "x", Targets: []string{"ep-1"},
			Payload: []byte(`{"body":{"endpoint_id":"ep-1"},"route":"/api/v1/endpoints/isolate","targets":["ep-1"]}`)}, true
	}, func(w http.ResponseWriter, r *http.Request) {
		gotID = r.Header.Get(approvalHeader)
		granted = len(approvalGrants(r))
		w.WriteHeader(http.StatusOK)
	})
	req := httptest.NewRequest("POST", "/x", strings.NewReader(`{}`))
	req.Header.Set(approvalHeader, "attacker-chosen")
	w := httptest.NewRecorder()
	h(w, req)
	if w.Code != http.StatusOK || gotID == "" || gotID == "attacker-chosen" || granted != 1 {
		t.Fatalf("status %d id %q grants %d", w.Code, gotID, granted)
	}
}

// What the authority will not sign is refused with its reason, audited, and
// the handler never runs.
func TestAuthorityRefusalStopsTheAction(t *testing.T) {
	t.Parallel()
	srv, store := setupTestServer(t)
	defer store.Close()
	ran := false
	h := srv.authorized(func(w http.ResponseWriter, r *http.Request, body []byte) (*actionPlan, bool) {
		return &actionPlan{Kind: responseauth.ActionKindIsolation, Action: "Isolate host", Summary: "x", Targets: []string{"ep-1"},
			Payload: []byte(`{"route":"/api/v1/endpoints/delete","body":{},"targets":["ep-1"]}`)}, true
	}, func(w http.ResponseWriter, r *http.Request) { ran = true })
	w := httptest.NewRecorder()
	h(w, httptest.NewRequest("POST", "/x", strings.NewReader(`{}`)))
	if ran || w.Code < 400 || !strings.Contains(w.Body.String(), "did not sign") {
		t.Fatalf("ran=%v status %d %s", ran, w.Code, w.Body.String())
	}
	if actions := auditCounts(t, store); actions["ACTION_REFUSED"] != 1 {
		t.Fatalf("audit: %v", actions)
	}
}

// Without the authority nothing is signed and nothing runs.
func TestNoAuthorityMeansNoAction(t *testing.T) {
	t.Parallel()
	srv, store := setupTestServer(t)
	defer store.Close()
	seedPlain(t, store, "ep-1")
	srv.responseAuth = nil
	w := adminPost(srv, "/api/v1/endpoints/isolate", `{"endpoint_id":"ep-1","force":true}`, "")
	if w.Code != http.StatusServiceUnavailable || isolated(t, store, "ep-1") {
		t.Fatalf("status %d %s", w.Code, w.Body.String())
	}
}

// The owner-approval plumbing is gone: no pending-approval, approval-rule or
// relay answer routes, no steward rule token route.
func TestApprovalRoutesAreGone(t *testing.T) {
	t.Parallel()
	srv, store := setupTestServer(t)
	defer store.Close()
	for _, p := range []string{
		"/api/v1/approvals", "/api/v1/approvals/rules", "/api/v1/screen/steward",
		"/api/v1/integrations/nightshift/approvals", "/api/v1/integrations/nightshift/approvals/answer",
		"/api/v1/integrations/nightshift/approval-rules", "/api/v1/integrations/nightshift/approval-rules/challenge",
		"/api/v1/integrations/nightshift/decisions", "/api/v1/integrations/nightshift/decisions/answer",
		"/api/v1/integrations/nightshift/steward-screen",
	} {
		for _, m := range []string{"GET", "POST", "DELETE"} {
			req := httptest.NewRequest(m, p, strings.NewReader(`{}`))
			req.Header.Set("X-API-Key", "mock_admin_token")
			w := httptest.NewRecorder()
			srv.Handler().ServeHTTP(w, req)
			if w.Code != http.StatusNotFound {
				t.Errorf("%s %s: %d, want 404", m, p, w.Code)
			}
		}
	}
	// The relay key survives: Nightshift still reads locks and builds with it.
	if r := httptest.NewRequest("GET", "/api/v1/integrations/nightshift/locks", nil); r != nil {
		w := httptest.NewRecorder()
		srv.Handler().ServeHTTP(w, r)
		if w.Code != http.StatusUnauthorized {
			t.Errorf("locks without the relay key: %d, want 401", w.Code)
		}
	}
}
