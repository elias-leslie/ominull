package server

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestTopologyWorkspaceRequiresOperator(t *testing.T) {
	t.Parallel()
	srv, store := setupTestServer(t)
	defer store.Close()
	for _, path := range []string{"/api/v1/topology/workspace"} {
		for _, key := range []string{"mock_tenant_token", "mock_admin_token"} {
			r := httptest.NewRequest("GET", path, nil)
			r.Header.Set("X-API-Key", key)
			r.Header.Set("X-Role", "admin")
			w := httptest.NewRecorder()
			srv.Handler().ServeHTTP(w, r)
			want := 403
			if key == "mock_admin_token" {
				want = 200
			}
			if w.Code != want {
				t.Fatalf("%s got %d want %d", path, w.Code, want)
			}
		}
	}
}
func TestTopologyRoleGateAcceptsAnalystAndAuditorReads(t *testing.T) {
	t.Parallel()
	for _, role := range []string{"admin", "analyst", "auditor"} {
		r := httptest.NewRequest("GET", "/", nil)
		r.Header.Set("X-Role", role)
		w := httptest.NewRecorder()
		requireTopologyOperator(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) })(w, r)
		if w.Code != 204 {
			t.Errorf("%s cannot read: %d", role, w.Code)
		}
	}
}
func TestTopologySnapshotConditionalRead(t *testing.T) {
	t.Parallel()
	srv, store := setupTestServer(t)
	defer store.Close()
	first := httptest.NewRecorder()
	srv.handleTopologyWorkspace(first, httptest.NewRequest("GET", "/api/v1/topology/workspace?window=24h", nil))
	tag := first.Header().Get("ETag")
	if first.Code != 200 || tag == "" || first.Header().Get("X-Snapshot-At") == "" {
		t.Fatalf("missing snapshot validators: status=%d etag=%q", first.Code, tag)
	}
	req := httptest.NewRequest("GET", "/api/v1/topology/workspace?window=24h", nil)
	req.Header.Set("If-None-Match", tag)
	second := httptest.NewRecorder()
	srv.handleTopologyWorkspace(second, req)
	if second.Code != 304 || second.Body.Len() != 0 {
		t.Fatalf("unchanged snapshot transferred: status=%d bytes=%d", second.Code, second.Body.Len())
	}
}
