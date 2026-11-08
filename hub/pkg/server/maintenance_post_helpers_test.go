package server

import (
	"net/http/httptest"
	"strings"
	"testing"

	"ominull/hub/pkg/storage"
)

// postAdmin sends one POST with the static admin key. Authorized routes
// answer at once (there is no second round).
func postAdmin(srv *Server, path, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest("POST", path, strings.NewReader(body))
	req.Header.Set("X-API-Key", "mock_admin_token")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	return w
}

// seedPlainEndpoints registers online endpoints with no extras.
func seedPlainEndpoints(t *testing.T, store *storage.Store, ids ...string) {
	t.Helper()
	for _, id := range ids {
		if err := store.UpsertEndpoint(storage.Endpoint{ID: id, TenantID: "default", Hostname: "host-" + id, OS: "test", Status: "online"}); err != nil {
			t.Fatal(err)
		}
	}
}

// auditRowsOf returns the audit rows with one action.
func auditRowsOf(t *testing.T, store *storage.Store, action string) []storage.AuditEntry {
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

// authorityWords returns how each signed action was put in the audit, with
// the words worked out from its payload, oldest first.
func authorityWords(t *testing.T, srv *Server) []string {
	t.Helper()
	rows := auditRowsOf(t, srv.store, "ACTION_AUTHORIZED")
	out := make([]string, 0, len(rows))
	for i := len(rows) - 1; i >= 0; i-- {
		out = append(out, rows[i].Details)
	}
	return out
}
