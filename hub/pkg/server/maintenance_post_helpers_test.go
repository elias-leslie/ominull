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

// authorityWords returns how the response authority put each action it
// signed in its own audit (action and summary), oldest first.
func authorityWords(t *testing.T, srv *Server) []string {
	t.Helper()
	rows, err := authorityOf(t, srv).auth.GetAuditLog("default", 500)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, r := range rows {
		if r.EventType == "action_authorized" {
			out = append(out, r.Details)
		}
	}
	if len(out) > 1 && rows[0].Timestamp.After(rows[len(rows)-1].Timestamp) {
		for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
			out[i], out[j] = out[j], out[i]
		}
	}
	return out
}
