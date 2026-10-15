package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"ominull/hub/pkg/storage"
)

func exclusionRequest(t *testing.T, srv *Server, method, path, key, body string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	r.Header.Set("X-API-Key", key)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, r)
	return w
}

func auditCount(t *testing.T, store *storage.Store, action string) int {
	t.Helper()
	entries, err := store.ListAuditLogs("", 500)
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, e := range entries {
		if e.Action == action {
			n++
		}
	}
	return n
}

// The tenant key ships to every endpoint, so it can read exclusions but never
// write, remove or toggle one - global or otherwise.
func TestExclusionWritesNeedTheAdminKey(t *testing.T) {
	t.Parallel()
	srv, store := setupTestServer(t)
	defer store.Close()
	expires := time.Now().UTC().Add(time.Hour).Format(time.RFC3339)
	global := `{"name":"hide me","scope":"global","process_path":"/tmp/implant","reason":"x","expires_at":"` + expires + `"}`
	scoped := `{"name":"hide me","scope":"client","scope_value":"t-01","process_path":"/tmp/implant","reason":"x","expires_at":"` + expires + `"}`
	for _, body := range []string{global, scoped} {
		if w := exclusionRequest(t, srv, http.MethodPost, "/api/v1/exclusions", "mock_tenant_token", body); w.Code != http.StatusForbidden {
			t.Fatalf("tenant create: %d %s", w.Code, w.Body.String())
		}
	}
	now := time.Now().UTC()
	if err := store.CreateExclusion(storage.Exclusion{ID: "ex-1", TenantID: "default", Scope: "global", Name: "tool",
		ProcessPath: "/usr/bin/tool", Reason: "fixture", Active: true, CreatedAt: now, ExpiresAt: now.Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	if w := exclusionRequest(t, srv, http.MethodDelete, "/api/v1/exclusions?id=ex-1", "mock_tenant_token", ""); w.Code != http.StatusForbidden {
		t.Fatalf("tenant delete: %d", w.Code)
	}
	if w := exclusionRequest(t, srv, http.MethodPost, "/api/v1/exclusions/toggle", "mock_tenant_token", `{"id":"ex-1","active":false}`); w.Code != http.StatusForbidden {
		t.Fatalf("tenant toggle: %d", w.Code)
	}
	if w := exclusionRequest(t, srv, http.MethodGet, "/api/v1/exclusions", "mock_tenant_token", ""); w.Code != http.StatusOK {
		t.Fatalf("tenant read: %d", w.Code)
	}
	if list, _ := store.ListExclusions(""); len(list) != 1 || !list[0].Active {
		t.Fatalf("tenant changed exclusions: %+v", list)
	}
}

func TestExclusionCreateRefusesBroadRows(t *testing.T) {
	t.Parallel()
	srv, store := setupTestServer(t)
	defer store.Close()
	soon := time.Now().UTC().Add(time.Hour).Format(time.RFC3339)
	far := time.Now().UTC().Add(91 * 24 * time.Hour).Format(time.RFC3339)
	past := time.Now().UTC().Add(-time.Hour).Format(time.RFC3339)
	for name, body := range map[string]string{
		"bad CIDR":         `{"name":"x","dst_ip_range":"10.0.0.0/33","reason":"r","expires_at":"` + soon + `"}`,
		"substring path":   `{"name":"x","process_path":"python","reason":"r","expires_at":"` + soon + `"}`,
		"glob path":        `{"name":"x","process_path":"/usr/bin/py*","reason":"r","expires_at":"` + soon + `"}`,
		"no selector":      `{"name":"x","reason":"r","expires_at":"` + soon + `"}`,
		"empty scope":      `{"name":"x","scope":"endpoint","process_path":"/usr/bin/tool","reason":"r","expires_at":"` + soon + `"}`,
		"no reason":        `{"name":"x","process_path":"/usr/bin/tool","expires_at":"` + soon + `"}`,
		"no expiry":        `{"name":"x","process_path":"/usr/bin/tool","reason":"r"}`,
		"expired":          `{"name":"x","process_path":"/usr/bin/tool","reason":"r","expires_at":"` + past + `"}`,
		"beyond 90 days":   `{"name":"x","process_path":"/usr/bin/tool","reason":"r","expires_at":"` + far + `"}`,
		"unknown protocol": `{"name":"x","process_path":"/usr/bin/tool","protocol":"gre","reason":"r","expires_at":"` + soon + `"}`,
	} {
		if w := exclusionRequest(t, srv, http.MethodPost, "/api/v1/exclusions", "mock_admin_token", body); w.Code != http.StatusBadRequest {
			t.Errorf("%s: %d %s", name, w.Code, w.Body.String())
		}
	}
	if list, _ := store.ListExclusions(""); len(list) != 0 {
		t.Fatalf("refused rows were stored: %+v", list)
	}
	w := exclusionRequest(t, srv, http.MethodPost, "/api/v1/exclusions", "mock_admin_token",
		`{"name":"bridge","process_path":"/usr/bin/docker-proxy","dst_ip_range":"172.18.0.0/16","port":7070,"protocol":"tcp","reason":"bridge","expires_at":"`+soon+`"}`)
	if w.Code != http.StatusCreated {
		t.Fatalf("valid create: %d %s", w.Code, w.Body.String())
	}
	var created storage.Exclusion
	if err := json.Unmarshal(w.Body.Bytes(), &created); err != nil || created.ExpiresAt.IsZero() {
		t.Fatalf("created = %+v (%v)", created, err)
	}
	if auditCount(t, store, "CREATE_EXCLUSION") != 1 {
		t.Fatal("create not audited")
	}
}

func TestExclusionDeleteAndToggleAreCheckedAndAudited(t *testing.T) {
	t.Parallel()
	srv, store := setupTestServer(t)
	defer store.Close()
	now := time.Now().UTC()
	for _, ex := range []storage.Exclusion{
		{ID: "ex-live", ExpiresAt: now.Add(time.Hour)},
		{ID: "ex-stale", ExpiresAt: now.Add(-time.Hour)},
	} {
		ex.TenantID, ex.Scope, ex.Name, ex.ProcessPath, ex.Reason, ex.CreatedAt = "default", "global", ex.ID, "/usr/bin/tool", "fixture", now
		if err := store.CreateExclusion(ex); err != nil {
			t.Fatal(err)
		}
	}
	if w := exclusionRequest(t, srv, http.MethodPost, "/api/v1/exclusions/toggle", "mock_admin_token", `{"id":"nope","active":false}`); w.Code != http.StatusNotFound {
		t.Fatalf("toggle unknown id: %d", w.Code)
	}
	if w := exclusionRequest(t, srv, http.MethodDelete, "/api/v1/exclusions?id=nope", "mock_admin_token", ""); w.Code != http.StatusNotFound {
		t.Fatalf("delete unknown id: %d", w.Code)
	}
	if w := exclusionRequest(t, srv, http.MethodPost, "/api/v1/exclusions/toggle", "mock_admin_token", `{"id":"ex-stale","active":true}`); w.Code != http.StatusConflict {
		t.Fatalf("enabling an expired exclusion: %d %s", w.Code, w.Body.String())
	}
	if w := exclusionRequest(t, srv, http.MethodPost, "/api/v1/exclusions/toggle", "mock_admin_token", `{"id":"ex-live","active":false}`); w.Code != http.StatusOK {
		t.Fatalf("disable: %d %s", w.Code, w.Body.String())
	}
	if w := exclusionRequest(t, srv, http.MethodDelete, "/api/v1/exclusions?id=ex-live", "mock_admin_token", ""); w.Code != http.StatusOK {
		t.Fatalf("delete: %d %s", w.Code, w.Body.String())
	}
	if auditCount(t, store, "TOGGLE_EXCLUSION") != 1 || auditCount(t, store, "DELETE_EXCLUSION") != 1 {
		t.Fatal("toggle and delete must each write one audit row")
	}
	if _, err := store.GetExclusion("ex-live"); err != storage.ErrExclusionNotFound {
		t.Fatalf("deleted row still present: %v", err)
	}
}
