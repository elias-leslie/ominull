package server

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestTopologyWorkspaceRequiresOperator(t *testing.T) {
	srv, store := setupTestServer(t)
	defer store.Close()
	for _, path := range []string{"/api/v1/topology/workspace", "/api/v1/topology/views"} {
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
func TestTopologyAuditorCannotWriteSavedViews(t *testing.T) {
	srv, store := setupTestServer(t)
	defer store.Close()
	r := httptest.NewRequest("PUT", "/", bytes.NewBufferString(`{"id":"one","name":"One","state":{}}`))
	r.Header.Set("X-Role", "auditor")
	r.Header.Set("X-Username", "reader")
	w := httptest.NewRecorder()
	srv.handleTopologyViews(w, r)
	if w.Code != 403 {
		t.Fatal(w.Code)
	}
}

func TestTopologySavedViewsUseAuthenticatedOwner(t *testing.T) {
	srv, store := setupTestServer(t)
	defer store.Close()
	for _, email := range []string{"first@example.invalid", "second@example.invalid"} {
		if err := store.UpsertOperator(email, "analyst", "test"); err != nil {
			t.Fatal(err)
		}
	}
	call := func(email, method, body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, "/api/v1/topology/views", bytes.NewBufferString(body))
		r.AddCookie(sessionFor(t, srv, email, "analyst"))
		r.Header.Set("X-Username", "first@example.invalid")
		w := httptest.NewRecorder()
		srv.Handler().ServeHTTP(w, r)
		return w
	}
	body := `{"id":"one","name":"One","state":{}}`
	if w := call("first@example.invalid", "PUT", body); w.Code != 200 {
		t.Fatalf("save: %d %s", w.Code, w.Body.String())
	}
	if w := call("second@example.invalid", "GET", ""); w.Code != 200 || bytes.Contains(w.Body.Bytes(), []byte(`"id":"one"`)) {
		t.Fatalf("owner leak: %d %s", w.Code, w.Body.String())
	}
	if w := call("first@example.invalid", "PUT", body); w.Code != 409 {
		t.Fatalf("conflict: %d", w.Code)
	}
	if w := call("first@example.invalid", "PUT", body+`{}`); w.Code != 400 {
		t.Fatalf("trailing JSON: %d", w.Code)
	}
}
