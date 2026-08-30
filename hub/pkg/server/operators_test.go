package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"ominull/hub/pkg/auth"
)

// Once a Google sign-in can carry a role, the role has to mean something. These
// tests cover the two ways it could quietly mean nothing: a read-only operator
// who can still change the fleet, and a console that hands the admin key to
// whoever it renders for.

// sessionFor mints the cookie the console would be given after a successful
// sign-in as this operator.
func sessionFor(t *testing.T, srv *Server, email, role string) *http.Cookie {
	t.Helper()
	token, err := auth.GenerateJWT(auth.Claims{Username: email, Role: role}, srv.adminKey, consoleSessionTTL)
	if err != nil {
		t.Fatalf("minting a session: %v", err)
	}
	return &http.Cookie{Name: consoleSessionCookie, Value: token}
}

// TestAnAuditorCannotChangeAnything. requireAdmin guards the routes that were
// obviously dangerous, but isolating a host never went through it: before roles
// could arrive from an identity provider, the only caller holding one was an
// administrator anyway. An auditor reaching /endpoints/isolate would be able to
// cut the fleet off the network while holding the role named "reads everything,
// changes nothing".
func TestAnAuditorCannotChangeAnything(t *testing.T) {
	srv, store := setupTestServer(t)
	defer store.Close()

	if err := store.UpsertOperator("auditor@example.com", "auditor", "test"); err != nil {
		t.Fatalf("seeding the auditor: %v", err)
	}
	cookie := sessionFor(t, srv, "auditor@example.com", auth.RoleAuditor)

	for _, path := range []string{
		"/api/v1/endpoints/isolate",
		"/api/v1/endpoints/unisolate",
		"/api/v1/endpoints/isolate-bulk",
		"/api/v1/mesh/quarantine",
		"/api/v1/operators",
	} {
		r := httptest.NewRequest("POST", path, strings.NewReader(`{"endpoint_id":"anything"}`))
		r.AddCookie(cookie)
		w := httptest.NewRecorder()
		srv.Handler().ServeHTTP(w, r)
		if w.Code != http.StatusForbidden {
			t.Errorf("POST %s as an auditor answered %d, want 403", path, w.Code)
		}
	}

	// And the same operator can still read, or the role is useless.
	r := httptest.NewRequest("GET", "/api/v1/endpoints", nil)
	r.AddCookie(cookie)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Errorf("GET /api/v1/endpoints as an auditor answered %d, want 200", w.Code)
	}
}

// TestOnlyAnAdministratorSeesTheOperatorList. An analyst who can read it learns
// which addresses are worth phishing; an analyst who can write it is an
// administrator.
func TestOnlyAnAdministratorSeesTheOperatorList(t *testing.T) {
	srv, store := setupTestServer(t)
	defer store.Close()

	if err := store.UpsertOperator("analyst@example.com", "analyst", "test"); err != nil {
		t.Fatalf("seeding the analyst: %v", err)
	}

	r := httptest.NewRequest("GET", "/api/v1/operators", nil)
	r.AddCookie(sessionFor(t, srv, "analyst@example.com", auth.RoleAnalyst))
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusForbidden {
		t.Errorf("an analyst read the operator list: %d", w.Code)
	}
}

// TestTheLastAdministratorCannotBeRemoved. The failure this prevents is not "the
// list is empty" but "nobody can open the console to repair the list", which
// takes a shell on the hub to undo.
func TestTheLastAdministratorCannotBeRemoved(t *testing.T) {
	srv, store := setupTestServer(t)
	defer store.Close()

	if err := store.EnsureBootstrapAdmin("boss@example.com"); err != nil {
		t.Fatalf("seeding the administrator: %v", err)
	}
	cookie := sessionFor(t, srv, "boss@example.com", auth.RoleAdmin)

	post := func(path, body string) int {
		r := httptest.NewRequest("POST", path, strings.NewReader(body))
		r.AddCookie(cookie)
		w := httptest.NewRecorder()
		srv.Handler().ServeHTTP(w, r)
		return w.Code
	}

	if code := post("/api/v1/operators/remove", `{"email":"boss@example.com"}`); code != http.StatusConflict {
		t.Errorf("removing the only administrator answered %d, want 409", code)
	}
	if code := post("/api/v1/operators", `{"email":"boss@example.com","role":"auditor"}`); code != http.StatusConflict {
		t.Errorf("demoting the only administrator answered %d, want 409", code)
	}

	// With a second administrator in place, the first may step down.
	if code := post("/api/v1/operators", `{"email":"deputy@example.com","role":"admin"}`); code != http.StatusOK {
		t.Fatalf("granting a second administrator answered %d", code)
	}
	if code := post("/api/v1/operators/remove", `{"email":"boss@example.com"}`); code != http.StatusOK {
		t.Errorf("removing an administrator who is not the last answered %d", code)
	}
}

// TestTheConsoleDoesNotHandOutTheAdminKey. The document embeds the key so the
// page can call the API with it. Handing that to everyone the console renders
// for would mean granting someone the auditor role also posts them the
// credential that runs the whole fleet - and one that cannot be revoked, only
// rotated.
func TestTheConsoleDoesNotHandOutTheAdminKey(t *testing.T) {
	srv, store := setupTestServer(t)
	defer store.Close()

	if err := store.UpsertOperator("auditor@example.com", "auditor", "test"); err != nil {
		t.Fatalf("seeding the auditor: %v", err)
	}

	r := httptest.NewRequest("GET", "/", nil)
	r.AddCookie(sessionFor(t, srv, "auditor@example.com", auth.RoleAuditor))
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("a signed-in auditor could not open the console: %d", w.Code)
	}
	body := w.Body.String()
	if strings.Contains(body, srv.adminKey) {
		t.Errorf("the console handed the admin key to an auditor")
	}
	if !strings.Contains(body, "auditor@example.com") {
		t.Errorf("the console did not name the operator it rendered for")
	}

	// The caller who presented the key still gets it back: that is how the page
	// calls the API when there is no Access in front of the hub.
	r = httptest.NewRequest("GET", "/", nil)
	r.Header.Set("X-API-Key", srv.adminKey)
	w = httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, r)
	if !strings.Contains(w.Body.String(), srv.adminKey) {
		t.Errorf("the console withheld the key from the caller that presented it")
	}
}

// TestAnOperatorGrantIsAudited. Who may sign in is a change to the fleet like
// any other, and the whole reason to move the list off a file on the hub was to
// make that change visible.
func TestAnOperatorGrantIsAudited(t *testing.T) {
	srv, store := setupTestServer(t)
	defer store.Close()

	if err := store.EnsureBootstrapAdmin("boss@example.com"); err != nil {
		t.Fatalf("seeding the administrator: %v", err)
	}

	body, _ := json.Marshal(map[string]string{"email": "new@example.com", "role": "analyst"})
	r := httptest.NewRequest("POST", "/api/v1/operators", bytes.NewReader(body))
	r.AddCookie(sessionFor(t, srv, "boss@example.com", auth.RoleAdmin))
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("granting a role answered %d: %s", w.Code, w.Body.String())
	}

	logs, err := store.ListAuditLogs("", 50)
	if err != nil {
		t.Fatalf("reading the audit log: %v", err)
	}
	found := false
	for _, l := range logs {
		if l.Action == "OPERATOR_GRANT" && l.Resource == "new@example.com" && l.Username == "boss@example.com" {
			found = true
		}
	}
	if !found {
		t.Errorf("granting a role left no audit entry naming who granted it")
	}
}
