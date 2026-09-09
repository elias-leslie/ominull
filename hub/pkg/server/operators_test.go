package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

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

// The HTTP assertion always runs. The optional browser portion uses ST's
// managed headless profile and a disposable hub, never the deployed hub or an
// operator credential. A distinct loopback address isolates its host cookies.
func TestExpiredConsoleSessionAndBrowserRecovery(t *testing.T) {
	srv, store := setupTestServer(t)
	defer store.Close()
	token, err := auth.GenerateJWT(auth.Claims{Username: "fixture@example.invalid", Role: auth.RoleAdmin}, srv.adminKey, -time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	expired := &http.Cookie{Name: consoleSessionCookie, Value: token, Path: "/", HttpOnly: true}
	req := httptest.NewRequest("GET", "/api/v1/endpoints", nil)
	req.AddCookie(expired)
	recorder := httptest.NewRecorder()
	srv.Handler().ServeHTTP(recorder, req)
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("expired signed session returned %d", recorder.Code)
	}
	if os.Getenv("OMINULL_MANAGED_BROWSER_TEST") != "1" {
		return
	}
	if err := store.UpsertOperator("sentinel-switch@example.invalid", auth.RoleAuditor, "fixture"); err != nil {
		t.Fatal(err)
	}
	auditor := sessionFor(t, srv, "sentinel-switch@example.invalid", auth.RoleAuditor)
	auditor.Path, auditor.HttpOnly = "/", true

	handler := srv.Handler()
	fixture := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/fixture/expire":
			http.SetCookie(w, expired)
			w.WriteHeader(http.StatusNoContent)
		case "/fixture/logout":
			http.SetCookie(w, &http.Cookie{Name: consoleSessionCookie, Path: "/", MaxAge: -1, HttpOnly: true})
			w.WriteHeader(http.StatusNoContent)
		case "/fixture/auditor":
			http.SetCookie(w, auditor)
			w.WriteHeader(http.StatusNoContent)
		default:
			handler.ServeHTTP(w, r)
		}
	}))
	fixture.Listener.Close()
	fixture.Listener, err = net.Listen("tcp", "127.0.0.55:0")
	if err != nil {
		t.Fatal(err)
	}
	fixture.Start()
	defer fixture.Close()
	run := func(args ...string) {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 35*time.Second)
		defer cancel()
		out, err := exec.CommandContext(ctx, "st", append([]string{"browser"}, args...)...).CombinedOutput()
		if err != nil {
			t.Fatalf("managed fixture browser: %v: %s", err, out)
		}
	}
	run("open", fixture.URL)
	defer run("open", "about:blank")
	key, _ := json.Marshal(srv.adminKey)
	login := `(async()=>{const r=await fetch('/',{method:'POST',body:new URLSearchParams({key:` + string(key) + `})});if(!r.ok)throw Error('fixture sign-in failed');return 'signed in';})()`
	run("eval", login)
	// Cookie-authenticated GET clears the POST response's bootstrap API key.
	run("reload")
	run("eval", `(async()=>{if(!document.querySelector('#view'))throw Error('console not rendered');if((await fetch('/api/v1/endpoints')).status!==200)throw Error('cookie read refused');if([...document.querySelectorAll('a')].some(a=>a.href.includes('mock_admin_token')))throw Error('credential in navigation');return 'cookie console verified';})()`)
	run("eval", `(async()=>{await fetch('/fixture/expire');if((await fetch('/api/v1/endpoints')).status!==401)throw Error('expired session accepted');const until=Date.now()+20000;while(Date.now()<until){if(document.querySelector('.connection-status')?.textContent.includes('Sign in required'))return 'expiry visible';await new Promise(r=>setTimeout(r,100));}throw Error('expiry not visible in console');})()`)
	run("open", fixture.URL+"/status")
	run("eval", `(()=>{if(!document.querySelector('input[name="key"]'))throw Error('expired diagnostics did not recover through sign-in');return 'sign-in required';})()`)
	run("eval", login)
	run("open", fixture.URL)
	run("eval", `(async()=>{if(!document.querySelector('#view')||(await fetch('/api/v1/endpoints')).status!==200)throw Error('sign-in recovery failed');await fetch('/fixture/auditor');return 'recovered and switched fixture identity';})()`)
	run("reload")
	run("eval", `(async()=>{document.getElementById('user-avatar-btn').click();if(!document.body.innerText.includes('Read-only access'))throw Error('auditor role not visible');if((await fetch('/api/v1/endpoints/isolate',{method:'POST',headers:{'Content-Type':'application/json'},body:'{"endpoint_id":"nonexistent-fixture"}'})).status!==403)throw Error('auditor mutation not refused');await navigator.serviceWorker.ready;const names=(await caches.keys()).filter(n=>n.startsWith('ominull-shell-v'));if(!names.length)throw Error('worker cache not installed');for(const name of names){const cache=await caches.open(name);for(const request of await cache.keys()){const pathname=new URL(request.url).pathname;if(pathname==='/'||pathname.startsWith('/api/'))throw Error('personalized route cached');const body=await(await cache.match(request)).text();if(body.includes('mock_admin_token')||body.includes('sentinel-switch@example.invalid'))throw Error('identity or credential cached');}}await fetch('/fixture/logout');await Promise.all((await navigator.serviceWorker.getRegistrations()).map(r=>r.unregister()));await Promise.all(names.map(n=>caches.delete(n)));return 'auditor role, authorization and anonymous cache verified';})()`)
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

// TestASignInIsRecordedOnceAndNotOnEveryReload. The hub logged an assertion it
// refused and said nothing about one it accepted, so an operator who reopened
// their browser and was not asked to sign in had no way to tell whether Access
// had just authenticated them or whether they were still on an old session.
func TestASignInIsRecordedOnceAndNotOnEveryReload(t *testing.T) {
	srv, store := setupTestServer(t)
	defer store.Close()

	if err := store.UpsertOperator("analyst@example.com", "analyst", "test"); err != nil {
		t.Fatalf("seeding the analyst: %v", err)
	}
	cookie := sessionFor(t, srv, "analyst@example.com", auth.RoleAnalyst)

	signIns := func() int {
		logs, err := store.ListAuditLogs("", 100)
		if err != nil {
			t.Fatalf("reading the audit log: %v", err)
		}
		n := 0
		for _, l := range logs {
			if l.Action == "CONSOLE_SIGNIN" && l.Username == "analyst@example.com" {
				n++
			}
		}
		return n
	}

	// First arrival: no session yet, so this is a sign-in.
	r := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("an anonymous caller opened the console: %d", w.Code)
	}

	r = httptest.NewRequest("GET", "/", nil)
	r.Header.Set("X-API-Key", srv.adminKey)
	w = httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("the key holder could not open the console: %d", w.Code)
	}

	if n := signIns(); n != 0 {
		t.Fatalf("the analyst has %d sign-ins before signing in", n)
	}

	for i := 0; i < 3; i++ {
		r = httptest.NewRequest("GET", "/", nil)
		r.AddCookie(cookie)
		w = httptest.NewRecorder()
		srv.Handler().ServeHTTP(w, r)
		if w.Code != http.StatusOK {
			t.Fatalf("reload %d answered %d", i, w.Code)
		}
	}
	// Three loads on one live session is one person still being there.
	if n := signIns(); n != 0 {
		t.Errorf("reloading an existing session recorded %d sign-ins", n)
	}
}
