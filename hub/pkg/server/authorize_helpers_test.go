package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"ominull/hub/pkg/responseauth"
	"ominull/hub/pkg/storage"
)

type testAuthority struct {
	auth *responseauth.Authority
}

var testAuthorities sync.Map // *Server -> *testAuthority

// installTestAuthority gives a test hub an in-process response authority.
func installTestAuthority(t testing.TB, srv *Server, dir string) *testAuthority {
	t.Helper()
	authDir := filepath.Join(dir, "authority")
	if err := os.MkdirAll(filepath.Join(authDir, "keys"), 0o700); err != nil {
		t.Fatal(err)
	}
	auth, err := responseauth.NewAuthorityWithStore(responseauth.Config{StateDir: authDir}, responseauth.NewMemoryStore())
	if err != nil {
		t.Fatal(err)
	}
	srv.SetResponseAuth(responseauth.NewInProcessClient(auth))
	a := &testAuthority{auth: auth}
	testAuthorities.Store(srv, a)
	return a
}

// useTestAuthority registers an authority a test built itself.
func useTestAuthority(srv *Server, auth *responseauth.Authority) *testAuthority {
	a := &testAuthority{auth: auth}
	testAuthorities.Store(srv, a)
	return a
}

// doAuthorized sends one request over a real HTTP client (for tests that need
// cookies and WebSockets). Authorized routes answer at once; there is no
// second round.
func doAuthorized(t testing.TB, client *http.Client, method, url, body string, auth func(*http.Request)) *http.Response {
	t.Helper()
	req, _ := http.NewRequest(method, url, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	auth(req)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, url, err)
	}
	return resp
}

// seedTerminalEndpoint registers an endpoint that reports a terminal.
func seedTerminalEndpoint(t testing.TB, srv *Server, tenantID, id string, programs ...string) {
	t.Helper()
	if len(programs) == 0 {
		programs = []string{"/bin/bash", "/bin/sh"}
	}
	caps, _ := json.Marshal(map[string]interface{}{"isolate": true, "terminal": map[string]interface{}{"programs": programs}})
	if err := srv.store.UpsertEndpoint(storage.Endpoint{ID: id, TenantID: tenantID, Hostname: id, OS: "test", Status: "online", ResponseCapabilities: string(caps)}); err != nil {
		t.Fatal(err)
	}
}

func authorityOf(t testing.TB, srv *Server) *testAuthority {
	t.Helper()
	if a, ok := testAuthorities.Load(srv); ok {
		return a.(*testAuthority)
	}
	t.Fatal("test hub has no test authority installed")
	return nil
}

// serveAuthorized sends a request through the hub and records the answer.
func serveAuthorized(t testing.TB, h http.Handler, req *http.Request) *httptest.ResponseRecorder {
	t.Helper()
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return w
}
