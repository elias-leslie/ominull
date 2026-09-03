package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestTheConsoleAsksForItsAssetsByVersion. "no-cache" asks a browser to
// revalidate; it does not guarantee one does. An operator on a hub that had
// just shipped a new console section clicked it and nothing happened, because
// the browser had served the previous build's script without asking. The
// document is never cached, so naming the running version in the asset URL is
// what makes an upgrade reach the browser: a URL it has never seen cannot come
// from a cache.
func TestTheConsoleAsksForItsAssetsByVersion(t *testing.T) {
	srv, store := setupTestServer(t)
	defer store.Close()

	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("X-API-Key", srv.adminKey)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, r)

	body := w.Body.String()
	for _, want := range []string{"app.js?v=" + srv.agentVersion, "app.css?v=" + srv.agentVersion} {
		if !strings.Contains(body, want) {
			t.Errorf("the console does not ask for %s", want)
		}
	}
	if strings.Contains(body, "{{HUB_VERSION}}") {
		t.Errorf("the version placeholder survived into the served document")
	}

	// And the versioned URL still resolves: the query string is not part of the
	// path this handler matches on.
	r = httptest.NewRequest("GET", "/app.js?v="+srv.agentVersion, nil)
	w = httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("a versioned asset URL answered %d", w.Code)
	}
	if w.Header().Get("ETag") == "" {
		t.Errorf("the asset lost its validator")
	}
}

func TestConsoleContainsNoUnimplementedShellControls(t *testing.T) {
	srv, store := setupTestServer(t)
	defer store.Close()

	r := httptest.NewRequest("GET", "/app.js?v="+srv.agentVersion, nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("fetching /app.js returned %d", w.Code)
	}

	body := w.Body.String()
	forbiddenStrings := []string{
		"openTerminalSession",
		"terminal-modal",
		"SESSION ACTIVE",
		"Open remote shell",
		"Interactive Remote Shell",
		"Command queued on endpoint heartbeat relay",
		"via Ominull Relay",
	}

	for _, forbidden := range forbiddenStrings {
		if strings.Contains(body, forbidden) {
			t.Errorf("served app.js contains forbidden unimplemented shell claim: %q", forbidden)
		}
	}
}
