package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// What these tests are about: the console has to be able to hand an operator a
// working install command without the fleet's admin key ever appearing in a URL,
// and the credential that replaces it has to be worth less than the key it
// replaced - single use, short lived, and good for one platform.

// ticketFrom pulls the ?t= value out of a rendered one-line install command.
func ticketFrom(t *testing.T, oneLiner string) string {
	t.Helper()
	i := strings.Index(oneLiner, "?t=")
	if i < 0 {
		t.Fatalf("no ticket in %q", oneLiner)
	}
	tok := oneLiner[i+3:]
	if j := strings.IndexAny(tok, " '\"|"); j >= 0 {
		tok = tok[:j]
	}
	return tok
}

func renderInstaller(t *testing.T, srv *Server, platform string, oneLiner bool) map[string]interface{} {
	t.Helper()
	body := `{"platform":"` + platform + `","one_liner":` + map[bool]string{true: "true", false: "false"}[oneLiner] + `}`
	w := postJSON(t, srv, "/api/v1/enrolment/script", body)
	if w.Code != http.StatusOK {
		t.Fatalf("%s: rendering an installer returned %d: %s", platform, w.Code, w.Body.String())
	}
	var out map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("%s: %v", platform, err)
	}
	if cc := w.Header().Get("Cache-Control"); cc != "no-store" {
		t.Errorf("%s: Cache-Control is %q, so a proxy may keep a copy of a credential", platform, cc)
	}
	return out
}

func TestTheConsoleCanRenderAnInstallerWithoutPuttingTheKeyInAURL(t *testing.T) {
	srv, store := setupTestServer(t)
	defer store.Close()

	for _, platform := range []string{"linux", "macos", "windows"} {
		out := renderInstaller(t, srv, platform, true)

		script, _ := out["script"].(string)
		if len(script) < 200 {
			t.Fatalf("%s: the rendered script is %d bytes, which is not an installer", platform, len(script))
		}
		one, _ := out["one_liner"].(string)
		if one == "" {
			t.Fatalf("%s: no one-line form was returned", platform)
		}
		// The whole point. The command an operator pastes on a host must not
		// carry the hub's admin key, because that command lands in shell
		// history and in every log on the path.
		if strings.Contains(one, "mock_admin_token") {
			t.Fatalf("%s: the install command carries the admin key: %s", platform, one)
		}
		if !strings.Contains(one, "?t=") {
			t.Fatalf("%s: the install command carries no ticket: %s", platform, one)
		}
	}
}

func TestAnInstallLinkWorksOnceAndThenStopsWorking(t *testing.T) {
	srv, store := setupTestServer(t)
	defer store.Close()

	out := renderInstaller(t, srv, "linux", true)
	one, _ := out["one_liner"].(string)
	ticket := ticketFrom(t, one)

	first := httptest.NewRecorder()
	srv.Handler().ServeHTTP(first, httptest.NewRequest("GET", "/bootstrap.sh?t="+ticket, nil))
	if first.Code != http.StatusOK {
		t.Fatalf("the first redemption was refused: %d %s", first.Code, first.Body.String())
	}
	if !strings.Contains(strings.ToLower(first.Body.String()), "ominull") {
		t.Fatalf("the redeemed body is not an installer: %.120s", first.Body.String())
	}

	second := httptest.NewRecorder()
	srv.Handler().ServeHTTP(second, httptest.NewRequest("GET", "/bootstrap.sh?t="+ticket, nil))
	if second.Code == http.StatusOK {
		t.Fatalf("a spent install link was redeemed a second time")
	}
	if !strings.Contains(strings.ToLower(second.Body.String()), "already been used") {
		t.Errorf("a spent link should say so plainly; got %q", strings.TrimSpace(second.Body.String()))
	}
}

func TestAnInstallLinkIsBoundToItsPlatform(t *testing.T) {
	srv, store := setupTestServer(t)
	defer store.Close()

	out := renderInstaller(t, srv, "windows", true)
	one, _ := out["one_liner"].(string)
	ticket := ticketFrom(t, one)

	// A Windows ticket must not fetch the Linux installer. The two carry
	// different enrolment payloads, and a host that runs the wrong one either
	// fails or enrols as something it is not.
	wrong := httptest.NewRecorder()
	srv.Handler().ServeHTTP(wrong, httptest.NewRequest("GET", "/bootstrap.sh?t="+ticket, nil))
	if wrong.Code == http.StatusOK {
		t.Fatalf("a Windows install link fetched the Linux installer")
	}
}

// TestAnInstallerIsNotRenderedWithoutOneBeingAskedFor. Minting a ticket is a
// second credential with its own audit line, so merely looking at the screen
// must not create one.
func TestNoTicketIsMintedUnlessTheOneLinerIsAskedFor(t *testing.T) {
	srv, store := setupTestServer(t)
	defer store.Close()

	out := renderInstaller(t, srv, "linux", false)
	if _, ok := out["one_liner"]; ok {
		t.Fatalf("a ticket was minted for a request that did not ask for one")
	}
	if s, _ := out["script"].(string); len(s) < 200 {
		t.Fatalf("the script itself should still be rendered; got %d bytes", len(s))
	}
}

func TestRenderingAnInstallerNeedsAnAdministrator(t *testing.T) {
	srv, store := setupTestServer(t)
	defer store.Close()

	req := httptest.NewRequest("POST", "/api/v1/enrolment/script", strings.NewReader(`{"platform":"linux"}`))
	req.Header.Set("X-API-Key", "mock_tenant_token")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	if w.Code == http.StatusOK {
		t.Fatalf("a non-administrator rendered an installer carrying the tenant key")
	}
}
