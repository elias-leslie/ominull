package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// What these tests are about: the console has to hand an operator a working
// install script without an admin or shared tenant credential ever appearing
// in the command or URL. The enrollment code is body-only and one-use.
func enrollmentCode(t *testing.T, out map[string]interface{}) string {
	t.Helper()
	code, ok := out["enrollment_code"].(string)
	if !ok || !strings.HasPrefix(code, "one_") {
		t.Fatalf("no one-use enrollment code in %#v", out)
	}
	return code
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

	for _, platform := range []string{"linux", "windows"} {
		out := renderInstaller(t, srv, platform, true)

		script, _ := out["script"].(string)
		if len(script) < 200 {
			t.Fatalf("%s: the rendered script is %d bytes, which is not an installer", platform, len(script))
		}
		one, _ := out["one_liner"].(string)
		if one == "" {
			t.Fatalf("%s: no one-line form was returned", platform)
		}
		// The command an operator pastes on a host must not carry any credential.
		if strings.Contains(one, "mock_admin_token") {
			t.Fatalf("%s: the install command carries the admin key: %s", platform, one)
		}
		if strings.Contains(one, "?t=") || strings.Contains(one, "?key=") || strings.Contains(one, "one_") {
			t.Fatalf("%s: the install command carries enrollment material in its URL: %s", platform, one)
		}
		if strings.Contains(script, "mock_admin_token") || strings.Contains(script, "mock_tenant_token") {
			t.Fatalf("%s: the script carries a static hub credential", platform)
		}
	}
}

// Console traffic and agent traffic deliberately use different addresses. The
// console may be plain HTTP on a trusted LAN or protected by an interactive
// identity proxy; package download and enrollment must use the HTTPS agent
// address instead. The self-service page itself remains on the console address
// so a workstation on that LAN reaches the hub directly and retains its source
// address for the network authorization check.
func TestInstallTrafficUsesTheAgentURLAndThePortalUsesTheConsoleURL(t *testing.T) {
	srv, store := setupTestServer(t)
	defer store.Close()
	srv.SetAgentHubURL("https://10.0.0.57:9443")

	out := renderInstaller(t, srv, "windows", false)
	script, _ := out["script"].(string)
	if !strings.Contains(script, "$HubURL = 'https://10.0.0.57:9443'") {
		t.Fatalf("Windows installer does not fetch from the HTTPS agent address:\n%s", script)
	}
	if strings.Contains(script, "$HubURL = 'http://10.0.0.57:9999'") {
		t.Fatal("Windows installer still fetches packages from the HTTP console address")
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/enrolment/windows", nil)
	req.Header.Set("X-API-Key", "mock_admin_token")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("listing LAN enrollment access returned %d: %s", w.Code, w.Body.String())
	}
	var windows map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &windows); err != nil {
		t.Fatal(err)
	}
	if got := windows["portal_url"]; got != "http://10.0.0.57:9999/install" {
		t.Fatalf("portal_url = %v, want the configured LAN console address", got)
	}
}

func TestReusableProfileCannotPinEveryInstallToOneEndpoint(t *testing.T) {
	srv, store := setupTestServer(t)
	defer store.Close()

	for _, kind := range []string{"campaign", "deployment"} {
		w := postJSON(t, srv, "/api/v1/enrolment/script",
			`{"platform":"linux","kind":"`+kind+`","endpoint_id":"same-host"}`)
		if w.Code != http.StatusBadRequest {
			t.Errorf("%s profile with a fixed endpoint id returned %d, want 400: %s", kind, w.Code, w.Body.String())
		}
	}
}

func TestAnEnrollmentCodeWorksOnceAndThenStopsWorking(t *testing.T) {
	srv, store := setupTestServer(t)
	defer store.Close()

	out := renderInstaller(t, srv, "linux", true)
	code := enrollmentCode(t, out)

	first := httptest.NewRecorder()
	firstReq := httptest.NewRequest("POST", "/api/v1/enrollment/redeem", strings.NewReader(`{"code":"`+code+`","platform":"linux","hostname":"linux-test"}`))
	firstReq.Header.Set("Content-Type", "application/json")
	srv.Handler().ServeHTTP(first, firstReq)
	if first.Code != http.StatusOK {
		t.Fatalf("the first redemption was refused: %d %s", first.Code, first.Body.String())
	}
	var bundle map[string]interface{}
	if err := json.Unmarshal(first.Body.Bytes(), &bundle); err != nil {
		t.Fatalf("the first redemption did not return JSON: %v", err)
	}
	if !strings.HasPrefix(bundle["device_credential"].(string), "omd_") {
		t.Fatalf("the first redemption did not issue a unique device credential: %#v", bundle)
	}

	second := httptest.NewRecorder()
	secondReq := httptest.NewRequest("POST", "/api/v1/enrollment/redeem", strings.NewReader(`{"code":"`+code+`","platform":"linux","hostname":"linux-test-2"}`))
	secondReq.Header.Set("Content-Type", "application/json")
	srv.Handler().ServeHTTP(second, secondReq)
	if second.Code == http.StatusOK {
		t.Fatalf("a spent enrollment code was redeemed a second time")
	}
	if !strings.Contains(strings.ToLower(second.Body.String()), "already been used") {
		t.Errorf("a spent code should say so plainly; got %q", strings.TrimSpace(second.Body.String()))
	}
}

func TestAnEnrollmentCodeIsBoundToItsPlatform(t *testing.T) {
	srv, store := setupTestServer(t)
	defer store.Close()

	out := renderInstaller(t, srv, "windows", true)
	code := enrollmentCode(t, out)

	// A Windows code must not redeem as Linux. The code remains available for
	// the correct platform after the refused attempt.
	wrong := httptest.NewRecorder()

	wrongReq := httptest.NewRequest("POST", "/api/v1/enrollment/redeem", strings.NewReader(`{"code":"`+code+`","platform":"linux","hostname":"linux-wrong"}`))
	wrongReq.Header.Set("Content-Type", "application/json")
	srv.Handler().ServeHTTP(wrong, wrongReq)
	if wrong.Code == http.StatusOK {
		t.Fatalf("a Windows enrollment code redeemed as Linux")
	}

	right := httptest.NewRecorder()
	rightReq := httptest.NewRequest("POST", "/api/v1/enrollment/redeem", strings.NewReader(`{"code":"`+code+`","platform":"windows","hostname":"windows-right"}`))
	rightReq.Header.Set("Content-Type", "application/json")
	srv.Handler().ServeHTTP(right, rightReq)
	if right.Code != http.StatusOK {
		t.Fatalf("the Windows enrollment code was not reusable after wrong-platform refusal: %d %s", right.Code, right.Body.String())
	}
}

// The generic one-line command is optional. A script request still returns the
// one-use code needed by the script, but does not add a command containing it.
func TestNoOneLinerIsRenderedUnlessAskedFor(t *testing.T) {
	srv, store := setupTestServer(t)
	defer store.Close()

	out := renderInstaller(t, srv, "linux", false)
	if _, ok := out["one_liner"]; ok {
		t.Fatalf("a one-line command was rendered for a request that did not ask for one")
	}
	_ = enrollmentCode(t, out)
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

// A public URL that answers with someone else's page must not end up in an
// install link. This is the defect an operator hit in the field: --hub-url
// pointed at a domain behind an identity proxy, the proxy answered the
// installer's unauthenticated fetch with a sign-in page, and the one-line
// command piped HTML into bash.
func TestProbeRejectsAnOriginThatIsNotThisHub(t *testing.T) {
	cases := []struct {
		name    string
		handler http.HandlerFunc
		want    bool
	}{
		{"this hub", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"valid admin key required"}`))
		}, true},
		{"identity proxy redirect", func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "https://example.cloudflareaccess.com/login", http.StatusFound)
		}, false},
		{"sign-in page served as 200", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html; charset=UTF-8")
			_, _ = w.Write([]byte("<!DOCTYPE html><html><body>Sign in</body></html>"))
		}, false},
		{"cdn error page", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(http.StatusBadGateway)
			_, _ = w.Write([]byte("<html>502</html>"))
		}, false},
		{"right status, wrong body type", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte("<html>401</html>"))
		}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			srv := httptest.NewServer(c.handler)
			defer srv.Close()
			if got := probeServesHub(srv.URL); got != c.want {
				t.Errorf("probeServesHub(%s) = %v, want %v", c.name, got, c.want)
			}
		})
	}
	if probeServesHub("") {
		t.Error("an empty public URL is not a usable origin")
	}
	if probeServesHub("http://127.0.0.1:1") {
		t.Error("an origin nothing answers on is not usable")
	}
}

// The URL carries a "?", which zsh treats as a glob and refuses when it matches
// nothing - so an unquoted install command fails outright on the target host.
func TestOneLinerQuotesTheURL(t *testing.T) {
	for _, p := range enrolmentPlatforms() {
		cmd := p.oneLiner("http://hub.example:9999", "abc123")
		if !strings.Contains(cmd, "\"http://hub.example:9999/bootstrap") &&
			!strings.Contains(cmd, "'http://hub.example:9999/bootstrap") {
			t.Errorf("%s one-liner leaves the URL unquoted: %s", p.key, cmd)
		}
	}
}
