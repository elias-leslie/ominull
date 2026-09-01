package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
)

// The portal is the one route on the hub that hands out an enrollment profile
// to a caller holding no credential at all. These tests cover its network and
// passcode boundary plus body-only code redemption.

// portalGet and portalPost drive the portal as a browser on the LAN would, with
// RemoteAddr standing in for where the request came from.
func portalGet(t *testing.T, srv *Server, from string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest("GET", "/enrol", nil)
	req.RemoteAddr = from + ":54321"
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	return w
}

func portalPost(t *testing.T, srv *Server, from, form string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest("POST", "/enrol", strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.RemoteAddr = from + ":54321"
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	return w
}

func openTestWindow(t *testing.T, srv *Server, body string) map[string]interface{} {
	t.Helper()
	w := postJSON(t, srv, "/api/v1/enrolment/windows", body)
	if w.Code != http.StatusOK {
		t.Fatalf("opening a window returned %d: %s", w.Code, w.Body.String())
	}
	var out map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("decoding: %v", err)
	}
	return out
}

func portalEnrollmentCode(t *testing.T, body string) string {
	t.Helper()
	code := regexp.MustCompile(`one_[0-9a-f]{64}`).FindString(body)
	if code == "" {
		t.Fatalf("portal did not show a body-only enrollment code: %s", body)
	}
	return code
}

// With no window open, the portal must hand out nothing to anyone. This is the
// default state of the hub, and it is the state that matters most.
func TestThePortalGivesNothingWithNoWindowOpen(t *testing.T) {
	srv, store := setupTestServer(t)
	defer store.Close()

	for _, from := range []string{"10.0.0.57", "127.0.0.1", "8.8.8.8"} {
		w := portalPost(t, srv, from, "platform=linux")
		body := w.Body.String()
		if strings.Contains(body, "one_") || strings.Contains(body, "?t=") {
			t.Fatalf("%s was handed an install command with no enrolment window open", from)
		}
		if !strings.Contains(body, "not authorised") {
			t.Fatalf("%s should be told it is not authorised, got: %s", from, body)
		}
	}
}

// The happy path, and the shape the whole feature exists for: an administrator
// opens a window for the LAN, and a machine on it gets its own command.
func TestAMachineOnAnOpenNetworkGetsItsOwnCommand(t *testing.T) {
	srv, store := setupTestServer(t)
	defer store.Close()

	openTestWindow(t, srv, `{"label":"office","cidrs":["10.0.0.0/24"],"hours":4}`)

	w := portalPost(t, srv, "10.0.0.57", "platform=linux")
	if w.Code != http.StatusOK {
		t.Fatalf("the portal returned %d", w.Code)
	}
	body := w.Body.String()
	if !strings.Contains(body, "/bootstrap.sh") || strings.Contains(body, "?t=") {
		t.Fatalf("no install command on the page: %s", body)
	}
	// The command is generic; the displayed code is redeemed in the request body.
	code := portalEnrollmentCode(t, body)
	req := httptest.NewRequest("POST", "/api/v1/enrollment/redeem", strings.NewReader(`{"code":"`+code+`","platform":"linux","hostname":"portal-linux"}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("the portal's own command did not redeem: %d %s", rec.Code, rec.Body.String())
	}
	rec2 := httptest.NewRecorder()
	req2 := httptest.NewRequest("POST", "/api/v1/enrollment/redeem", strings.NewReader(`{"code":"`+code+`","platform":"linux","hostname":"portal-linux-2"}`))
	req2.Header.Set("Content-Type", "application/json")
	srv.Handler().ServeHTTP(rec2, req2)
	if rec2.Code == http.StatusOK {
		t.Fatal("a portal-minted enrollment code was redeemable twice")
	}
}

// A window for one network must not serve the next one over.
func TestThePortalRefusesAMachineOutsideTheWindow(t *testing.T) {
	srv, store := setupTestServer(t)
	defer store.Close()

	openTestWindow(t, srv, `{"cidrs":["10.0.0.0/24"],"hours":4}`)

	w := portalPost(t, srv, "10.0.9.57", "platform=linux")
	if strings.Contains(w.Body.String(), "one_") || strings.Contains(w.Body.String(), "?t=") {
		t.Fatal("a machine outside the window was handed an install command")
	}
}

// Merely looking at the page must not spend the budget: link previews, scanners
// and browser prefetch all issue GETs.
func TestLookingAtThePortalSpendsNothing(t *testing.T) {
	srv, store := setupTestServer(t)
	defer store.Close()

	openTestWindow(t, srv, `{"cidrs":["10.0.0.0/24"],"hours":4,"max_uses":1}`)

	for i := 0; i < 3; i++ {
		if w := portalGet(t, srv, "10.0.0.57"); w.Code != http.StatusOK {
			t.Fatalf("GET %d returned %d", i, w.Code)
		}
	}
	w := portalPost(t, srv, "10.0.0.57", "platform=linux")
	if !strings.Contains(w.Body.String(), "one_") {
		t.Fatalf("three page loads consumed the only use: %s", w.Body.String())
	}
}

// A window with a passcode must ask for it, and must not leak the ticket to a
// caller that guesses wrong.
func TestAPasscodeWindowAsksBeforeItGives(t *testing.T) {
	srv, store := setupTestServer(t)
	defer store.Close()

	openTestWindow(t, srv, `{"cidrs":["10.0.0.0/24"],"hours":4,"passcode":"open-sesame"}`)

	w := portalGet(t, srv, "10.0.0.57")
	if !strings.Contains(w.Body.String(), "passcode") {
		t.Fatalf("a passcode window did not ask for one: %s", w.Body.String())
	}

	w = portalPost(t, srv, "10.0.0.57", "platform=linux&passcode=wrong")
	if strings.Contains(w.Body.String(), "?t=") {
		t.Fatal("the wrong passcode was handed an install command")
	}

	w = portalPost(t, srv, "10.0.0.57", "platform=linux&passcode=open-sesame")
	if !strings.Contains(w.Body.String(), "one_") {
		t.Fatalf("the right passcode was refused: %s", w.Body.String())
	}
}

// Revoking has to take effect on the next request, because the reason an
// operator revokes is that something is wrong right now.
func TestRevokingAWindowStopsThePortalAtOnce(t *testing.T) {
	srv, store := setupTestServer(t)
	defer store.Close()

	out := openTestWindow(t, srv, `{"cidrs":["10.0.0.0/24"],"hours":4}`)
	id := out["window"].(map[string]interface{})["id"].(string)

	if w := portalPost(t, srv, "10.0.0.57", "platform=linux"); !strings.Contains(w.Body.String(), "one_") {
		t.Fatal("the window did not work before revocation")
	}

	req := httptest.NewRequest("DELETE", "/api/v1/enrolment/windows?id="+id, nil)
	req.Header.Set("X-API-Key", "mock_admin_token")
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("revoking returned %d: %s", rec.Code, rec.Body.String())
	}

	if w := portalPost(t, srv, "10.0.0.57", "platform=linux"); strings.Contains(w.Body.String(), "one_") {
		t.Fatal("a revoked window kept handing out install commands")
	}
}

// Opening a window is an administrative act. A tenant key must not be able to
// pre-authorise a network to join the fleet.
func TestOnlyAnAdminMayOpenAWindow(t *testing.T) {
	srv, store := setupTestServer(t)
	defer store.Close()

	req := httptest.NewRequest("POST", "/api/v1/enrolment/windows",
		strings.NewReader(`{"cidrs":["10.0.0.0/24"],"hours":4}`))
	req.Header.Set("X-API-Key", "mock_tenant_token")
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code == http.StatusOK {
		t.Fatalf("a tenant key opened an enrolment window: %d", rec.Code)
	}
}

// A window may not be left open indefinitely.
func TestAWindowMayNotOutliveAWeek(t *testing.T) {
	srv, store := setupTestServer(t)
	defer store.Close()

	w := postJSON(t, srv, "/api/v1/enrolment/windows", `{"cidrs":["10.0.0.0/24"],"hours":800}`)
	if w.Code == http.StatusOK {
		t.Fatal("a window was opened for a month")
	}
}

// The page carries a live enrollment code, so it must not be cacheable and must
// not leak its URL onward in a Referer.
func TestThePortalPageIsNotCacheable(t *testing.T) {
	srv, store := setupTestServer(t)
	defer store.Close()

	openTestWindow(t, srv, `{"cidrs":["10.0.0.0/24"],"hours":4}`)
	w := portalPost(t, srv, "10.0.0.57", "platform=linux")

	if got := w.Header().Get("Cache-Control"); !strings.Contains(got, "no-store") {
		t.Fatalf("the portal page is cacheable: Cache-Control=%q", got)
	}
	if got := w.Header().Get("Referrer-Policy"); got != "no-referrer" {
		t.Fatalf("the portal page leaks its URL onward: Referrer-Policy=%q", got)
	}
	if got := w.Header().Get("Content-Security-Policy"); !strings.Contains(got, "default-src 'none'") {
		t.Fatalf("the portal page has no content policy: %q", got)
	}
}

// The portal offers the command for the platform asked for, and the code is
// bound to it - a Windows code must not redeem as Linux.
func TestAPortalEnrollmentCodeIsBoundToItsPlatform(t *testing.T) {
	srv, store := setupTestServer(t)
	defer store.Close()

	openTestWindow(t, srv, `{"cidrs":["10.0.0.0/24"],"hours":4}`)
	w := portalPost(t, srv, "10.0.0.57", "platform=windows")
	body := w.Body.String()
	if !strings.Contains(body, "/bootstrap.ps1") || strings.Contains(body, "?t=") {
		t.Fatalf("asking for Windows did not give a Windows command: %s", body)
	}
	code := portalEnrollmentCode(t, body)
	rec := httptest.NewRecorder()
	wrong := httptest.NewRequest("POST", "/api/v1/enrollment/redeem", strings.NewReader(`{"code":"`+code+`","platform":"linux","hostname":"wrong-linux"}`))
	wrong.Header.Set("Content-Type", "application/json")
	srv.Handler().ServeHTTP(rec, wrong)
	if rec.Code == http.StatusOK {
		t.Fatal("a Windows enrollment code redeemed as Linux")
	}
}

// The expiry is read by somebody standing at a laptop, not an operator reading
// logs, so it must not be a Go duration string.
func TestThePortalSaysHowLongInEnglish(t *testing.T) {
	srv, store := setupTestServer(t)
	defer store.Close()

	openTestWindow(t, srv, `{"cidrs":["10.0.0.0/24"],"hours":4}`)
	body := portalPost(t, srv, "10.0.0.57", "platform=linux").Body.String()

	if strings.Contains(body, "30m0s") {
		t.Fatalf("the portal printed a Go duration at the visitor: %s", body)
	}
	if !strings.Contains(body, "30 minutes") {
		t.Fatalf("the portal did not say how long the link lasts: %s", body)
	}
}

// A guess at the operating system is a convenience, never an authorisation: the
// ticket must be minted for what the visitor picked.
func TestThePortalGuessesTheOSButObeysThePick(t *testing.T) {
	srv, store := setupTestServer(t)
	defer store.Close()
	openTestWindow(t, srv, `{"cidrs":["10.0.0.0/24"],"hours":4,"max_uses":10}`)

	for _, tc := range []struct{ ua, want string }{
		{"Mozilla/5.0 (Windows NT 10.0; Win64; x64)", "windows"},
		{"Mozilla/5.0 (X11; Linux x86_64)", "linux"},
	} {
		if got := portalOSFromAgent(tc.ua); got != tc.want {
			t.Errorf("%q was read as %s, want %s", tc.ua, got, tc.want)
		}
	}

	// A Windows browser that picks Linux gets Linux.
	req := httptest.NewRequest("POST", "/enrol", strings.NewReader("platform=linux"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)")
	req.RemoteAddr = "10.0.0.57:5000"
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if !strings.Contains(rec.Body.String(), "/bootstrap.sh") || strings.Contains(rec.Body.String(), "?t=") {
		t.Fatalf("a Windows browser asking for Linux did not get the Linux command: %s", rec.Body.String())
	}
}
