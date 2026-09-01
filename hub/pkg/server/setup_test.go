package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"ominull/hub/pkg/setup"
)

func setupCookie(t *testing.T, w *httptest.ResponseRecorder) *http.Cookie {
	t.Helper()
	resp := &http.Response{Header: w.Header()}
	cookies := resp.Cookies()
	if len(cookies) != 1 || cookies[0].Name != setupSessionCookie {
		t.Fatalf("setup session did not set its cookie: %#v", cookies)
	}
	return cookies[0]
}

func setupCSRFToken(t *testing.T, body string) string {
	t.Helper()
	match := regexp.MustCompile(`"csrf":"([^"]+)"`).FindStringSubmatch(body)
	if len(match) != 2 || match[1] == "" {
		t.Fatalf("setup document did not contain a CSRF token")
	}
	return match[1]
}

func setupCall(t *testing.T, srv *Server, method, path, body string, cookie *http.Cookie, csrf string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	if cookie != nil {
		req.AddCookie(cookie)
	}
	if csrf != "" {
		req.Header.Set("X-CSRF-Token", csrf)
	}
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	return w
}

func TestFirstRunSetupConsumesLocalTokenAndUsesCSRFSession(t *testing.T) {
	srv, store := setupTestServer(t)
	defer store.Close()

	root := t.TempDir()
	tokenPath := filepath.Join(root, "setup.token")
	envPath := filepath.Join(root, "hub.env")
	if err := setup.Ensure(tokenPath); err != nil {
		t.Fatalf("setup.Ensure: %v", err)
	}
	raw, err := os.ReadFile(tokenPath)
	if err != nil {
		t.Fatalf("read setup token: %v", err)
	}
	token := strings.TrimSpace(string(raw))
	srv.SetSetupPaths(tokenPath, envPath, filepath.Join(root, "ominull.db"), filepath.Join(root, "admin.key"), root)

	gate := setupCall(t, srv, http.MethodGet, "/setup", "", nil, "")
	if gate.Code != http.StatusOK || !strings.Contains(gate.Body.String(), "ominullctl setup-token") {
		t.Fatalf("setup gate did not render: %d %s", gate.Code, gate.Body.String())
	}

	opened := setupCall(t, srv, http.MethodPost, "/api/v1/setup/session", `{"token":"`+token+`"}`, nil, "")
	if opened.Code != http.StatusOK {
		t.Fatalf("valid setup token refused: %d %s", opened.Code, opened.Body.String())
	}
	cookie := setupCookie(t, opened)

	replay := setupCall(t, srv, http.MethodPost, "/api/v1/setup/session", `{"token":"`+token+`"}`, nil, "")
	if replay.Code != http.StatusUnauthorized {
		t.Fatalf("setup token was reusable: %d %s", replay.Code, replay.Body.String())
	}

	wizard := setupCall(t, srv, http.MethodGet, "/setup", "", cookie, "")
	if wizard.Code != http.StatusOK || !strings.Contains(wizard.Body.String(), "Ominull setup wizard") {
		t.Fatalf("setup session did not open wizard: %d %s", wizard.Code, wizard.Body.String())
	}
	csrf := setupCSRFToken(t, wizard.Body.String())

	missingCSRF := setupCall(t, srv, http.MethodPost, "/api/v1/setup/apply", `{}`, cookie, "")
	if missingCSRF.Code != http.StatusForbidden {
		t.Fatalf("setup mutation without CSRF returned %d: %s", missingCSRF.Code, missingCSRF.Body.String())
	}

	apply := setupCall(t, srv, http.MethodPost, "/api/v1/setup/apply", `{"configuration":{"network_mode":"lan","tls_mode":"self-issued","console_url":"http://127.0.0.1:9999","agent_url":"https://127.0.0.1:9443"},"local_admin_email":"operator@example.invalid"}`, cookie, csrf)
	if apply.Code != http.StatusOK {
		t.Fatalf("setup apply failed: %d %s", apply.Code, apply.Body.String())
	}
	env, err := os.ReadFile(envPath)
	if err != nil {
		t.Fatalf("read package environment: %v", err)
	}
	if strings.Contains(string(env), "device_credential") || strings.Contains(string(env), "client_secret") || strings.Contains(string(env), "service-token") {
		t.Fatalf("package environment contains secret material: %s", env)
	}

	status := setupCall(t, srv, http.MethodGet, "/api/v1/setup/status", "", cookie, "")
	if status.Code != http.StatusOK {
		t.Fatalf("setup status failed with session cookie: %d %s", status.Code, status.Body.String())
	}
	var statusBody struct {
		SetupComplete bool `json:"setup_complete"`
		HasFailures   bool `json:"has_failures"`
	}
	if err := json.Unmarshal(status.Body.Bytes(), &statusBody); err != nil {
		t.Fatalf("decode setup status: %v", err)
	}
	if statusBody.SetupComplete || !statusBody.HasFailures {
		t.Fatalf("setup status did not retain incomplete proof state: %#v", statusBody)
	}
}

func TestSetupTokenIsNotAcceptedFromURL(t *testing.T) {
	srv, store := setupTestServer(t)
	defer store.Close()
	path := filepath.Join(t.TempDir(), "setup.token")
	if err := setup.Ensure(path); err != nil {
		t.Fatal(err)
	}
	srv.SetSetupPaths(path, "", "", "", "")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/setup/session?token="+strings.TrimSpace(string(raw)), strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("setup token in URL was accepted: %d %s", w.Code, w.Body.String())
	}
}
