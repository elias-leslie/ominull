package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Opening an enrolment window is a loosening the authority signs at once: the
// first request opens exactly the window asked for and the audit says it was
// authorized; closing one needs no authorization.
func TestOpeningAnEnrolmentWindowIsAuthorizedAtOnce(t *testing.T) {
	t.Parallel()
	srv, store := setupTestServer(t)
	defer store.Close()
	body := `{"label":"reinstall","cidrs":["10.0.0.0/24"],"hours":2,"max_uses":2}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/enrolment/windows", strings.NewReader(body))
	req.Header.Set("X-API-Key", "mock_admin_token")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK || strings.Contains(w.Body.String(), "approval_id") {
		t.Fatalf("first request: %d %s", w.Code, w.Body.String())
	}
	windows, _ := store.ListEnrolmentWindows()
	if len(windows) != 1 || windows[0].MaxUses != 2 || len(windows[0].CIDRs) != 1 || windows[0].CIDRs[0] != "10.0.0.0/24" {
		t.Fatalf("the window asked for did not open: %+v", windows)
	}
	var out struct {
		Window struct {
			ID string `json:"id"`
		} `json:"window"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	if out.Window.ID == "" {
		t.Fatalf("no window in the answer: %s", w.Body.String())
	}
	logs, _ := store.ListAuditLogs("", 50)
	authorized := false
	for _, l := range logs {
		if l.Action == "ACTION_AUTHORIZED" && strings.Contains(l.Details, "10.0.0.0/24") {
			authorized = true
		}
	}
	if !authorized {
		t.Fatalf("opening the window left no ACTION_AUTHORIZED row: %+v", logs)
	}

	del := httptest.NewRequest(http.MethodDelete, "/api/v1/enrolment/windows?id="+out.Window.ID, nil)
	del.Header.Set("X-API-Key", "mock_admin_token")
	w = httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, del)
	if w.Code != http.StatusOK {
		t.Fatalf("closing a window: %d %s", w.Code, w.Body.String())
	}
}

// The portal listener answers the portal and the generic bootstrap scripts,
// and nothing else: no console, no API, no downloads.
func TestPortalListenerServesOnlyThePortal(t *testing.T) {
	t.Parallel()
	srv, store := setupTestServer(t)
	defer store.Close()
	h := srv.portalMux()
	get := func(path string) int {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.RemoteAddr = "10.0.0.9:5555"
		req.Header.Set("X-API-Key", "mock_admin_token")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		return w.Code
	}
	for _, p := range []string{"/install", "/enrol", "/bootstrap.sh", "/bootstrap.ps1"} {
		if code := get(p); code != http.StatusOK {
			t.Errorf("%s: %d", p, code)
		}
	}
	for _, p := range []string{"/", "/console/terminal", "/api/v1/hierarchy", "/api/v1/enrolment/windows", "/download/x.deb", "/api/v1/terminal/ws/operator"} {
		if code := get(p); code != http.StatusNotFound {
			t.Errorf("%s answered %d on the portal listener", p, code)
		}
	}
}
