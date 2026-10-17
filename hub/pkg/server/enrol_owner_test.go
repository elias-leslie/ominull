package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Opening an enrolment window waits for the owner: the first request creates
// nothing, the approved retry opens exactly the window approved, and closing
// one needs no approval.
func TestOpeningAnEnrolmentWindowWaitsForTheOwner(t *testing.T) {
	t.Parallel()
	srv, store := setupTestServer(t)
	defer store.Close()
	body := `{"label":"reinstall","cidrs":["10.0.0.0/24"],"hours":2,"max_uses":2}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/enrolment/windows", strings.NewReader(body))
	req.Header.Set("X-API-Key", "mock_admin_token")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusAccepted || !strings.Contains(w.Body.String(), `"approval_id"`) {
		t.Fatalf("first request: %d %s", w.Code, w.Body.String())
	}
	if windows, _ := store.ListEnrolmentWindows(); len(windows) != 0 {
		t.Fatalf("a window opened before the owner approved: %+v", windows)
	}
	var pending struct {
		ID      string `json:"approval_id"`
		Summary string `json:"summary"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &pending)
	if !strings.Contains(pending.Summary, "10.0.0.0/24") || !strings.Contains(pending.Summary, "at most 2 installs") {
		t.Fatalf("the owner is not shown what opens: %q", pending.Summary)
	}

	// The approval covers this window only: a wider one is refused with it.
	ownerOf(t, srv).approve(t, pending.ID)
	wider := httptest.NewRequest(http.MethodPost, "/api/v1/enrolment/windows", strings.NewReader(`{"label":"reinstall","cidrs":["10.0.0.0/16"],"hours":2,"max_uses":2}`))
	wider.Header.Set("X-API-Key", "mock_admin_token")
	wider.Header.Set(approvalHeader, pending.ID)
	w = httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, wider)
	if w.Code == http.StatusOK {
		t.Fatalf("a wider window was opened under the approval: %s", w.Body.String())
	}

	out := openTestWindow(t, srv, body)
	win, _ := out["window"].(map[string]interface{})
	id, _ := win["id"].(string)
	if id == "" {
		t.Fatalf("no window: %v", out)
	}
	del := httptest.NewRequest(http.MethodDelete, "/api/v1/enrolment/windows?id="+id, nil)
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
