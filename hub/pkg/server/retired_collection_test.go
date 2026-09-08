package server

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRetiredDNSRoutesAreNotConsolePages(t *testing.T) {
	srv, store := setupTestServer(t)
	defer store.Close()
	for _, path := range []string{"/api/v1/dns/status", "/api/v1/dns/events", "/api/v1/dns/policy", "/api/v1/dns/policy/test"} {
		r := httptest.NewRequest(http.MethodGet, path, nil)
		r.Header.Set("X-API-Key", "mock_admin_token")
		w := httptest.NewRecorder()
		srv.Handler().ServeHTTP(w, r)
		if w.Code != http.StatusNotFound {
			t.Errorf("retired %s returned %d", path, w.Code)
		}
	}
}
