package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The enforcement rules an operator writes here are carried out by an agent
// running as root on every endpoint in the fleet. The ones that cannot be undone
// are the ones worth a test.

// TestTheHubRefusesToQuarantineItself. A mesh quarantine is a drop rule in both
// directions on every endpoint. Pointed at the hub, it stops the fleet from
// reaching the only host that can withdraw it: the console would go on offering
// an "unquarantine" button whose order no agent could ever receive.
func TestTheHubRefusesToQuarantineItself(t *testing.T) {
	srv, store := setupTestServer(t)
	defer store.Close()

	// setupTestServer points --hub-url at 10.0.0.57.
	for _, addr := range []string{"10.0.0.57", "127.0.0.1", "::1"} {
		body := strings.NewReader(`{"target_ip":"` + addr + `","reason":"test"}`)
		req := httptest.NewRequest("POST", "/api/v1/mesh/quarantine", body)
		req.Header.Set("X-API-Key", "mock_admin_token")
		w := httptest.NewRecorder()
		srv.Handler().ServeHTTP(w, req)

		if w.Code != http.StatusConflict {
			t.Errorf("quarantining the hub at %s returned %d, want 409: the fleet would have been cut off from its controller", addr, w.Code)
			continue
		}
		if !strings.Contains(w.Body.String(), "own address") {
			t.Errorf("the refusal for %s does not say why: %s", addr, w.Body.String())
		}
	}

	// Nothing may have been recorded by a refused order.
	peers, err := store.GetQuarantinedPeers()
	if err != nil {
		t.Fatalf("listing quarantined peers: %v", err)
	}
	if len(peers) != 0 {
		t.Errorf("a refused quarantine still wrote %d peer(s) to the database", len(peers))
	}
}

// TestAnOrdinaryPeerIsStillQuarantined guards the check above from being widened
// into one that refuses everything.
func TestAnOrdinaryPeerIsStillQuarantined(t *testing.T) {
	srv, store := setupTestServer(t)
	defer store.Close()

	body := strings.NewReader(`{"target_ip":"10.0.0.77","reason":"test"}`)
	req := httptest.NewRequest("POST", "/api/v1/mesh/quarantine", body)
	req.Header.Set("X-API-Key", "mock_admin_token")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("quarantining an ordinary peer returned %d: %s", w.Code, w.Body.String())
	}
	var out map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("decoding the reply: %v", err)
	}
	if out["status"] != "quarantined" {
		t.Errorf("status is %v, want quarantined", out["status"])
	}
}
