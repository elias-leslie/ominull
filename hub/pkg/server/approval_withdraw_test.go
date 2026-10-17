package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// A requester that stops waiting withdraws its own pending approval: it
// leaves the pending list (so the relay closes the owner's ask) and the
// request can no longer be sent under it.
func TestRequesterWithdrawsItsPendingApproval(t *testing.T) {
	t.Parallel()
	s, db := setupTestServer(t)
	defer db.Close()
	s.agentVersion = "1.2.0"
	seedSignedRelease(t, s.binaryDir, "ominull-agent_1.2.0_amd64.deb")
	seedEndpointWithCapability(t, db, "ep-1", "Linux", "1.1.0", "deb")
	body := `{"endpoint_ids":["ep-1"],"version":"1.2.0"}`
	send := func(method, path, body, approval string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		r.Header.Set("X-API-Key", "mock_admin_token")
		if approval != "" {
			r.Header.Set(approvalHeader, approval)
		}
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		return w
	}
	w := send("POST", "/api/v1/agents/update", body, "")
	if w.Code != http.StatusAccepted {
		t.Fatalf("first send: %d %s", w.Code, w.Body.String())
	}
	var pending struct {
		ID string `json:"approval_id"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &pending)

	w = send("DELETE", "/api/v1/approvals?id="+pending.ID, "", "")
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"state":"denied"`) {
		t.Fatalf("withdraw: %d %s", w.Code, w.Body.String())
	}
	if list := ownerOf(t, s).auth.PendingApprovals(); len(list) != 0 {
		t.Fatalf("withdrawn approval still pending: %+v", list)
	}
	if w = send("DELETE", "/api/v1/approvals?id="+pending.ID, "", ""); w.Code != http.StatusConflict {
		t.Fatalf("second withdraw: %d %s", w.Code, w.Body.String())
	}
	if w = send("POST", "/api/v1/agents/update", body, pending.ID); w.Code < 400 {
		t.Fatalf("request ran under a withdrawn approval: %d %s", w.Code, w.Body.String())
	}
	if w = send("DELETE", "/api/v1/approvals?id=nope", "", ""); w.Code < 400 {
		t.Fatalf("unknown approval: %d", w.Code)
	}
}
