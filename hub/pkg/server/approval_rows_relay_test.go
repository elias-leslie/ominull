package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"ominull/hub/pkg/response"
	"ominull/hub/pkg/responseauth"
	"ominull/hub/pkg/storage"
)

// The owner's Approvals rows decide maintenance asks: an enforce run inside
// the machine's window (machine time, from its agent's clock offset) runs
// without asking; Nightshift's tightening save makes it ask; loosening back
// takes the owner's tap on the signed approval_rules ask, relayed like any
// approval, then the save that names it.
func TestApprovalRowsRelayAndInWindowRun(t *testing.T) {
	t.Parallel()
	srv, store := setupTestServer(t)
	defer store.Close()
	srv.responseEnabled = true
	owner := ownerOf(t, srv)
	if err := store.UpsertEndpoint(storage.Endpoint{ID: "ep-lap", TenantID: "default", Hostname: "laptop-1", OS: "Windows 11 Home", Status: "online", LastSeenAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	syncRealPackage(t, srv, "cleanup.ps1")
	// The machine is 2 h east of UTC; its window is the two hours around now.
	off := 120
	srv.trust.mu.Lock()
	srv.trust.init()
	srv.trust.reports["ep-lap"] = trustReportSeen{report: response.AgentTrustReport{V: 1, UTCOffset: &off}, at: time.Now()}
	srv.trust.mu.Unlock()
	h := time.Now().UTC().Add(2 * time.Hour).Hour()
	if w := adminDo(srv, http.MethodPut, "/api/v1/maintenance/windows?endpoint_id=ep-lap", fmt.Sprintf(`{"ranges":["%02d:00-%02d:00"]}`, (h+23)%24, (h+1)%24)); w.Code != http.StatusOK {
		t.Fatalf("window: %d %s", w.Code, w.Body.String())
	}
	enforce := `{"endpoint_ids":["ep-lap"],"packages":["windows-cleanup"],"mode":"enforce"}`
	if w := adminPost(srv, "/api/v1/maintenance/run", enforce, ""); w.Code != http.StatusCreated {
		t.Fatalf("an in-window run should go without asking under the default rows: %d %s", w.Code, w.Body.String())
	}

	issue := adminPost(srv, "/api/v1/integrations/nightshift/approval-key", ``, "")
	var k struct {
		Key string `json:"key"`
	}
	_ = json.Unmarshal(issue.Body.Bytes(), &k)
	relay := func(method, path, body string) (int, map[string]any) {
		t.Helper()
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		req.Header.Set("X-API-Key", k.Key)
		w := httptest.NewRecorder()
		srv.Handler().ServeHTTP(w, req)
		var m map[string]any
		_ = json.Unmarshal(w.Body.Bytes(), &m)
		return w.Code, m
	}
	const rulesPath = "/api/v1/integrations/nightshift/approval-rules"
	if code, m := relay(http.MethodGet, rulesPath, ""); code != 200 || m["stored"] != false {
		t.Fatalf("defaults view: %d %v", code, m)
	}
	if code, _ := relay(http.MethodGet, rulesPath, ""); code != 200 {
		t.Fatal("relay GET")
	}
	strict := `{"rows":{"ominull.maintenance.in":"ask"},"session":null,"lab":[],"saved_at":"2026-10-18T13:00:00Z"}`
	if code, m := relay(http.MethodPost, rulesPath, strict); code != 200 || m["accepted"] != true {
		t.Fatalf("tightening save: %d %v", code, m)
	}
	pendingID(t, adminPost(srv, "/api/v1/maintenance/run", enforce, ""))

	loose := `{"rows":{"ominull.maintenance.in":"auto"},"session":null,"lab":[]}`
	if code, m := relay(http.MethodPost, rulesPath, loose); code != http.StatusForbidden || !strings.Contains(fmt.Sprint(m["error"]), "approval_rules") {
		t.Fatalf("loosening without the tap: %d %v", code, m)
	}
	code, m := relay(http.MethodPost, rulesPath+"/challenge", loose)
	ap, _ := m["approval"].(map[string]any)
	if code != 200 || ap == nil || ap["kind"] != responseauth.ApprovalKindRules {
		t.Fatalf("challenge: %d %v", code, m)
	}
	id := ap["id"].(string)
	if _, list := relay(http.MethodGet, "/api/v1/integrations/nightshift/approvals?wait=0", ""); !strings.Contains(fmt.Sprint(list), id) {
		t.Fatalf("the rules ask is not relayed: %v", list)
	}
	owner.approve(t, id)
	body := strings.Replace(loose, `"lab":[]`, `"lab":[],"approval_id":"`+id+`"`, 1)
	if code, m := relay(http.MethodPost, rulesPath, body); code != 200 || m["accepted"] != true {
		t.Fatalf("approved loosening: %d %v", code, m)
	}
	if w := adminPost(srv, "/api/v1/maintenance/run", enforce, ""); w.Code != http.StatusCreated {
		t.Fatalf("in-window run after loosening back: %d %s", w.Code, w.Body.String())
	}
	if code, _ := relay(http.MethodPost, rulesPath, `{"rows":{"ominull.nope":"auto"}}`); code != http.StatusBadRequest {
		t.Fatalf("unknown row: %d", code)
	}
	// The admin key cannot save rows: only Nightshift's relay key.
	if w := adminPost(srv, rulesPath, strict, ""); w.Code != http.StatusUnauthorized {
		t.Fatalf("admin key on the relay route: %d", w.Code)
	}
}
