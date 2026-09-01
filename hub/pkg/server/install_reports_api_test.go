package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestReportInstallErrorAndRetrieve(t *testing.T) {
	srv, store := setupTestServer(t)
	defer store.Close()

	// 1. Submit error report without authentication (as visitor on /install)
	payload := `{"error_output":"curl: (56) OpenSSL SSL_read: error:0A00045C:SSL routines::tlsv13 alert certificate required","platform":"windows","window_id":"win-test-456","system_info":{"browser":"Chrome 128","os":"Windows NT 10.0"}}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/enrolment/report-error", bytes.NewBufferString(payload))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.handleReportInstallError(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("handleReportInstallError returned status %d, want 200: %s", w.Code, w.Body.String())
	}

	var res struct {
		Status string `json:"status"`
		ID     string `json:"id"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &res); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if res.ID == "" || !strings.HasPrefix(res.ID, "rpt_") {
		t.Fatalf("expected report id starting with rpt_, got %q", res.ID)
	}

	// 2. Query reports as admin
	wList := call(srv, requireAdmin(srv.handleInstallReports), http.MethodGet, "/api/v1/enrolment/install-errors", "mock_admin_token", "")
	if wList.Code != http.StatusOK {
		t.Fatalf("handleInstallReports GET returned status %d, want 200: %s", wList.Code, wList.Body.String())
	}
	var listRes struct {
		Status  string `json:"status"`
		Count   int    `json:"count"`
		Reports []struct {
			ID          string                 `json:"id"`
			ClientIP    string                 `json:"client_ip"`
			Platform    string                 `json:"platform"`
			ErrorOutput string                 `json:"error_output"`
			SystemInfo  map[string]interface{} `json:"system_info"`
		} `json:"reports"`
	}
	if err := json.Unmarshal(wList.Body.Bytes(), &listRes); err != nil {
		t.Fatalf("failed to decode list response: %v", err)
	}
	if listRes.Count != 1 {
		t.Fatalf("expected count 1, got %d", listRes.Count)
	}
	if listRes.Reports[0].ID != res.ID {
		t.Errorf("expected report ID %q, got %q", res.ID, listRes.Reports[0].ID)
	}
	if listRes.Reports[0].Platform != "windows" {
		t.Errorf("expected platform windows, got %q", listRes.Reports[0].Platform)
	}
	if !strings.Contains(listRes.Reports[0].ErrorOutput, "tlsv13 alert certificate required") {
		t.Errorf("error output not preserved: %q", listRes.Reports[0].ErrorOutput)
	}

	// 3. Query individual report as admin
	wGet := call(srv, requireAdmin(srv.handleInstallReports), http.MethodGet, "/api/v1/enrolment/install-errors?id="+res.ID, "mock_admin_token", "")
	if wGet.Code != http.StatusOK {
		t.Fatalf("handleInstallReports single GET returned status %d, want 200", wGet.Code)
	}

	// 4. Non-admin cannot read reports
	wTenant := call(srv, requireAdmin(srv.handleInstallReports), http.MethodGet, "/api/v1/enrolment/install-errors", "mock_tenant_token", "")
	if wTenant.Code != http.StatusForbidden {
		t.Errorf("tenant key reached install-errors: got %d, want 403", wTenant.Code)
	}
}
