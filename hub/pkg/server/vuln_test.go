package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"ominull/hub/pkg/vuln"
)

func TestServer_VulnAPI(t *testing.T) {
	srv, _, _, cleanup := setupTestServerWithResponse(t)
	defer cleanup()

	handler := srv.Handler()
	endpointID := "ep-vuln-node-1"

	// 1. Ingest CVE Catalog
	syncBody, _ := json.Marshal(map[string]interface{}{
		"vulnerabilities": []vuln.Vulnerability{
			{
				CVEID:       "CVE-2024-6387",
				Title:       "regreSSHion OpenSSH RCE",
				Description: "Signal handler race in OpenSSH server",
				Severity:    "HIGH",
				CVSS:        8.1,
				IsKEV:       true,
				CPEPattern:  "openssh",
				PublishedAt: time.Now(),
			},
		},
	})
	reqSync := httptest.NewRequest(http.MethodPost, "/api/v1/vulnerabilities/sync", bytes.NewReader(syncBody))
	reqSync.Header.Set("X-API-Key", "test-admin-key-12345")
	reqSync.Header.Set("Content-Type", "application/json")
	wSync := httptest.NewRecorder()
	handler.ServeHTTP(wSync, reqSync)

	if wSync.Code != http.StatusOK {
		t.Fatalf("sync vulnerabilities returned %d: %s", wSync.Code, wSync.Body.String())
	}

	// 2. Report Installed Software from Endpoint
	reportSoftwareBody, _ := json.Marshal(map[string]interface{}{
		"endpoint_id": endpointID,
		"packages": []vuln.InstalledSoftware{
			{
				Source:       "dpkg",
				Vendor:       "Ubuntu",
				Product:      "openssh-server",
				Version:      "1:8.9p1-3ubuntu0.6",
				Architecture: "amd64",
			},
		},
	})
	reqSW := httptest.NewRequest(http.MethodPost, "/api/v1/software", bytes.NewReader(reportSoftwareBody))
	reqSW.Header.Set("X-API-Key", "test-admin-key-12345")
	reqSW.Header.Set("Content-Type", "application/json")
	wSW := httptest.NewRecorder()
	handler.ServeHTTP(wSW, reqSW)

	if wSW.Code != http.StatusCreated {
		t.Fatalf("report software returned %d: %s", wSW.Code, wSW.Body.String())
	}

	// 3. Query Correlated Vulnerabilities
	reqQuery := httptest.NewRequest(http.MethodGet, "/api/v1/vulnerabilities?endpoint_id="+endpointID, nil)
	reqQuery.Header.Set("X-API-Key", "test-admin-key-12345")
	wQuery := httptest.NewRecorder()
	handler.ServeHTTP(wQuery, reqQuery)

	if wQuery.Code != http.StatusOK {
		t.Fatalf("query vulnerabilities returned %d: %s", wQuery.Code, wQuery.Body.String())
	}

	var resp struct {
		Vulnerabilities []vuln.VulnerabilityMatch `json:"vulnerabilities"`
	}
	if err := json.NewDecoder(wQuery.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode vulnerabilities response: %v", err)
	}

	if len(resp.Vulnerabilities) != 1 {
		t.Fatalf("expected 1 correlated vulnerability, got %d", len(resp.Vulnerabilities))
	}
	if resp.Vulnerabilities[0].CVEID != "CVE-2024-6387" {
		t.Fatalf("unexpected cve id: %s", resp.Vulnerabilities[0].CVEID)
	}

	// 4. Query Software Inventory via GET /api/v1/software
	reqGetSW := httptest.NewRequest(http.MethodGet, "/api/v1/software?endpoint_id="+endpointID, nil)
	reqGetSW.Header.Set("X-API-Key", "test-admin-key-12345")
	wGetSW := httptest.NewRecorder()
	handler.ServeHTTP(wGetSW, reqGetSW)

	if wGetSW.Code != http.StatusOK {
		t.Fatalf("query software returned %d: %s", wGetSW.Code, wGetSW.Body.String())
	}

	var swResp vuln.SoftwareInventoryPage
	if err := json.NewDecoder(wGetSW.Body).Decode(&swResp); err != nil {
		t.Fatalf("failed to decode software page: %v", err)
	}
	if swResp.Total != 1 || len(swResp.Packages) != 1 {
		t.Fatalf("expected 1 package in inventory, got total=%d len=%d", swResp.Total, len(swResp.Packages))
	}
	if swResp.Packages[0].Product != "openssh-server" {
		t.Fatalf("unexpected package product: %s", swResp.Packages[0].Product)
	}

	// 5. Query Software Inventory with search filter
	reqSearchSW := httptest.NewRequest(http.MethodGet, "/api/v1/software?endpoint_id="+endpointID+"&search=openssh", nil)
	reqSearchSW.Header.Set("X-API-Key", "test-admin-key-12345")
	wSearchSW := httptest.NewRecorder()
	handler.ServeHTTP(wSearchSW, reqSearchSW)

	if wSearchSW.Code != http.StatusOK {
		t.Fatalf("search software returned %d: %s", wSearchSW.Code, wSearchSW.Body.String())
	}
	var searchResp vuln.SoftwareInventoryPage
	if err := json.NewDecoder(wSearchSW.Body).Decode(&searchResp); err != nil {
		t.Fatalf("failed to decode search page: %v", err)
	}
	if searchResp.Total != 1 {
		t.Fatalf("expected 1 search result, got %d", searchResp.Total)
	}

	// 6. Delete Software Inventory via DELETE /api/v1/software
	reqDelSW := httptest.NewRequest(http.MethodDelete, "/api/v1/software?endpoint_id="+endpointID, nil)
	reqDelSW.Header.Set("X-API-Key", "test-admin-key-12345")
	wDelSW := httptest.NewRecorder()
	handler.ServeHTTP(wDelSW, reqDelSW)

	if wDelSW.Code != http.StatusOK {
		t.Fatalf("delete software returned %d: %s", wDelSW.Code, wDelSW.Body.String())
	}

	// Verify inventory is cleared
	reqAfterDel := httptest.NewRequest(http.MethodGet, "/api/v1/software?endpoint_id="+endpointID, nil)
	reqAfterDel.Header.Set("X-API-Key", "test-admin-key-12345")
	wAfterDel := httptest.NewRecorder()
	handler.ServeHTTP(wAfterDel, reqAfterDel)

	var afterDelResp vuln.SoftwareInventoryPage
	_ = json.NewDecoder(wAfterDel.Body).Decode(&afterDelResp)
	if afterDelResp.Total != 0 {
		t.Fatalf("expected 0 packages after delete, got %d", afterDelResp.Total)
	}
}
