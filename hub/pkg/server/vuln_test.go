package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
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

func TestServer_VulnSnapshotsAndCatalog(t *testing.T) {
	srv, _, _, cleanup := setupTestServerWithResponse(t)
	defer cleanup()

	handler := srv.Handler()

	nvdRaw := `{
		"format": "NVD_CVE",
		"version": "2.0",
		"totalResults": 2,
		"vulnerabilities": [
			{
				"cve": {
					"id": "CVE-2024-6387",
					"descriptions": [{"lang": "en", "value": "Signal handler race in OpenSSH server"}],
					"metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 8.1, "baseSeverity": "HIGH"}}]},
					"configurations": [{"nodes": [{"cpeMatch": [{"vulnerable": true, "criteria": "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*"}]}]}]
				}
			},
			{
				"cve": {
					"id": "CVE-2023-4863",
					"descriptions": [{"lang": "en", "value": "Heap buffer overflow in libwebp"}],
					"metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL"}}]},
					"configurations": [{"nodes": [{"cpeMatch": [{"vulnerable": true, "criteria": "cpe:2.3:a:webmproject:libwebp:*:*:*:*:*:*:*:*"}]}]}]
				}
			}
		]
	}`

	cisaRaw := `{
		"catalogVersion": "2026.09.04",
		"count": 1,
		"vulnerabilities": [
			{
				"cveID": "CVE-2024-6387",
				"vendorProject": "OpenBSD",
				"product": "OpenSSH",
				"vulnerabilityName": "OpenSSH Race Condition",
				"dateAdded": "2024-07-08",
				"shortDescription": "Signal handler race condition leads to RCE",
				"requiredAction": "Apply vendor updates",
				"dueDate": "2024-07-29",
				"knownRansomwareCampaignUse": "Known"
			}
		]
	}`

	epssRaw := `{
		"status": "OK",
		"total": 1,
		"data": [
			{"cve": "CVE-2024-6387", "epss": "0.925", "percentile": "0.989", "date": "2026-09-04"}
		]
	}`

	// 1. POST /api/v1/vulnerabilities/sync with raw feeds
	syncReqBody, _ := json.Marshal(map[string]interface{}{
		"snapshot_id":  "snap-20260904-api-1",
		"metadata":     `{"source":"nist_nvd_cisa_epss"}`,
		"raw_nvd":      nvdRaw,
		"raw_cisa_kev": cisaRaw,
		"raw_epss":     epssRaw,
	})

	reqSync := httptest.NewRequest(http.MethodPost, "/api/v1/vulnerabilities/sync", bytes.NewReader(syncReqBody))
	reqSync.Header.Set("X-API-Key", "test-admin-key-12345")
	reqSync.Header.Set("Content-Type", "application/json")
	wSync := httptest.NewRecorder()
	handler.ServeHTTP(wSync, reqSync)

	if wSync.Code != http.StatusOK {
		t.Fatalf("sync returned %d: %s", wSync.Code, wSync.Body.String())
	}

	var syncResp struct {
		Status       string `json:"status"`
		SnapshotID   string `json:"snapshot_id"`
		NVDCount     int    `json:"nvd_count"`
		CISAKEVCount int    `json:"cisa_kev_count"`
		EPSSCount    int    `json:"epss_count"`
		Activated    bool   `json:"activated"`
	}
	if err := json.NewDecoder(wSync.Body).Decode(&syncResp); err != nil {
		t.Fatalf("failed to decode sync response: %v", err)
	}
	if syncResp.SnapshotID != "snap-20260904-api-1" || syncResp.NVDCount != 2 || syncResp.CISAKEVCount != 1 || syncResp.EPSSCount != 1 || !syncResp.Activated {
		t.Fatalf("unexpected sync response: %+v", syncResp)
	}

	// 2. GET /api/v1/vulnerabilities/snapshots
	reqSnaps := httptest.NewRequest(http.MethodGet, "/api/v1/vulnerabilities/snapshots", nil)
	reqSnaps.Header.Set("X-API-Key", "test-admin-key-12345")
	wSnaps := httptest.NewRecorder()
	handler.ServeHTTP(wSnaps, reqSnaps)

	if wSnaps.Code != http.StatusOK {
		t.Fatalf("list snapshots returned %d: %s", wSnaps.Code, wSnaps.Body.String())
	}
	var snapsResp struct {
		Snapshots []*vuln.FeedSnapshot `json:"snapshots"`
	}
	if err := json.NewDecoder(wSnaps.Body).Decode(&snapsResp); err != nil {
		t.Fatalf("failed to decode snapshots list: %v", err)
	}
	if len(snapsResp.Snapshots) != 1 || snapsResp.Snapshots[0].ID != "snap-20260904-api-1" {
		t.Fatalf("unexpected snapshots list: %+v", snapsResp.Snapshots)
	}

	// 3. GET /api/v1/vulnerabilities/snapshots/active
	reqActive := httptest.NewRequest(http.MethodGet, "/api/v1/vulnerabilities/snapshots/active", nil)
	reqActive.Header.Set("X-API-Key", "test-admin-key-12345")
	wActive := httptest.NewRecorder()
	handler.ServeHTTP(wActive, reqActive)

	if wActive.Code != http.StatusOK {
		t.Fatalf("get active snapshot returned %d: %s", wActive.Code, wActive.Body.String())
	}
	var activeResp struct {
		Snapshot *vuln.FeedSnapshot `json:"snapshot"`
	}
	if err := json.NewDecoder(wActive.Body).Decode(&activeResp); err != nil {
		t.Fatalf("failed to decode active snapshot: %v", err)
	}
	if activeResp.Snapshot == nil || activeResp.Snapshot.Status != vuln.SnapshotActive {
		t.Fatalf("unexpected active snapshot: %+v", activeResp.Snapshot)
	}

	// 4. GET /api/v1/vulnerabilities?scope=catalog
	reqCat := httptest.NewRequest(http.MethodGet, "/api/v1/vulnerabilities?scope=catalog", nil)
	reqCat.Header.Set("X-API-Key", "test-admin-key-12345")
	wCat := httptest.NewRecorder()
	handler.ServeHTTP(wCat, reqCat)

	if wCat.Code != http.StatusOK {
		t.Fatalf("query catalog returned %d: %s", wCat.Code, wCat.Body.String())
	}
	var catResp struct {
		Total           int                  `json:"total"`
		Vulnerabilities []vuln.Vulnerability `json:"vulnerabilities"`
	}
	if err := json.NewDecoder(wCat.Body).Decode(&catResp); err != nil {
		t.Fatalf("failed to decode catalog response: %v", err)
	}
	if catResp.Total != 2 || len(catResp.Vulnerabilities) != 2 {
		t.Fatalf("expected 2 catalog items, got total=%d, len=%d", catResp.Total, len(catResp.Vulnerabilities))
	}

	// First item should be libwebp because CVSS 9.8 > 8.1
	if catResp.Vulnerabilities[0].CVEID != "CVE-2023-4863" {
		t.Fatalf("expected CVE-2023-4863 first due to CVSS ordering, got %s", catResp.Vulnerabilities[0].CVEID)
	}

	// 5. GET /api/v1/vulnerabilities?scope=catalog&is_kev=true
	reqKEV := httptest.NewRequest(http.MethodGet, "/api/v1/vulnerabilities?scope=catalog&is_kev=true", nil)
	reqKEV.Header.Set("X-API-Key", "test-admin-key-12345")
	wKEV := httptest.NewRecorder()
	handler.ServeHTTP(wKEV, reqKEV)

	var kevResp struct {
		Total           int                  `json:"total"`
		Vulnerabilities []vuln.Vulnerability `json:"vulnerabilities"`
	}
	_ = json.NewDecoder(wKEV.Body).Decode(&kevResp)
	if kevResp.Total != 1 || len(kevResp.Vulnerabilities) != 1 || kevResp.Vulnerabilities[0].CVEID != "CVE-2024-6387" {
		t.Fatalf("expected 1 KEV item (CVE-2024-6387), got %+v", kevResp)
	}

	// 6. GET /api/v1/vulnerabilities?scope=catalog&search=libwebp
	reqSearch := httptest.NewRequest(http.MethodGet, "/api/v1/vulnerabilities?scope=catalog&search=libwebp", nil)
	reqSearch.Header.Set("X-API-Key", "test-admin-key-12345")
	wSearch := httptest.NewRecorder()
	handler.ServeHTTP(wSearch, reqSearch)

	var searchResp struct {
		Total           int                  `json:"total"`
		Vulnerabilities []vuln.Vulnerability `json:"vulnerabilities"`
	}
	_ = json.NewDecoder(wSearch.Body).Decode(&searchResp)
	if searchResp.Total != 1 || len(searchResp.Vulnerabilities) != 1 || searchResp.Vulnerabilities[0].CVEID != "CVE-2023-4863" {
		t.Fatalf("expected 1 search result (CVE-2023-4863), got %+v", searchResp)
	}

	// 7. Reproducible query from snapshot_id
	reqHist := httptest.NewRequest(http.MethodGet, "/api/v1/vulnerabilities?scope=catalog&snapshot_id=snap-20260904-api-1", nil)
	reqHist.Header.Set("X-API-Key", "test-admin-key-12345")
	wHist := httptest.NewRecorder()
	handler.ServeHTTP(wHist, reqHist)

	var histResp struct {
		Total           int                  `json:"total"`
		Vulnerabilities []vuln.Vulnerability `json:"vulnerabilities"`
	}
	_ = json.NewDecoder(wHist.Body).Decode(&histResp)
	if histResp.Total != 2 {
		t.Fatalf("expected 2 items for historical snapshot, got %d", histResp.Total)
	}
}

func TestServer_VulnMatchingAndPrioritization(t *testing.T) {
	srv, _, _, cleanup := setupTestServerWithResponse(t)
	defer cleanup()

	handler := srv.Handler()
	endpointID := "ep-match-test"

	// 1. Sync CVEs with CPE Match Criteria
	sshCrit, _ := json.Marshal([]vuln.CPEMatchCriteria{
		{Criteria: "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*", VersionStartIncluding: "8.5p1", VersionEndExcluding: "9.8p1"},
	})
	sudoCrit, _ := json.Marshal([]vuln.CPEMatchCriteria{
		{Criteria: "cpe:2.3:a:todd_miller:sudo:*:*:*:*:*:*:*:*", VersionStartIncluding: "1.8.2", VersionEndIncluding: "1.8.31p2"},
	})

	syncReqBody, _ := json.Marshal(map[string]interface{}{
		"snapshot_id": "snap-match-01",
		"vulnerabilities": []vuln.Vulnerability{
			{
				CVEID:       "CVE-2024-6387",
				Title:       "OpenSSH regreSSHion",
				Description: "Signal handler race in OpenSSH server",
				Severity:    "HIGH",
				CVSS:        8.1,
				IsKEV:       true,
				EPSS:        0.92,
				CPEPattern:  string(sshCrit),
				PublishedAt: time.Now(),
			},
			{
				CVEID:       "CVE-2021-3156",
				Title:       "sudo Baron Samedit",
				Description: "Heap-based buffer overflow in sudo",
				Severity:    "CRITICAL",
				CVSS:        7.8,
				IsKEV:       true,
				EPSS:        0.85,
				CPEPattern:  string(sudoCrit),
				PublishedAt: time.Now(),
			},
		},
	})
	reqSync := httptest.NewRequest(http.MethodPost, "/api/v1/vulnerabilities/sync", bytes.NewReader(syncReqBody))
	reqSync.Header.Set("X-API-Key", "test-admin-key-12345")
	reqSync.Header.Set("Content-Type", "application/json")
	wSync := httptest.NewRecorder()
	handler.ServeHTTP(wSync, reqSync)

	if wSync.Code != http.StatusOK {
		t.Fatalf("sync returned %d: %s", wSync.Code, wSync.Body.String())
	}

	// 2. Report Endpoint Software (OpenSSH 8.9p1 -> vulnerable, sudo 1.9.5p2 -> patched/not_affected)
	swBody, _ := json.Marshal(map[string]interface{}{
		"endpoint_id": endpointID,
		"packages": []vuln.InstalledSoftware{
			{
				Source:       "dpkg",
				Vendor:       "Ubuntu",
				Product:      "openssh-server",
				Version:      "1:8.9p1-3ubuntu0.6",
				Architecture: "amd64",
			},
			{
				Source:       "dpkg",
				Vendor:       "Ubuntu",
				Product:      "sudo",
				Version:      "1.9.5p2-1ubuntu1",
				Architecture: "amd64",
			},
		},
	})
	reqSW := httptest.NewRequest(http.MethodPost, "/api/v1/software", bytes.NewReader(swBody))
	reqSW.Header.Set("X-API-Key", "test-admin-key-12345")
	reqSW.Header.Set("Content-Type", "application/json")
	wSW := httptest.NewRecorder()
	handler.ServeHTTP(wSW, reqSW)

	if wSW.Code != http.StatusCreated {
		t.Fatalf("report software returned %d: %s", wSW.Code, wSW.Body.String())
	}

	// 3. Query all matches
	reqAll := httptest.NewRequest(http.MethodGet, "/api/v1/vulnerabilities?endpoint_id="+endpointID, nil)
	reqAll.Header.Set("X-API-Key", "test-admin-key-12345")
	wAll := httptest.NewRecorder()
	handler.ServeHTTP(wAll, reqAll)

	var allResp struct {
		Vulnerabilities []vuln.VulnerabilityMatch `json:"vulnerabilities"`
	}
	_ = json.NewDecoder(wAll.Body).Decode(&allResp)
	if len(allResp.Vulnerabilities) != 2 {
		t.Fatalf("expected 2 matches, got %d", len(allResp.Vulnerabilities))
	}

	// First match must be OpenSSH (matched) with high priority score
	first := allResp.Vulnerabilities[0]
	if first.CVEID != "CVE-2024-6387" || first.Status != vuln.MatchStatusMatched {
		t.Fatalf("expected first match to be CVE-2024-6387 matched, got %+v", first)
	}
	if first.PriorityScore < 80.0 {
		t.Fatalf("expected priority score >= 80, got %f", first.PriorityScore)
	}
	if first.Evidence == "" || !strings.Contains(first.Evidence, "vulnerable_range") {
		t.Fatalf("expected structured evidence in match, got: %s", first.Evidence)
	}

	// 4. Query with status filter (status=matched)
	reqMatched := httptest.NewRequest(http.MethodGet, "/api/v1/vulnerabilities?endpoint_id="+endpointID+"&status=matched", nil)
	reqMatched.Header.Set("X-API-Key", "test-admin-key-12345")
	wMatched := httptest.NewRecorder()
	handler.ServeHTTP(wMatched, reqMatched)

	var matchedResp struct {
		Vulnerabilities []vuln.VulnerabilityMatch `json:"vulnerabilities"`
	}
	_ = json.NewDecoder(wMatched.Body).Decode(&matchedResp)
	if len(matchedResp.Vulnerabilities) != 1 || matchedResp.Vulnerabilities[0].CVEID != "CVE-2024-6387" {
		t.Fatalf("expected 1 matched item, got %+v", matchedResp)
	}

	// 5. Query with status filter (status=not_affected)
	reqNotAff := httptest.NewRequest(http.MethodGet, "/api/v1/vulnerabilities?endpoint_id="+endpointID+"&status=not_affected", nil)
	reqNotAff.Header.Set("X-API-Key", "test-admin-key-12345")
	wNotAff := httptest.NewRecorder()
	handler.ServeHTTP(wNotAff, reqNotAff)

	var notAffResp struct {
		Vulnerabilities []vuln.VulnerabilityMatch `json:"vulnerabilities"`
	}
	_ = json.NewDecoder(wNotAff.Body).Decode(&notAffResp)
	if len(notAffResp.Vulnerabilities) != 1 || notAffResp.Vulnerabilities[0].CVEID != "CVE-2021-3156" {
		t.Fatalf("expected 1 not_affected item (sudo), got %+v", notAffResp)
	}
}


