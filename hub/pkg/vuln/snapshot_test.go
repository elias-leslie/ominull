package vuln

import (
	"context"
	"database/sql"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

func TestVuln_NVD20Parser(t *testing.T) {
	nvdJSON := `{
		"format": "NVD_CVE",
		"version": "2.0",
		"totalResults": 1,
		"vulnerabilities": [
			{
				"cve": {
					"id": "CVE-2024-6387",
					"published": "2024-07-01T08:15:05.120Z",
					"lastModified": "2024-07-08T14:15:10.000Z",
					"descriptions": [
						{"lang": "es", "value": "Condicion de carrera..."},
						{"lang": "en", "value": "A signal handler race condition in OpenSSH server"}
					],
					"metrics": {
						"cvssMetricV31": [
							{
								"cvssData": {
									"baseScore": 8.1,
									"baseSeverity": "HIGH"
								}
							}
						]
					},
					"configurations": [
						{
							"nodes": [
								{
									"cpeMatch": [
										{
											"vulnerable": true,
											"criteria": "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*",
											"versionStartIncluding": "8.5p1",
											"versionEndExcluding": "9.8p1"
										}
									]
								}
							]
						}
					]
				}
			}
		]
	}`

	vulns, err := ParseNVD20(strings.NewReader(nvdJSON))
	if err != nil {
		t.Fatalf("ParseNVD20 failed: %v", err)
	}
	if len(vulns) != 1 {
		t.Fatalf("expected 1 vuln, got %d", len(vulns))
	}
	v := vulns[0]
	if v.CVEID != "CVE-2024-6387" {
		t.Fatalf("unexpected CVE ID: %s", v.CVEID)
	}
	if v.Severity != "HIGH" || v.CVSS != 8.1 {
		t.Fatalf("unexpected CVSS score: %s / %f", v.Severity, v.CVSS)
	}
	if !strings.Contains(v.Description, "race condition in OpenSSH") {
		t.Fatalf("unexpected description: %s", v.Description)
	}
	if !strings.Contains(v.CPEPattern, "8.5p1") || !strings.Contains(v.CPEPattern, "9.8p1") {
		t.Fatalf("expected CPE version boundaries in pattern: %s", v.CPEPattern)
	}
}

func TestVuln_CISAKEVParser(t *testing.T) {
	kevJSON := `{
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

	items, err := ParseCISAKEV(strings.NewReader(kevJSON))
	if err != nil {
		t.Fatalf("ParseCISAKEV failed: %v", err)
	}
	if len(items) != 1 || items[0].CVEID != "CVE-2024-6387" {
		t.Fatalf("unexpected KEV items: %+v", items)
	}
	if items[0].KnownRansomwareCampaignUse != "Known" {
		t.Fatalf("unexpected ransomware flag: %s", items[0].KnownRansomwareCampaignUse)
	}
}

func TestVuln_EPSSParser(t *testing.T) {
	epssJSON := `{
		"status": "OK",
		"total": 1,
		"data": [
			{
				"cve": "CVE-2024-6387",
				"epss": "0.92541",
				"percentile": "0.98921",
				"date": "2026-09-04"
			}
		]
	}`

	scores, err := ParseEPSSJSON(strings.NewReader(epssJSON))
	if err != nil {
		t.Fatalf("ParseEPSSJSON failed: %v", err)
	}
	s, ok := scores["CVE-2024-6387"]
	if !ok {
		t.Fatalf("CVE-2024-6387 not found in scores")
	}
	if s.Score < 0.92 || s.Percentile < 0.98 {
		t.Fatalf("unexpected score values: %+v", s)
	}
}

func TestVuln_SnapshotLifecycle(t *testing.T) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("sql.Open failed: %v", err)
	}
	defer db.Close()

	store, err := NewStore(db)
	if err != nil {
		t.Fatalf("NewStore failed: %v", err)
	}

	// 1. Initial State: No active snapshot
	_, err = store.GetActiveSnapshot()
	if err != ErrNoActiveSnapshot {
		t.Fatalf("expected ErrNoActiveSnapshot, got %v", err)
	}

	// 2. Create Snapshot 1 (Building)
	snap1ID := "snap-20260904-001"
	snap1, err := store.CreateSnapshot(snap1ID, `{"source":"nvd20+cisa"}`)
	if err != nil {
		t.Fatalf("CreateSnapshot failed: %v", err)
	}
	if snap1.Status != SnapshotBuilding {
		t.Fatalf("expected status building, got %s", snap1.Status)
	}

	// 3. Ingest data into Snapshot 1
	vulns1 := []Vulnerability{
		{
			CVEID:       "CVE-2024-6387",
			Title:       "CVE-2024-6387",
			Description: "OpenSSH race condition",
			Severity:    "HIGH",
			CVSS:        8.1,
			CPEPattern:  "openssh",
			PublishedAt: time.Now().UTC(),
		},
		{
			CVEID:       "CVE-2023-4863",
			Title:       "CVE-2023-4863",
			Description: "libwebp heap overflow",
			Severity:    "CRITICAL",
			CVSS:        9.8,
			CPEPattern:  "libwebp",
			PublishedAt: time.Now().UTC(),
		},
	}
	kev1 := []CISAKEVItem{
		{
			CVEID:             "CVE-2024-6387",
			VendorProject:     "OpenBSD",
			Product:           "OpenSSH",
			VulnerabilityName: "OpenSSH Race Condition",
		},
	}
	epss1 := map[string]EPSSScore{
		"CVE-2024-6387": {CVEID: "CVE-2024-6387", Score: 0.92, Percentile: 0.98},
	}

	if err := store.IngestSnapshotData(snap1ID, vulns1, kev1, epss1); err != nil {
		t.Fatalf("IngestSnapshotData failed: %v", err)
	}

	// 4. Atomically Activate Snapshot 1
	if err := store.ActivateSnapshot(snap1ID); err != nil {
		t.Fatalf("ActivateSnapshot failed: %v", err)
	}

	activeSnap, err := store.GetActiveSnapshot()
	if err != nil || activeSnap.ID != snap1ID {
		t.Fatalf("expected active snapshot %s, got %+v (err=%v)", snap1ID, activeSnap, err)
	}
	if activeSnap.Status != SnapshotActive || activeSnap.ActivatedAt == nil {
		t.Fatalf("expected active status with timestamp: %+v", activeSnap)
	}
	if activeSnap.NVDCount != 2 || activeSnap.CISAKEVCount != 1 || activeSnap.EPSSCount != 1 {
		t.Fatalf("unexpected snapshot counts: %+v", activeSnap)
	}

	// 5. Query Vulnerabilities from Active Snapshot
	vulnsActive, total, err := store.GetVulnerabilitiesForSnapshot(VulnFilter{})
	if err != nil || total != 2 || len(vulnsActive) != 2 {
		t.Fatalf("failed to query active vulnerabilities: total=%d, err=%v", total, err)
	}
	// Verify KEV and EPSS merging
	foundKEV := false
	for _, v := range vulnsActive {
		if v.CVEID == "CVE-2024-6387" {
			if !v.IsKEV {
				t.Fatalf("expected CVE-2024-6387 to have IsKEV=true")
			}
			if v.EPSS < 0.90 {
				t.Fatalf("expected CVE-2024-6387 to have EPSS score >= 0.90, got %f", v.EPSS)
			}
			foundKEV = true
		}
	}
	if !foundKEV {
		t.Fatalf("CVE-2024-6387 not found in active snapshot")
	}

	// 6. Build Snapshot 2 off to the side, then fail it (simulate corrupted feed / rate limit)
	snap2ID := "snap-20260904-002"
	_, err = store.CreateSnapshot(snap2ID, `{"source":"corrupt_attempt"}`)
	if err != nil {
		t.Fatalf("CreateSnapshot 2 failed: %v", err)
	}

	err = store.FailSnapshot(snap2ID, "HTTP 429 Too Many Requests: NVD rate limit exceeded")
	if err != nil {
		t.Fatalf("FailSnapshot failed: %v", err)
	}

	// Verify that Snapshot 1 remains active and uncorrupted!
	activeSnapStill, err := store.GetActiveSnapshot()
	if err != nil || activeSnapStill.ID != snap1ID {
		t.Fatalf("active snapshot was corrupted! Expected %s, got %+v", snap1ID, activeSnapStill)
	}

	// 7. Refusal to activate empty snapshot
	emptySnapID := "snap-empty-003"
	_, _ = store.CreateSnapshot(emptySnapID, `{}`)
	err = store.ActivateSnapshot(emptySnapID)
	if err == nil {
		t.Fatalf("expected error activating empty snapshot, got nil")
	}
	if !strings.Contains(err.Error(), "refusing to activate empty snapshot") {
		t.Fatalf("unexpected error message: %v", err)
	}

	// 8. Build Snapshot 3 with updated catalog and atomically promote
	snap3ID := "snap-20260904-003"
	_, _ = store.CreateSnapshot(snap3ID, `{"source":"nvd20+cisa_v3"}`)
	vulns3 := []Vulnerability{
		{
			CVEID:       "CVE-2024-6387",
			Title:       "CVE-2024-6387",
			Description: "OpenSSH race condition",
			Severity:    "HIGH",
			CVSS:        8.1,
			PublishedAt: time.Now().UTC(),
		},
		{
			CVEID:       "CVE-2023-4863",
			Title:       "CVE-2023-4863",
			Description: "libwebp heap overflow",
			Severity:    "CRITICAL",
			CVSS:        9.8,
			PublishedAt: time.Now().UTC(),
		},
		{
			CVEID:       "CVE-2024-21626",
			Title:       "runc container breakout",
			Description: "runc working directory file descriptor leak",
			Severity:    "HIGH",
			CVSS:        8.6,
			PublishedAt: time.Now().UTC(),
		},
	}
	_ = store.IngestSnapshotData(snap3ID, vulns3, nil, nil)
	if err := store.ActivateSnapshot(snap3ID); err != nil {
		t.Fatalf("ActivateSnapshot 3 failed: %v", err)
	}

	// Verify Snapshot 3 is active and Snapshot 1 is superseded
	activeSnap3, err := store.GetActiveSnapshot()
	if err != nil || activeSnap3.ID != snap3ID {
		t.Fatalf("expected active snapshot %s, got %+v", snap3ID, activeSnap3)
	}

	// List all snapshots
	allSnaps, err := store.ListSnapshots()
	if err != nil || len(allSnaps) < 3 {
		t.Fatalf("expected at least 3 snapshots in history, got %d", len(allSnaps))
	}
	for _, s := range allSnaps {
		if s.ID == snap1ID && s.Status != SnapshotSuperseded {
			t.Fatalf("expected snap1 to be superseded, got %s", s.Status)
		}
		if s.ID == snap2ID && s.Status != SnapshotFailed {
			t.Fatalf("expected snap2 to be failed, got %s", s.Status)
		}
		if s.ID == snap3ID && s.Status != SnapshotActive {
			t.Fatalf("expected snap3 to be active, got %s", s.Status)
		}
	}

	// 9. Query from specific historical snapshot ID (reproducibility)
	historicalVulns, histTotal, err := store.GetVulnerabilitiesForSnapshot(VulnFilter{SnapshotID: snap1ID})
	if err != nil || histTotal != 2 || len(historicalVulns) != 2 {
		t.Fatalf("failed to query historical snapshot 1: total=%d, err=%v", histTotal, err)
	}
}

func TestVuln_SyncFeedsMockPipeline(t *testing.T) {
	nvdResponse := `{
		"format": "NVD_CVE",
		"version": "2.0",
		"totalResults": 1,
		"vulnerabilities": [
			{
				"cve": {
					"id": "CVE-2024-1111",
					"descriptions": [{"lang": "en", "value": "Sample vulnerability in coreutils"}],
					"metrics": {
						"cvssMetricV31": [{"cvssData": {"baseScore": 7.5, "baseSeverity": "HIGH"}}]
					},
					"configurations": [
						{"nodes": [{"cpeMatch": [{"vulnerable": true, "criteria": "cpe:2.3:a:gnu:coreutils:*:*:*:*:*:*:*:*"}]}]}
					]
				}
			}
		]
	}`

	cisaKEVResponse := `{
		"catalogVersion": "2026.09.04",
		"count": 1,
		"vulnerabilities": [
			{
				"cveID": "CVE-2024-1111",
				"vendorProject": "GNU",
				"product": "Coreutils",
				"vulnerabilityName": "Coreutils flaw",
				"dateAdded": "2026-09-04",
				"shortDescription": "Sample flaw",
				"requiredAction": "Patch",
				"dueDate": "2026-09-25",
				"knownRansomwareCampaignUse": "Unknown"
			}
		]
	}`

	epssResponse := `{
		"status": "OK",
		"total": 1,
		"data": [{"cve": "CVE-2024-1111", "epss": "0.75", "percentile": "0.88", "date": "2026-09-04"}]
	}`

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.Contains(r.URL.Path, "/cve"):
			w.Write([]byte(nvdResponse))
		case strings.Contains(r.URL.Path, "/kev"):
			w.Write([]byte(cisaKEVResponse))
		case strings.Contains(r.URL.Path, "/epss"):
			w.Write([]byte(epssResponse))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("sql.Open failed: %v", err)
	}
	defer db.Close()

	store, err := NewStore(db)
	if err != nil {
		t.Fatalf("NewStore failed: %v", err)
	}

	opts := FeedSyncOptions{
		HTTPClient:    server.Client(),
		NVDURL:        server.URL + "/cve",
		CISAKEVURL:    server.URL + "/kev",
		EPSSURL:       server.URL + "/epss",
		MaxNVDResults: 10,
	}

	snap, err := SyncFeeds(context.Background(), store, opts, "snap-mock-01", "mock-sync")
	if err != nil {
		t.Fatalf("SyncFeeds failed: %v", err)
	}

	if snap.Status != SnapshotActive {
		t.Fatalf("expected snapshot active, got %s", snap.Status)
	}
	if snap.NVDCount != 1 || snap.CISAKEVCount != 1 || snap.EPSSCount != 1 {
		t.Fatalf("unexpected counts in activated snapshot: %+v", snap)
	}

	// Verify querying active snapshot
	vulns, total, err := store.GetVulnerabilitiesForSnapshot(VulnFilter{})
	if err != nil || total != 1 || len(vulns) != 1 {
		t.Fatalf("query failed: total=%d, err=%v", total, err)
	}
	if !vulns[0].IsKEV || vulns[0].EPSS != 0.75 {
		t.Fatalf("vuln item did not merge KEV or EPSS properly: %+v", vulns[0])
	}
}

func TestVuln_SyncFeedsRateLimitHandling(t *testing.T) {
	// First establish an active snapshot
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("sql.Open failed: %v", err)
	}
	defer db.Close()

	store, err := NewStore(db)
	if err != nil {
		t.Fatalf("NewStore failed: %v", err)
	}

	initialSnapID := "snap-initial-good"
	_, _ = store.CreateSnapshot(initialSnapID, "initial")
	_ = store.IngestSnapshotData(initialSnapID, []Vulnerability{
		{CVEID: "CVE-2023-0001", Title: "t", Description: "d", Severity: "LOW", PublishedAt: time.Now()},
	}, nil, nil)
	_ = store.ActivateSnapshot(initialSnapID)

	// Now simulate rate limit HTTP 429 from NVD server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/cve") {
			w.WriteHeader(http.StatusTooManyRequests)
			w.Write([]byte("Rate limit exceeded"))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"catalogVersion":"2026.09.04","vulnerabilities":[{"cveID":"CVE-2024-9999","vendorProject":"p","product":"prod","vulnerabilityName":"n","dateAdded":"2026","shortDescription":"d","requiredAction":"a","dueDate":"d","knownRansomwareCampaignUse":"k"}]}`))
	}))
	defer server.Close()

	opts := FeedSyncOptions{
		HTTPClient: server.Client(),
		NVDURL:     server.URL + "/cve",
		CISAKEVURL: server.URL + "/kev",
	}

	failedSnapID := "snap-attempt-ratelimited"
	_, err = SyncFeeds(context.Background(), store, opts, failedSnapID, "rate-limited-attempt")
	if err == nil {
		t.Fatalf("expected error from rate limited sync, got nil")
	}

	// Invariant: Initial active snapshot MUST remain active and uncorrupted!
	activeSnap, err := store.GetActiveSnapshot()
	if err != nil || activeSnap.ID != initialSnapID {
		t.Fatalf("active snapshot was corrupted! Expected %s, got %+v (err=%v)", initialSnapID, activeSnap, err)
	}

	// Verify failed snapshot status
	allSnaps, _ := store.ListSnapshots()
	foundFailed := false
	for _, s := range allSnaps {
		if s.ID == failedSnapID {
			if s.Status != SnapshotFailed {
				t.Fatalf("expected failed snapshot status, got %s", s.Status)
			}
			if !strings.Contains(s.ErrorMessage, "429") {
				t.Fatalf("expected error message to cite 429, got: %s", s.ErrorMessage)
			}
			foundFailed = true
		}
	}
	if !foundFailed {
		t.Fatalf("failed snapshot record not found in snapshot history")
	}
}
