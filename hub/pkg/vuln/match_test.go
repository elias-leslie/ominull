package vuln

import (
	"database/sql"
	"encoding/json"
	"strings"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

func TestVuln_CPEParser(t *testing.T) {
	// 1. Valid CPE 2.3 formatted string
	cpeStr := `cpe:2.3:a:openbsd:openssh:8.9p1:*:*:*:*:*:*:*`
	cpe, err := ParseCPE(cpeStr)
	if err != nil {
		t.Fatalf("ParseCPE failed: %v", err)
	}
	if cpe.Part != "a" || cpe.Vendor != "openbsd" || cpe.Product != "openssh" || cpe.Version != "8.9p1" {
		t.Fatalf("unexpected CPE fields: %+v", cpe)
	}

	// 2. Escaped characters
	escapedStr := `cpe:2.3:a:vendor\:corp:product\:app:1.0\:sp1:*:*:*:*:*:*:*`
	escCPE, err := ParseCPE(escapedStr)
	if err != nil {
		t.Fatalf("ParseCPE failed on escaped: %v", err)
	}
	if escCPE.Vendor != "vendor:corp" || escCPE.Product != "product:app" || escCPE.Version != "1.0:sp1" {
		t.Fatalf("escaped components not unescaped: %+v", escCPE)
	}

	// 3. CPE 2.2 URI
	uriStr := `cpe:/a:apache:log4j:2.14.1`
	uriCPE, err := ParseCPE(uriStr)
	if err != nil {
		t.Fatalf("ParseCPE failed on URI: %v", err)
	}
	if uriCPE.Vendor != "apache" || uriCPE.Product != "log4j" || uriCPE.Version != "2.14.1" {
		t.Fatalf("unexpected URI fields: %+v", uriCPE)
	}

	// 4. Product matching
	matched, conf := cpe.MatchesProduct("Ubuntu", "openssh-server")
	if !matched || conf < 0.90 {
		t.Fatalf("expected openssh-server to match openssh, got matched=%v conf=%f", matched, conf)
	}

	matchedLib, confLib := uriCPE.MatchesProduct("Apache", "log4j-core")
	if !matchedLib || confLib < 0.90 {
		t.Fatalf("expected log4j-core to match log4j, got matched=%v conf=%f", matchedLib, confLib)
	}
}

func TestVuln_VersionComparisonConformance(t *testing.T) {
	cases := []struct {
		v1       string
		v2       string
		expected int // -1 (v1 < v2), 0 (v1 == v2), 1 (v1 > v2)
		label    string
	}{
		// OpenSSH versions
		{"8.5p1", "8.9p1", -1, "OpenSSH 8.5p1 < 8.9p1"},
		{"8.9p1", "9.8p1", -1, "OpenSSH 8.9p1 < 9.8p1"},
		{"9.8p1", "9.8p1", 0, "OpenSSH 9.8p1 == 9.8p1"},
		{"9.8p2", "9.8p1", 1, "OpenSSH 9.8p2 > 9.8p1"},
		{"7.9p1", "8.5p1", -1, "OpenSSH 7.9p1 < 8.5p1"},

		// Debian epoch and revisions
		{"1:8.9p1-3ubuntu0.6", "1:8.9p1-3ubuntu0.7", -1, "Ubuntu revision increment"},
		{"2:1.0", "1:2.0", 1, "Epoch takes precedence"},
		{"1.0-1", "1.0-2", -1, "Debian revision increment"},

		// Prereleases and Tildes
		{"1.0~rc1", "1.0", -1, "Debian tilde is smaller than final"},
		{"1.0~beta2", "1.0~rc1", -1, "Beta is smaller than RC"},
		{"2.0-beta9", "2.0", -1, "SemVer prerelease is smaller than release"},
		{"2.0-alpha1", "2.0-beta9", -1, "Alpha is smaller than beta"},
		{"2.14.1", "2.15.0", -1, "Log4j 2.14.1 < 2.15.0"},

		// Patch versions
		{"1.8.31", "1.8.31p1", -1, "Patch suffix is greater than base"},
		{"1.8.31p1", "1.8.31p2", -1, "Patch 1 < Patch 2"},
		{"1.8.31p2", "1.8.32", -1, "1.8.31p2 < 1.8.32"},

		// XZ versions
		{"5.2.4", "5.4.5", -1, "XZ 5.2.4 < 5.4.5"},
		{"5.4.5", "5.6.0", -1, "XZ 5.4.5 < 5.6.0"},
		{"5.6.0", "5.6.1", -1, "XZ 5.6.0 < 5.6.1"},
		{"5.6.1", "5.6.2", -1, "XZ 5.6.1 < 5.6.2"},

		// Windows dotted versions
		{"10.0.19041.1200", "10.0.19041.1300", -1, "Windows build increment"},
		{"10.0.19042.1000", "10.0.19041.9999", 1, "Windows major build precedence"},
	}

	for _, tc := range cases {
		t.Run(tc.label, func(t *testing.T) {
			res := CompareVersions(tc.v1, tc.v2)
			if res != tc.expected {
				t.Fatalf("[%s] CompareVersions(%q, %q) = %d, expected %d", tc.label, tc.v1, tc.v2, res, tc.expected)
			}
		})
	}
}

func TestVuln_BoundaryConditions(t *testing.T) {
	// 1. OpenSSH regreSSHion (CVE-2024-6387): [8.5p1, 9.8p1)
	sshCrit := CPEMatchCriteria{
		Criteria:              "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*",
		VersionStartIncluding: "8.5p1",
		VersionEndExcluding:   "9.8p1",
	}

	// Exact start boundary
	st, _, _ := EvaluateVersionRange("8.5p1", sshCrit)
	if st != MatchStatusMatched {
		t.Fatalf("expected 8.5p1 to be matched, got %s", st)
	}

	// Inside vulnerable range
	st, _, _ = EvaluateVersionRange("8.9p1", sshCrit)
	if st != MatchStatusMatched {
		t.Fatalf("expected 8.9p1 to be matched, got %s", st)
	}

	// Debian packaged version with epoch
	st, _, _ = EvaluateVersionRange("1:8.9p1-3ubuntu0.6", sshCrit)
	if st != MatchStatusMatched {
		t.Fatalf("expected 1:8.9p1-3ubuntu0.6 to be matched, got %s", st)
	}

	// Exact end boundary (patched!)
	st, _, _ = EvaluateVersionRange("9.8p1", sshCrit)
	if st != MatchStatusNotAffected {
		t.Fatalf("expected 9.8p1 to be not_affected, got %s", st)
	}

	// Newer patched version
	st, _, _ = EvaluateVersionRange("9.8p2", sshCrit)
	if st != MatchStatusNotAffected {
		t.Fatalf("expected 9.8p2 to be not_affected, got %s", st)
	}

	// Older un-affected version
	st, _, _ = EvaluateVersionRange("7.9p1", sshCrit)
	if st != MatchStatusNotAffected {
		t.Fatalf("expected 7.9p1 to be not_affected, got %s", st)
	}

	// 2. Log4j (CVE-2021-44228): [2.0-beta9, 2.14.1]
	log4jCrit := CPEMatchCriteria{
		Criteria:              "cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*",
		VersionStartIncluding: "2.0-beta9",
		VersionEndIncluding:   "2.14.1",
	}

	// Inside
	st, _, _ = EvaluateVersionRange("2.12.1", log4jCrit)
	if st != MatchStatusMatched {
		t.Fatalf("expected log4j 2.12.1 to be matched, got %s", st)
	}

	// Exact start
	st, _, _ = EvaluateVersionRange("2.0-beta9", log4jCrit)
	if st != MatchStatusMatched {
		t.Fatalf("expected log4j 2.0-beta9 to be matched, got %s", st)
	}

	// Older than start
	st, _, _ = EvaluateVersionRange("2.0-alpha1", log4jCrit)
	if st != MatchStatusNotAffected {
		t.Fatalf("expected log4j 2.0-alpha1 to be not_affected, got %s", st)
	}

	// Exact end (inclusive)
	st, _, _ = EvaluateVersionRange("2.14.1", log4jCrit)
	if st != MatchStatusMatched {
		t.Fatalf("expected log4j 2.14.1 to be matched, got %s", st)
	}

	// Patched version
	st, _, _ = EvaluateVersionRange("2.15.0", log4jCrit)
	if st != MatchStatusNotAffected {
		t.Fatalf("expected log4j 2.15.0 to be not_affected, got %s", st)
	}

	// 3. Insufficient data case
	st, _, _ = EvaluateVersionRange("", log4jCrit)
	if st != MatchStatusInsufficientData {
		t.Fatalf("expected empty version to return insufficient_data, got %s", st)
	}
}

func TestVuln_PrioritizationAndEvidence(t *testing.T) {
	// Test prioritization formula
	// CVSS 9.8 (58.8) + KEV (25) + EPSS 0.90 (13.5) = 97.3
	p1 := CalculatePriorityScore(9.8, true, 0.90, "CRITICAL", 1.0)
	if p1 < 97.0 || p1 > 98.0 {
		t.Fatalf("unexpected priority score: %f", p1)
	}

	// CVSS 4.0 (24.0) + no KEV (0) + EPSS 0.01 (0.15) = 24.2
	p2 := CalculatePriorityScore(4.0, false, 0.01, "MEDIUM", 1.0)
	if p2 < 24.0 || p2 > 25.0 {
		t.Fatalf("unexpected priority score: %f", p2)
	}

	// Verify correlation produces exact explainable evidence
	criteria := []CPEMatchCriteria{
		{
			Criteria:              "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*",
			VersionStartIncluding: "8.5p1",
			VersionEndExcluding:   "9.8p1",
		},
	}
	critJSON, _ := json.Marshal(criteria)

	vuln := Vulnerability{
		CVEID:       "CVE-2024-6387",
		Severity:    "HIGH",
		CVSS:        8.1,
		IsKEV:       true,
		EPSS:        0.92,
		CPEPattern:  string(critJSON),
		PublishedAt: time.Now(),
	}

	swVulnerable := InstalledSoftware{
		ID:         "sw-1",
		TenantID:   "tenant-1",
		EndpointID: "ep-1",
		Source:     "dpkg",
		Vendor:     "Ubuntu",
		Product:    "openssh-server",
		Version:    "1:8.9p1-3ubuntu0.6",
		Confidence: ConfidenceAuthoritative,
	}

	match := CorrelateSoftwareItem(swVulnerable, vuln, "snap-01")
	if match == nil {
		t.Fatalf("expected match, got nil")
	}
	if match.Status != MatchStatusMatched {
		t.Fatalf("expected status matched, got %s", match.Status)
	}
	if !match.IsKEV || match.EPSS != 0.92 || match.CVSS != 8.1 {
		t.Fatalf("independent source values not preserved: %+v", match)
	}
	if match.FeedSnapshotID != "snap-01" {
		t.Fatalf("snapshot ID not recorded: %s", match.FeedSnapshotID)
	}

	var ev VulnerabilityMatchEvidence
	if err := json.Unmarshal([]byte(match.Evidence), &ev); err != nil {
		t.Fatalf("failed to parse evidence JSON: %v", err)
	}
	if ev.Product != "openssh-server" || ev.Version != "1:8.9p1-3ubuntu0.6" || !strings.Contains(ev.VulnerableRange, "8.5p1") {
		t.Fatalf("unexpected evidence fields: %+v", ev)
	}

	// Test patched software item returns not_affected
	swPatched := InstalledSoftware{
		ID:         "sw-2",
		TenantID:   "tenant-1",
		EndpointID: "ep-1",
		Source:     "dpkg",
		Vendor:     "Ubuntu",
		Product:    "openssh-server",
		Version:    "1:9.8p1-1",
		Confidence: ConfidenceAuthoritative,
	}
	notAffMatch := CorrelateSoftwareItem(swPatched, vuln, "snap-01")
	if notAffMatch == nil {
		t.Fatalf("expected not_affected candidate, got nil")
	}
	if notAffMatch.Status != MatchStatusNotAffected {
		t.Fatalf("expected status not_affected, got %s", notAffMatch.Status)
	}
}

func TestVuln_StoreCorrelationLifecycle(t *testing.T) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("sql.Open failed: %v", err)
	}
	defer db.Close()

	store, err := NewStore(db)
	if err != nil {
		t.Fatalf("NewStore failed: %v", err)
	}

	tenantID := "default"
	endpointID := "node-prod-01"

	// 1. Create snapshot with CVE-2024-6387 (OpenSSH) and CVE-2023-4863 (libwebp)
	snapID := "snap-20260904-corr"
	_, _ = store.CreateSnapshot(snapID, "test-corr")

	sshCrit, _ := json.Marshal([]CPEMatchCriteria{
		{Criteria: "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*", VersionStartIncluding: "8.5p1", VersionEndExcluding: "9.8p1"},
	})
	webpCrit, _ := json.Marshal([]CPEMatchCriteria{
		{Criteria: "cpe:2.3:a:webmproject:libwebp:*:*:*:*:*:*:*:*", VersionEndExcluding: "1.3.2"},
	})

	vulns := []Vulnerability{
		{
			CVEID:       "CVE-2024-6387",
			Title:       "regreSSHion",
			Severity:    "HIGH",
			CVSS:        8.1,
			IsKEV:       true,
			EPSS:        0.92,
			CPEPattern:  string(sshCrit),
			PublishedAt: time.Now(),
		},
		{
			CVEID:       "CVE-2023-4863",
			Title:       "libwebp heap overflow",
			Severity:    "CRITICAL",
			CVSS:        9.8,
			IsKEV:       true,
			EPSS:        0.95,
			CPEPattern:  string(webpCrit),
			PublishedAt: time.Now(),
		},
	}
	_ = store.IngestSnapshotData(snapID, vulns, nil, nil)
	_ = store.ActivateSnapshot(snapID)

	// 2. Ingest Software Inventory for Endpoint
	// One vulnerable (OpenSSH 8.9p1), one patched (libwebp 1.3.2), one clean (curl)
	swItems := []InstalledSoftware{
		{
			Source:       "dpkg",
			Vendor:       "Ubuntu",
			Product:      "openssh-server",
			Version:      "1:8.9p1-3ubuntu0.6",
			Architecture: "amd64",
			Confidence:   ConfidenceAuthoritative,
		},
		{
			Source:       "dpkg",
			Vendor:       "Ubuntu",
			Product:      "libwebp7",
			Version:      "1.3.2-0.4ubuntu1",
			Architecture: "amd64",
			Confidence:   ConfidenceAuthoritative,
		},
		{
			Source:       "dpkg",
			Vendor:       "Ubuntu",
			Product:      "curl",
			Version:      "8.5.0-2ubuntu10",
			Architecture: "amd64",
			Confidence:   ConfidenceAuthoritative,
		},
	}
	if err := store.ReplaceSoftwareInventory(tenantID, endpointID, swItems); err != nil {
		t.Fatalf("ReplaceSoftwareInventory failed: %v", err)
	}

	// 3. Correlate
	matches, err := store.CorrelateEndpoint(tenantID, endpointID)
	if err != nil {
		t.Fatalf("CorrelateEndpoint failed: %v", err)
	}
	if len(matches) != 2 {
		t.Fatalf("expected 2 match candidates (1 matched, 1 not_affected), got %d", len(matches))
	}

	// 4. Query all matches
	allMatches, err := store.ListMatches(tenantID, endpointID)
	if err != nil || len(allMatches) != 2 {
		t.Fatalf("ListMatches failed: total=%d err=%v", len(allMatches), err)
	}

	// 5. Query filtered by status=matched
	matchedOnly, err := store.ListMatchesFiltered(tenantID, endpointID, MatchStatusMatched)
	if err != nil || len(matchedOnly) != 1 {
		t.Fatalf("expected 1 matched status, got %d (err=%v)", len(matchedOnly), err)
	}
	if matchedOnly[0].CVEID != "CVE-2024-6387" {
		t.Fatalf("unexpected matched CVE: %s", matchedOnly[0].CVEID)
	}
	if matchedOnly[0].PriorityScore < 80.0 {
		t.Fatalf("expected priority score >= 80, got %f", matchedOnly[0].PriorityScore)
	}

	// 6. Query filtered by status=not_affected
	notAffectedOnly, err := store.ListMatchesFiltered(tenantID, endpointID, MatchStatusNotAffected)
	if err != nil || len(notAffectedOnly) != 1 {
		t.Fatalf("expected 1 not_affected status, got %d (err=%v)", len(notAffectedOnly), err)
	}
	if notAffectedOnly[0].CVEID != "CVE-2023-4863" {
		t.Fatalf("unexpected not_affected CVE: %s", notAffectedOnly[0].CVEID)
	}
}
