package vuln

import (
	"database/sql"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

func TestVuln_InventoryAndCorrelation(t *testing.T) {
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
	endpointID := "linux-srv-01"

	// 1. Ingest Vulnerabilities (NVD / CISA KEV)
	vulns := []Vulnerability{
		{
			CVEID:       "CVE-2024-6387",
			Title:       "regreSSHion: OpenSSH Remote Unauthenticated Code Execution",
			Description: "A signal handler race condition in OpenSSH server...",
			Severity:    "HIGH",
			CVSS:        8.1,
			IsKEV:       true,
			EPSS:        0.92,
			CPEPattern:  "openssh",
			PublishedAt: time.Now(),
		},
		{
			CVEID:       "CVE-2023-4863",
			Title:       "Heap buffer overflow in libwebp",
			Description: "Opening a malicious WebP image leads to out-of-bounds write...",
			Severity:    "CRITICAL",
			CVSS:        9.8,
			IsKEV:       true,
			EPSS:        0.95,
			CPEPattern:  "libwebp",
			PublishedAt: time.Now(),
		},
	}
	if err := store.IngestVulnerabilities(vulns); err != nil {
		t.Fatalf("IngestVulnerabilities failed: %v", err)
	}

	// 2. Report Installed Software from Endpoint
	sw := []InstalledSoftware{
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
			Product:      "curl",
			Version:      "7.81.0-1ubuntu1.15",
			Architecture: "amd64",
		},
	}
	if err := store.ReplaceSoftwareInventory(tenantID, endpointID, sw); err != nil {
		t.Fatalf("ReplaceSoftwareInventory failed: %v", err)
	}

	// 3. Correlate Vulnerabilities
	matches, err := store.CorrelateEndpoint(tenantID, endpointID)
	if err != nil {
		t.Fatalf("CorrelateEndpoint failed: %v", err)
	}
	if len(matches) != 1 {
		t.Fatalf("expected 1 correlated vulnerability match, got %d", len(matches))
	}
	if matches[0].CVEID != "CVE-2024-6387" || !matches[0].IsKEV {
		t.Fatalf("unexpected match result: %+v", matches[0])
	}

	// 4. List Matches
	savedMatches, err := store.ListMatches(tenantID, endpointID)
	if err != nil || len(savedMatches) != 1 {
		t.Fatalf("failed to retrieve saved matches: %v", err)
	}
}

func TestVuln_SoftwareInventoryLifecycle(t *testing.T) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("sql.Open failed: %v", err)
	}
	defer db.Close()

	store, err := NewStore(db)
	if err != nil {
		t.Fatalf("NewStore failed: %v", err)
	}

	tenantID := "tenant-alpha"
	endpoint1 := "node-linux-1"
	endpoint2 := "node-win-1"

	// 1. Ingest Linux dpkg packages
	dpkgPackages := []InstalledSoftware{
		{
			Source:       "dpkg",
			Vendor:       "Canonical Ltd.",
			Product:      "nginx",
			Version:      "1.18.0-0ubuntu1.4",
			Architecture: "amd64",
			InstallScope: "system",
			Confidence:   ConfidenceAuthoritative,
			RawVendor:    "Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>",
			RawProduct:   "nginx",
			RawVersion:   "1.18.0-0ubuntu1.4",
		},
		{
			Source:       "dpkg",
			Vendor:       "OpenSSL Project",
			Product:      "openssl",
			Version:      "3.0.2-0ubuntu1.15",
			Architecture: "amd64",
			InstallScope: "system",
			Confidence:   ConfidenceAuthoritative,
			RawVendor:    "Ubuntu Developers",
			RawProduct:   "openssl",
			RawVersion:   "3.0.2-0ubuntu1.15",
		},
	}
	if err := store.ReplaceSoftwareInventoryBySource(tenantID, endpoint1, "dpkg", dpkgPackages); err != nil {
		t.Fatalf("ReplaceSoftwareInventoryBySource dpkg failed: %v", err)
	}

	// Ingest snap packages on same endpoint without clobbering dpkg
	snapPackages := []InstalledSoftware{
		{
			Source:       "snap",
			Vendor:       "Canonical Ltd.",
			Product:      "core22",
			Version:      "20240111",
			Architecture: "amd64",
			InstallScope: "system",
			Confidence:   ConfidenceAuthoritative,
			RawVendor:    "Canonical",
			RawProduct:   "core22",
			RawVersion:   "20240111",
		},
	}
	if err := store.ReplaceSoftwareInventoryBySource(tenantID, endpoint1, "snap", snapPackages); err != nil {
		t.Fatalf("ReplaceSoftwareInventoryBySource snap failed: %v", err)
	}

	// Ingest Windows packages on endpoint 2
	winPackages := []InstalledSoftware{
		{
			Source:       "win_registry",
			Vendor:       "Microsoft Corporation",
			Product:      "Microsoft Edge",
			Version:      "122.0.2365.92",
			Architecture: "x64",
			InstallScope: "system",
			Confidence:   ConfidenceAuthoritative,
			RawVendor:    "Microsoft Corporation",
			RawProduct:   "Microsoft Edge",
			RawVersion:   "122.0.2365.92",
		},
		{
			Source:       "win_registry",
			Vendor:       "Git for Windows",
			Product:      "Git",
			Version:      "2.44.0",
			Architecture: "x64",
			InstallScope: "user",
			Confidence:   ConfidenceAuthoritative,
			RawVendor:    "The Git Development Community",
			RawProduct:   "Git version 2.44.0",
			RawVersion:   "2.44.0",
		},
	}
	if err := store.ReplaceSoftwareInventory(tenantID, endpoint2, winPackages); err != nil {
		t.Fatalf("ReplaceSoftwareInventory winPackages failed: %v", err)
	}

	// Query endpoint 1: should have 3 packages (2 dpkg + 1 snap)
	page1, err := store.ListSoftwareInventory(SoftwareFilter{
		TenantID:   tenantID,
		EndpointID: endpoint1,
	})
	if err != nil {
		t.Fatalf("ListSoftwareInventory endpoint1 failed: %v", err)
	}
	if page1.Total != 3 || len(page1.Packages) != 3 {
		t.Fatalf("expected 3 packages for endpoint1, got total=%d len=%d", page1.Total, len(page1.Packages))
	}

	// Query endpoint 1 with source filter: should have 2 dpkg packages
	pageDpkg, err := store.ListSoftwareInventory(SoftwareFilter{
		TenantID:   tenantID,
		EndpointID: endpoint1,
		Source:     "dpkg",
	})
	if err != nil {
		t.Fatalf("ListSoftwareInventory dpkg failed: %v", err)
	}
	if pageDpkg.Total != 2 {
		t.Fatalf("expected 2 dpkg packages, got %d", pageDpkg.Total)
	}

	// Query with search term "git" across tenant: should return 1 result (on endpoint 2)
	pageSearch, err := store.ListSoftwareInventory(SoftwareFilter{
		TenantID: tenantID,
		Search:   "Git",
	})
	if err != nil {
		t.Fatalf("ListSoftwareInventory search failed: %v", err)
	}
	if pageSearch.Total != 1 || pageSearch.Packages[0].Product != "Git" {
		t.Fatalf("expected 1 Git package, got total=%d", pageSearch.Total)
	}
	if pageSearch.Packages[0].RawProduct != "Git version 2.44.0" {
		t.Fatalf("raw product not preserved: %s", pageSearch.Packages[0].RawProduct)
	}

	// Pagination test
	pagePaginated, err := store.ListSoftwareInventory(SoftwareFilter{
		TenantID: tenantID,
		Limit:    2,
		Offset:   0,
	})
	if err != nil {
		t.Fatalf("ListSoftwareInventory paginated failed: %v", err)
	}
	if pagePaginated.Total != 5 || len(pagePaginated.Packages) != 2 {
		t.Fatalf("expected 5 total and 2 items, got total=%d len=%d", pagePaginated.Total, len(pagePaginated.Packages))
	}

	// Delete endpoint 2 inventory
	if err := store.DeleteSoftwareInventory(tenantID, endpoint2); err != nil {
		t.Fatalf("DeleteSoftwareInventory failed: %v", err)
	}
	pageAfterDelete, err := store.ListSoftwareInventory(SoftwareFilter{
		TenantID:   tenantID,
		EndpointID: endpoint2,
	})
	if err != nil {
		t.Fatalf("ListSoftwareInventory after delete failed: %v", err)
	}
	if pageAfterDelete.Total != 0 {
		t.Fatalf("expected 0 packages after delete, got %d", pageAfterDelete.Total)
	}
}

func TestVuln_MigrationAdditive(t *testing.T) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("sql.Open failed: %v", err)
	}
	defer db.Close()

	// Pre-create table in legacy schema without additive columns
	_, err = db.Exec(`
		CREATE TABLE software_inventory (
			id TEXT PRIMARY KEY,
			tenant_id TEXT NOT NULL,
			endpoint_id TEXT NOT NULL,
			source TEXT NOT NULL,
			vendor TEXT NOT NULL,
			product TEXT NOT NULL,
			version TEXT NOT NULL,
			architecture TEXT,
			observed_at TIMESTAMP NOT NULL
		);
	`)
	if err != nil {
		t.Fatalf("failed to create legacy table: %v", err)
	}

	// Run NewStore which calls migrate()
	store, err := NewStore(db)
	if err != nil {
		t.Fatalf("NewStore on existing legacy table failed: %v", err)
	}

	// Verify we can insert and retrieve items with all additive columns
	err = store.ReplaceSoftwareInventory("t1", "ep1", []InstalledSoftware{
		{
			Source:       "dpkg",
			Vendor:       "Debian",
			Product:      "bash",
			Version:      "5.1-6ubuntu1",
			Architecture: "amd64",
			InstallScope: "system",
			Confidence:   ConfidenceAuthoritative,
			RawVendor:    "Debian Maintainers",
			RawProduct:   "bash",
			RawVersion:   "5.1-6ubuntu1",
		},
	})
	if err != nil {
		t.Fatalf("failed to insert into migrated table: %v", err)
	}

	page, err := store.ListSoftwareInventory(SoftwareFilter{TenantID: "t1", EndpointID: "ep1"})
	if err != nil || page.Total != 1 {
		t.Fatalf("failed to query migrated table: total=%d, err=%v", page.Total, err)
	}
	if page.Packages[0].RawVendor != "Debian Maintainers" || page.Packages[0].Confidence != ConfidenceAuthoritative {
		t.Fatalf("unexpected values from migrated table: %+v", page.Packages[0])
	}
}
