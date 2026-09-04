package vuln

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	_ "modernc.org/sqlite"
)

// Store manages software inventory, CVE catalog, and correlation.
type Store struct {
	mu sync.Mutex
	db *sql.DB
}

// NewStore initializes a software inventory and vulnerability store.
func NewStore(db *sql.DB) (*Store, error) {
	if db == nil {
		return nil, errors.New("nil db")
	}
	s := &Store{db: db}
	if err := s.migrate(); err != nil {
		return nil, fmt.Errorf("vuln store migration failed: %w", err)
	}
	return s, nil
}

func (s *Store) migrate() error {
	query := `
	CREATE TABLE IF NOT EXISTS software_inventory (
		id TEXT PRIMARY KEY,
		tenant_id TEXT NOT NULL,
		endpoint_id TEXT NOT NULL,
		source TEXT NOT NULL,
		vendor TEXT NOT NULL,
		product TEXT NOT NULL,
		version TEXT NOT NULL,
		architecture TEXT,
		install_scope TEXT DEFAULT 'system',
		confidence TEXT DEFAULT 'authoritative',
		raw_vendor TEXT DEFAULT '',
		raw_product TEXT DEFAULT '',
		raw_version TEXT DEFAULT '',
		observed_at TIMESTAMP NOT NULL
	);
	CREATE INDEX IF NOT EXISTS idx_software_endpoint ON software_inventory(tenant_id, endpoint_id);
	CREATE INDEX IF NOT EXISTS idx_software_search ON software_inventory(tenant_id, product, vendor);
	CREATE UNIQUE INDEX IF NOT EXISTS idx_software_identity ON software_inventory(tenant_id, endpoint_id, source, product, version, architecture);

	CREATE TABLE IF NOT EXISTS vulnerabilities (
		cve_id TEXT PRIMARY KEY,
		title TEXT NOT NULL,
		description TEXT NOT NULL,
		severity TEXT NOT NULL,
		cvss REAL NOT NULL,
		is_kev INTEGER DEFAULT 0,
		epss REAL DEFAULT 0.0,
		cpe_pattern TEXT NOT NULL,
		published_at TIMESTAMP NOT NULL
	);

	CREATE TABLE IF NOT EXISTS vulnerability_matches (
		id TEXT PRIMARY KEY,
		tenant_id TEXT NOT NULL,
		endpoint_id TEXT NOT NULL,
		software_id TEXT NOT NULL,
		product_name TEXT NOT NULL,
		version TEXT NOT NULL,
		cve_id TEXT NOT NULL,
		severity TEXT NOT NULL,
		is_kev INTEGER DEFAULT 0,
		status TEXT NOT NULL,
		confidence REAL NOT NULL,
		match_reason TEXT NOT NULL,
		detected_at TIMESTAMP NOT NULL
	);
	CREATE INDEX IF NOT EXISTS idx_vuln_matches_endpoint ON vulnerability_matches(tenant_id, endpoint_id);

	CREATE TABLE IF NOT EXISTS vuln_feed_snapshots (
		id TEXT PRIMARY KEY,
		created_at TIMESTAMP NOT NULL,
		activated_at TIMESTAMP,
		status TEXT NOT NULL,
		nvd_count INTEGER DEFAULT 0,
		cisa_kev_count INTEGER DEFAULT 0,
		epss_count INTEGER DEFAULT 0,
		source_metadata TEXT,
		error_message TEXT DEFAULT ''
	);
	CREATE INDEX IF NOT EXISTS idx_snapshots_status ON vuln_feed_snapshots(status);

	CREATE TABLE IF NOT EXISTS snapshot_vulnerabilities (
		snapshot_id TEXT NOT NULL,
		cve_id TEXT NOT NULL,
		title TEXT NOT NULL,
		description TEXT NOT NULL,
		severity TEXT NOT NULL,
		cvss REAL NOT NULL,
		is_kev INTEGER DEFAULT 0,
		epss REAL DEFAULT 0.0,
		cpe_pattern TEXT NOT NULL,
		published_at TIMESTAMP NOT NULL,
		PRIMARY KEY (snapshot_id, cve_id)
	);
	CREATE INDEX IF NOT EXISTS idx_snap_vuln_cve ON snapshot_vulnerabilities(cve_id);
	CREATE INDEX IF NOT EXISTS idx_snap_vuln_kev ON snapshot_vulnerabilities(snapshot_id, is_kev);
	CREATE INDEX IF NOT EXISTS idx_snap_vuln_sev ON snapshot_vulnerabilities(snapshot_id, severity);

	CREATE TABLE IF NOT EXISTS snapshot_cisa_kev (
		snapshot_id TEXT NOT NULL,
		cve_id TEXT NOT NULL,
		vendor_project TEXT NOT NULL,
		product TEXT NOT NULL,
		vulnerability_name TEXT NOT NULL,
		date_added TEXT NOT NULL,
		short_description TEXT NOT NULL,
		required_action TEXT NOT NULL,
		due_date TEXT NOT NULL,
		known_ransomware_campaign_use TEXT NOT NULL,
		PRIMARY KEY (snapshot_id, cve_id)
	);
	`
	if _, err := s.db.Exec(query); err != nil {
		return err
	}

	// Ensure additive columns exist if table predated this migration
	cols := []struct {
		col     string
		colType string
	}{
		{"install_scope", "TEXT DEFAULT 'system'"},
		{"confidence", "TEXT DEFAULT 'authoritative'"},
		{"raw_vendor", "TEXT DEFAULT ''"},
		{"raw_product", "TEXT DEFAULT ''"},
		{"raw_version", "TEXT DEFAULT ''"},
	}
	for _, c := range cols {
		if err := ensureColumn(s.db, "software_inventory", c.col, c.colType); err != nil {
			return err
		}
	}

	return nil
}

func ensureColumn(db *sql.DB, table, col, colType string) error {
	rows, err := db.Query(fmt.Sprintf("PRAGMA table_info(%s)", table))
	if err != nil {
		return err
	}
	defer rows.Close()

	for rows.Next() {
		var cid int
		var name, ctype string
		var notnull, pk int
		var dfltValue *string
		if err := rows.Scan(&cid, &name, &ctype, &notnull, &dfltValue, &pk); err == nil {
			if strings.EqualFold(name, col) {
				return nil
			}
		}
	}
	_, err = db.Exec(fmt.Sprintf("ALTER TABLE %s ADD COLUMN %s %s", table, col, colType))
	return err
}

// ReplaceSoftwareInventory replaces the current software inventory snapshot for an endpoint.
func (s *Store) ReplaceSoftwareInventory(tenantID, endpointID string, items []InstalledSoftware) error {
	return s.ReplaceSoftwareInventoryBySource(tenantID, endpointID, "", items)
}

// ReplaceSoftwareInventoryBySource replaces software inventory for an endpoint, optionally scoped to a single source.
func (s *Store) ReplaceSoftwareInventoryBySource(tenantID, endpointID, source string, items []InstalledSoftware) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	// Clear existing records for endpoint (optionally filtered by source)
	if source != "" {
		_, err = tx.Exec(`DELETE FROM software_inventory WHERE tenant_id = ? AND endpoint_id = ? AND source = ?`, tenantID, endpointID, source)
	} else {
		_, err = tx.Exec(`DELETE FROM software_inventory WHERE tenant_id = ? AND endpoint_id = ?`, tenantID, endpointID)
	}
	if err != nil {
		return err
	}

	stmt, err := tx.Prepare(`
		INSERT INTO software_inventory (
			id, tenant_id, endpoint_id, source, vendor, product, version, architecture,
			install_scope, confidence, raw_vendor, raw_product, raw_version, observed_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(tenant_id, endpoint_id, source, product, version, architecture) DO UPDATE SET
			vendor=excluded.vendor,
			install_scope=excluded.install_scope,
			confidence=excluded.confidence,
			raw_vendor=excluded.raw_vendor,
			raw_product=excluded.raw_product,
			raw_version=excluded.raw_version,
			observed_at=excluded.observed_at
	`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	now := time.Now().UTC()
	for _, it := range items {
		id := it.ID
		if id == "" {
			id = uuid.New().String()
		}
		confidence := it.Confidence
		if confidence == "" {
			confidence = ConfidenceAuthoritative
		}
		installScope := it.InstallScope
		if installScope == "" {
			installScope = "system"
		}
		rawVendor := it.RawVendor
		if rawVendor == "" {
			rawVendor = it.Vendor
		}
		rawProduct := it.RawProduct
		if rawProduct == "" {
			rawProduct = it.Product
		}
		rawVersion := it.RawVersion
		if rawVersion == "" {
			rawVersion = it.Version
		}
		obs := it.ObservedAt
		if obs.IsZero() {
			obs = now
		}

		_, err := stmt.Exec(
			id, tenantID, endpointID, it.Source, it.Vendor, it.Product, it.Version, it.Architecture,
			installScope, string(confidence), rawVendor, rawProduct, rawVersion, obs,
		)
		if err != nil {
			return err
		}
	}

	return tx.Commit()
}

// ListSoftwareInventory queries installed software matching the provided filter.
func (s *Store) ListSoftwareInventory(filter SoftwareFilter) (*SoftwareInventoryPage, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if filter.TenantID == "" {
		return nil, errors.New("tenant_id is required")
	}

	limit := filter.Limit
	if limit <= 0 {
		limit = 50
	} else if limit > 500 {
		limit = 500
	}
	offset := filter.Offset
	if offset < 0 {
		offset = 0
	}

	var whereClauses []string
	var args []interface{}

	whereClauses = append(whereClauses, "tenant_id = ?")
	args = append(args, filter.TenantID)

	if filter.EndpointID != "" {
		whereClauses = append(whereClauses, "endpoint_id = ?")
		args = append(args, filter.EndpointID)
	}

	if filter.Source != "" {
		whereClauses = append(whereClauses, "source = ?")
		args = append(args, filter.Source)
	}

	if filter.Search != "" {
		searchPattern := "%" + filter.Search + "%"
		whereClauses = append(whereClauses, "(product LIKE ? OR vendor LIKE ? OR raw_product LIKE ?)")
		args = append(args, searchPattern, searchPattern, searchPattern)
	}

	whereSQL := strings.Join(whereClauses, " AND ")

	// Count total
	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM software_inventory WHERE %s", whereSQL)
	var total int
	if err := s.db.QueryRow(countQuery, args...).Scan(&total); err != nil {
		return nil, fmt.Errorf("software inventory count failed: %w", err)
	}

	// Fetch items
	selectQuery := fmt.Sprintf(`
		SELECT id, tenant_id, endpoint_id, source, vendor, product, version, architecture,
		       install_scope, confidence, raw_vendor, raw_product, raw_version, observed_at
		FROM software_inventory
		WHERE %s
		ORDER BY product ASC, version ASC
		LIMIT ? OFFSET ?
	`, whereSQL)

	fetchArgs := append(args, limit, offset)
	rows, err := s.db.Query(selectQuery, fetchArgs...)
	if err != nil {
		return nil, fmt.Errorf("software inventory query failed: %w", err)
	}
	defer rows.Close()

	var packages []InstalledSoftware
	for rows.Next() {
		var it InstalledSoftware
		var confStr string
		var obs time.Time
		if err := rows.Scan(
			&it.ID, &it.TenantID, &it.EndpointID, &it.Source, &it.Vendor, &it.Product, &it.Version, &it.Architecture,
			&it.InstallScope, &confStr, &it.RawVendor, &it.RawProduct, &it.RawVersion, &obs,
		); err != nil {
			return nil, fmt.Errorf("software inventory scan failed: %w", err)
		}
		it.Confidence = SoftwareConfidence(confStr)
		it.ObservedAt = obs
		packages = append(packages, it)
	}

	if packages == nil {
		packages = []InstalledSoftware{}
	}

	return &SoftwareInventoryPage{
		Total:    total,
		Packages: packages,
		Limit:    limit,
		Offset:   offset,
	}, nil
}

// DeleteSoftwareInventory removes software inventory and correlation matches for an endpoint.
func (s *Store) DeleteSoftwareInventory(tenantID, endpointID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	if _, err := tx.Exec(`DELETE FROM software_inventory WHERE tenant_id = ? AND endpoint_id = ?`, tenantID, endpointID); err != nil {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM vulnerability_matches WHERE tenant_id = ? AND endpoint_id = ?`, tenantID, endpointID); err != nil {
		return err
	}

	return tx.Commit()
}

// IngestVulnerabilities inserts or updates CVE definitions.
func (s *Store) IngestVulnerabilities(vulns []Vulnerability) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	stmt, err := tx.Prepare(`
		INSERT INTO vulnerabilities (cve_id, title, description, severity, cvss, is_kev, epss, cpe_pattern, published_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(cve_id) DO UPDATE SET
			title=excluded.title,
			description=excluded.description,
			severity=excluded.severity,
			cvss=excluded.cvss,
			is_kev=excluded.is_kev,
			epss=excluded.epss,
			cpe_pattern=excluded.cpe_pattern,
			published_at=excluded.published_at
	`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	for _, v := range vulns {
		isKEV := 0
		if v.IsKEV {
			isKEV = 1
		}
		_, err := stmt.Exec(v.CVEID, v.Title, v.Description, v.Severity, v.CVSS, isKEV, v.EPSS, v.CPEPattern, v.PublishedAt)
		if err != nil {
			return err
		}
	}
	return tx.Commit()
}

// CorrelateEndpoint matches an endpoint's installed software against the vulnerability catalog.
func (s *Store) CorrelateEndpoint(tenantID, endpointID string) ([]*VulnerabilityMatch, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Load installed software
	rows, err := s.db.Query(`
		SELECT id, product, version
		FROM software_inventory
		WHERE tenant_id = ? AND endpoint_id = ?
	`, tenantID, endpointID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	type swItem struct {
		id      string
		product string
		version string
	}
	var swList []swItem
	for rows.Next() {
		var it swItem
		if err := rows.Scan(&it.id, &it.product, &it.version); err == nil {
			swList = append(swList, it)
		}
	}

	// Load vulnerabilities
	vRows, err := s.db.Query(`SELECT cve_id, severity, is_kev, cpe_pattern FROM vulnerabilities`)
	if err != nil {
		return nil, err
	}
	defer vRows.Close()

	type vItem struct {
		cveID      string
		severity   string
		isKEV      bool
		cpePattern string
	}
	var vList []vItem
	for vRows.Next() {
		var v vItem
		var kev int
		if err := vRows.Scan(&v.cveID, &v.severity, &kev, &v.cpePattern); err == nil {
			v.isKEV = (kev == 1)
			vList = append(vList, v)
		}
	}

	// Correlate
	var matches []*VulnerabilityMatch
	now := time.Now().UTC()

	// Clear old matches
	_, _ = s.db.Exec(`DELETE FROM vulnerability_matches WHERE tenant_id = ? AND endpoint_id = ?`, tenantID, endpointID)

	stmt, err := s.db.Prepare(`
		INSERT INTO vulnerability_matches (id, tenant_id, endpoint_id, software_id, product_name, version, cve_id, severity, is_kev, status, confidence, match_reason, detected_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`)
	if err != nil {
		return nil, err
	}
	defer stmt.Close()

	for _, sw := range swList {
		for _, v := range vList {
			if strings.Contains(strings.ToLower(sw.product), strings.ToLower(v.cpePattern)) {
				m := &VulnerabilityMatch{
					ID:          uuid.New().String(),
					TenantID:    tenantID,
					EndpointID:  endpointID,
					SoftwareID:  sw.id,
					ProductName: sw.product,
					Version:     sw.version,
					CVEID:       v.cveID,
					Severity:    v.severity,
					IsKEV:       v.isKEV,
					Status:      MatchStatusMatched,
					Confidence:  0.95,
					MatchReason: fmt.Sprintf("Authoritative package match: %s v%s against CPE %s", sw.product, sw.version, v.cpePattern),
					DetectedAt:  now,
				}
				kevInt := 0
				if m.IsKEV {
					kevInt = 1
				}
				_, _ = stmt.Exec(m.ID, m.TenantID, m.EndpointID, m.SoftwareID, m.ProductName, m.Version, m.CVEID, m.Severity, kevInt, string(m.Status), m.Confidence, m.MatchReason, m.DetectedAt)
				matches = append(matches, m)
			}
		}
	}

	return matches, nil
}

// ListMatches returns recorded vulnerability matches for an endpoint.
func (s *Store) ListMatches(tenantID, endpointID string) ([]*VulnerabilityMatch, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	var rows *sql.Rows
	var err error
	if endpointID != "" {
		rows, err = s.db.Query(`
			SELECT id, tenant_id, endpoint_id, software_id, product_name, version, cve_id, severity, is_kev, status, confidence, match_reason, detected_at
			FROM vulnerability_matches WHERE tenant_id = ? AND endpoint_id = ? ORDER BY severity DESC
		`, tenantID, endpointID)
	} else {
		rows, err = s.db.Query(`
			SELECT id, tenant_id, endpoint_id, software_id, product_name, version, cve_id, severity, is_kev, status, confidence, match_reason, detected_at
			FROM vulnerability_matches WHERE tenant_id = ? ORDER BY severity DESC
		`, tenantID)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var matches []*VulnerabilityMatch
	for rows.Next() {
		var m VulnerabilityMatch
		var kev int
		if err := rows.Scan(&m.ID, &m.TenantID, &m.EndpointID, &m.SoftwareID, &m.ProductName, &m.Version, &m.CVEID, &m.Severity, &kev, &m.Status, &m.Confidence, &m.MatchReason, &m.DetectedAt); err != nil {
			return nil, err
		}
		m.IsKEV = (kev == 1)
		matches = append(matches, &m)
	}
	return matches, nil
}
