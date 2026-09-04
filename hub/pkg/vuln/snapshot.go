package vuln

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

// SnapshotStatus indicates the lifecycle state of a vulnerability feed snapshot.
type SnapshotStatus string

const (
	SnapshotBuilding   SnapshotStatus = "building"
	SnapshotActive     SnapshotStatus = "active"
	SnapshotSuperseded SnapshotStatus = "superseded"
	SnapshotFailed     SnapshotStatus = "failed"
)

var ErrNoActiveSnapshot = errors.New("no active vulnerability feed snapshot found")

// FeedSnapshot represents a versioned vulnerability catalog snapshot.
type FeedSnapshot struct {
	ID             string         `json:"id"`
	CreatedAt      time.Time      `json:"created_at"`
	ActivatedAt    *time.Time     `json:"activated_at,omitempty"`
	Status         SnapshotStatus `json:"status"`
	NVDCount       int            `json:"nvd_count"`
	CISAKEVCount   int            `json:"cisa_kev_count"`
	EPSSCount      int            `json:"epss_count"`
	SourceMetadata string         `json:"source_metadata,omitempty"`
	ErrorMessage   string         `json:"error_message,omitempty"`
}

// VulnFilter provides querying and filtering options for the vulnerability catalog.
type VulnFilter struct {
	SnapshotID string `json:"snapshot_id,omitempty"`
	Search     string `json:"search,omitempty"`
	Severity   string `json:"severity,omitempty"`
	IsKEV      *bool  `json:"is_kev,omitempty"`
	Limit      int    `json:"limit,omitempty"`
	Offset     int    `json:"offset,omitempty"`
}

// CreateSnapshot registers a new snapshot in building status off to the side.
func (s *Store) CreateSnapshot(id, metadata string) (*FeedSnapshot, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now().UTC()
	query := `
		INSERT INTO vuln_feed_snapshots (id, created_at, status, nvd_count, cisa_kev_count, epss_count, source_metadata, error_message)
		VALUES (?, ?, ?, 0, 0, 0, ?, '')
	`
	_, err := s.db.Exec(query, id, now, string(SnapshotBuilding), metadata)
	if err != nil {
		return nil, fmt.Errorf("failed to create snapshot: %w", err)
	}

	return &FeedSnapshot{
		ID:             id,
		CreatedAt:      now,
		Status:         SnapshotBuilding,
		SourceMetadata: metadata,
	}, nil
}

// IngestSnapshotData writes parsed feed data into isolated tables for the specified snapshot.
func (s *Store) IngestSnapshotData(
	snapshotID string,
	vulns []Vulnerability,
	kevItems []CISAKEVItem,
	epssScores map[string]EPSSScore,
) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	// Verify snapshot exists and is building
	var status string
	err = tx.QueryRow(`SELECT status FROM vuln_feed_snapshots WHERE id = ?`, snapshotID).Scan(&status)
	if err != nil {
		return fmt.Errorf("snapshot %s not found: %w", snapshotID, err)
	}
	if status != string(SnapshotBuilding) {
		return fmt.Errorf("snapshot %s is not in building status (current: %s)", snapshotID, status)
	}

	// 1. Ingest CISA KEV
	kevMap := make(map[string]CISAKEVItem)
	if len(kevItems) > 0 {
		stmtKEV, err := tx.Prepare(`
			INSERT INTO snapshot_cisa_kev (
				snapshot_id, cve_id, vendor_project, product, vulnerability_name,
				date_added, short_description, required_action, due_date, known_ransomware_campaign_use
			) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
			ON CONFLICT(snapshot_id, cve_id) DO UPDATE SET
				vendor_project=excluded.vendor_project,
				product=excluded.product,
				vulnerability_name=excluded.vulnerability_name,
				date_added=excluded.date_added,
				short_description=excluded.short_description,
				required_action=excluded.required_action,
				due_date=excluded.due_date,
				known_ransomware_campaign_use=excluded.known_ransomware_campaign_use
		`)
		if err != nil {
			return err
		}
		defer stmtKEV.Close()

		for _, k := range kevItems {
			kevMap[k.CVEID] = k
			_, err := stmtKEV.Exec(
				snapshotID, k.CVEID, k.VendorProject, k.Product, k.VulnerabilityName,
				k.DateAdded, k.ShortDescription, k.RequiredAction, k.DueDate, k.KnownRansomwareCampaignUse,
			)
			if err != nil {
				return fmt.Errorf("failed to insert CISA KEV %s: %w", k.CVEID, err)
			}
		}
	}

	// 2. Ingest Vulnerabilities (merged with KEV and EPSS)
	stmtVuln, err := tx.Prepare(`
		INSERT INTO snapshot_vulnerabilities (
			snapshot_id, cve_id, title, description, severity, cvss, is_kev, epss, cpe_pattern, published_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(snapshot_id, cve_id) DO UPDATE SET
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
	defer stmtVuln.Close()

	nvdCount := 0
	for _, v := range vulns {
		isKEV := 0
		if v.IsKEV {
			isKEV = 1
		}
		if _, exists := kevMap[v.CVEID]; exists {
			isKEV = 1
		}

		epssVal := v.EPSS
		if epssScores != nil {
			if score, ok := epssScores[v.CVEID]; ok {
				epssVal = score.Score
			}
		}

		_, err := stmtVuln.Exec(
			snapshotID, v.CVEID, v.Title, v.Description, v.Severity, v.CVSS, isKEV, epssVal, v.CPEPattern, v.PublishedAt,
		)
		if err != nil {
			return fmt.Errorf("failed to insert snapshot vuln %s: %w", v.CVEID, err)
		}
		nvdCount++
	}

	// Also insert any KEV items not present in NVD batch
	for cveID, k := range kevMap {
		var exists int
		_ = tx.QueryRow(`SELECT 1 FROM snapshot_vulnerabilities WHERE snapshot_id = ? AND cve_id = ?`, snapshotID, cveID).Scan(&exists)
		if exists == 0 {
			now := time.Now().UTC()
			_, err := stmtVuln.Exec(
				snapshotID, k.CVEID, k.VulnerabilityName, k.ShortDescription, "HIGH", 7.5, 1, 0.0, "", now,
			)
			if err != nil {
				return fmt.Errorf("failed to insert standalone KEV %s: %w", k.CVEID, err)
			}
			nvdCount++
		}
	}

	// Update counts in metadata
	epssCount := len(epssScores)
	cisaCount := len(kevMap)
	_, err = tx.Exec(`
		UPDATE vuln_feed_snapshots
		SET nvd_count = ?, cisa_kev_count = ?, epss_count = ?
		WHERE id = ?
	`, nvdCount, cisaCount, epssCount, snapshotID)
	if err != nil {
		return err
	}

	return tx.Commit()
}

// ActivateSnapshot validates and atomically promotes a building snapshot to active.
func (s *Store) ActivateSnapshot(snapshotID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	var status string
	var nvdCount int
	err = tx.QueryRow(`SELECT status, nvd_count FROM vuln_feed_snapshots WHERE id = ?`, snapshotID).Scan(&status, &nvdCount)
	if err != nil {
		return fmt.Errorf("snapshot %s not found: %w", snapshotID, err)
	}
	if status != string(SnapshotBuilding) {
		return fmt.Errorf("cannot activate snapshot %s in state %s", snapshotID, status)
	}
	if nvdCount == 0 {
		return fmt.Errorf("refusing to activate empty snapshot %s (0 CVEs)", snapshotID)
	}

	now := time.Now().UTC()

	// Demote existing active snapshots to superseded
	_, err = tx.Exec(`UPDATE vuln_feed_snapshots SET status = ? WHERE status = ?`, string(SnapshotSuperseded), string(SnapshotActive))
	if err != nil {
		return err
	}

	// Promote new snapshot to active
	_, err = tx.Exec(`UPDATE vuln_feed_snapshots SET status = ?, activated_at = ? WHERE id = ?`, string(SnapshotActive), now, snapshotID)
	if err != nil {
		return err
	}

	// Synchronize base table for backward compatibility
	_, err = tx.Exec(`DELETE FROM vulnerabilities`)
	if err != nil {
		return err
	}
	_, err = tx.Exec(`
		INSERT INTO vulnerabilities (cve_id, title, description, severity, cvss, is_kev, epss, cpe_pattern, published_at)
		SELECT cve_id, title, description, severity, cvss, is_kev, epss, cpe_pattern, published_at
		FROM snapshot_vulnerabilities WHERE snapshot_id = ?
	`, snapshotID)
	if err != nil {
		return err
	}

	return tx.Commit()
}

// FailSnapshot records an aborted or failed sync without touching the active snapshot.
func (s *Store) FailSnapshot(snapshotID string, errMsg string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	_, err := s.db.Exec(`
		UPDATE vuln_feed_snapshots
		SET status = ?, error_message = ?
		WHERE id = ?
	`, string(SnapshotFailed), errMsg, snapshotID)
	return err
}

// GetActiveSnapshot returns the currently active feed snapshot.
func (s *Store) GetActiveSnapshot() (*FeedSnapshot, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	row := s.db.QueryRow(`
		SELECT id, created_at, activated_at, status, nvd_count, cisa_kev_count, epss_count, source_metadata, error_message
		FROM vuln_feed_snapshots WHERE status = ?
		ORDER BY activated_at DESC LIMIT 1
	`, string(SnapshotActive))

	var snap FeedSnapshot
	var actTime sql.NullTime
	err := row.Scan(
		&snap.ID, &snap.CreatedAt, &actTime, &snap.Status,
		&snap.NVDCount, &snap.CISAKEVCount, &snap.EPSSCount,
		&snap.SourceMetadata, &snap.ErrorMessage,
	)
	if err == sql.ErrNoRows {
		return nil, ErrNoActiveSnapshot
	}
	if err != nil {
		return nil, err
	}
	if actTime.Valid {
		snap.ActivatedAt = &actTime.Time
	}
	return &snap, nil
}

// ListSnapshots returns all registered snapshots in reverse chronological order.
func (s *Store) ListSnapshots() ([]*FeedSnapshot, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	rows, err := s.db.Query(`
		SELECT id, created_at, activated_at, status, nvd_count, cisa_kev_count, epss_count, source_metadata, error_message
		FROM vuln_feed_snapshots
		ORDER BY created_at DESC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var list []*FeedSnapshot
	for rows.Next() {
		var snap FeedSnapshot
		var actTime sql.NullTime
		if err := rows.Scan(
			&snap.ID, &snap.CreatedAt, &actTime, &snap.Status,
			&snap.NVDCount, &snap.CISAKEVCount, &snap.EPSSCount,
			&snap.SourceMetadata, &snap.ErrorMessage,
		); err != nil {
			return nil, err
		}
		if actTime.Valid {
			snap.ActivatedAt = &actTime.Time
		}
		list = append(list, &snap)
	}

	return list, nil
}

// GetVulnerabilitiesForSnapshot retrieves vulnerabilities from a specific snapshot (or the active snapshot if empty).
func (s *Store) GetVulnerabilitiesForSnapshot(filter VulnFilter) ([]Vulnerability, int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	snapshotID := filter.SnapshotID
	if snapshotID == "" {
		// Resolve active snapshot ID
		var activeID string
		err := s.db.QueryRow(`SELECT id FROM vuln_feed_snapshots WHERE status = ? ORDER BY activated_at DESC LIMIT 1`, string(SnapshotActive)).Scan(&activeID)
		if err == sql.ErrNoRows {
			return []Vulnerability{}, 0, nil
		}
		if err != nil {
			return nil, 0, err
		}
		snapshotID = activeID
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

	whereClauses = append(whereClauses, "snapshot_id = ?")
	args = append(args, snapshotID)

	if filter.Severity != "" {
		whereClauses = append(whereClauses, "severity = ?")
		args = append(args, strings.ToUpper(filter.Severity))
	}

	if filter.IsKEV != nil {
		whereClauses = append(whereClauses, "is_kev = ?")
		if *filter.IsKEV {
			args = append(args, 1)
		} else {
			args = append(args, 0)
		}
	}

	if filter.Search != "" {
		pat := "%" + filter.Search + "%"
		whereClauses = append(whereClauses, "(cve_id LIKE ? OR title LIKE ? OR description LIKE ?)")
		args = append(args, pat, pat, pat)
	}

	whereSQL := strings.Join(whereClauses, " AND ")

	// Total count
	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM snapshot_vulnerabilities WHERE %s", whereSQL)
	var total int
	if err := s.db.QueryRow(countQuery, args...).Scan(&total); err != nil {
		return nil, 0, err
	}

	// Items
	selectQuery := fmt.Sprintf(`
		SELECT cve_id, title, description, severity, cvss, is_kev, epss, cpe_pattern, published_at
		FROM snapshot_vulnerabilities
		WHERE %s
		ORDER BY cvss DESC, cve_id ASC
		LIMIT ? OFFSET ?
	`, whereSQL)

	fetchArgs := append(args, limit, offset)
	rows, err := s.db.Query(selectQuery, fetchArgs...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var results []Vulnerability
	for rows.Next() {
		var v Vulnerability
		var kevInt int
		if err := rows.Scan(
			&v.CVEID, &v.Title, &v.Description, &v.Severity, &v.CVSS, &kevInt, &v.EPSS, &v.CPEPattern, &v.PublishedAt,
		); err != nil {
			return nil, 0, err
		}
		v.IsKEV = (kevInt == 1)
		results = append(results, v)
	}

	return results, total, nil
}
