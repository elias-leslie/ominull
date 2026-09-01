package storage

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// InstallReport stores error output and automatically gathered system context
// submitted from the /install self-service portal.
type InstallReport struct {
	ID          string                 `json:"id"`
	CreatedAt   time.Time              `json:"created_at"`
	ClientIP    string                 `json:"client_ip"`
	Platform    string                 `json:"platform"`
	UserAgent   string                 `json:"user_agent"`
	SystemInfo  map[string]interface{} `json:"system_info,omitempty"`
	ErrorOutput string                 `json:"error_output"`
	WindowID    string                 `json:"window_id,omitempty"`
}

func (s *Store) initInstallReportsTable() error {
	schema := `
	CREATE TABLE IF NOT EXISTS install_reports (
		id TEXT PRIMARY KEY,
		client_ip TEXT NOT NULL,
		platform TEXT NOT NULL DEFAULT '',
		user_agent TEXT NOT NULL DEFAULT '',
		system_info TEXT NOT NULL DEFAULT '{}',
		error_output TEXT NOT NULL,
		window_id TEXT NOT NULL DEFAULT '',
		created_at DATETIME NOT NULL
	);
	CREATE INDEX IF NOT EXISTS idx_install_reports_created ON install_reports(created_at DESC);
	`
	_, err := s.db.Exec(schema)
	return err
}

// CreateInstallReport records an installer error report with auto-captured metadata.
func (s *Store) CreateInstallReport(report InstallReport) (InstallReport, error) {
	if strings.TrimSpace(report.ErrorOutput) == "" {
		return InstallReport{}, errors.New("error output cannot be empty")
	}
	if report.ID == "" {
		var raw [12]byte
		if _, err := rand.Read(raw[:]); err != nil {
			return InstallReport{}, fmt.Errorf("crypto rand failed: %w", err)
		}
		report.ID = "rpt_" + hex.EncodeToString(raw[:])
	}
	if report.CreatedAt.IsZero() {
		report.CreatedAt = time.Now().UTC()
	}
	if report.SystemInfo == nil {
		report.SystemInfo = map[string]interface{}{}
	}
	sysJSON, err := json.Marshal(report.SystemInfo)
	if err != nil {
		sysJSON = []byte("{}")
	}

	query := `
	INSERT INTO install_reports (
		id, client_ip, platform, user_agent, system_info, error_output, window_id, created_at
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
	`
	_, err = s.db.Exec(query,
		report.ID,
		strings.TrimSpace(report.ClientIP),
		strings.TrimSpace(report.Platform),
		strings.TrimSpace(report.UserAgent),
		string(sysJSON),
		strings.TrimSpace(report.ErrorOutput),
		strings.TrimSpace(report.WindowID),
		report.CreatedAt,
	)
	if err != nil {
		return InstallReport{}, fmt.Errorf("failed to save install report: %w", err)
	}
	return report, nil
}

// ListInstallReports returns recent install reports in descending chronological order.
func (s *Store) ListInstallReports(limit int) ([]InstallReport, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	query := `
	SELECT id, client_ip, platform, user_agent, system_info, error_output, window_id, created_at
	FROM install_reports
	ORDER BY created_at DESC
	LIMIT ?
	`
	rows, err := s.db.Query(query, limit)
	if err != nil {
		return nil, fmt.Errorf("query install reports failed: %w", err)
	}
	defer rows.Close()

	var reports []InstallReport
	for rows.Next() {
		var r InstallReport
		var sysStr string
		if err := rows.Scan(
			&r.ID,
			&r.ClientIP,
			&r.Platform,
			&r.UserAgent,
			&sysStr,
			&r.ErrorOutput,
			&r.WindowID,
			&r.CreatedAt,
		); err != nil {
			return nil, err
		}
		if sysStr != "" {
			_ = json.Unmarshal([]byte(sysStr), &r.SystemInfo)
		}
		if r.SystemInfo == nil {
			r.SystemInfo = map[string]interface{}{}
		}
		reports = append(reports, r)
	}
	return reports, rows.Err()
}

// GetInstallReport fetches a single report by ID.
func (s *Store) GetInstallReport(id string) (InstallReport, error) {
	query := `
	SELECT id, client_ip, platform, user_agent, system_info, error_output, window_id, created_at
	FROM install_reports
	WHERE id = ?
	`
	var r InstallReport
	var sysStr string
	err := s.db.QueryRow(query, id).Scan(
		&r.ID,
		&r.ClientIP,
		&r.Platform,
		&r.UserAgent,
		&sysStr,
		&r.ErrorOutput,
		&r.WindowID,
		&r.CreatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return InstallReport{}, fmt.Errorf("install report %q not found", id)
		}
		return InstallReport{}, err
	}
	if sysStr != "" {
		_ = json.Unmarshal([]byte(sysStr), &r.SystemInfo)
	}
	return r, nil
}

// DeleteInstallReport removes a report by ID.
func (s *Store) DeleteInstallReport(id string) error {
	res, err := s.db.Exec("DELETE FROM install_reports WHERE id = ?", id)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("install report %q not found", id)
	}
	return nil
}
