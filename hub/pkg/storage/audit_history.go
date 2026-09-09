package storage

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"
)

type AuditFilter struct {
	Actor, Action string
	From, To      time.Time
}
type AuditPage struct {
	Entries []AuditEntry `json:"entries"`
	Next    string       `json:"next_cursor"`
	Limit   int          `json:"limit"`
}
type auditCursor struct {
	Snapshot int64  `json:"s"`
	At       int64  `json:"t"`
	ID       string `json:"i"`
}

func (s *Store) initAuditHistorySchema() error {
	if err := runAdditiveMigration(s.db, "ALTER TABLE audit_logs ADD COLUMN event_time INTEGER"); err != nil {
		return err
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	rows, err := tx.Query("SELECT id,timestamp FROM audit_logs WHERE event_time IS NULL")
	if err != nil {
		return err
	}
	type oldRow struct {
		id string
		at time.Time
	}
	var old []oldRow
	for rows.Next() {
		var row oldRow
		if err := rows.Scan(&row.id, &row.at); err != nil {
			rows.Close()
			return err
		}
		old = append(old, row)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	for _, row := range old {
		if _, err = tx.Exec("UPDATE audit_logs SET event_time=? WHERE id=?", row.at.UnixNano(), row.id); err != nil {
			return err
		}
	}
	if _, err = tx.Exec("CREATE INDEX IF NOT EXISTS idx_audit_chronology ON audit_logs(event_time DESC,id DESC)"); err != nil {
		return err
	}
	return tx.Commit()
}

// A high-water mark freezes the browsing snapshot, including backdated inserts.
// The keyset orders equal timestamps by ID and never shifts with new writes.
func (s *Store) AuditHistory(tenant string, limit int, cursor string, filter AuditFilter) (AuditPage, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	page := AuditPage{Entries: []AuditEntry{}, Limit: limit}
	var c auditCursor
	if cursor != "" {
		raw, err := base64.RawURLEncoding.DecodeString(cursor)
		if err != nil || len(raw) > 1024 {
			return page, fmt.Errorf("invalid audit cursor")
		}
		if json.Unmarshal(raw, &c) != nil || c.Snapshot < 0 || c.ID == "" {
			return page, fmt.Errorf("invalid audit cursor")
		}
	} else if err := s.db.QueryRow("SELECT COALESCE(MAX(rowid),0) FROM audit_logs").Scan(&c.Snapshot); err != nil {
		return page, err
	}
	where := " WHERE rowid<=?"
	args := []any{c.Snapshot}
	if tenant != "" {
		where += " AND tenant_id=?"
		args = append(args, tenant)
	}
	if cursor != "" {
		where += " AND (event_time<? OR (event_time=? AND id<?))"
		args = append(args, c.At, c.At, c.ID)
	}
	if filter.Actor != "" {
		where += " AND (username=? OR user_id=?)"
		args = append(args, filter.Actor, filter.Actor)
	}
	if filter.Action != "" {
		where += " AND action=?"
		args = append(args, filter.Action)
	}
	if !filter.From.IsZero() {
		where += " AND event_time>=?"
		args = append(args, filter.From.UnixNano())
	}
	if !filter.To.IsZero() {
		where += " AND event_time<?"
		args = append(args, filter.To.UnixNano())
	}
	args = append(args, limit+1)
	rows, err := s.db.Query("SELECT id,tenant_id,user_id,username,action,resource,details,ip_address,timestamp,event_time FROM audit_logs"+where+" ORDER BY event_time DESC,id DESC LIMIT ?", args...)
	if err != nil {
		return page, err
	}
	defer rows.Close()
	for rows.Next() {
		var a AuditEntry
		var at int64
		if err := rows.Scan(&a.ID, &a.TenantID, &a.UserID, &a.Username, &a.Action, &a.Resource, &a.Details, &a.IPAddress, &a.Timestamp, &at); err != nil {
			return page, err
		}
		if len(page.Entries) == limit {
			raw, _ := json.Marshal(c)
			page.Next = base64.RawURLEncoding.EncodeToString(raw)
			break
		}
		page.Entries = append(page.Entries, a)
		c.At = at
		c.ID = a.ID
	}
	return page, rows.Err()
}
