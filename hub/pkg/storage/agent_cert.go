package storage

import (
	"database/sql"
	"strings"
	"time"
)

// Agent client certificates are issued for one year (pki.ClientCertLifetime)
// at enrolment. Before 1.8.104 nothing renewed them, so a whole fleet enrolled
// in the same week would lose mTLS in the same week a year later. The hub now
// remembers, per endpoint, the certificate it last saw on a verified handshake
// and whether a renewal was asked for or offered, and hands a renewal-capable
// agent a fresh certificate in its heartbeat reply well before expiry
// (server/agent_cert.go).
//
// Times are stored as RFC 3339 text and compared in Go: SQLite's datetime
// functions do not reliably parse the driver's own time strings.

// AgentCertState is what the hub knows about one endpoint's client certificate.
type AgentCertState struct {
	EndpointID string
	// NotAfter and Serial describe the certificate the endpoint last presented
	// on a verified handshake; SeenAt is when. Zero when it never presented one
	// since the hub started recording (1.8.104).
	NotAfter time.Time
	Serial   string
	SeenAt   time.Time
	// RenewRequestedAt is an operator's request to replace the certificate now
	// rather than at the renewal window. It is satisfied once the endpoint
	// presents a certificate issued after it.
	RenewRequestedAt time.Time
	// OfferedAt is the last time a renewed certificate went out in a heartbeat
	// reply. A reply can be lost, so the offer is repeated, but not on every
	// beat (key generation is not free).
	OfferedAt time.Time
}

func (s *Store) initAgentCertSchema() error {
	_, err := s.db.Exec(`
	CREATE TABLE IF NOT EXISTS endpoint_certificates (
		endpoint_id TEXT PRIMARY KEY,
		not_after TEXT NOT NULL DEFAULT '',
		serial TEXT NOT NULL DEFAULT '',
		seen_at TEXT NOT NULL DEFAULT '',
		renew_requested_at TEXT NOT NULL DEFAULT '',
		offered_at TEXT NOT NULL DEFAULT ''
	)`)
	return err
}

func formatCertTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339Nano)
}

func parseCertTime(v string) time.Time {
	t, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(v))
	if err != nil {
		return time.Time{}
	}
	return t
}

// RecordAgentCertSeen notes the certificate an endpoint presented on a verified
// handshake. Written on every heartbeat that carries one; cheap and idempotent.
func (s *Store) RecordAgentCertSeen(endpointID string, notAfter time.Time, serial string, at time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec(`INSERT INTO endpoint_certificates (endpoint_id, not_after, serial, seen_at) VALUES (?, ?, ?, ?)
		ON CONFLICT(endpoint_id) DO UPDATE SET not_after = excluded.not_after, serial = excluded.serial, seen_at = excluded.seen_at`,
		endpointID, formatCertTime(notAfter), serial, formatCertTime(at))
	return err
}

// RequestAgentCertRenewal asks for the endpoint's certificate to be replaced
// on its next heartbeat, whatever its expiry.
func (s *Store) RequestAgentCertRenewal(endpointID string, at time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec(`INSERT INTO endpoint_certificates (endpoint_id, renew_requested_at) VALUES (?, ?)
		ON CONFLICT(endpoint_id) DO UPDATE SET renew_requested_at = excluded.renew_requested_at, offered_at = ''`,
		endpointID, formatCertTime(at))
	return err
}

// MarkAgentCertOffered records that a renewed certificate went out.
func (s *Store) MarkAgentCertOffered(endpointID string, at time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec(`INSERT INTO endpoint_certificates (endpoint_id, offered_at) VALUES (?, ?)
		ON CONFLICT(endpoint_id) DO UPDATE SET offered_at = excluded.offered_at`,
		endpointID, formatCertTime(at))
	return err
}

// GetAgentCertState returns the endpoint's row, or a zero state naming it.
func (s *Store) GetAgentCertState(endpointID string) (AgentCertState, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	st, err := scanAgentCert(s.db.QueryRow(`SELECT endpoint_id, not_after, serial, seen_at, renew_requested_at, offered_at
		FROM endpoint_certificates WHERE endpoint_id = ?`, endpointID))
	if err == sql.ErrNoRows {
		return AgentCertState{EndpointID: endpointID}, nil
	}
	return st, err
}

// ListAgentCertStates returns every endpoint's row.
func (s *Store) ListAgentCertStates() ([]AgentCertState, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	rows, err := s.db.Query(`SELECT endpoint_id, not_after, serial, seen_at, renew_requested_at, offered_at
		FROM endpoint_certificates ORDER BY endpoint_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AgentCertState
	for rows.Next() {
		st, err := scanAgentCert(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, st)
	}
	return out, rows.Err()
}

func scanAgentCert(row interface{ Scan(...any) error }) (AgentCertState, error) {
	var st AgentCertState
	var notAfter, seen, requested, offered string
	if err := row.Scan(&st.EndpointID, &notAfter, &st.Serial, &seen, &requested, &offered); err != nil {
		return AgentCertState{}, err
	}
	st.NotAfter, st.SeenAt = parseCertTime(notAfter), parseCertTime(seen)
	st.RenewRequestedAt, st.OfferedAt = parseCertTime(requested), parseCertTime(offered)
	return st, nil
}
