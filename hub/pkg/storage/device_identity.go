package storage

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"
)

// DeviceCredentialAuth is the identity established by a device credential.
// The credential itself is never returned from storage after issuance.
type DeviceCredentialAuth struct {
	EndpointID string
	TenantID   string
}

// DeviceCredential is safe to list in operator views. Secret material is not
// part of this type; only its hash is stored in SQLite.
type DeviceCredential struct {
	ID         string     `json:"id"`
	EndpointID string     `json:"endpoint_id"`
	CreatedAt  time.Time  `json:"created_at"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
	RevokedAt  *time.Time `json:"revoked_at,omitempty"`
}

const deviceCredentialPrefix = "omd_"

// IssueDeviceCredential revokes any prior credential for the endpoint and
// returns one new high-entropy bearer credential exactly once. The caller must
// deliver the returned string through a protected enrollment response.
func (s *Store) IssueDeviceCredential(endpointID string) (string, DeviceCredential, error) {
	endpointID = strings.TrimSpace(endpointID)
	if endpointID == "" {
		return "", DeviceCredential{}, errors.New("endpoint id is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.issueDeviceCredentialLocked(endpointID)
}

// issueDeviceCredentialLocked is the rotation primitive. The caller holds the
// store write lock, which also makes the legacy-agent migration decision and
// credential issuance one serial operation.
func (s *Store) issueDeviceCredentialLocked(endpointID string) (string, DeviceCredential, error) {
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", DeviceCredential{}, fmt.Errorf("generating device credential: %w", err)
	}
	credential := deviceCredentialPrefix + hex.EncodeToString(raw[:])
	var idRaw [16]byte
	if _, err := rand.Read(idRaw[:]); err != nil {
		return "", DeviceCredential{}, fmt.Errorf("generating device credential id: %w", err)
	}
	id := hex.EncodeToString(idRaw[:])
	now := time.Now().UTC()

	tx, err := s.db.Begin()
	if err != nil {
		return "", DeviceCredential{}, err
	}
	rollback := func(err error) (string, DeviceCredential, error) {
		_ = tx.Rollback()
		return "", DeviceCredential{}, err
	}
	if _, err := tx.Exec(`UPDATE device_credentials SET revoked_at = ?
		WHERE endpoint_id = ? AND revoked_at IS NULL`, now, endpointID); err != nil {
		return rollback(err)
	}
	result, err := tx.Exec(`INSERT INTO device_credentials
		(id, endpoint_id, tenant_id, credential_hash, created_at)
		SELECT ?, id, tenant_id, ?, ? FROM endpoints WHERE id = ?`,
		id, hashEnrollmentToken(credential), now, endpointID)
	if err != nil {
		return rollback(err)
	}
	inserted, err := result.RowsAffected()
	if err != nil {
		return rollback(err)
	}
	if inserted != 1 {
		return rollback(fmt.Errorf("endpoint %q does not exist", endpointID))
	}
	if err := tx.Commit(); err != nil {
		return "", DeviceCredential{}, err
	}
	return credential, DeviceCredential{ID: id, EndpointID: endpointID, CreatedAt: now}, nil
}

// EnsureDeviceCredential migrates one older shared-key endpoint. It returns a
// plaintext credential only when the endpoint needs one, and only for the
// heartbeat that will deliver it to the new agent. A just-issued but unused
// credential is rotated if a legacy heartbeat arrives again: that covers a
// lost response without storing the secret in SQLite. Once the new agent uses
// it, last_used_at is set and legacy requests no longer rotate it.
func (s *Store) EnsureDeviceCredential(endpointID string) (string, bool, error) {
	endpointID = strings.TrimSpace(endpointID)
	if endpointID == "" {
		return "", false, errors.New("endpoint id is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var id string
	var lastUsed sql.NullTime
	err := s.db.QueryRow(`SELECT id, last_used_at FROM device_credentials
		WHERE endpoint_id = ? AND revoked_at IS NULL ORDER BY created_at DESC LIMIT 1`, endpointID).
		Scan(&id, &lastUsed)
	if err == nil && lastUsed.Valid {
		return "", false, nil
	}
	if err != nil && err != sql.ErrNoRows {
		return "", false, err
	}
	credential, _, err := s.issueDeviceCredentialLocked(endpointID)
	if err != nil {
		return "", false, err
	}
	return credential, true, nil
}

// VerifyDeviceCredential authenticates a new agent request and records last
// use. High-entropy credentials are indexed by their SHA-256 digest; storing a
// plaintext credential would turn a database read into fleet access.
func (s *Store) VerifyDeviceCredential(raw string) (DeviceCredentialAuth, bool, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" || !strings.HasPrefix(raw, deviceCredentialPrefix) {
		return DeviceCredentialAuth{}, false, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var auth DeviceCredentialAuth
	var revoked sql.NullTime
	err := s.db.QueryRow(`SELECT endpoint_id, tenant_id, revoked_at
		FROM device_credentials WHERE credential_hash = ?`, hashEnrollmentToken(raw)).
		Scan(&auth.EndpointID, &auth.TenantID, &revoked)
	if err == sql.ErrNoRows {
		return DeviceCredentialAuth{}, false, nil
	}
	if err != nil {
		return DeviceCredentialAuth{}, false, err
	}
	if revoked.Valid {
		return DeviceCredentialAuth{}, false, nil
	}
	now := time.Now().UTC()
	if _, err := s.db.Exec(`UPDATE device_credentials SET last_used_at = ?
		WHERE credential_hash = ? AND revoked_at IS NULL`, now, hashEnrollmentToken(raw)); err != nil {
		return DeviceCredentialAuth{}, false, err
	}
	return auth, true, nil
}

func (s *Store) RevokeDeviceCredentials(endpointID string) error {
	endpointID = strings.TrimSpace(endpointID)
	if endpointID == "" {
		return errors.New("endpoint id is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	res, err := s.db.Exec(`UPDATE device_credentials SET revoked_at = ?
		WHERE endpoint_id = ? AND revoked_at IS NULL`, time.Now().UTC(), endpointID)
	if err != nil {
		return err
	}
	count, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if count == 0 {
		return sql.ErrNoRows
	}
	return nil
}

func (s *Store) ListDeviceCredentials() ([]DeviceCredential, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	rows, err := s.db.Query(`SELECT id, endpoint_id, created_at, last_used_at, revoked_at
		FROM device_credentials ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []DeviceCredential
	for rows.Next() {
		var item DeviceCredential
		if err := rows.Scan(&item.ID, &item.EndpointID, &item.CreatedAt, &item.LastUsedAt, &item.RevokedAt); err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func (s *Store) initDeviceIdentitySchema() error {
	_, err := s.db.Exec(`
	CREATE TABLE IF NOT EXISTS device_credentials (
		id TEXT PRIMARY KEY,
		endpoint_id TEXT NOT NULL REFERENCES endpoints(id) ON DELETE CASCADE,
		tenant_id TEXT NOT NULL,
		credential_hash TEXT NOT NULL UNIQUE,
		created_at DATETIME NOT NULL,
		last_used_at DATETIME,
		revoked_at DATETIME
	);
	CREATE INDEX IF NOT EXISTS idx_device_credentials_endpoint ON device_credentials(endpoint_id);
	CREATE INDEX IF NOT EXISTS idx_device_credentials_hash ON device_credentials(credential_hash);
	`)
	return err
}
