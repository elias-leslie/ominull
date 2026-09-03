package responseauth

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

var (
	ErrNotFound       = errors.New("record not found")
	ErrAlreadyExists  = errors.New("record already exists")
	ErrNonceReplayed  = errors.New("nonce already used or replayed")
	ErrTokenExpired   = errors.New("token expired")
	ErrTokenUsed      = errors.New("token already used")
	ErrSessionLocked  = errors.New("session locked")
	ErrSessionExpired = errors.New("session expired")
)

// MembershipRole defines operator role within tenant response authority.
type MembershipRole string

const (
	RoleResponseAdmin    MembershipRole = "response_admin"
	RoleResponseOperator MembershipRole = "response_operator"
)

// MembershipRecord defines durable operator response membership.
type MembershipRecord struct {
	TenantID   string         `json:"tenant_id"`
	OperatorID string         `json:"operator_id"`
	Role       MembershipRole `json:"role"`
	Status     string         `json:"status"` // "active", "suspended", "revoked"
	CreatedAt  time.Time      `json:"created_at"`
	UpdatedAt  time.Time      `json:"updated_at"`
}

// TenantKeyRecord stores durable response signing keys.
type TenantKeyRecord struct {
	TenantID   string     `json:"tenant_id"`
	KeyID      string     `json:"key_id"` // hex SHA-256 fingerprint
	PublicKey  string     `json:"public_key"`
	PrivateKey string     `json:"private_key"`
	Partition  string     `json:"partition"`
	Status     string     `json:"status"` // "active", "rotated", "revoked"
	CreatedAt  time.Time  `json:"created_at"`
	RotatedAt  *time.Time `json:"rotated_at,omitempty"`
}

// MethodPolicyRecord stores tenant-scoped authentication policy.
type MethodPolicyRecord struct {
	TenantID         string       `json:"tenant_id"`
	AllowedMethods   []AuthMethod `json:"allowed_methods"`
	RequireStepUp    bool         `json:"require_step_up"`
	MaxSessionTTLSec int64        `json:"max_session_ttl_sec"`
	MaxIdleTTLSec    int64        `json:"max_idle_ttl_sec"`
	UpdatedAt        time.Time    `json:"updated_at"`
}

// RecoveryTokenRecord stores single-use root emergency enrollment tokens.
type RecoveryTokenRecord struct {
	TokenHash  string     `json:"token_hash"`
	TenantID   string     `json:"tenant_id"`
	OperatorID string     `json:"operator_id"`
	CreatedAt  time.Time  `json:"created_at"`
	ExpiresAt  time.Time  `json:"expires_at"`
	Used       bool       `json:"used"`
	UsedAt     *time.Time `json:"used_at,omitempty"`
}

// SignerAuditEntry records security-relevant signer events.
type SignerAuditEntry struct {
	ID         int64     `json:"id"`
	Timestamp  time.Time `json:"timestamp"`
	TenantID   string    `json:"tenant_id"`
	OperatorID string    `json:"operator_id"`
	EventType  string    `json:"event_type"`
	ActionKind string    `json:"action_kind,omitempty"`
	EndpointID string    `json:"endpoint_id,omitempty"`
	GrantID    string    `json:"grant_id,omitempty"`
	Status     string    `json:"status"` // "success", "denied", "error"
	Details    string    `json:"details,omitempty"`
}

// Store defines the durable persistence interface for the Response Authority.
type Store interface {
	// Tenant Keys
	GetTenantKey(ctx context.Context, tenantID string) (*TenantKeyRecord, error)
	SaveTenantKey(ctx context.Context, key *TenantKeyRecord) error
	ListTenantKeys(ctx context.Context) ([]*TenantKeyRecord, error)

	// Memberships
	GetMembership(ctx context.Context, tenantID, operatorID string) (*MembershipRecord, error)
	SaveMembership(ctx context.Context, m *MembershipRecord) error
	ListMemberships(ctx context.Context, tenantID string) ([]*MembershipRecord, error)
	RevokeMembership(ctx context.Context, tenantID, operatorID string) error

	// Authenticators
	GetAuthenticator(ctx context.Context, id string) (*AuthenticatorRecord, error)
	ListAuthenticators(ctx context.Context, tenantID, operatorID string) ([]*AuthenticatorRecord, error)
	SaveAuthenticator(ctx context.Context, auth *AuthenticatorRecord) error
	UpdateAuthenticatorUsage(ctx context.Context, id string, lastUsed time.Time, failureCount int, lockedUntil *time.Time) error
	RevokeAuthenticator(ctx context.Context, id string) error

	// Method Policy
	GetPolicy(ctx context.Context, tenantID string) (*MethodPolicyRecord, error)
	SavePolicy(ctx context.Context, p *MethodPolicyRecord) error

	// Sessions
	GetSession(ctx context.Context, sessionID string) (*ResponseSession, error)
	SaveSession(ctx context.Context, s *ResponseSession) error
	UpdateSession(ctx context.Context, s *ResponseSession) error
	LockSession(ctx context.Context, sessionID string) error
	PruneExpiredSessions(ctx context.Context, now time.Time) (int64, error)

	// Replay State
	CheckAndRecordNonce(ctx context.Context, nonce, purpose, tenantID string, expiresAt time.Time) error

	// Recovery Tokens
	SaveRecoveryToken(ctx context.Context, tok *RecoveryTokenRecord) error
	GetRecoveryToken(ctx context.Context, tokenHash string) (*RecoveryTokenRecord, error)
	ConsumeRecoveryToken(ctx context.Context, tokenHash string, usedAt time.Time) error

	// Signer Audit
	RecordAudit(ctx context.Context, entry *SignerAuditEntry) error
	QueryAudit(ctx context.Context, tenantID string, limit int) ([]*SignerAuditEntry, error)

	// Metrics & Counts
	CountActiveSessions(ctx context.Context, tenantID string, now time.Time) (int, error)
	CountAuthenticators(ctx context.Context, tenantID string) (int, error)

	Close() error
}

// SQLiteStore implements Store backed by modernc.org/sqlite.
type SQLiteStore struct {
	db *sql.DB
}

// NewSQLiteStore initializes SQLiteStore and runs migrations.
func NewSQLiteStore(dbPath string) (*SQLiteStore, error) {
	dsn := fmt.Sprintf("%s?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)", dbPath)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open sqlite store: %w", err)
	}

	store := &SQLiteStore{db: db}
	if err := store.migrate(); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("migrate authority store: %w", err)
	}
	return store, nil
}

func (s *SQLiteStore) migrate() error {
	schema := `
	CREATE TABLE IF NOT EXISTS tenant_keys (
		tenant_id TEXT PRIMARY KEY,
		key_id TEXT NOT NULL,
		public_key TEXT NOT NULL,
		private_key TEXT NOT NULL,
		partition TEXT NOT NULL,
		status TEXT NOT NULL,
		created_at TIMESTAMP NOT NULL,
		rotated_at TIMESTAMP
	);

	CREATE TABLE IF NOT EXISTS memberships (
		tenant_id TEXT NOT NULL,
		operator_id TEXT NOT NULL,
		role TEXT NOT NULL,
		status TEXT NOT NULL,
		created_at TIMESTAMP NOT NULL,
		updated_at TIMESTAMP NOT NULL,
		PRIMARY KEY (tenant_id, operator_id)
	);

	CREATE TABLE IF NOT EXISTS authenticators (
		id TEXT PRIMARY KEY,
		tenant_id TEXT NOT NULL,
		operator_id TEXT NOT NULL,
		type TEXT NOT NULL,
		label TEXT NOT NULL,
		secret_or_key TEXT NOT NULL,
		status TEXT NOT NULL,
		enrolled_at TIMESTAMP NOT NULL,
		last_used_at TIMESTAMP,
		failure_count INTEGER NOT NULL DEFAULT 0,
		locked_until TIMESTAMP
	);

	CREATE TABLE IF NOT EXISTS method_policies (
		tenant_id TEXT PRIMARY KEY,
		allowed_methods TEXT NOT NULL,
		require_step_up INTEGER NOT NULL DEFAULT 0,
		max_session_ttl_sec INTEGER NOT NULL DEFAULT 28800,
		max_idle_ttl_sec INTEGER NOT NULL DEFAULT 1800,
		updated_at TIMESTAMP NOT NULL
	);

	CREATE TABLE IF NOT EXISTS response_sessions (
		session_id TEXT PRIMARY KEY,
		tenant_id TEXT NOT NULL,
		operator_id TEXT NOT NULL,
		browser_session_id TEXT NOT NULL,
		browser_public_key TEXT NOT NULL,
		allowed_action_kinds TEXT NOT NULL,
		auth_method TEXT NOT NULL,
		issued_at TIMESTAMP NOT NULL,
		idle_expires_at TIMESTAMP NOT NULL,
		absolute_expires_at TIMESTAMP NOT NULL,
		locked INTEGER NOT NULL DEFAULT 0
	);

	CREATE TABLE IF NOT EXISTS used_nonces (
		nonce TEXT PRIMARY KEY,
		purpose TEXT NOT NULL,
		tenant_id TEXT NOT NULL,
		seen_at TIMESTAMP NOT NULL,
		expires_at TIMESTAMP NOT NULL
	);

	CREATE TABLE IF NOT EXISTS recovery_tokens (
		token_hash TEXT PRIMARY KEY,
		tenant_id TEXT NOT NULL,
		operator_id TEXT NOT NULL,
		created_at TIMESTAMP NOT NULL,
		expires_at TIMESTAMP NOT NULL,
		used INTEGER NOT NULL DEFAULT 0,
		used_at TIMESTAMP
	);

	CREATE TABLE IF NOT EXISTS signer_audit (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		timestamp TIMESTAMP NOT NULL,
		tenant_id TEXT NOT NULL,
		operator_id TEXT NOT NULL,
		event_type TEXT NOT NULL,
		action_kind TEXT,
		endpoint_id TEXT,
		grant_id TEXT,
		status TEXT NOT NULL,
		details TEXT
	);

	CREATE INDEX IF NOT EXISTS idx_memberships_tenant ON memberships(tenant_id);
	CREATE INDEX IF NOT EXISTS idx_authenticators_operator ON authenticators(tenant_id, operator_id);
	CREATE INDEX IF NOT EXISTS idx_sessions_tenant ON response_sessions(tenant_id);
	CREATE INDEX IF NOT EXISTS idx_nonces_expiry ON used_nonces(expires_at);
	CREATE INDEX IF NOT EXISTS idx_audit_tenant_ts ON signer_audit(tenant_id, timestamp);
	`
	_, err := s.db.Exec(schema)
	return err
}

func (s *SQLiteStore) Close() error {
	return s.db.Close()
}

// Tenant Keys

func (s *SQLiteStore) GetTenantKey(ctx context.Context, tenantID string) (*TenantKeyRecord, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT tenant_id, key_id, public_key, private_key, partition, status, created_at, rotated_at
		FROM tenant_keys WHERE tenant_id = ?`, tenantID)

	var rec TenantKeyRecord
	var rotatedAt sql.NullTime
	if err := row.Scan(&rec.TenantID, &rec.KeyID, &rec.PublicKey, &rec.PrivateKey, &rec.Partition, &rec.Status, &rec.CreatedAt, &rotatedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	if rotatedAt.Valid {
		rec.RotatedAt = &rotatedAt.Time
	}
	return &rec, nil
}

func (s *SQLiteStore) SaveTenantKey(ctx context.Context, key *TenantKeyRecord) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO tenant_keys (tenant_id, key_id, public_key, private_key, partition, status, created_at, rotated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(tenant_id) DO UPDATE SET
			key_id = excluded.key_id,
			public_key = excluded.public_key,
			private_key = excluded.private_key,
			partition = excluded.partition,
			status = excluded.status,
			rotated_at = excluded.rotated_at`,
		key.TenantID, key.KeyID, key.PublicKey, key.PrivateKey, key.Partition, key.Status, key.CreatedAt, key.RotatedAt)
	return err
}

func (s *SQLiteStore) ListTenantKeys(ctx context.Context) ([]*TenantKeyRecord, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT tenant_id, key_id, public_key, private_key, partition, status, created_at, rotated_at
		FROM tenant_keys WHERE status = 'active'`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var res []*TenantKeyRecord
	for rows.Next() {
		var rec TenantKeyRecord
		var rotatedAt sql.NullTime
		if err := rows.Scan(&rec.TenantID, &rec.KeyID, &rec.PublicKey, &rec.PrivateKey, &rec.Partition, &rec.Status, &rec.CreatedAt, &rotatedAt); err != nil {
			return nil, err
		}
		if rotatedAt.Valid {
			rec.RotatedAt = &rotatedAt.Time
		}
		res = append(res, &rec)
	}
	return res, rows.Err()
}

// Memberships

func (s *SQLiteStore) GetMembership(ctx context.Context, tenantID, operatorID string) (*MembershipRecord, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT tenant_id, operator_id, role, status, created_at, updated_at
		FROM memberships WHERE tenant_id = ? AND operator_id = ?`, tenantID, operatorID)

	var rec MembershipRecord
	if err := row.Scan(&rec.TenantID, &rec.OperatorID, &rec.Role, &rec.Status, &rec.CreatedAt, &rec.UpdatedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &rec, nil
}

func (s *SQLiteStore) SaveMembership(ctx context.Context, m *MembershipRecord) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO memberships (tenant_id, operator_id, role, status, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?)
		ON CONFLICT(tenant_id, operator_id) DO UPDATE SET
			role = excluded.role,
			status = excluded.status,
			updated_at = excluded.updated_at`,
		m.TenantID, m.OperatorID, string(m.Role), m.Status, m.CreatedAt, m.UpdatedAt)
	return err
}

func (s *SQLiteStore) ListMemberships(ctx context.Context, tenantID string) ([]*MembershipRecord, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT tenant_id, operator_id, role, status, created_at, updated_at
		FROM memberships WHERE tenant_id = ? AND status = 'active'`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var res []*MembershipRecord
	for rows.Next() {
		var rec MembershipRecord
		if err := rows.Scan(&rec.TenantID, &rec.OperatorID, &rec.Role, &rec.Status, &rec.CreatedAt, &rec.UpdatedAt); err != nil {
			return nil, err
		}
		res = append(res, &rec)
	}
	return res, rows.Err()
}

func (s *SQLiteStore) RevokeMembership(ctx context.Context, tenantID, operatorID string) error {
	_, err := s.db.ExecContext(ctx, `
		UPDATE memberships SET status = 'revoked', updated_at = ?
		WHERE tenant_id = ? AND operator_id = ?`, time.Now(), tenantID, operatorID)
	return err
}

// Authenticators

func (s *SQLiteStore) GetAuthenticator(ctx context.Context, id string) (*AuthenticatorRecord, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT id, tenant_id, operator_id, type, label, secret_or_key, status, enrolled_at, last_used_at, failure_count, locked_until
		FROM authenticators WHERE id = ?`, id)

	var rec AuthenticatorRecord
	var lastUsed, lockedUntil sql.NullTime
	if err := row.Scan(&rec.ID, &rec.TenantID, &rec.OperatorID, &rec.Type, &rec.Label, &rec.SecretOrKey, &rec.Status, &rec.EnrolledAt, &lastUsed, &rec.FailureCount, &lockedUntil); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	if lastUsed.Valid {
		rec.LastUsedAt = &lastUsed.Time
	}
	if lockedUntil.Valid {
		rec.LockedUntil = &lockedUntil.Time
	}
	return &rec, nil
}

func (s *SQLiteStore) ListAuthenticators(ctx context.Context, tenantID, operatorID string) ([]*AuthenticatorRecord, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, tenant_id, operator_id, type, label, secret_or_key, status, enrolled_at, last_used_at, failure_count, locked_until
		FROM authenticators WHERE tenant_id = ? AND operator_id = ? AND status = 'active'`, tenantID, operatorID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var res []*AuthenticatorRecord
	for rows.Next() {
		var rec AuthenticatorRecord
		var lastUsed, lockedUntil sql.NullTime
		if err := rows.Scan(&rec.ID, &rec.TenantID, &rec.OperatorID, &rec.Type, &rec.Label, &rec.SecretOrKey, &rec.Status, &rec.EnrolledAt, &lastUsed, &rec.FailureCount, &lockedUntil); err != nil {
			return nil, err
		}
		if lastUsed.Valid {
			rec.LastUsedAt = &lastUsed.Time
		}
		if lockedUntil.Valid {
			rec.LockedUntil = &lockedUntil.Time
		}
		res = append(res, &rec)
	}
	return res, rows.Err()
}

func (s *SQLiteStore) SaveAuthenticator(ctx context.Context, auth *AuthenticatorRecord) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO authenticators (id, tenant_id, operator_id, type, label, secret_or_key, status, enrolled_at, last_used_at, failure_count, locked_until)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			label = excluded.label,
			secret_or_key = excluded.secret_or_key,
			status = excluded.status,
			last_used_at = excluded.last_used_at,
			failure_count = excluded.failure_count,
			locked_until = excluded.locked_until`,
		auth.ID, auth.TenantID, auth.OperatorID, string(auth.Type), auth.Label, auth.SecretOrKey, auth.Status, auth.EnrolledAt, auth.LastUsedAt, auth.FailureCount, auth.LockedUntil)
	return err
}

func (s *SQLiteStore) UpdateAuthenticatorUsage(ctx context.Context, id string, lastUsed time.Time, failureCount int, lockedUntil *time.Time) error {
	_, err := s.db.ExecContext(ctx, `
		UPDATE authenticators SET
			last_used_at = ?,
			failure_count = ?,
			locked_until = ?
		WHERE id = ?`, lastUsed, failureCount, lockedUntil, id)
	return err
}

func (s *SQLiteStore) RevokeAuthenticator(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE authenticators SET status = 'revoked' WHERE id = ?`, id)
	return err
}

// Method Policy

func (s *SQLiteStore) GetPolicy(ctx context.Context, tenantID string) (*MethodPolicyRecord, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT tenant_id, allowed_methods, require_step_up, max_session_ttl_sec, max_idle_ttl_sec, updated_at
		FROM method_policies WHERE tenant_id = ?`, tenantID)

	var rec MethodPolicyRecord
	var rawMethods string
	var stepUp int
	if err := row.Scan(&rec.TenantID, &rawMethods, &stepUp, &rec.MaxSessionTTLSec, &rec.MaxIdleTTLSec, &rec.UpdatedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			// default policy
			return &MethodPolicyRecord{
				TenantID:         tenantID,
				AllowedMethods:   []AuthMethod{AuthMethodTOTP, AuthMethodWebAuthn},
				RequireStepUp:    false,
				MaxSessionTTLSec: 28800,
				MaxIdleTTLSec:    1800,
				UpdatedAt:        time.Now(),
			}, nil
		}
		return nil, err
	}
	_ = json.Unmarshal([]byte(rawMethods), &rec.AllowedMethods)
	rec.RequireStepUp = stepUp != 0
	return &rec, nil
}

func (s *SQLiteStore) SavePolicy(ctx context.Context, p *MethodPolicyRecord) error {
	rawMethods, err := json.Marshal(p.AllowedMethods)
	if err != nil {
		return err
	}
	stepUp := 0
	if p.RequireStepUp {
		stepUp = 1
	}
	_, err = s.db.ExecContext(ctx, `
		INSERT INTO method_policies (tenant_id, allowed_methods, require_step_up, max_session_ttl_sec, max_idle_ttl_sec, updated_at)
		VALUES (?, ?, ?, ?, ?, ?)
		ON CONFLICT(tenant_id) DO UPDATE SET
			allowed_methods = excluded.allowed_methods,
			require_step_up = excluded.require_step_up,
			max_session_ttl_sec = excluded.max_session_ttl_sec,
			max_idle_ttl_sec = excluded.max_idle_ttl_sec,
			updated_at = excluded.updated_at`,
		p.TenantID, string(rawMethods), stepUp, p.MaxSessionTTLSec, p.MaxIdleTTLSec, p.UpdatedAt)
	return err
}

// Sessions

func (s *SQLiteStore) GetSession(ctx context.Context, sessionID string) (*ResponseSession, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT session_id, tenant_id, operator_id, browser_session_id, browser_public_key, allowed_action_kinds, auth_method, issued_at, idle_expires_at, absolute_expires_at, locked
		FROM response_sessions WHERE session_id = ?`, sessionID)

	var sess ResponseSession
	var rawKinds string
	var locked int
	if err := row.Scan(&sess.SessionID, &sess.TenantID, &sess.OperatorID, &sess.BrowserSessionID, &sess.BrowserPublicKey, &rawKinds, &sess.AuthMethod, &sess.IssuedAt, &sess.IdleExpiresAt, &sess.AbsoluteExpiresAt, &locked); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	_ = json.Unmarshal([]byte(rawKinds), &sess.AllowedActionKinds)
	sess.Locked = locked != 0
	return &sess, nil
}

func (s *SQLiteStore) SaveSession(ctx context.Context, sess *ResponseSession) error {
	rawKinds, err := json.Marshal(sess.AllowedActionKinds)
	if err != nil {
		return err
	}
	locked := 0
	if sess.Locked {
		locked = 1
	}
	_, err = s.db.ExecContext(ctx, `
		INSERT INTO response_sessions (session_id, tenant_id, operator_id, browser_session_id, browser_public_key, allowed_action_kinds, auth_method, issued_at, idle_expires_at, absolute_expires_at, locked)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(session_id) DO UPDATE SET
			idle_expires_at = excluded.idle_expires_at,
			locked = excluded.locked`,
		sess.SessionID, sess.TenantID, sess.OperatorID, sess.BrowserSessionID, sess.BrowserPublicKey, string(rawKinds), string(sess.AuthMethod), sess.IssuedAt, sess.IdleExpiresAt, sess.AbsoluteExpiresAt, locked)
	return err
}

func (s *SQLiteStore) UpdateSession(ctx context.Context, sess *ResponseSession) error {
	return s.SaveSession(ctx, sess)
}

func (s *SQLiteStore) LockSession(ctx context.Context, sessionID string) error {
	res, err := s.db.ExecContext(ctx, `UPDATE response_sessions SET locked = 1 WHERE session_id = ?`, sessionID)
	if err != nil {
		return err
	}
	rows, _ := res.RowsAffected()
	if rows == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *SQLiteStore) PruneExpiredSessions(ctx context.Context, now time.Time) (int64, error) {
	res, err := s.db.ExecContext(ctx, `
		DELETE FROM response_sessions
		WHERE absolute_expires_at < ? OR (idle_expires_at < ? AND locked = 1)`, now, now)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// Replay State

func (s *SQLiteStore) CheckAndRecordNonce(ctx context.Context, nonce, purpose, tenantID string, expiresAt time.Time) error {
	now := time.Now()
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO used_nonces (nonce, purpose, tenant_id, seen_at, expires_at)
		VALUES (?, ?, ?, ?, ?)`,
		nonce, purpose, tenantID, now, expiresAt)
	if err != nil {
		return ErrNonceReplayed
	}
	return nil
}

// Recovery Tokens

func (s *SQLiteStore) SaveRecoveryToken(ctx context.Context, tok *RecoveryTokenRecord) error {
	used := 0
	if tok.Used {
		used = 1
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO recovery_tokens (token_hash, tenant_id, operator_id, created_at, expires_at, used, used_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(token_hash) DO UPDATE SET
			used = excluded.used,
			used_at = excluded.used_at`,
		tok.TokenHash, tok.TenantID, tok.OperatorID, tok.CreatedAt, tok.ExpiresAt, used, tok.UsedAt)
	return err
}

func (s *SQLiteStore) GetRecoveryToken(ctx context.Context, tokenHash string) (*RecoveryTokenRecord, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT token_hash, tenant_id, operator_id, created_at, expires_at, used, used_at
		FROM recovery_tokens WHERE token_hash = ?`, tokenHash)

	var tok RecoveryTokenRecord
	var used int
	var usedAt sql.NullTime
	if err := row.Scan(&tok.TokenHash, &tok.TenantID, &tok.OperatorID, &tok.CreatedAt, &tok.ExpiresAt, &used, &usedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	tok.Used = used != 0
	if usedAt.Valid {
		tok.UsedAt = &usedAt.Time
	}
	return &tok, nil
}

func (s *SQLiteStore) ConsumeRecoveryToken(ctx context.Context, tokenHash string, usedAt time.Time) error {
	tok, err := s.GetRecoveryToken(ctx, tokenHash)
	if err != nil {
		return err
	}
	if tok.Used {
		return ErrTokenUsed
	}
	if usedAt.After(tok.ExpiresAt) {
		return ErrTokenExpired
	}
	_, err = s.db.ExecContext(ctx, `
		UPDATE recovery_tokens SET used = 1, used_at = ? WHERE token_hash = ?`, usedAt, tokenHash)
	return err
}

// Signer Audit

func (s *SQLiteStore) RecordAudit(ctx context.Context, entry *SignerAuditEntry) error {
	if entry.Timestamp.IsZero() {
		entry.Timestamp = time.Now()
	}
	res, err := s.db.ExecContext(ctx, `
		INSERT INTO signer_audit (timestamp, tenant_id, operator_id, event_type, action_kind, endpoint_id, grant_id, status, details)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		entry.Timestamp, entry.TenantID, entry.OperatorID, entry.EventType, entry.ActionKind, entry.EndpointID, entry.GrantID, entry.Status, entry.Details)
	if err != nil {
		return err
	}
	id, err := res.LastInsertId()
	if err == nil {
		entry.ID = id
	}
	return nil
}

func (s *SQLiteStore) QueryAudit(ctx context.Context, tenantID string, limit int) ([]*SignerAuditEntry, error) {
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	var rows *sql.Rows
	var err error
	if tenantID != "" {
		rows, err = s.db.QueryContext(ctx, `
			SELECT id, timestamp, tenant_id, operator_id, event_type, action_kind, endpoint_id, grant_id, status, details
			FROM signer_audit WHERE tenant_id = ?
			ORDER BY timestamp DESC LIMIT ?`, tenantID, limit)
	} else {
		rows, err = s.db.QueryContext(ctx, `
			SELECT id, timestamp, tenant_id, operator_id, event_type, action_kind, endpoint_id, grant_id, status, details
			FROM signer_audit
			ORDER BY timestamp DESC LIMIT ?`, limit)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var entries []*SignerAuditEntry
	for rows.Next() {
		var e SignerAuditEntry
		var actionKind, endpointID, grantID, details sql.NullString
		if err := rows.Scan(&e.ID, &e.Timestamp, &e.TenantID, &e.OperatorID, &e.EventType, &actionKind, &endpointID, &grantID, &e.Status, &details); err != nil {
			return nil, err
		}
		if actionKind.Valid {
			e.ActionKind = actionKind.String
		}
		if endpointID.Valid {
			e.EndpointID = endpointID.String
		}
		if grantID.Valid {
			e.GrantID = grantID.String
		}
		if details.Valid {
			e.Details = details.String
		}
		entries = append(entries, &e)
	}
	return entries, rows.Err()
}

func (s *SQLiteStore) CountActiveSessions(ctx context.Context, tenantID string, now time.Time) (int, error) {
	var count int
	var err error
	if tenantID != "" {
		err = s.db.QueryRowContext(ctx, `
			SELECT COUNT(*) FROM response_sessions
			WHERE tenant_id = ? AND locked = 0 AND idle_expires_at > ? AND absolute_expires_at > ?`,
			tenantID, now, now).Scan(&count)
	} else {
		err = s.db.QueryRowContext(ctx, `
			SELECT COUNT(*) FROM response_sessions
			WHERE locked = 0 AND idle_expires_at > ? AND absolute_expires_at > ?`,
			now, now).Scan(&count)
	}
	return count, err
}

func (s *SQLiteStore) CountAuthenticators(ctx context.Context, tenantID string) (int, error) {
	var count int
	var err error
	if tenantID != "" {
		err = s.db.QueryRowContext(ctx, `
			SELECT COUNT(*) FROM authenticators
			WHERE tenant_id = ? AND status = 'active'`, tenantID).Scan(&count)
	} else {
		err = s.db.QueryRowContext(ctx, `
			SELECT COUNT(*) FROM authenticators
			WHERE status = 'active'`).Scan(&count)
	}
	return count, err
}

// MemoryStore provides in-memory Store for unit tests.
type MemoryStore struct {
	mu             sync.RWMutex
	tenantKeys     map[string]*TenantKeyRecord
	memberships    map[string]*MembershipRecord
	authenticators map[string]*AuthenticatorRecord
	policies       map[string]*MethodPolicyRecord
	sessions       map[string]*ResponseSession
	nonces         map[string]time.Time
	recoveryTokens map[string]*RecoveryTokenRecord
	auditLog       []*SignerAuditEntry
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		tenantKeys:     make(map[string]*TenantKeyRecord),
		memberships:    make(map[string]*MembershipRecord),
		authenticators: make(map[string]*AuthenticatorRecord),
		policies:       make(map[string]*MethodPolicyRecord),
		sessions:       make(map[string]*ResponseSession),
		nonces:         make(map[string]time.Time),
		recoveryTokens: make(map[string]*RecoveryTokenRecord),
		auditLog:       make([]*SignerAuditEntry, 0),
	}
}

func (m *MemoryStore) Close() error { return nil }

func (m *MemoryStore) GetTenantKey(ctx context.Context, tenantID string) (*TenantKeyRecord, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	k, ok := m.tenantKeys[tenantID]
	if !ok {
		return nil, ErrNotFound
	}
	return k, nil
}

func (m *MemoryStore) SaveTenantKey(ctx context.Context, key *TenantKeyRecord) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.tenantKeys[key.TenantID] = key
	return nil
}

func (m *MemoryStore) ListTenantKeys(ctx context.Context) ([]*TenantKeyRecord, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	res := make([]*TenantKeyRecord, 0, len(m.tenantKeys))
	for _, k := range m.tenantKeys {
		if k.Status == "active" {
			res = append(res, k)
		}
	}
	return res, nil
}

func (m *MemoryStore) GetMembership(ctx context.Context, tenantID, operatorID string) (*MembershipRecord, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	key := tenantID + ":" + operatorID
	mem, ok := m.memberships[key]
	if !ok {
		return nil, ErrNotFound
	}
	return mem, nil
}

func (m *MemoryStore) SaveMembership(ctx context.Context, mem *MembershipRecord) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := mem.TenantID + ":" + mem.OperatorID
	m.memberships[key] = mem
	return nil
}

func (m *MemoryStore) ListMemberships(ctx context.Context, tenantID string) ([]*MembershipRecord, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var res []*MembershipRecord
	for _, mem := range m.memberships {
		if mem.TenantID == tenantID && mem.Status == "active" {
			res = append(res, mem)
		}
	}
	return res, nil
}

func (m *MemoryStore) RevokeMembership(ctx context.Context, tenantID, operatorID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := tenantID + ":" + operatorID
	if mem, ok := m.memberships[key]; ok {
		mem.Status = "revoked"
		mem.UpdatedAt = time.Now()
	}
	return nil
}

func (m *MemoryStore) GetAuthenticator(ctx context.Context, id string) (*AuthenticatorRecord, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	auth, ok := m.authenticators[id]
	if !ok {
		return nil, ErrNotFound
	}
	return auth, nil
}

func (m *MemoryStore) ListAuthenticators(ctx context.Context, tenantID, operatorID string) ([]*AuthenticatorRecord, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var res []*AuthenticatorRecord
	for _, a := range m.authenticators {
		if a.TenantID == tenantID && a.OperatorID == operatorID && a.Status == "active" {
			res = append(res, a)
		}
	}
	return res, nil
}

func (m *MemoryStore) SaveAuthenticator(ctx context.Context, auth *AuthenticatorRecord) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.authenticators[auth.ID] = auth
	return nil
}

func (m *MemoryStore) UpdateAuthenticatorUsage(ctx context.Context, id string, lastUsed time.Time, failureCount int, lockedUntil *time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	auth, ok := m.authenticators[id]
	if !ok {
		return ErrNotFound
	}
	auth.LastUsedAt = &lastUsed
	auth.FailureCount = failureCount
	auth.LockedUntil = lockedUntil
	return nil
}

func (m *MemoryStore) RevokeAuthenticator(ctx context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if a, ok := m.authenticators[id]; ok {
		a.Status = "revoked"
	}
	return nil
}

func (m *MemoryStore) GetPolicy(ctx context.Context, tenantID string) (*MethodPolicyRecord, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if p, ok := m.policies[tenantID]; ok {
		return p, nil
	}
	return &MethodPolicyRecord{
		TenantID:         tenantID,
		AllowedMethods:   []AuthMethod{AuthMethodTOTP, AuthMethodWebAuthn},
		RequireStepUp:    false,
		MaxSessionTTLSec: 28800,
		MaxIdleTTLSec:    1800,
		UpdatedAt:        time.Now(),
	}, nil
}

func (m *MemoryStore) SavePolicy(ctx context.Context, p *MethodPolicyRecord) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.policies[p.TenantID] = p
	return nil
}

func (m *MemoryStore) GetSession(ctx context.Context, sessionID string) (*ResponseSession, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	s, ok := m.sessions[sessionID]
	if !ok {
		return nil, ErrNotFound
	}
	return s, nil
}

func (m *MemoryStore) SaveSession(ctx context.Context, s *ResponseSession) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sessions[s.SessionID] = s
	return nil
}

func (m *MemoryStore) UpdateSession(ctx context.Context, s *ResponseSession) error {
	return m.SaveSession(ctx, s)
}

func (m *MemoryStore) LockSession(ctx context.Context, sessionID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.sessions[sessionID]
	if !ok {
		return ErrNotFound
	}
	s.Locked = true
	return nil
}

func (m *MemoryStore) PruneExpiredSessions(ctx context.Context, now time.Time) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var count int64
	for id, s := range m.sessions {
		if now.After(s.AbsoluteExpiresAt) || (now.After(s.IdleExpiresAt) && s.Locked) {
			delete(m.sessions, id)
			count++
		}
	}
	return count, nil
}

func (m *MemoryStore) CheckAndRecordNonce(ctx context.Context, nonce, purpose, tenantID string, expiresAt time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if exp, exists := m.nonces[nonce]; exists && time.Now().Before(exp) {
		return ErrNonceReplayed
	}
	m.nonces[nonce] = expiresAt
	return nil
}

func (m *MemoryStore) SaveRecoveryToken(ctx context.Context, tok *RecoveryTokenRecord) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.recoveryTokens[tok.TokenHash] = tok
	return nil
}

func (m *MemoryStore) GetRecoveryToken(ctx context.Context, tokenHash string) (*RecoveryTokenRecord, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	tok, ok := m.recoveryTokens[tokenHash]
	if !ok {
		return nil, ErrNotFound
	}
	return tok, nil
}

func (m *MemoryStore) ConsumeRecoveryToken(ctx context.Context, tokenHash string, usedAt time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	tok, ok := m.recoveryTokens[tokenHash]
	if !ok {
		return ErrNotFound
	}
	if tok.Used {
		return ErrTokenUsed
	}
	if usedAt.After(tok.ExpiresAt) {
		return ErrTokenExpired
	}
	tok.Used = true
	tok.UsedAt = &usedAt
	return nil
}

func (m *MemoryStore) RecordAudit(ctx context.Context, entry *SignerAuditEntry) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if entry.Timestamp.IsZero() {
		entry.Timestamp = time.Now()
	}
	entry.ID = int64(len(m.auditLog) + 1)
	m.auditLog = append(m.auditLog, entry)
	return nil
}

func (m *MemoryStore) QueryAudit(ctx context.Context, tenantID string, limit int) ([]*SignerAuditEntry, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	var res []*SignerAuditEntry
	for i := len(m.auditLog) - 1; i >= 0; i-- {
		e := m.auditLog[i]
		if tenantID == "" || e.TenantID == tenantID {
			res = append(res, e)
			if len(res) >= limit {
				break
			}
		}
	}
	return res, nil
}

func (m *MemoryStore) CountActiveSessions(ctx context.Context, tenantID string, now time.Time) (int, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	count := 0
	for _, s := range m.sessions {
		if (tenantID == "" || s.TenantID == tenantID) && s.IsValid(now) {
			count++
		}
	}
	return count, nil
}

func (m *MemoryStore) CountAuthenticators(ctx context.Context, tenantID string) (int, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	count := 0
	for _, a := range m.authenticators {
		if (tenantID == "" || a.TenantID == tenantID) && a.Status == "active" {
			count++
		}
	}
	return count, nil
}

