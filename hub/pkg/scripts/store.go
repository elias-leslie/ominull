package scripts

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

const (
	MaxScriptSourceBytes = 65536 // 64 KiB source code bound
)

var (
	ErrNotFound           = errors.New("script not found")
	ErrTenantMismatch     = errors.New("tenant mismatch")
	ErrInvalidInterpreter = errors.New("invalid interpreter; must be /bin/sh, /bin/bash, powershell.exe, cmd.exe, or pwsh.exe")
	ErrScriptRetired      = errors.New("cannot update retired script")
	ErrScriptTooLarge     = errors.New("script source exceeds maximum allowed size")

	AllowedInterpreters = map[string]bool{
		"/bin/sh":        true,
		"/bin/bash":      true,
		"powershell.exe": true,
		"cmd.exe":        true,
		"pwsh.exe":       true,
	}
)

// Store manages the immutable script library in SQLite.
type Store struct {
	mu sync.Mutex
	db *sql.DB
}

// NewStore initializes a script store.
func NewStore(db *sql.DB) (*Store, error) {
	if db == nil {
		return nil, errors.New("nil db")
	}
	s := &Store{db: db}
	if err := s.migrate(); err != nil {
		return nil, fmt.Errorf("scripts store migration failed: %w", err)
	}
	return s, nil
}

func (s *Store) migrate() error {
	query := `
	CREATE TABLE IF NOT EXISTS scripts (
		id TEXT PRIMARY KEY,
		tenant_id TEXT NOT NULL,
		name TEXT NOT NULL,
		description TEXT NOT NULL,
		interpreter TEXT NOT NULL,
		latest_version INTEGER DEFAULT 1,
		retired INTEGER DEFAULT 0,
		created_at TIMESTAMP NOT NULL,
		updated_at TIMESTAMP NOT NULL
	);
	CREATE INDEX IF NOT EXISTS idx_scripts_tenant ON scripts(tenant_id);

	CREATE TABLE IF NOT EXISTS script_versions (
		script_id TEXT NOT NULL,
		version INTEGER NOT NULL,
		source TEXT NOT NULL,
		digest_sha256 TEXT NOT NULL,
		parameter_schema_json TEXT,
		created_by TEXT NOT NULL,
		created_at TIMESTAMP NOT NULL,
		PRIMARY KEY(script_id, version)
	);
	`
	_, err := s.db.Exec(query)
	return err
}

// CreateScript registers a new immutable script definition and version 1.
func (s *Store) CreateScript(tenantID, name, description, interpreter, source, paramSchema, createdBy string) (*Script, *ScriptVersion, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	tenantID = strings.TrimSpace(tenantID)
	name = strings.TrimSpace(name)
	if tenantID == "" || name == "" || strings.TrimSpace(source) == "" {
		return nil, nil, errors.New("missing required script fields (tenant_id, name, source)")
	}

	interpreter = strings.TrimSpace(interpreter)
	if interpreter == "" {
		interpreter = "/bin/bash"
	}
	if !AllowedInterpreters[interpreter] {
		return nil, nil, fmt.Errorf("%w: %q", ErrInvalidInterpreter, interpreter)
	}

	if len(source) > MaxScriptSourceBytes {
		return nil, nil, fmt.Errorf("%w: %d bytes (limit %d)", ErrScriptTooLarge, len(source), MaxScriptSourceBytes)
	}

	// Validate parameter schema if present
	if _, err := ValidateSchema(paramSchema); err != nil {
		return nil, nil, fmt.Errorf("parameter schema validation failed: %w", err)
	}

	scriptID := uuid.New().String()
	now := time.Now().UTC()
	digest := ComputeScriptDigest(source)

	script := &Script{
		ID:            scriptID,
		TenantID:      tenantID,
		Name:          name,
		Description:   description,
		Interpreter:   interpreter,
		LatestVersion: 1,
		Retired:       false,
		CreatedAt:     now,
		UpdatedAt:     now,
	}

	version := &ScriptVersion{
		ScriptID:            scriptID,
		Version:             1,
		Source:              source,
		DigestSHA256:        digest,
		ParameterSchemaJSON: paramSchema,
		CreatedBy:           createdBy,
		CreatedAt:           now,
	}

	_, err := s.db.Exec(`
		INSERT INTO scripts (id, tenant_id, name, description, interpreter, latest_version, retired, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, 1, 0, ?, ?)
	`, script.ID, script.TenantID, script.Name, script.Description, script.Interpreter, script.CreatedAt, script.UpdatedAt)
	if err != nil {
		return nil, nil, err
	}

	_, err = s.db.Exec(`
		INSERT INTO script_versions (script_id, version, source, digest_sha256, parameter_schema_json, created_by, created_at)
		VALUES (?, 1, ?, ?, ?, ?, ?)
	`, version.ScriptID, version.Source, version.DigestSHA256, version.ParameterSchemaJSON, version.CreatedBy, version.CreatedAt)
	if err != nil {
		return nil, nil, err
	}

	return script, version, nil
}

// UpdateScript appends a new immutable version to an existing script under tenant control.
func (s *Store) UpdateScript(tenantID, scriptID, source, paramSchema, createdBy string) (*ScriptVersion, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return nil, errors.New("missing tenant_id")
	}
	if strings.TrimSpace(source) == "" {
		return nil, errors.New("source cannot be empty")
	}
	if len(source) > MaxScriptSourceBytes {
		return nil, fmt.Errorf("%w: %d bytes (limit %d)", ErrScriptTooLarge, len(source), MaxScriptSourceBytes)
	}

	// Validate parameter schema if present
	if _, err := ValidateSchema(paramSchema); err != nil {
		return nil, fmt.Errorf("parameter schema validation failed: %w", err)
	}

	var storedTenant string
	var latestVer int
	var retired int
	err := s.db.QueryRow(`SELECT tenant_id, latest_version, retired FROM scripts WHERE id = ?`, scriptID).Scan(&storedTenant, &latestVer, &retired)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("failed to query script: %w", err)
	}
	if storedTenant != tenantID {
		return nil, ErrTenantMismatch
	}
	if retired == 1 {
		return nil, ErrScriptRetired
	}

	newVer := latestVer + 1
	now := time.Now().UTC()
	digest := ComputeScriptDigest(source)

	version := &ScriptVersion{
		ScriptID:            scriptID,
		Version:             newVer,
		Source:              source,
		DigestSHA256:        digest,
		ParameterSchemaJSON: paramSchema,
		CreatedBy:           createdBy,
		CreatedAt:           now,
	}

	_, err = s.db.Exec(`
		INSERT INTO script_versions (script_id, version, source, digest_sha256, parameter_schema_json, created_by, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)
	`, version.ScriptID, version.Version, version.Source, version.DigestSHA256, version.ParameterSchemaJSON, version.CreatedBy, version.CreatedAt)
	if err != nil {
		return nil, err
	}

	_, err = s.db.Exec(`UPDATE scripts SET latest_version = ?, updated_at = ? WHERE id = ? AND tenant_id = ?`, newVer, now, scriptID, tenantID)
	return version, err
}

// RetireScript marks a script retired under tenant control.
func (s *Store) RetireScript(tenantID, scriptID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return errors.New("missing tenant_id")
	}

	var storedTenant string
	err := s.db.QueryRow(`SELECT tenant_id FROM scripts WHERE id = ?`, scriptID).Scan(&storedTenant)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		return err
	}
	if storedTenant != tenantID {
		return ErrTenantMismatch
	}

	now := time.Now().UTC()
	res, err := s.db.Exec(`UPDATE scripts SET retired = 1, updated_at = ? WHERE id = ? AND tenant_id = ?`, now, scriptID, tenantID)
	if err != nil {
		return err
	}
	rows, _ := res.RowsAffected()
	if rows == 0 {
		return ErrNotFound
	}
	return nil
}

// GetScript returns a script by ID verifying tenant ownership.
func (s *Store) GetScript(tenantID, scriptID string) (*Script, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return nil, errors.New("missing tenant_id")
	}

	var sc Script
	var ret int
	err := s.db.QueryRow(`
		SELECT id, tenant_id, name, description, interpreter, latest_version, retired, created_at, updated_at
		FROM scripts WHERE id = ?
	`, scriptID).Scan(&sc.ID, &sc.TenantID, &sc.Name, &sc.Description, &sc.Interpreter, &sc.LatestVersion, &ret, &sc.CreatedAt, &sc.UpdatedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	if sc.TenantID != tenantID {
		return nil, ErrTenantMismatch
	}
	sc.Retired = (ret == 1)
	return &sc, nil
}

// GetScriptVersion returns an exact immutable script version verifying tenant ownership.
func (s *Store) GetScriptVersion(tenantID, scriptID string, version int) (*ScriptVersion, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return nil, errors.New("missing tenant_id")
	}

	var sv ScriptVersion
	var pSchema sql.NullString
	var scriptTenant string
	err := s.db.QueryRow(`
		SELECT sv.script_id, sv.version, sv.source, sv.digest_sha256, sv.parameter_schema_json, sv.created_by, sv.created_at, s.tenant_id
		FROM script_versions sv
		JOIN scripts s ON s.id = sv.script_id
		WHERE sv.script_id = ? AND sv.version = ?
	`, scriptID, version).Scan(&sv.ScriptID, &sv.Version, &sv.Source, &sv.DigestSHA256, &pSchema, &sv.CreatedBy, &sv.CreatedAt, &scriptTenant)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	if scriptTenant != tenantID {
		return nil, ErrTenantMismatch
	}
	if pSchema.Valid {
		sv.ParameterSchemaJSON = pSchema.String
	}
	return &sv, nil
}

// ListScripts returns all scripts for a tenant.
func (s *Store) ListScripts(tenantID string) ([]*Script, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return nil, errors.New("missing tenant_id")
	}

	rows, err := s.db.Query(`
		SELECT id, tenant_id, name, description, interpreter, latest_version, retired, created_at, updated_at
		FROM scripts WHERE tenant_id = ? ORDER BY name ASC
	`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var list []*Script
	for rows.Next() {
		var sc Script
		var ret int
		if err := rows.Scan(&sc.ID, &sc.TenantID, &sc.Name, &sc.Description, &sc.Interpreter, &sc.LatestVersion, &ret, &sc.CreatedAt, &sc.UpdatedAt); err != nil {
			return nil, err
		}
		sc.Retired = (ret == 1)
		list = append(list, &sc)
	}
	return list, nil
}
