package scripts

import (
	"database/sql"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
	_ "modernc.org/sqlite"
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

	if tenantID == "" || name == "" || source == "" {
		return nil, nil, errors.New("missing required script fields")
	}
	if interpreter == "" {
		interpreter = "/bin/bash"
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

// UpdateScript appends a new immutable version to an existing script.
func (s *Store) UpdateScript(scriptID, source, paramSchema, createdBy string) (*ScriptVersion, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	var latestVer int
	var retired int
	err := s.db.QueryRow(`SELECT latest_version, retired FROM scripts WHERE id = ?`, scriptID).Scan(&latestVer, &retired)
	if err != nil {
		return nil, fmt.Errorf("script not found: %w", err)
	}
	if retired == 1 {
		return nil, errors.New("cannot update retired script")
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

	_, err = s.db.Exec(`UPDATE scripts SET latest_version = ?, updated_at = ? WHERE id = ?`, newVer, now, scriptID)
	return version, err
}

// RetireScript marks a script retired.
func (s *Store) RetireScript(scriptID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now().UTC()
	_, err := s.db.Exec(`UPDATE scripts SET retired = 1, updated_at = ? WHERE id = ?`, now, scriptID)
	return err
}

// GetScript returns a script by ID.
func (s *Store) GetScript(scriptID string) (*Script, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	var sc Script
	var ret int
	err := s.db.QueryRow(`
		SELECT id, tenant_id, name, description, interpreter, latest_version, retired, created_at, updated_at
		FROM scripts WHERE id = ?
	`, scriptID).Scan(&sc.ID, &sc.TenantID, &sc.Name, &sc.Description, &sc.Interpreter, &sc.LatestVersion, &ret, &sc.CreatedAt, &sc.UpdatedAt)
	if err != nil {
		return nil, err
	}
	sc.Retired = (ret == 1)
	return &sc, nil
}

// GetScriptVersion returns an exact immutable script version.
func (s *Store) GetScriptVersion(scriptID string, version int) (*ScriptVersion, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	var sv ScriptVersion
	var pSchema sql.NullString
	err := s.db.QueryRow(`
		SELECT script_id, version, source, digest_sha256, parameter_schema_json, created_by, created_at
		FROM script_versions WHERE script_id = ? AND version = ?
	`, scriptID, version).Scan(&sv.ScriptID, &sv.Version, &sv.Source, &sv.DigestSHA256, &pSchema, &sv.CreatedBy, &sv.CreatedAt)
	if err != nil {
		return nil, err
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
