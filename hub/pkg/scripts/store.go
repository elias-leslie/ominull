package scripts

import (
	"database/sql"
	"encoding/json"
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
	ErrNotFound             = errors.New("script not found")
	ErrTenantMismatch       = errors.New("tenant mismatch")
	ErrInvalidInterpreter   = errors.New("invalid interpreter; must be /bin/sh, /bin/bash, powershell.exe, cmd.exe, or pwsh.exe")
	ErrScriptRetired        = errors.New("cannot update retired script")
	ErrScriptTooLarge       = errors.New("script source exceeds maximum allowed size")
	ErrScheduleNotFound     = errors.New("script schedule not found")
	ErrEmptyTargetEndpoints = errors.New("schedule must target explicit endpoints; empty target list forbidden")
	ErrInvalidRecurrence    = errors.New("invalid recurrence; must be hourly, daily, or weekly")

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

	CREATE TABLE IF NOT EXISTS script_schedules (
		id TEXT PRIMARY KEY,
		tenant_id TEXT NOT NULL,
		script_id TEXT NOT NULL,
		version INTEGER NOT NULL,
		script_digest TEXT NOT NULL,
		target_endpoints_json TEXT NOT NULL,
		parameters_json TEXT,
		recurrence TEXT NOT NULL,
		start_time TIMESTAMP NOT NULL,
		end_time TIMESTAMP,
		max_runs INTEGER DEFAULT 0,
		runs_count INTEGER DEFAULT 0,
		timeout_seconds INTEGER DEFAULT 60,
		max_output_bytes INTEGER DEFAULT 1048576,
		status TEXT DEFAULT 'active',
		created_by TEXT NOT NULL,
		created_at TIMESTAMP NOT NULL,
		updated_at TIMESTAMP NOT NULL
	);
	CREATE INDEX IF NOT EXISTS idx_script_schedules_tenant ON script_schedules(tenant_id);
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

// ScriptSchedule represents a frozen script execution schedule.
type ScriptSchedule struct {
	ID              string            `json:"id"`
	TenantID        string            `json:"tenant_id"`
	ScriptID        string            `json:"script_id"`
	Version         int               `json:"version"`
	ScriptDigest    string            `json:"script_digest"`
	TargetEndpoints []string          `json:"target_endpoints"`
	Parameters      map[string]string `json:"parameters,omitempty"`
	Recurrence      string            `json:"recurrence"`
	StartTime       time.Time         `json:"start_time"`
	EndTime         *time.Time        `json:"end_time,omitempty"`
	MaxRuns         int               `json:"max_runs"`
	RunsCount       int               `json:"runs_count"`
	TimeoutSeconds  int               `json:"timeout_seconds"`
	MaxOutputBytes  int64             `json:"max_output_bytes"`
	Status          string            `json:"status"`
	CreatedBy       string            `json:"created_by"`
	CreatedAt       time.Time         `json:"created_at"`
	UpdatedAt       time.Time         `json:"updated_at"`
}

// CreateSchedule freezes a schedule to an immutable script digest and explicit endpoint snapshot.
func (s *Store) CreateSchedule(
	tenantID, scriptID string,
	version int,
	targetEndpoints []string,
	parameters map[string]string,
	recurrence string,
	startTime time.Time,
	endTime *time.Time,
	maxRuns, timeout int,
	maxOutput int64,
	createdBy string,
) (*ScriptSchedule, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	tenantID = strings.TrimSpace(tenantID)
	scriptID = strings.TrimSpace(scriptID)
	if tenantID == "" || scriptID == "" || version <= 0 {
		return nil, errors.New("missing or invalid schedule arguments")
	}

	// 1. Verify script is not retired
	var scRetired int
	err := s.db.QueryRow(`SELECT retired FROM scripts WHERE tenant_id = ? AND id = ?`, tenantID, scriptID).Scan(&scRetired)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	if scRetired == 1 {
		return nil, ErrScriptRetired
	}

	// 2. Retrieve version and freeze to exact script digest
	var scriptDigest string
	var pSchema sql.NullString
	err = s.db.QueryRow(`
		SELECT digest_sha256, parameter_schema_json
		FROM script_versions
		WHERE script_id = ? AND version = ?
	`, scriptID, version).Scan(&scriptDigest, &pSchema)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}

	// 3. Enforce explicit endpoint snapshot (never empty or wildcard)
	if len(targetEndpoints) == 0 {
		return nil, ErrEmptyTargetEndpoints
	}
	var cleanTargets []string
	for _, ep := range targetEndpoints {
		t := strings.TrimSpace(ep)
		if t != "" && t != "*" {
			cleanTargets = append(cleanTargets, t)
		}
	}
	if len(cleanTargets) == 0 {
		return nil, ErrEmptyTargetEndpoints
	}

	// 4. Validate parameters against schema
	if pSchema.Valid && strings.TrimSpace(pSchema.String) != "" {
		schema, err := ValidateSchema(pSchema.String)
		if err != nil {
			return nil, fmt.Errorf("invalid script schema: %w", err)
		}
		if err := ValidateParameters(schema, parameters); err != nil {
			return nil, fmt.Errorf("parameter validation failed: %w", err)
		}
	}

	// 5. Bounds & recurrence normalization
	recurrence = strings.ToLower(strings.TrimSpace(recurrence))
	if recurrence == "" {
		recurrence = "daily"
	}
	if timeout <= 0 || timeout > 300 {
		timeout = 60
	}
	if maxOutput <= 0 || maxOutput > 5242880 {
		maxOutput = 1048576
	}
	if startTime.IsZero() {
		startTime = time.Now().UTC()
	}

	schedID := "sched-" + uuid.New().String()
	targetsBytes, _ := json.Marshal(cleanTargets)
	paramsBytes, _ := json.Marshal(parameters)
	now := time.Now().UTC()

	var endTimeVal sql.NullTime
	if endTime != nil && !endTime.IsZero() {
		endTimeVal = sql.NullTime{Time: endTime.UTC(), Valid: true}
	}

	_, err = s.db.Exec(`
		INSERT INTO script_schedules (
			id, tenant_id, script_id, version, script_digest,
			target_endpoints_json, parameters_json, recurrence,
			start_time, end_time, max_runs, runs_count,
			timeout_seconds, max_output_bytes, status,
			created_by, created_at, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?, 'active', ?, ?, ?)
	`, schedID, tenantID, scriptID, version, scriptDigest,
		string(targetsBytes), string(paramsBytes), recurrence,
		startTime.UTC(), endTimeVal, maxRuns,
		timeout, maxOutput, createdBy, now, now)
	if err != nil {
		return nil, err
	}

	return &ScriptSchedule{
		ID:              schedID,
		TenantID:        tenantID,
		ScriptID:        scriptID,
		Version:         version,
		ScriptDigest:    scriptDigest,
		TargetEndpoints: cleanTargets,
		Parameters:      parameters,
		Recurrence:      recurrence,
		StartTime:       startTime.UTC(),
		EndTime:         endTime,
		MaxRuns:         maxRuns,
		RunsCount:       0,
		TimeoutSeconds:  timeout,
		MaxOutputBytes:  maxOutput,
		Status:          "active",
		CreatedBy:       createdBy,
		CreatedAt:       now,
		UpdatedAt:       now,
	}, nil
}

// ListSchedules returns all script schedules for a tenant.
func (s *Store) ListSchedules(tenantID string) ([]*ScriptSchedule, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return nil, errors.New("missing tenant_id")
	}

	rows, err := s.db.Query(`
		SELECT id, tenant_id, script_id, version, script_digest,
		       target_endpoints_json, parameters_json, recurrence,
		       start_time, end_time, max_runs, runs_count,
		       timeout_seconds, max_output_bytes, status,
		       created_by, created_at, updated_at
		FROM script_schedules
		WHERE tenant_id = ?
		ORDER BY created_at DESC
	`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var list []*ScriptSchedule
	for rows.Next() {
		var sc ScriptSchedule
		var targetsJSON, paramsJSON string
		var endT sql.NullTime

		if err := rows.Scan(
			&sc.ID, &sc.TenantID, &sc.ScriptID, &sc.Version, &sc.ScriptDigest,
			&targetsJSON, &paramsJSON, &sc.Recurrence,
			&sc.StartTime, &endT, &sc.MaxRuns, &sc.RunsCount,
			&sc.TimeoutSeconds, &sc.MaxOutputBytes, &sc.Status,
			&sc.CreatedBy, &sc.CreatedAt, &sc.UpdatedAt,
		); err != nil {
			return nil, err
		}

		_ = json.Unmarshal([]byte(targetsJSON), &sc.TargetEndpoints)
		if strings.TrimSpace(paramsJSON) != "" {
			_ = json.Unmarshal([]byte(paramsJSON), &sc.Parameters)
		}
		if endT.Valid {
			sc.EndTime = &endT.Time
		}

		list = append(list, &sc)
	}
	return list, nil
}

// GetSchedule retrieves a script schedule by ID with tenant scoping.
func (s *Store) GetSchedule(tenantID, scheduleID string) (*ScriptSchedule, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	var sc ScriptSchedule
	var targetsJSON, paramsJSON string
	var endT sql.NullTime

	err := s.db.QueryRow(`
		SELECT id, tenant_id, script_id, version, script_digest,
		       target_endpoints_json, parameters_json, recurrence,
		       start_time, end_time, max_runs, runs_count,
		       timeout_seconds, max_output_bytes, status,
		       created_by, created_at, updated_at
		FROM script_schedules
		WHERE tenant_id = ? AND id = ?
	`, tenantID, scheduleID).Scan(
		&sc.ID, &sc.TenantID, &sc.ScriptID, &sc.Version, &sc.ScriptDigest,
		&targetsJSON, &paramsJSON, &sc.Recurrence,
		&sc.StartTime, &endT, &sc.MaxRuns, &sc.RunsCount,
		&sc.TimeoutSeconds, &sc.MaxOutputBytes, &sc.Status,
		&sc.CreatedBy, &sc.CreatedAt, &sc.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrScheduleNotFound
		}
		return nil, err
	}

	_ = json.Unmarshal([]byte(targetsJSON), &sc.TargetEndpoints)
	if strings.TrimSpace(paramsJSON) != "" {
		_ = json.Unmarshal([]byte(paramsJSON), &sc.Parameters)
	}
	if endT.Valid {
		sc.EndTime = &endT.Time
	}

	return &sc, nil
}

// CancelSchedule cancels an active script schedule.
func (s *Store) CancelSchedule(tenantID, scheduleID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now().UTC()
	res, err := s.db.Exec(`
		UPDATE script_schedules
		SET status = 'cancelled', updated_at = ?
		WHERE tenant_id = ? AND id = ? AND status = 'active'
	`, now, tenantID, scheduleID)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrScheduleNotFound
	}
	return nil
}
