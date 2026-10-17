package scripts

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Maintenance packages are ordinary library scripts (packages/windows/*.ps1 in
// the repository) whose metadata names the package. A run is an ordinary
// script_exec job; the script's last stdout line is a PackageResult.

// PackageMeta is the metadata object a package script carries.
type PackageMeta struct {
	Package string `json:"package"`
	Title   string `json:"title,omitempty"`
	Risk    string `json:"risk,omitempty"`   // safe | careful
	Reboot  bool   `json:"reboot,omitempty"` // the package may need a reboot
	Timeout int    `json:"timeout,omitempty"`
}

// Package returns the script's package metadata, or nil when it is not a package.
func (sc *Script) Package() *PackageMeta {
	if sc == nil || len(sc.Metadata) == 0 {
		return nil
	}
	var m PackageMeta
	if json.Unmarshal(sc.Metadata, &m) != nil || m.Package == "" {
		return nil
	}
	return &m
}

// PackageResult is the one-line JSON a package prints last.
type PackageResult struct {
	V       int             `json:"v"`
	State   string          `json:"state"` // ok | fixed | drift | failed | skipped
	Reboot  bool            `json:"reboot"`
	Changed []string        `json:"changed"`
	Detail  json.RawMessage `json:"detail,omitempty"`
}

var packageStates = map[string]bool{"ok": true, "fixed": true, "drift": true, "failed": true, "skipped": true}

// ParsePackageResult reads the last non-empty stdout line. A missing or
// unparseable line is reported as ok=false; callers treat it as failed.
func ParsePackageResult(stdout string) (*PackageResult, bool) {
	lines := strings.Split(strings.TrimRight(stdout, "\r\n\t "), "\n")
	last := strings.TrimSpace(lines[len(lines)-1])
	if !strings.HasPrefix(last, "{") {
		return nil, false
	}
	var r PackageResult
	if err := json.Unmarshal([]byte(last), &r); err != nil || r.V != 1 || !packageStates[r.State] {
		return nil, false
	}
	return &r, true
}

// SyncScript makes the library's script called name match source: it creates
// the script, appends a version only when the source digest or parameter schema
// changed, and updates description and metadata in place (no new version).
// It returns "created", "updated" or "unchanged".
func (s *Store) SyncScript(tenantID, name, description, interpreter, source, paramSchema, metadata, createdBy string) (*Script, *ScriptVersion, string, error) {
	meta, err := normalizeMetadata(metadata)
	if err != nil {
		return nil, nil, "", err
	}
	tenantID, name = strings.TrimSpace(tenantID), strings.TrimSpace(name)
	if tenantID == "" || name == "" {
		return nil, nil, "", errors.New("missing tenant_id or name")
	}

	var id string
	s.mu.Lock()
	err = s.db.QueryRow(`SELECT id FROM scripts WHERE tenant_id = ? AND name = ? AND retired = 0 ORDER BY updated_at DESC LIMIT 1`,
		tenantID, name).Scan(&id)
	s.mu.Unlock()
	if errors.Is(err, sql.ErrNoRows) {
		sc, sv, err := s.CreateScript(tenantID, name, description, interpreter, source, paramSchema, createdBy)
		if err != nil {
			return nil, nil, "", err
		}
		if err := s.setDescriptionAndMetadata(tenantID, sc.ID, description, meta); err != nil {
			return nil, nil, "", err
		}
		sc.setMetadata(meta)
		return sc, sv, "created", nil
	}
	if err != nil {
		return nil, nil, "", err
	}

	sc, err := s.GetScript(tenantID, id)
	if err != nil {
		return nil, nil, "", err
	}
	if want := strings.TrimSpace(interpreter); want != "" && want != sc.Interpreter {
		return nil, nil, "", fmt.Errorf("script %q uses %s, not %s; retire it first", name, sc.Interpreter, want)
	}
	latest, err := s.GetScriptVersion(tenantID, id, sc.LatestVersion)
	if err != nil {
		return nil, nil, "", err
	}
	action := "unchanged"
	sv := latest
	if latest.DigestSHA256 != ComputeScriptDigest(source) || strings.TrimSpace(latest.ParameterSchemaJSON) != strings.TrimSpace(paramSchema) {
		if sv, err = s.UpdateScript(tenantID, id, source, paramSchema, createdBy); err != nil {
			return nil, nil, "", err
		}
		action = "updated"
		sc.LatestVersion = sv.Version
	}
	if sc.Description != description || string(sc.Metadata) != meta {
		if err := s.setDescriptionAndMetadata(tenantID, id, description, meta); err != nil {
			return nil, nil, "", err
		}
		sc.Description = description
		sc.Metadata = nil
		sc.setMetadata(meta)
	}
	return sc, sv, action, nil
}

func (s *Store) setDescriptionAndMetadata(tenantID, scriptID, description, meta string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec(`UPDATE scripts SET description = ?, metadata_json = ?, updated_at = ? WHERE id = ? AND tenant_id = ?`,
		description, meta, time.Now().UTC(), scriptID, tenantID)
	return err
}
