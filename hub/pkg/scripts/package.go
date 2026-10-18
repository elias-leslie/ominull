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
	Package  string `json:"package"`
	Title    string `json:"title,omitempty"`
	Category string `json:"category,omitempty"` // maintenance | security ("" reads as maintenance)
	Interval string `json:"interval,omitempty"` // default schedule
	Risk     string `json:"risk,omitempty"`     // safe | careful
	Reboot   bool   `json:"reboot,omitempty"`   // the package may need a reboot
	Timeout  int    `json:"timeout,omitempty"`
	Platform string `json:"platform,omitempty"` // windows | linux ("" reads as windows)
	Role     string `json:"role,omitempty"`     // maintenance_mode, reboot, or empty
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
	State   string          `json:"state"` // ok | fixed | drift | failed | skipped | na
	Reboot  bool            `json:"reboot"`
	Changed []string        `json:"changed"`
	Detail  json.RawMessage `json:"detail,omitempty"`
}

var packageStates = map[string]bool{"ok": true, "fixed": true, "drift": true, "failed": true, "skipped": true, "na": true}

// Control is one checked control in a result's detail.controls.
type Control struct {
	ID       string `json:"id"`
	CIS      string `json:"cis,omitempty"` // benchmark reference id only, e.g. "CIS WIN11 1.1.4"
	Expected string `json:"expected,omitempty"`
	Actual   string `json:"actual,omitempty"`
	State    string `json:"state"`          // pass | fail | fixed | na
	Risk     string `json:"risk,omitempty"` // safe | careful
}

var controlStates = map[string]bool{"pass": true, "fail": true, "fixed": true, "na": true}

// Controls reads detail.controls, keeping only well-formed entries.
func (r *PackageResult) Controls() []Control {
	if r == nil || len(r.Detail) == 0 {
		return nil
	}
	var d struct {
		Controls []Control `json:"controls"`
	}
	if json.Unmarshal(r.Detail, &d) != nil {
		return nil
	}
	out := d.Controls[:0]
	for _, c := range d.Controls {
		if c.ID != "" && controlStates[c.State] {
			out = append(out, c)
		}
	}
	return out
}

// Compliance counts controls: passed (pass or fixed) and failed; na counts
// for neither.
func Compliance(controls []Control) (pass, fail int) {
	for _, c := range controls {
		switch c.State {
		case "pass", "fixed":
			pass++
		case "fail":
			fail++
		}
	}
	return pass, fail
}

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

// RecurrenceInterval is how often a schedule's package should succeed.
func RecurrenceInterval(recurrence string) (time.Duration, bool) {
	switch recurrence {
	case "hourly":
		return time.Hour, true
	case "daily":
		return 24 * time.Hour, true
	case "weekly":
		return 7 * 24 * time.Hour, true
	}
	return 0, false
}

// Maintenance settings: one small table keyed by (package, endpoint) where
// endpoint "" is the fleet default and package "@<category>" holds a
// category's enable. A NULL field inherits: endpoint -> fleet -> built in
// (packages off, categories on, mode audit, the header's interval and
// parameter defaults). Security compliance packages use the same rows.

// CategoryKey is the settings row name of a category.
func CategoryKey(category string) string { return "@" + category }

// PackageSetting is one row: what a fleet default or an endpoint override sets.
type PackageSetting struct {
	Package    string            `json:"package"`
	EndpointID string            `json:"endpoint_id,omitempty"`
	Enabled    *bool             `json:"enabled,omitempty"`
	Mode       *string           `json:"mode,omitempty"`
	Interval   *string           `json:"interval,omitempty"`
	Params     map[string]string `json:"params,omitempty"`
	Reason     string            `json:"reason,omitempty"`     // required on an endpoint override
	ExpiresAt  *time.Time        `json:"expires_at,omitempty"` // an expired override no longer applies
	UpdatedAt  time.Time         `json:"updated_at"`
	UpdatedBy  string            `json:"updated_by,omitempty"`
}

// Empty: the row overrides nothing.
func (p *PackageSetting) Empty() bool {
	return p.Enabled == nil && p.Mode == nil && p.Interval == nil && len(p.Params) == 0
}

func (s *Store) initSettings() error {
	_, err := s.db.Exec(`CREATE TABLE IF NOT EXISTS maintenance_settings (
		tenant_id TEXT NOT NULL,
		package TEXT NOT NULL,
		endpoint_id TEXT NOT NULL DEFAULT '',
		enabled INTEGER,
		mode TEXT,
		interval TEXT,
		params_json TEXT NOT NULL DEFAULT '{}',
		updated_at TIMESTAMP NOT NULL,
		updated_by TEXT NOT NULL DEFAULT '',
		reason TEXT NOT NULL DEFAULT '',
		expires_at TIMESTAMP,
		PRIMARY KEY(tenant_id, package, endpoint_id)
	)`)
	return err
}

// ListSettings returns every settings row of a tenant.
func (s *Store) ListSettings(tenantID string) ([]PackageSetting, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rows, err := s.db.Query(`SELECT package, endpoint_id, enabled, mode, interval, params_json, updated_at, updated_by, reason, expires_at
		FROM maintenance_settings WHERE tenant_id = ? ORDER BY package, endpoint_id`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []PackageSetting
	for rows.Next() {
		var r PackageSetting
		var enabled sql.NullInt64
		var mode, interval sql.NullString
		var params string
		var expires sql.NullTime
		if err := rows.Scan(&r.Package, &r.EndpointID, &enabled, &mode, &interval, &params, &r.UpdatedAt, &r.UpdatedBy, &r.Reason, &expires); err != nil {
			return nil, err
		}
		if expires.Valid {
			t := expires.Time.UTC()
			r.ExpiresAt = &t
		}
		if enabled.Valid {
			b := enabled.Int64 != 0
			r.Enabled = &b
		}
		if mode.Valid {
			r.Mode = &mode.String
		}
		if interval.Valid {
			r.Interval = &interval.String
		}
		_ = json.Unmarshal([]byte(params), &r.Params)
		out = append(out, r)
	}
	return out, rows.Err()
}

// PutSetting replaces one row (an empty row is removed). Callers validate.
func (s *Store) PutSetting(tenantID string, r PackageSetting) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if r.Empty() {
		_, err := s.db.Exec(`DELETE FROM maintenance_settings WHERE tenant_id = ? AND package = ? AND endpoint_id = ?`,
			tenantID, r.Package, r.EndpointID)
		return err
	}
	var enabled interface{}
	if r.Enabled != nil {
		enabled = 0
		if *r.Enabled {
			enabled = 1
		}
	}
	var mode, interval interface{}
	if r.Mode != nil {
		mode = *r.Mode
	}
	if r.Interval != nil {
		interval = *r.Interval
	}
	params, _ := json.Marshal(r.Params)
	if r.Params == nil {
		params = []byte("{}")
	}
	var expires interface{}
	if r.ExpiresAt != nil {
		expires = r.ExpiresAt.UTC()
	}
	_, err := s.db.Exec(`INSERT INTO maintenance_settings (tenant_id, package, endpoint_id, enabled, mode, interval, params_json, updated_at, updated_by, reason, expires_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(tenant_id, package, endpoint_id) DO UPDATE SET enabled = excluded.enabled, mode = excluded.mode,
		interval = excluded.interval, params_json = excluded.params_json, updated_at = excluded.updated_at, updated_by = excluded.updated_by,
		reason = excluded.reason, expires_at = excluded.expires_at`,
		tenantID, r.Package, r.EndpointID, enabled, mode, interval, string(params), time.Now().UTC(), r.UpdatedBy, r.Reason, expires)
	return err
}

// EffectiveSetting is what applies to one package on one endpoint (or the fleet).
type EffectiveSetting struct {
	Enabled         bool              `json:"enabled"`          // package and category both on
	PackageEnabled  bool              `json:"package_enabled"`  // the package's own switch
	CategoryEnabled bool              `json:"category_enabled"` // its category's switch
	Mode            string            `json:"mode"`
	Interval        string            `json:"interval"`
	Params          map[string]string `json:"params"` // every declared param
}

// Settings indexes a tenant's rows.
type Settings map[string]map[string]PackageSetting // package -> endpoint ("" fleet) -> row

// IndexSettings builds the index.
func IndexSettings(rows []PackageSetting) Settings {
	out := Settings{}
	for _, r := range rows {
		if out[r.Package] == nil {
			out[r.Package] = map[string]PackageSetting{}
		}
		out[r.Package][r.EndpointID] = r
	}
	return out
}

// Expired: an override past its expiry, which no longer applies.
func (p *PackageSetting) Expired(now time.Time) bool {
	return p.ExpiresAt != nil && !now.Before(*p.ExpiresAt)
}

// IndexSettings builds the index of the rows in force at now (expired
// overrides fall back to the fleet default).
func IndexSettingsAt(rows []PackageSetting, now time.Time) Settings {
	var live []PackageSetting
	for _, r := range rows {
		if !r.Expired(now) {
			live = append(live, r)
		}
	}
	return IndexSettings(live)
}

// CategoryEnabled resolves a category's switch for an endpoint ("" = fleet).
func (st Settings) CategoryEnabled(category, endpointID string) bool {
	rows := st[CategoryKey(category)]
	if endpointID != "" {
		if r, ok := rows[endpointID]; ok && r.Enabled != nil {
			return *r.Enabled
		}
	}
	if r, ok := rows[""]; ok && r.Enabled != nil {
		return *r.Enabled
	}
	return true
}

// Effective resolves a package's settings for an endpoint ("" = fleet).
func (st Settings) Effective(h *PackageHeader, endpointID string) EffectiveSetting {
	e := EffectiveSetting{Mode: "audit", Interval: h.Interval, Params: h.Defaults()}
	layers := []PackageSetting{st[h.Name][""]}
	if endpointID != "" {
		layers = append(layers, st[h.Name][endpointID])
	}
	for _, r := range layers {
		if r.Enabled != nil {
			e.PackageEnabled = *r.Enabled
		}
		if r.Mode != nil {
			e.Mode = *r.Mode
		}
		if r.Interval != nil {
			e.Interval = *r.Interval
		}
		for k, v := range r.Params {
			if p := h.Param(k); p != nil && p.Type != "catalog" && p.Check(v) == nil {
				e.Params[k] = v
			}
		}
	}
	cat := h.Category
	if cat == "" {
		cat = "maintenance"
	}
	e.CategoryEnabled = st.CategoryEnabled(cat, endpointID)
	e.Enabled = e.PackageEnabled && e.CategoryEnabled
	return e
}

// RunParams is the parameter map of a run with these settings: mode plus
// every declared param.
func (e EffectiveSetting) RunParams(mode string) map[string]string {
	out := make(map[string]string, len(e.Params)+1)
	for k, v := range e.Params {
		out[k] = v
	}
	if mode == "" {
		mode = e.Mode
	}
	out["mode"] = mode
	return out
}
