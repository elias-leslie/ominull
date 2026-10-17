package server

// Maintenance settings: GET/PUT /api/v1/maintenance/settings. Each package
// (maintenance or security) has a fleet default (enabled, mode, interval,
// parameter values) that an endpoint may override; each category has a fleet
// and endpoint enable on top. Changing a setting never grants anything: the
// schedule runs the effective settings, and a run the owner has not approved
// (enforce, a careful package, changed parameters) asks the owner first.

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"ominull/hub/pkg/scripts"
)

// packageDef is one library package with its parsed header.
type packageDef struct {
	Script  *scripts.Script
	Version *scripts.ScriptVersion
	Header  *scripts.PackageHeader
}

// packageDefs lists the tenant's live packages (latest versions).
func (s *Server) packageDefs(tenantID string) ([]packageDef, error) {
	list, err := s.scriptsStore.ListScripts(tenantID)
	if err != nil {
		return nil, err
	}
	var out []packageDef
	for _, sc := range list {
		if sc.Package() == nil || sc.Retired {
			continue
		}
		sv, err := s.scriptsStore.GetScriptVersion(tenantID, sc.ID, sc.LatestVersion)
		if err != nil {
			return nil, err
		}
		h, err := scripts.ParsePackageHeader(sv.Source)
		if err != nil {
			continue // a package from before typed headers: runnable from the library only
		}
		out = append(out, packageDef{Script: sc, Version: sv, Header: h})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Header.Name < out[j].Header.Name })
	return out, nil
}

// maintenanceSettings is the settings in force now: expired overrides fall
// back to the fleet default.
func (s *Server) maintenanceSettings(tenantID string) (scripts.Settings, error) {
	rows, err := s.scriptsStore.ListSettings(tenantID)
	if err != nil {
		return nil, err
	}
	return scripts.IndexSettingsAt(rows, time.Now().UTC()), nil
}

// maintenanceRows is every stored row, expired overrides included.
func (s *Server) maintenanceRows(tenantID string) (scripts.Settings, error) {
	rows, err := s.scriptsStore.ListSettings(tenantID)
	if err != nil {
		return nil, err
	}
	return scripts.IndexSettings(rows), nil
}

type settingsParamView struct {
	Name        string   `json:"name"`
	Type        string   `json:"type"`
	Default     string   `json:"default"`
	Min         *int64   `json:"min,omitempty"`
	Max         *int64   `json:"max,omitempty"`
	Values      []string `json:"values,omitempty"`
	MaxItems    int      `json:"max_items,omitempty"`
	Description string   `json:"description"`
}

type settingsPackageView struct {
	ScriptID    string                    `json:"script_id"`
	Name        string                    `json:"name"`
	Title       string                    `json:"title"`
	Description string                    `json:"description"`
	Category    string                    `json:"category"`
	Platform    string                    `json:"platform"`
	Role        string                    `json:"role,omitempty"`
	Risk        string                    `json:"risk"`
	Reboot      bool                      `json:"reboot"`
	Version     int                       `json:"version"`
	Interval    string                    `json:"default_interval"`
	Params      []settingsParamView       `json:"params"`
	Fleet       *scripts.PackageSetting   `json:"fleet,omitempty"`
	Endpoint    *scripts.PackageSetting   `json:"endpoint,omitempty"`
	FleetEff    scripts.EffectiveSetting  `json:"fleet_effective"`
	Effective   *scripts.EffectiveSetting `json:"effective,omitempty"`
}

type settingsCategoryView struct {
	Name     string `json:"name"`
	Fleet    *bool  `json:"fleet,omitempty"`
	Endpoint *bool  `json:"endpoint,omitempty"`
	FleetOn  bool   `json:"fleet_enabled"`
	On       *bool  `json:"enabled,omitempty"` // for the endpoint asked about
	// Override is the endpoint's row (reason, expiry; expired ones too).
	Override *scripts.PackageSetting `json:"override,omitempty"`
}

func rowPtr(st scripts.Settings, pkg, ep string) *scripts.PackageSetting {
	if r, ok := st[pkg][ep]; ok {
		return &r
	}
	return nil
}

func (s *Server) handleMaintenanceSettings(w http.ResponseWriter, r *http.Request) {
	if s.scriptsStore == nil {
		writeJSONError(w, http.StatusServiceUnavailable, "scripts engine not initialized")
		return
	}
	tenantID := s.tenantFromRequest(r)
	if tenantID == "" {
		tenantID = "default"
	}
	switch r.Method {
	case http.MethodGet:
		s.getMaintenanceSettings(w, r, tenantID)
	case http.MethodPut:
		if r.Header.Get("X-Role") != "admin" {
			writeJSONError(w, http.StatusForbidden, "admin credential required to change maintenance settings")
			return
		}
		s.putMaintenanceSettings(w, r, tenantID)
	default:
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (s *Server) getMaintenanceSettings(w http.ResponseWriter, r *http.Request, tenantID string) {
	ep := strings.TrimSpace(r.URL.Query().Get("endpoint_id"))
	defs, err := s.packageDefs(tenantID)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	st, err := s.maintenanceSettings(tenantID)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	all, err := s.maintenanceRows(tenantID)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	cats := make([]settingsCategoryView, 0, len(scripts.PackageCategories))
	for _, c := range []string{"maintenance", "security"} {
		v := settingsCategoryView{Name: c, FleetOn: st.CategoryEnabled(c, "")}
		if row := rowPtr(st, scripts.CategoryKey(c), ""); row != nil {
			v.Fleet = row.Enabled
		}
		if ep != "" {
			if row := rowPtr(all, scripts.CategoryKey(c), ep); row != nil {
				v.Endpoint = row.Enabled
				v.Override = row
			}
			on := st.CategoryEnabled(c, ep)
			v.On = &on
		}
		cats = append(cats, v)
	}
	pkgs := make([]settingsPackageView, 0, len(defs))
	for _, d := range defs {
		h := d.Header
		v := settingsPackageView{ScriptID: d.Script.ID, Name: h.Name, Title: h.Title, Description: h.Description,
			Category: h.Category, Platform: h.PlatformName(), Role: h.Role, Risk: h.Risk, Reboot: h.Reboot, Version: d.Version.Version, Interval: h.Interval,
			Fleet: rowPtr(st, h.Name, ""), FleetEff: st.Effective(h, "")}
		for i := range h.Params {
			p := &h.Params[i]
			v.Params = append(v.Params, settingsParamView{Name: p.Name, Type: p.Type, Default: p.DefaultValue(), Min: p.Min,
				Max: p.Max, Values: p.Values, MaxItems: p.MaxItems, Description: p.Description})
		}
		if ep != "" {
			v.Endpoint = rowPtr(all, h.Name, ep) // expired ones too: the card shows them
			eff := st.Effective(h, ep)
			v.Effective = &eff
		}
		pkgs = append(pkgs, v)
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"categories": cats, "packages": pkgs})
}

// settingsChange is one PUT: a package or a category, fleet or endpoint.
// Fields left out keep their value; null clears (inherit); reset clears all.
type settingsChange struct {
	Package    string                      `json:"package"`
	Category   string                      `json:"category"`
	EndpointID string                      `json:"endpoint_id"`
	Enabled    json.RawMessage             `json:"enabled"`
	Mode       json.RawMessage             `json:"mode"`
	Interval   json.RawMessage             `json:"interval"`
	Params     map[string]*json.RawMessage `json:"params"`
	Reason     *string                     `json:"reason"`     // required on an endpoint override
	ExpiresAt  json.RawMessage             `json:"expires_at"` // RFC 3339 or YYYY-MM-DD; null clears
	Reset      bool                        `json:"reset"`
}

// optString reads an optional field: absent -> keep, null -> clear.
func optString(raw json.RawMessage, cur *string) (*string, error) {
	if raw == nil {
		return cur, nil
	}
	if string(raw) == "null" {
		return nil, nil
	}
	var v string
	if err := json.Unmarshal(raw, &v); err != nil {
		return nil, err
	}
	return &v, nil
}

func optBool(raw json.RawMessage, cur *bool) (*bool, error) {
	if raw == nil {
		return cur, nil
	}
	if string(raw) == "null" {
		return nil, nil
	}
	var v bool
	if err := json.Unmarshal(raw, &v); err != nil {
		return nil, err
	}
	return &v, nil
}

func (s *Server) putMaintenanceSettings(w http.ResponseWriter, r *http.Request, tenantID string) {
	var c settingsChange
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64*1024))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid json body: "+err.Error())
		return
	}
	c.EndpointID = strings.TrimSpace(c.EndpointID)
	if c.EndpointID != "" {
		ep, err := s.store.GetEndpoint(c.EndpointID)
		if err != nil || ep == nil || ep.Status == "retired" {
			writeJSONError(w, http.StatusBadRequest, "endpoint not found")
			return
		}
	}
	var key string
	var h *scripts.PackageHeader
	switch {
	case c.Category != "" && c.Package == "":
		if !scripts.PackageCategories[c.Category] {
			writeJSONError(w, http.StatusBadRequest, "category must be maintenance or security")
			return
		}
		if c.Mode != nil || c.Interval != nil || len(c.Params) > 0 {
			writeJSONError(w, http.StatusBadRequest, "a category has only an enable switch")
			return
		}
		key = scripts.CategoryKey(c.Category)
	case c.Package != "" && c.Category == "":
		defs, err := s.packageDefs(tenantID)
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, err.Error())
			return
		}
		for _, d := range defs {
			if d.Header.Name == c.Package {
				h = d.Header
			}
		}
		if h == nil {
			writeJSONError(w, http.StatusBadRequest, fmt.Sprintf("no package called %q", c.Package))
			return
		}
		key = h.Name
	default:
		writeJSONError(w, http.StatusBadRequest, "name a package or a category")
		return
	}
	all, err := s.maintenanceRows(tenantID)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	row := scripts.PackageSetting{Package: key, EndpointID: c.EndpointID}
	if cur, ok := all[key][c.EndpointID]; ok && !c.Reset {
		row = cur
		if row.Expired(time.Now()) {
			// Editing an expired override starts it again from nothing.
			row = scripts.PackageSetting{Package: key, EndpointID: c.EndpointID}
		}
	}
	if c.Reason != nil {
		row.Reason = strings.TrimSpace(*c.Reason)
		if len(row.Reason) > 300 {
			writeJSONError(w, http.StatusBadRequest, "keep the reason under 300 characters")
			return
		}
	}
	if c.ExpiresAt != nil {
		if string(c.ExpiresAt) == "null" {
			row.ExpiresAt = nil
		} else {
			var raw string
			if err := json.Unmarshal(c.ExpiresAt, &raw); err != nil {
				writeJSONError(w, http.StatusBadRequest, "expires_at must be a date")
				return
			}
			t, err := time.Parse(time.RFC3339, raw)
			if err != nil {
				t, err = time.Parse("2006-01-02", raw)
			}
			if err != nil || !t.After(time.Now()) {
				writeJSONError(w, http.StatusBadRequest, "expires_at must be a date in the future")
				return
			}
			t = t.UTC()
			row.ExpiresAt = &t
		}
	}
	row.UpdatedBy = s.operatorFromRequest(r)
	if row.Enabled, err = optBool(c.Enabled, row.Enabled); err != nil {
		writeJSONError(w, http.StatusBadRequest, "enabled must be true, false or null")
		return
	}
	if row.Mode, err = optString(c.Mode, row.Mode); err != nil || (row.Mode != nil && *row.Mode != "audit" && *row.Mode != "enforce") {
		writeJSONError(w, http.StatusBadRequest, "mode must be audit, enforce or null")
		return
	}
	if row.Interval, err = optString(c.Interval, row.Interval); err != nil {
		writeJSONError(w, http.StatusBadRequest, "interval must be a string or null")
		return
	}
	if row.Interval != nil {
		if _, ok := scripts.RecurrenceInterval(*row.Interval); !ok {
			writeJSONError(w, http.StatusBadRequest, "interval must be hourly, daily or weekly")
			return
		}
	}
	if len(c.Params) > 0 {
		next := map[string]string{}
		for k, v := range row.Params {
			next[k] = v
		}
		for k, raw := range c.Params {
			p := h.Param(k)
			if p == nil {
				writeJSONError(w, http.StatusBadRequest, fmt.Sprintf("%s has no setting %q", h.Name, k))
				return
			}
			if raw == nil || string(*raw) == "null" {
				delete(next, k)
				continue
			}
			var v string
			if err := json.Unmarshal(*raw, &v); err != nil {
				writeJSONError(w, http.StatusBadRequest, fmt.Sprintf("%s: send the value as a string", k))
				return
			}
			if err := p.Check(v); err != nil {
				writeJSONError(w, http.StatusBadRequest, fmt.Sprintf("%s: %v", k, err))
				return
			}
			next[k] = v
		}
		row.Params = next
	}
	if c.EndpointID != "" && !row.Empty() && row.Reason == "" {
		writeJSONError(w, http.StatusBadRequest, "say why this machine differs from the fleet default (reason)")
		return
	}
	if row.Empty() {
		row.Reason, row.ExpiresAt = "", nil
	}
	if err := s.scriptsStore.PutSetting(tenantID, row); err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	scope := "fleet"
	if c.EndpointID != "" {
		scope = c.EndpointID
	}
	detail, _ := json.Marshal(row)
	s.audit(r, "MAINTENANCE_SETTINGS_CHANGED", key, fmt.Sprintf("%s settings for %s: %s", key, scope, detail))
	// The schedule picks the change up on its next pass (and asks the owner
	// then if the new settings need a tap); run it now so it is prompt.
	s.maintBlocks.kicks.Add(1)
	go func() {
		defer s.maintBlocks.kicks.Done()
		s.runMaintenanceSchedules(time.Now().UTC())
	}()
	r.URL.RawQuery = url.Values{"endpoint_id": {c.EndpointID}}.Encode()
	s.getMaintenanceSettings(w, r, tenantID)
}
