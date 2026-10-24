package server

// Screen ask-first: GET/PUT /api/v1/screen/settings[?endpoint_id=]. Whether
// a screen session on a machine first asks the person at the keyboard to
// allow it. One fleet default plus per-endpoint overrides, kept in one row
// of the settings table (like terminal.limits). The open flow puts
// "ask_first":true into the digested approval payload and the offer, and the
// agent enforces it.
//
// Default: off. Asking first is the right default on a domain or Entra
// joined machine that someone else uses, but the hub does not know an
// endpoint's join type (agents do not report it), so it cannot recommend it
// per machine; the owner turns it on for the machines that need it.
//
// Turning ask-first on applies at once. Turning it off (or dropping an
// override so a machine follows a fleet default that is off) loosens safety,
// so the authority authorizes it and the audit records it, as raising the
// remote shell limits does.

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
	"sort"
	"strings"
	"sync"

	"ominull/hub/pkg/responseauth"
)

const (
	screenSettingsKey   = "screen.ask_first"
	screenSettingsAudit = "SCREEN_SETTINGS_CHANGED"
)

// screenSettingsMu serializes read-modify-write of the settings row.
var screenSettingsMu sync.Mutex

// screenAskFirstSettings is the saved row.
type screenAskFirstSettings struct {
	// Default is the fleet default; nil means never set (off).
	Default *bool `json:"default,omitempty"`
	// Endpoints holds per-endpoint overrides.
	Endpoints map[string]bool `json:"endpoints,omitempty"`
}

func (s *Server) loadScreenSettings() screenAskFirstSettings {
	var st screenAskFirstSettings
	raw, err := s.store.GetSetting(screenSettingsKey)
	if err != nil || raw == "" {
		return st
	}
	if err := json.Unmarshal([]byte(raw), &st); err != nil {
		log.Printf("[!] Ignoring unreadable saved screen settings: %v", err)
		return screenAskFirstSettings{}
	}
	return st
}

func (st screenAskFirstSettings) fleet() bool {
	return st.Default != nil && *st.Default
}

// askFirst is the effective setting for an endpoint and where it comes from
// ("endpoint", "fleet" or "default").
func (st screenAskFirstSettings) askFirst(endpointID string) (bool, string) {
	if v, ok := st.Endpoints[endpointID]; ok && endpointID != "" {
		return v, "endpoint"
	}
	if st.Default != nil {
		return *st.Default, "fleet"
	}
	return false, "default"
}

// screenAskFirst is whether a screen session on endpointID asks first.
func (s *Server) screenAskFirst(endpointID string) bool {
	screenSettingsMu.Lock()
	defer screenSettingsMu.Unlock()
	v, _ := s.loadScreenSettings().askFirst(endpointID)
	return v
}

func (s *Server) screenSettingsView(st screenAskFirstSettings, endpointID string) map[string]interface{} {
	if endpointID != "" {
		v, src := st.askFirst(endpointID)
		return map[string]interface{}{
			"endpoint_id": endpointID, "ask_first": v, "source": src, "fleet_ask_first": st.fleet(),
		}
	}
	eps := map[string]bool{}
	for k, v := range st.Endpoints {
		eps[k] = v
	}
	return map[string]interface{}{
		"ask_first": st.fleet(), "source": map[bool]string{true: "fleet", false: "default"}[st.Default != nil],
		"endpoints": eps,
		"note":      "Off unless set: the hub does not know which machines are domain or Entra joined.",
	}
}

func (s *Server) handleScreenSettings(w http.ResponseWriter, r *http.Request) {
	endpointID := strings.TrimSpace(r.URL.Query().Get("endpoint_id"))
	switch r.Method {
	case http.MethodGet:
		role := r.Header.Get("X-Role")
		if role != "admin" && role != "operator" && role != "auditor" {
			writeJSONError(w, http.StatusForbidden, "unauthorized role for screen settings")
			return
		}
		if endpointID != "" && !s.endpointInScope(w, r, endpointID) {
			return
		}
		screenSettingsMu.Lock()
		view := s.screenSettingsView(s.loadScreenSettings(), endpointID)
		screenSettingsMu.Unlock()
		writeJSON(w, http.StatusOK, view)
	case http.MethodPut:
		if r.Header.Get("X-Role") != "admin" {
			writeJSONError(w, http.StatusForbidden, "admin credential required to change screen settings")
			return
		}
		s.putScreenSettings(w, r, endpointID)
	default:
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

// putScreenSettings: {"ask_first": true|false} sets the fleet default, or
// with ?endpoint_id= (or "endpoint_id" in the body) that machine's override;
// {"reset": true} for an endpoint drops its override so it follows the fleet
// default, and for the fleet forgets the default (off).
func (s *Server) putScreenSettings(w http.ResponseWriter, r *http.Request, endpointID string) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 4*1024+1))
	if err != nil || len(body) > 4*1024 {
		writeJSONError(w, http.StatusBadRequest, "request body unreadable or over 4 KiB")
		return
	}
	var req struct {
		EndpointID string `json:"endpoint_id"`
		AskFirst   *bool  `json:"ask_first"`
		Reset      bool   `json:"reset"`
	}
	if !decodeInto(w, body, &req) {
		return
	}
	if endpointID == "" {
		endpointID = strings.TrimSpace(req.EndpointID)
	}
	if (req.AskFirst == nil) == !req.Reset {
		writeJSONError(w, http.StatusBadRequest, `send "ask_first": true or false, or "reset": true`)
		return
	}
	if endpointID != "" && !s.endpointInScope(w, r, endpointID) {
		return
	}

	screenSettingsMu.Lock()
	defer screenSettingsMu.Unlock()
	before := s.loadScreenSettings()
	after := screenAskFirstSettings{Endpoints: map[string]bool{}}
	if before.Default != nil {
		d := *before.Default
		after.Default = &d
	}
	for k, v := range before.Endpoints {
		after.Endpoints[k] = v
	}
	switch {
	case endpointID != "" && req.Reset:
		delete(after.Endpoints, endpointID)
	case endpointID != "":
		after.Endpoints[endpointID] = *req.AskFirst
	case req.Reset:
		after.Default = nil
	default:
		v := *req.AskFirst
		after.Default = &v
	}

	scope, target := "fleet", "screen:ask_first"
	var was, now bool
	if endpointID != "" {
		scope, target = endpointID, "screen:ask_first:"+endpointID
		was, _ = before.askFirst(endpointID)
		now, _ = after.askFirst(endpointID)
	} else {
		was, now = before.fleet(), after.fleet()
	}
	unchangedRow := equalScreenSettings(before, after)
	if was == now && unchangedRow {
		view := s.screenSettingsView(before, endpointID)
		view["changed"] = false
		writeJSON(w, http.StatusOK, view)
		return
	}
	wording := "no change in effect (" + scope + " setting rewritten)"
	c := policyChange{policy: "screen_ask_first", op: "off", target: target, subject: "screen safety"}
	if was != now {
		host := ""
		if endpointID != "" {
			host = s.endpointLabels([]string{endpointID})
		}
		b := map[string]interface{}{"scope": scope, "ask_first": was}
		a := map[string]interface{}{"scope": scope, "ask_first": now}
		if host != "" && host != endpointID {
			a["host"] = host
		}
		if wording, err = responseauth.ScreenAskFirstWording(target, b, a); err != nil {
			writeJSONError(w, http.StatusInternalServerError, "the change could not be described: "+err.Error())
			return
		}
		c.before, c.after, c.wording = b, a, wording
		if was && !now {
			c.loosens = []string{"asking the person at the keyboard first"}
		}
	}
	approvalID, ok := s.policyAuthorized(w, r, c)
	if !ok {
		return
	}
	raw, _ := json.Marshal(after)
	if after.Default == nil && len(after.Endpoints) == 0 {
		raw = nil
	}
	if err := s.store.SetSetting(screenSettingsKey, string(raw)); err != nil {
		writeJSONError(w, http.StatusInternalServerError, "the screen settings could not be saved: "+err.Error())
		return
	}
	how := "tightened"
	switch {
	case approvalID != "":
		how = "loosened, authorization " + approvalID
	case was == now:
		how = "rewritten"
	}
	s.audit(r, screenSettingsAudit, target, how+": "+wording+"; credential "+credentialOf(r)+" (unverified)")
	view := s.screenSettingsView(after, endpointID)
	view["changed"] = true
	if approvalID != "" {
		view["approval_id"] = approvalID
	}
	writeJSON(w, http.StatusOK, view)
}

func equalScreenSettings(a, b screenAskFirstSettings) bool {
	if (a.Default == nil) != (b.Default == nil) || (a.Default != nil && *a.Default != *b.Default) || len(a.Endpoints) != len(b.Endpoints) {
		return false
	}
	keys := make([]string, 0, len(a.Endpoints))
	for k := range a.Endpoints {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if v, ok := b.Endpoints[k]; !ok || v != a.Endpoints[k] {
			return false
		}
	}
	return true
}
