package server

// Remote shell limits: GET/PUT /api/v1/terminal/limits. How long a terminal
// session may run, when an idle one ends, and how many may be open per
// endpoint and per tenant. The hub's startup flags (--terminal-max-duration
// and friends) are the defaults; limits saved here win and survive restarts
// (one row in the settings table). Lowering a limit applies at once. Raising
// one is authorized by the response authority through the same hub-policy
// path a detection loosening uses and is recorded in the audit. Sessions
// already open keep the limits they started with.

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
	"time"

	"ominull/hub/pkg/responseauth"
	"ominull/hub/pkg/terminal"
)

const (
	terminalLimitsSetting = "terminal.limits"
	terminalLimitsAudit   = "TERMINAL_LIMITS_CHANGED"
	terminalLimitsTarget  = "terminal:limits"
)

// terminalLimitsJSON is the limits as the API, the settings row and the
// authorization payload carry them.
type terminalLimitsJSON struct {
	MaxDurationSeconds int64 `json:"max_duration_seconds"`
	IdleTimeoutSeconds int64 `json:"idle_timeout_seconds"`
	MaxPerEndpoint     int   `json:"max_per_endpoint"`
	MaxPerTenant       int   `json:"max_per_tenant"`
}

func limitsJSON(l terminal.Limits) terminalLimitsJSON {
	return terminalLimitsJSON{
		MaxDurationSeconds: int64(l.MaxDuration / time.Second), IdleTimeoutSeconds: int64(l.IdleTimeout / time.Second),
		MaxPerEndpoint: l.PerEndpoint, MaxPerTenant: l.PerTenant,
	}
}

func (j terminalLimitsJSON) limits() terminal.Limits {
	return terminal.Limits{
		MaxDuration: time.Duration(j.MaxDurationSeconds) * time.Second, IdleTimeout: time.Duration(j.IdleTimeoutSeconds) * time.Second,
		PerEndpoint: j.MaxPerEndpoint, PerTenant: j.MaxPerTenant,
	}
}

// savedTerminalLimits reads the limits saved from the console, if any.
func (s *Server) savedTerminalLimits() (terminal.Limits, bool) {
	raw, err := s.store.GetSetting(terminalLimitsSetting)
	if err != nil || raw == "" {
		return terminal.Limits{}, false
	}
	var j terminalLimitsJSON
	if err := json.Unmarshal([]byte(raw), &j); err != nil {
		log.Printf("[!] Ignoring unreadable saved remote shell limits: %v", err)
		return terminal.Limits{}, false
	}
	l := j.limits()
	if err := l.Validate(); err != nil {
		log.Printf("[!] Ignoring saved remote shell limits outside the safety bounds: %v", err)
		return terminal.Limits{}, false
	}
	return l, true
}

// SetTerminalLimits sets the startup defaults (flags or environment; zero
// fields take the built-in default) and applies the saved limits over them.
func (s *Server) SetTerminalLimits(defaults terminal.Limits) {
	base := terminal.DefaultLimits()
	if defaults.MaxDuration > 0 {
		base.MaxDuration = defaults.MaxDuration
	}
	if defaults.IdleTimeout > 0 {
		base.IdleTimeout = defaults.IdleTimeout
	}
	if defaults.PerEndpoint > 0 {
		base.PerEndpoint = defaults.PerEndpoint
	}
	if defaults.PerTenant > 0 {
		base.PerTenant = defaults.PerTenant
	}
	if err := base.Validate(); err != nil {
		log.Printf("[!] Ignoring configured remote shell limits (%v); using the built-in defaults.", err)
		base = terminal.DefaultLimits()
	}
	s.terminalLimitsMu.Lock()
	defer s.terminalLimitsMu.Unlock()
	s.terminalDefaults = base
	eff := base
	if saved, ok := s.savedTerminalLimits(); ok {
		eff = saved
	}
	s.terminalMgr.SetLimits(eff)
}

// limitRaises names each limit after raises over before.
func limitRaises(before, after terminal.Limits) []string {
	var out []string
	if after.MaxDuration > before.MaxDuration {
		out = append(out, "session length")
	}
	if after.IdleTimeout > before.IdleTimeout {
		out = append(out, "idle timeout")
	}
	if after.PerEndpoint > before.PerEndpoint {
		out = append(out, "sessions per endpoint")
	}
	if after.PerTenant > before.PerTenant {
		out = append(out, "sessions per tenant")
	}
	return out
}

func limitsMap(j terminalLimitsJSON) map[string]interface{} {
	raw, _ := json.Marshal(j)
	var m map[string]interface{}
	_ = json.Unmarshal(raw, &m)
	return m
}

func terminalLimitBounds() map[string]int64 {
	b := terminal.LimitBounds
	return map[string]int64{
		"min_duration_seconds": int64(b.MinDuration / time.Second), "max_duration_seconds": int64(b.MaxDuration / time.Second),
		"min_idle_seconds": int64(b.MinIdle / time.Second),
		"min_per_endpoint": int64(b.MinPerEndpoint), "max_per_endpoint": int64(b.MaxPerEndpoint),
		"min_per_tenant": int64(b.MinPerTenant), "max_per_tenant": int64(b.MaxPerTenant),
	}
}

func (s *Server) terminalLimitsView() map[string]interface{} {
	_, saved := s.savedTerminalLimits()
	return map[string]interface{}{
		"limits":   limitsJSON(s.terminalMgr.Limits()),
		"defaults": limitsJSON(s.terminalDefaults),
		"saved":    saved,
		"bounds":   terminalLimitBounds(),
	}
}

func (s *Server) handleTerminalLimits(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.terminalLimitsMu.Lock()
		view := s.terminalLimitsView()
		s.terminalLimitsMu.Unlock()
		writeJSON(w, http.StatusOK, view)
	case http.MethodPut:
		if r.Header.Get("X-Role") != "admin" {
			writeJSONError(w, http.StatusForbidden, "admin credential required to change remote shell limits")
			return
		}
		s.putTerminalLimits(w, r)
	default:
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

// putTerminalLimits: fields left out keep their value; reset returns to the
// startup defaults.
func (s *Server) putTerminalLimits(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 16*1024+1))
	if err != nil || len(body) > 16*1024 {
		writeJSONError(w, http.StatusBadRequest, "request body unreadable or over 16 KiB")
		return
	}
	var req struct {
		MaxDurationSeconds *int64 `json:"max_duration_seconds"`
		IdleTimeoutSeconds *int64 `json:"idle_timeout_seconds"`
		MaxPerEndpoint     *int   `json:"max_per_endpoint"`
		MaxPerTenant       *int   `json:"max_per_tenant"`
		Reset              bool   `json:"reset"`
	}
	if !decodeInto(w, body, &req) {
		return
	}
	s.terminalLimitsMu.Lock()
	defer s.terminalLimitsMu.Unlock()
	before := s.terminalMgr.Limits()
	after := before
	if req.Reset {
		after = s.terminalDefaults
	}
	if req.MaxDurationSeconds != nil {
		after.MaxDuration = time.Duration(*req.MaxDurationSeconds) * time.Second
	}
	if req.IdleTimeoutSeconds != nil {
		after.IdleTimeout = time.Duration(*req.IdleTimeoutSeconds) * time.Second
	}
	if req.MaxPerEndpoint != nil {
		after.PerEndpoint = *req.MaxPerEndpoint
	}
	if req.MaxPerTenant != nil {
		after.PerTenant = *req.MaxPerTenant
	}
	if err := after.Validate(); err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	// A reset with nothing different still forgets the saved row.
	_, saved := s.savedTerminalLimits()
	if after == before && !(req.Reset && saved) {
		view := s.terminalLimitsView()
		view["changed"] = false
		writeJSON(w, http.StatusOK, view)
		return
	}
	wording := ""
	if after != before {
		var err error
		if wording, err = responseauth.TerminalLimitsWording(limitsMap(limitsJSON(before)), limitsMap(limitsJSON(after))); err != nil {
			writeJSONError(w, http.StatusInternalServerError, "the change could not be described: "+err.Error())
			return
		}
	}
	c := policyChange{
		policy: "terminal_limits", op: "raise", target: terminalLimitsTarget,
		before: limitsJSON(before), after: limitsJSON(after),
		loosens: limitRaises(before, after), wording: wording, subject: "remote shell limits",
	}
	approvalID, ok := s.policyAuthorized(w, r, c)
	if !ok {
		return
	}
	value := ""
	if !req.Reset {
		raw, _ := json.Marshal(limitsJSON(after))
		value = string(raw)
	}
	if err := s.store.SetSetting(terminalLimitsSetting, value); err != nil {
		writeJSONError(w, http.StatusInternalServerError, "the limits could not be saved: "+err.Error())
		return
	}
	s.terminalMgr.SetLimits(after)
	how := "lowered"
	if approvalID != "" {
		how = "raised, authorization " + approvalID
	}
	if req.Reset {
		how += ", back to the startup defaults"
	}
	if wording == "" {
		wording = "unchanged values"
	}
	s.audit(r, terminalLimitsAudit, terminalLimitsTarget, how+": "+wording+"; credential "+credentialOf(r)+" (unverified)")
	view := s.terminalLimitsView()
	view["changed"] = true
	if approvalID != "" {
		view["approval_id"] = approvalID
	}
	writeJSON(w, http.StatusOK, view)
}
