package server

// The steward: Nightshift's maintenance agent, with its own key.
//
// The steward key (POST /api/v1/integrations/steward/key, admin, issued
// once; reissue revokes) is a credential of its own, not the admin key with
// a self-declared label: the hub names it "steward (steward-key)" to the
// response authority, which is what a steward screen rule
// (responseauth/steward_screen_rule.go) answers to. It reaches only the
// routes in stewardRoutes: reading and waiting on maintenance runs,
// escalating one to the owner, polling its own approvals, and taking a
// remote screen for a stuck run (open, attach, close).
//
// A steward screen request names the run it is for (steward_run). The hub
// opens it only while that run is a supervised maintenance run on that
// machine waiting on a dialog (needs_hands) or stalled, inside the
// machine's maintenance window when the owner's rule says so, never
// unattended, and no longer than the rule allows. The session is bound to
// the run and ends when the run moves on (stewardSessionSweep).
//
// The machine's "Steward remote screen" setting lives in Nightshift (its
// Approvals page is the one approval-rule store). Raising it asks the owner
// once: POST /api/v1/integrations/nightshift/steward-screen (relay key) or
// /api/v1/screen/steward (owner, console or ominullctl) returns, once the
// owner tapped, the authority's signed rule token, which Nightshift keeps
// with its own narrowing. The steward sends both with each screen request;
// the authority checks its signature and applies the narrowing as a floor.
// Narrowing or turning it off happens in Nightshift and needs no tap. The
// hub keeps no copy. Host-locked machines (a host authority file) never
// take a steward session without the owner's tap.

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"ominull/hub/pkg/response"
	"ominull/hub/pkg/responseauth"
	"ominull/hub/pkg/storage"
)

const (
	stewardKeySetting  = "steward.key_hash"
	stewardAuthMethod  = "steward-key"
	stewardUsername    = "steward"
	stewardKeyAudit    = "STEWARD_KEY_ISSUED"
	stewardScreenAudit = "STEWARD_SCREEN_SET"
	stewardSweepTick   = 15 * time.Second
	// stewardDefaultSeconds is a steward session's length when no rule sets it.
	stewardDefaultSeconds = 30 * 60
)

// stewardRoutes is everything the steward key reaches, by path and method.
var stewardRoutes = map[string][]string{
	"/api/v1/maintenance/wait":       {http.MethodGet},
	"/api/v1/maintenance/escalate":   {http.MethodPost},
	"/api/v1/approvals":              {http.MethodGet},
	"/api/v1/maintenance":            {http.MethodGet},
	"/api/v1/screen/sessions":        {http.MethodPost, http.MethodDelete},
	"/api/v1/screen/sessions/attach": {http.MethodPost},
	"/api/v1/screen/sessions/close":  {http.MethodPost},
}

func stewardAllowed(r *http.Request) bool {
	for _, m := range stewardRoutes[r.URL.Path] {
		if m == r.Method {
			return true
		}
	}
	return false
}

func isSteward(r *http.Request) bool {
	return r.Header.Get("X-Auth-Method") == stewardAuthMethod
}

// stewardKeyMatches says whether key is the live steward key.
func (s *Server) stewardKeyMatches(key string) bool {
	want, _ := s.store.GetSetting(stewardKeySetting)
	return key != "" && want != "" && secretEqual(hashFeedKey(key), want)
}

// handleStewardKey issues (POST) or revokes (DELETE) the steward key.
func (s *Server) handleStewardKey(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("X-Role") != "admin" || r.Header.Get("X-Tenant-ID") != "" || isSteward(r) {
		writeJSONError(w, http.StatusForbidden, "only an administrator can issue the steward key")
		return
	}
	switch r.Method {
	case http.MethodPost:
		raw := make([]byte, 32)
		if _, err := rand.Read(raw); err != nil {
			writeJSONError(w, http.StatusInternalServerError, "generating the key failed")
			return
		}
		key := "nss_" + hex.EncodeToString(raw)
		if err := s.store.SetSetting(stewardKeySetting, hashFeedKey(key)); err != nil {
			writeJSONError(w, http.StatusInternalServerError, "the key could not be saved")
			return
		}
		s.audit(r, stewardKeyAudit, "steward", "Issued the steward key; any earlier steward key is revoked; credential "+credentialOf(r))
		w.Header().Set("Cache-Control", "no-store")
		writeJSON(w, http.StatusOK, map[string]interface{}{"key": key, "routes": stewardRouteList()})
	case http.MethodDelete:
		if err := s.store.SetSetting(stewardKeySetting, ""); err != nil {
			writeJSONError(w, http.StatusInternalServerError, "the key could not be revoked")
			return
		}
		s.audit(r, stewardKeyAudit, "steward", "Revoked the steward key; credential "+credentialOf(r))
		writeJSON(w, http.StatusOK, map[string]bool{"revoked": true})
	default:
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func stewardRouteList() []string {
	out := []string{}
	for p, methods := range stewardRoutes {
		for _, m := range methods {
			out = append(out, m+" "+p)
		}
	}
	sort.Strings(out)
	return out
}

// stewardRun checks the run a steward screen request names: a supervised
// maintenance job on that machine, waiting on a dialog or stalled. It
// returns why not, or "".
func (s *Server) stewardRunRefusal(tenantID, endpointID, jobID string) string {
	if s.responseStore == nil {
		return "the response store is not available"
	}
	job, err := s.responseStore.GetJob(tenantID, jobID)
	if err != nil || job == nil || job.Kind != response.ActionKindScriptExec {
		return "no such maintenance run: " + jobID
	}
	if job.EndpointID != endpointID {
		return "run " + jobID + " is on another machine"
	}
	run := s.liveRun(job, time.Now())
	if run == nil || (run.State != "needs_hands" && run.State != "stalled") {
		state := "unknown"
		if run != nil {
			state = run.State
		}
		return fmt.Sprintf("run %s is not waiting on a dialog or stalled (it is %s); the steward takes the screen only for a stuck run", jobID, state)
	}
	return ""
}

// hostLocked says the machine carries a host authority file (the owner's
// own infrastructure, locked on the host).
func (s *Server) hostLocked(endpointID string) bool {
	s.trust.mu.Lock()
	defer s.trust.mu.Unlock()
	s.trust.init()
	seen, ok := s.trust.reports[endpointID]
	return ok && seen.report.HostAuthority
}

// stewardSessions binds open steward screen sessions to their runs.
var stewardSessions = struct {
	sync.Mutex
	byID map[string]stewardBinding
}{byID: map[string]stewardBinding{}}

type stewardBinding struct {
	Tenant, Endpoint, Run string
}

func bindStewardSession(sessionID string, b stewardBinding) {
	stewardSessions.Lock()
	stewardSessions.byID[sessionID] = b
	stewardSessions.Unlock()
}

// StewardRunOf is the run a screen session was opened for ("" when none).
func stewardRunOf(sessionID string) string {
	stewardSessions.Lock()
	defer stewardSessions.Unlock()
	return stewardSessions.byID[sessionID].Run
}

func (s *Server) stewardSessionLoop() {
	t := time.NewTicker(stewardSweepTick)
	defer t.Stop()
	for range t.C {
		s.stewardSessionSweep()
	}
}

// stewardSessionSweep ends steward sessions whose run is no longer stuck
// (finished, cancelled, or moving again) and forgets ended sessions.
func (s *Server) stewardSessionSweep() int {
	if s.terminalMgr == nil {
		return 0
	}
	stewardSessions.Lock()
	list := make(map[string]stewardBinding, len(stewardSessions.byID))
	for id, b := range stewardSessions.byID {
		list[id] = b
	}
	stewardSessions.Unlock()
	closed := 0
	for id, b := range list {
		sess, err := s.terminalMgr.GetSession(id)
		if err != nil || sess == nil || !sess.IsLive() {
			stewardSessions.Lock()
			delete(stewardSessions.byID, id)
			stewardSessions.Unlock()
			continue
		}
		why := s.stewardRunRefusal(b.Tenant, b.Endpoint, b.Run)
		if why == "" {
			continue
		}
		if s.terminalMgr.CloseSession(id, "steward_run_resolved") == nil {
			screenCreds.Forget(id)
			closed++
			s.recordHubAudit(b.Tenant, "SCREEN_SESSION_CLOSED", id, fmt.Sprintf("Closed the steward's screen session on %s: maintenance run %s no longer needs it (%s)", b.Endpoint, b.Run, why))
		}
		stewardSessions.Lock()
		delete(stewardSessions.byID, id)
		stewardSessions.Unlock()
	}
	return closed
}

// handleStewardScreen raises a machine's steward screen setting. POST
// {endpoint_id, mode, max_minutes, ask_first, only_in_window} runs behind
// ownerApproved/resolveStewardScreen: the first call asks the owner (202 with
// the approval id), the repeat with the approval header returns the rule
// token. GET ?approval_id= returns the token of an approved ask.
func (s *Server) handleStewardScreen(w http.ResponseWriter, r *http.Request) {
	if s.responseAuth == nil {
		writeJSONError(w, http.StatusServiceUnavailable, "response authority not available")
		return
	}
	tenantID := s.tenantFromRequest(r)
	if tenantID == "" {
		tenantID = "default"
	}
	id := strings.TrimSpace(r.URL.Query().Get("approval_id"))
	switch r.Method {
	case http.MethodGet:
		if !stewardRaiser(r) {
			writeJSONError(w, http.StatusForbidden, "the owner or Nightshift reads a steward screen rule token")
			return
		}
	case http.MethodPost:
		id = r.Header.Get(approvalHeader)
	default:
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	v, err := s.responseAuth.GetApproval(r.Context(), id, tenantID)
	if err != nil || v == nil || v.StewardRule == "" {
		writeJSONError(w, http.StatusNotFound, "no approved steward screen rule under that approval")
		return
	}
	rule, err := responseauth.ReadStewardRuleToken(v.StewardRule)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if r.Method == http.MethodPost {
		s.audit(r, stewardScreenAudit, rule.EndpointID, "Steward remote screen on "+s.endpointLabels([]string{rule.EndpointID})+" raised with the owner's approval "+id+": "+responseauth.StewardRuleLabel(rule))
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, map[string]interface{}{"rule_token": v.StewardRule, "rule": stewardRuleView(rule, s.endpointLabels([]string{rule.EndpointID}))})
}

func stewardRuleView(r responseauth.StewardScreenRule, host string) map[string]interface{} {
	return map[string]interface{}{"endpoint_id": r.EndpointID, "hostname": host, "mode": r.Mode, "max_seconds": r.MaxSeconds,
		"ask_first": r.AskFirst, "only_in_window": r.OnlyInWindow, "approver_id": r.ApproverID, "approval_id": r.ApprovalID,
		"created_at": time.Unix(r.Created, 0).UTC(), "expires_at": time.Unix(r.Expires, 0).UTC(), "label": responseauth.StewardRuleLabel(r)}
}

// stewardRaiser: who may ask the owner to raise the setting: the owner
// (admin, not an agent and not the steward) or Nightshift's relay.
func stewardRaiser(r *http.Request) bool {
	if isSteward(r) {
		return false
	}
	if r.Header.Get("X-Role") == "approval-relay" {
		return true
	}
	if r.Header.Get("X-Role") != "admin" || r.Header.Get("X-Tenant-ID") != "" {
		return false
	}
	label, _ := agentLabel(r)
	return label == ""
}

type stewardScreenRaise struct {
	EndpointID   string `json:"endpoint_id"`
	Mode         string `json:"mode"`
	MaxMinutes   int64  `json:"max_minutes"`
	AskFirst     *bool  `json:"ask_first"`
	OnlyInWindow *bool  `json:"only_in_window"`
}

// resolveStewardScreen asks the owner to raise a machine's steward screen
// setting. The payload is the screen payload the steward's sessions will
// carry; the authority words the ask from it and StewardRule.
func (s *Server) resolveStewardScreen(w http.ResponseWriter, r *http.Request, body []byte) (*approvalPlan, bool) {
	if !stewardRaiser(r) {
		writeJSONError(w, http.StatusForbidden, "the owner raises the steward screen setting (Nightshift, the console or ominullctl with the admin key, no agent label)")
		return nil, false
	}
	var req stewardScreenRaise
	if !decodeInto(w, body, &req) || !s.endpointInScope(w, r, req.EndpointID) {
		return nil, false
	}
	mode := strings.TrimSpace(req.Mode)
	if mode == "" {
		mode = response.ScreenModeControl
	}
	if mode != response.ScreenModeControl && mode != response.ScreenModeView {
		writeJSONError(w, http.StatusBadRequest, `mode is "control" or "view" (turning it off is PUT mode "off", no tap)`)
		return nil, false
	}
	if req.MaxMinutes == 0 {
		req.MaxMinutes = stewardDefaultSeconds / 60
	}
	if req.MaxMinutes < 5 || req.MaxMinutes*60 > responseauth.StewardScreenMaxSeconds {
		writeJSONError(w, http.StatusBadRequest, fmt.Sprintf("max_minutes is 5 to %d", responseauth.StewardScreenMaxSeconds/60))
		return nil, false
	}
	askFirst := req.AskFirst == nil || *req.AskFirst
	inWindow := req.OnlyInWindow == nil || *req.OnlyInWindow
	if s.hostLocked(req.EndpointID) {
		writeJSONError(w, http.StatusConflict, "this machine is locked on the host (the owner's own infrastructure); the steward never takes its screen without asking")
		return nil, false
	}
	if !s.screenCapable(w, r, req.EndpointID, mode) {
		return nil, false
	}
	payload, err := json.Marshal(response.ScreenSessionPayload{Mode: mode, AskFirst: askFirst})
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return nil, false
	}
	label := s.endpointLabels([]string{req.EndpointID})
	return &approvalPlan{
		Kind: response.ActionKindScreenSession, Action: "Let the steward use the screen",
		Summary: "Nightshift's steward may take the screen on " + label + " without asking, only for a stuck maintenance run",
		Targets: []string{req.EndpointID}, Payload: payload, AskFirst: askFirst,
		StewardRule: &responseauth.StewardScreenAsk{MaxSeconds: req.MaxMinutes * 60, OnlyInWindow: inWindow},
	}, true
}

// stewardScreenPlan applies the steward's limits to a screen request: the
// run must be stuck, the window open when the rule says so, never
// unattended; the length is the rule's. It returns the session length and
// ask-first to use, or false after writing the refusal.
func (s *Server) stewardScreenPlan(w http.ResponseWriter, r *http.Request, req *screenOpenRequest) (time.Duration, bool, bool) {
	tenantID := s.tenantFromRequest(r)
	if tenantID == "" {
		tenantID = "default"
	}
	run := strings.TrimSpace(req.StewardRun)
	if run == "" {
		writeJSONError(w, http.StatusBadRequest, "the steward names the stuck run it takes the screen for (steward_run)")
		return 0, false, false
	}
	if req.Unattended {
		writeJSONError(w, http.StatusBadRequest, "the steward never opens a screen with nobody at the keyboard")
		return 0, false, false
	}
	if why := s.stewardRunRefusal(tenantID, req.EndpointID, run); why != "" {
		writeJSONError(w, http.StatusConflict, why)
		return 0, false, false
	}
	if s.hostLocked(req.EndpointID) {
		writeJSONError(w, http.StatusConflict, "this machine is locked on the host (the owner's own infrastructure); the steward does not take its screen")
		return 0, false, false
	}
	// The token is read here only to hold the window and set the length;
	// the authority checks its signature before it approves anything.
	d := time.Duration(stewardDefaultSeconds) * time.Second
	askFirst := s.screenAskFirst(req.EndpointID)
	if req.RuleToken != "" {
		rule, err := responseauth.ReadStewardRuleToken(req.RuleToken)
		if err != nil || rule.EndpointID != req.EndpointID {
			writeJSONError(w, http.StatusBadRequest, "rule_token is not a steward screen rule for this machine")
			return 0, false, false
		}
		rule = rule.Narrowed(req.Narrow)
		d, askFirst = time.Duration(rule.MaxSeconds)*time.Second, rule.AskFirst
		if rule.OnlyInWindow {
			maintenanceWindowsMu.Lock()
			win, _ := s.windowFor(s.loadMaintenanceWindows(), req.EndpointID)
			maintenanceWindowsMu.Unlock()
			if in, known := win.Contains(time.Now(), s.endpointUTCOffset(req.EndpointID)); !known || !in {
				writeJSONError(w, http.StatusConflict, "the owner allows the steward on this machine's screen only inside its maintenance window ("+win.Param()+"), and it is closed or its clock is unknown; escalate the run instead")
				return 0, false, false
			}
		}
	}
	if req.MaxDurationSeconds > 0 && time.Duration(req.MaxDurationSeconds)*time.Second < d {
		d = time.Duration(req.MaxDurationSeconds) * time.Second
	}
	return d, askFirst, true
}

// recordHubAudit leaves an audit row for something the hub did on its own.
func (s *Server) recordHubAudit(tenantID, action, resource, details string) {
	_ = s.store.RecordAudit(storage.AuditEntry{
		ID: uuid.New().String(), TenantID: tenantID, Username: "hub", Action: action,
		Resource: resource, Details: details, Timestamp: time.Now().UTC(),
	})
}
