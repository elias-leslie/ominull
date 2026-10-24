package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	"ominull/hub/pkg/response"
	"ominull/hub/pkg/responseauth"
	"ominull/hub/pkg/screen"
	"ominull/hub/pkg/storage"
	"ominull/hub/pkg/terminal"

	"github.com/google/uuid"
)

// Remote screen sessions (docs/REMOTE_SCREEN.md). A screen session is a
// terminal session of the screen kind (hub/pkg/screen): the same manager,
// relay, caps, limits and sweeper, its own routes, frame policy, approval
// wording and audit lines. There is no console page: ominullctl opens the
// session and hands the one-use operator token to the native viewer on its
// stdin; the viewer attaches with it in the X-Screen-Token header. No cookie
// is ever set, and an operator upgrade that carries an Origin header (any
// browser page) is refused, so no web page can drive a screen session.

// screenSessionFor loads a session for a screen route: it must exist, be a
// screen session and belong to the caller's tenant.
func (s *Server) screenSessionFor(w http.ResponseWriter, r *http.Request, id string) (*terminal.TerminalSession, bool) {
	if id == "" {
		writeJSONError(w, http.StatusBadRequest, "missing session id")
		return nil, false
	}
	sess, err := s.terminalMgr.GetSession(id)
	if err != nil || !screen.IsScreen(sess.Program) {
		writeJSONError(w, http.StatusNotFound, "screen session not found")
		return nil, false
	}
	tenantID := s.tenantFromRequest(r)
	if tenantID == "" {
		tenantID = "default"
	}
	if sess.TenantID != tenantID {
		writeJSONError(w, http.StatusForbidden, "session belongs to different tenant")
		return nil, false
	}
	return sess, true
}

// screenSummary is a screen session as the screen routes show it.
func screenSummary(sess *terminal.TerminalSession) map[string]interface{} {
	sum := sess.Summary()
	mode, _ := screen.ModeOf(sess.Program)
	sum["mode"] = mode
	sum["kind"] = "screen"
	return sum
}

func screenRoleCanOpen(r *http.Request) bool {
	role := r.Header.Get("X-Role")
	return role == "admin" || role == "operator" || (role == "steward" && isSteward(r))
}

// screenSessionLength is how long a session has run, for the audit.
func screenSessionLength(sess *terminal.TerminalSession, now time.Time) string {
	start := sess.CreatedAt
	if sess.StartedAt != nil {
		start = *sess.StartedAt
	}
	return now.Sub(start).Round(time.Second).String()
}

// handleScreenSessions lists and shows screen sessions (GET), opens one
// with the authority's authorization (POST, behind authorized/resolveScreen) and
// ends one (DELETE ?id=).
func (s *Server) handleScreenSessions(w http.ResponseWriter, r *http.Request) {
	if s.terminalMgr == nil {
		writeJSONError(w, http.StatusServiceUnavailable, "terminal manager not initialized")
		return
	}
	tenantID := s.tenantFromRequest(r)
	if tenantID == "" {
		tenantID = "default"
	}

	switch r.Method {
	case http.MethodGet:
		if r.Header.Get("X-Auth-Method") == "api-key" {
			writeJSONError(w, http.StatusForbidden, "static API keys cannot list or inspect screen sessions")
			return
		}
		role := r.Header.Get("X-Role")
		if role != "admin" && role != "operator" && role != "auditor" {
			writeJSONError(w, http.StatusForbidden, "unauthorized role for screen session inspection")
			return
		}
		if id := r.URL.Query().Get("id"); id != "" {
			sess, ok := s.screenSessionFor(w, r, id)
			if !ok {
				return
			}
			writeJSON(w, http.StatusOK, screenSummary(sess))
			return
		}
		out := []map[string]interface{}{}
		for _, sess := range s.terminalMgr.ListSessions(tenantID) {
			if screen.IsScreen(sess.Program) {
				out = append(out, screenSummary(sess))
			}
		}
		writeJSON(w, http.StatusOK, map[string]interface{}{"sessions": out})

	case http.MethodPost:
		// authorized (resolveScreen) has checked the request, asked the
		// owner and spent the approval; its grant is this session's only
		// authority.
		var req screenOpenRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSONError(w, http.StatusBadRequest, "invalid json: "+err.Error())
			return
		}
		if s.refuseRemoteAccess(w, req.EndpointID) {
			return
		}
		mode, ok := req.mode(w)
		if !ok || !s.screenCapable(w, r, req.EndpointID, mode) {
			return
		}
		operatorID := s.operatorFromRequest(r)
		var grant *response.EndpointGrant
		for _, g := range approvalGrants(r) {
			if g.EndpointID == req.EndpointID && g.ActionKind == response.ActionKindScreenSession {
				grant = g
			}
		}
		if grant == nil {
			writeJSONError(w, http.StatusForbidden, "a screen session was not authorized")
			return
		}
		d := s.terminalDuration(req.MaxDurationSeconds)
		if isSteward(r) && req.ResolvedSeconds > 0 {
			d = time.Duration(req.ResolvedSeconds) * time.Second
		}
		sess, err := screen.CreateSession(s.terminalMgr, tenantID, req.EndpointID, operatorID, mode, grant, d)
		if err != nil {
			writeJSONError(w, http.StatusConflict, "failed to create screen session: "+err.Error())
			return
		}

		// The endpoint receives the offer on its next heartbeat. The agent
		// rebuilds the digested payload from mode (and unattended) and
		// checks it against the grant.
		// operator is not digested: the helper shows it in the consent
		// prompt. ask_first is re-read from the setting resolveScreen just
		// digested; if it changed in between, offer and grant disagree and
		// the agent refuses the session.
		// The helper's consent prompt and banner show it ("controlled by
		// ..."), so an admin-key agent's self-declared label is named there
		// too. The agent strips quotes and keeps at most 64 characters.
		who := operatorID
		if isSteward(r) {
			who = "Nightshift's steward (steward key), for a stuck maintenance run"
		} else if r.Header.Get("X-Auth-Method") == "api-key" {
			who = "an agent (admin key)"
			if label, _ := agentLabel(r); label != "" {
				who = "agent \"" + label + "\" (admin key)"
			}
		}
		offer := map[string]interface{}{"session_id": sess.SessionID, "mode": mode, "connect_token": sess.ConnectToken, "operator": who}
		if req.Unattended {
			offer["unattended"] = true
		}
		askFirst := s.screenAskFirst(req.EndpointID)
		if isSteward(r) && req.ResolvedAskFirst != nil {
			askFirst = *req.ResolvedAskFirst
		}
		if askFirst {
			offer["ask_first"] = true
		}
		payloadJSON, _ := json.Marshal(offer)
		if s.responseStore != nil {
			_, _ = s.responseStore.CreateJob(tenantID, req.EndpointID, response.ActionKindScreenSession, operatorID, grant, string(payloadJSON), "")
		}

		unattended := ""
		if askFirst {
			unattended += ", asks the person at the keyboard first"
		} else {
			unattended += ", without asking the person at the keyboard"
		}
		if req.Unattended {
			unattended += ", may open with nobody at the keyboard"
		}
		s.audit(r, "SCREEN_SESSION_CREATED", sess.SessionID, fmt.Sprintf(
			"Opened a %s screen session on %s for %s under grant %s, up to %s%s",
			mode, req.EndpointID, s.screenCaller(r), grant.GrantID, d.Round(time.Minute), unattended))
		screenCreds.SetControlMinter(sess.SessionID, screenAgentName(r))
		if isSteward(r) {
			bindStewardSession(sess.SessionID, stewardBinding{Tenant: tenantID, Endpoint: req.EndpointID, Run: req.StewardRun})
			s.audit(r, "STEWARD_SCREEN_OPENED", sess.SessionID, fmt.Sprintf("The steward took the screen on %s for maintenance run %s (%s, up to %s)", req.EndpointID, req.StewardRun, mode, d.Round(time.Minute)))
		}
		out := screenSummary(sess)
		// An agent (ominullctl, admin key) gets the operator's one-use token
		// once, here, and hands it to the viewer on stdin; it never reaches a
		// URL. The console gets no token at all: it asks /launch for a
		// one-use launch code instead, so a page never holds a credential
		// that drives the screen.
		if r.Header.Get("X-Auth-Method") == "api-key" || isSteward(r) {
			out["connect_token"] = sess.OperatorToken
		}
		writeJSON(w, http.StatusCreated, out)

	case http.MethodDelete:
		s.closeScreenSession(w, r, r.URL.Query().Get("id"), "operator_closed")

	default:
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

// closeScreenSession ends a screen session for its tenant's operator.
func (s *Server) closeScreenSession(w http.ResponseWriter, r *http.Request, id, reason string) {
	if !screenRoleCanOpen(r) {
		writeJSONError(w, http.StatusForbidden, "insufficient role permissions to close a screen session")
		return
	}
	sess, ok := s.screenSessionFor(w, r, id)
	if !ok {
		return
	}
	if err := s.terminalMgr.CloseSession(id, reason); err != nil {
		writeJSONError(w, http.StatusInternalServerError, "failed to close session: "+err.Error())
		return
	}
	screenCreds.Forget(id)
	mode, _ := screen.ModeOf(sess.Program)
	grantID := ""
	if sess.Grant != nil {
		grantID = sess.Grant.GrantID
	}
	s.audit(r, "SCREEN_SESSION_CLOSED", id, fmt.Sprintf("Closed the %s screen session on %s opened by %s under grant %s after %s (%s)",
		mode, sess.EndpointID, sess.OperatorID, grantID, screenSessionLength(sess, time.Now()), reason))
	writeJSON(w, http.StatusOK, map[string]interface{}{"status": "closed", "closed": true, "session_id": id})
}

// handleScreenSessionClose is POST /api/v1/screen/sessions/close
// {session_id, reason}, for a caller that cannot send DELETE.
func (s *Server) handleScreenSessionClose(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if s.terminalMgr == nil {
		writeJSONError(w, http.StatusServiceUnavailable, "terminal manager not initialized")
		return
	}
	var req struct {
		SessionID string `json:"session_id"`
		Reason    string `json:"reason"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.SessionID == "" {
		writeJSONError(w, http.StatusBadRequest, "missing session_id")
		return
	}
	reason := req.Reason
	if reason == "" || len(reason) > 64 {
		reason = "operator_close"
	}
	s.closeScreenSession(w, r, req.SessionID, reason)
}

// handleScreenSessionAttach mints a fresh one-use operator token for a live
// screen session (a viewer that lost its connection), returned once in the
// body as connect_token, like the terminal's attach rotates its cookie. No
// fresh approval: coming back to a session the owner already approved is not
// a new one.
func (s *Server) handleScreenSessionAttach(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if s.terminalMgr == nil {
		writeJSONError(w, http.StatusServiceUnavailable, "terminal manager not initialized")
		return
	}
	if !screenRoleCanOpen(r) {
		writeJSONError(w, http.StatusForbidden, "insufficient role permissions to attach to a screen session")
		return
	}
	// The console never holds an operator token (a page could leak it); it
	// opens the viewer with a one-use launch code from /launch.
	if r.Header.Get("X-Auth-Method") == "console" {
		writeJSONError(w, http.StatusForbidden, "the console opens the viewer with a launch code (/api/v1/screen/sessions/launch)")
		return
	}
	var req struct {
		SessionID string `json:"session_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.SessionID == "" {
		writeJSONError(w, http.StatusBadRequest, "missing session_id")
		return
	}
	sess, ok := s.screenSessionFor(w, r, req.SessionID)
	if !ok {
		return
	}
	if sess.OperatorID != s.operatorFromRequest(r) {
		writeJSONError(w, http.StatusForbidden, "only the operator who opened this screen session can view it")
		return
	}
	if !sess.IsLive() {
		writeJSONError(w, http.StatusConflict, s.screenNotLive(req.SessionID, "session is no longer live and cannot be attached"))
		return
	}
	token, err := s.terminalMgr.RotateOperatorToken(req.SessionID)
	if err != nil {
		writeJSONError(w, http.StatusConflict, "attach refused: "+err.Error())
		return
	}
	screenCreds.SetControlMinter(req.SessionID, screenAgentName(r))
	s.audit(r, "SCREEN_SESSION_REATTACHED", req.SessionID, fmt.Sprintf("Operator reattached to screen session %s on %s", req.SessionID, sess.EndpointID))
	out := screenSummary(sess)
	out["connect_token"] = token
	writeJSON(w, http.StatusOK, out)
}

// handleScreenWSOperator attaches the native viewer (or ominull-screen ctl).
// Its token is the one-use X-Screen-Token header only (never a URL or a
// cookie). A request with an Origin header comes from a web page, and no web
// page may drive a screen session: refused before the token is looked at (or
// spent). A watch token attaches a watch (view-only) attachment; otherwise
// the token must be the session's control token. Every attach and detach is
// audited with its kind and who.
func (s *Server) handleScreenWSOperator(w http.ResponseWriter, r *http.Request) {
	if s.terminalMgr == nil {
		writeJSONError(w, http.StatusServiceUnavailable, "terminal manager not initialized")
		return
	}
	if _, browser := r.Header["Origin"]; browser {
		writeJSONError(w, http.StatusForbidden, "screen attachment rejected: screen sessions are not opened from web pages")
		return
	}
	sessionID := r.URL.Query().Get("session_id")
	if sessionID == "" {
		writeJSONError(w, http.StatusBadRequest, "missing session_id")
		return
	}
	token := r.Header.Get("X-Screen-Token")
	if token == "" {
		writeJSONError(w, http.StatusUnauthorized, "missing screen token")
		return
	}
	sess, err := s.terminalMgr.GetSession(sessionID)
	if err != nil || !screen.IsScreen(sess.Program) {
		writeJSONError(w, http.StatusUnauthorized, "screen attachment rejected: screen session not found")
		return
	}

	if who, ok := screenCreds.TakeWatchToken(sessionID, token); ok {
		s.auditScreen(r, sess, who, "SCREEN_ATTACHED", "watch attachment by "+who)
		if err := s.terminalMgr.AttachWatcher(w, r, sessionID); err != nil {
			s.auditScreen(r, sess, who, "SCREEN_DETACHED", "watch attachment by "+who+" refused: "+err.Error())
			writeJSONError(w, http.StatusConflict, "screen attachment rejected: "+err.Error())
			return
		}
		s.auditScreen(r, sess, who, "SCREEN_DETACHED", "watch attachment by "+who+" left")
		return
	}

	// Checked here only to word the audit; AttachOperator checks and spends
	// it under the session lock.
	if !sess.ValidateOperatorToken(token) {
		writeJSONError(w, http.StatusUnauthorized, "screen attachment rejected: invalid or expired screen token")
		return
	}
	who := sess.OperatorID
	if agent := screenCreds.ControlAgent(sessionID); agent != "" {
		who = agent
		clear := screen.SetInputAudit(sessionID, func(line string) {
			s.auditScreen(r, sess, who, "SCREEN_AGENT_INPUT", line)
		})
		defer clear()
	}
	s.auditScreen(r, sess, who, "SCREEN_ATTACHED", "control attachment by "+who)
	if err := s.terminalMgr.AttachOperator(w, r, sessionID, token); err != nil {
		s.auditScreen(r, sess, who, "SCREEN_DETACHED", "control attachment by "+who+" refused: "+err.Error())
		writeJSONError(w, http.StatusUnauthorized, "screen attachment rejected: "+err.Error())
		return
	}
	s.auditScreen(r, sess, who, "SCREEN_DETACHED", "control attachment by "+who+" left")
}

// auditScreen records a screen attachment event. The WebSocket routes run
// outside authMiddleware (the token is the credential), so the tenant and
// identity come from the session and the credential, not request headers.
func (s *Server) auditScreen(r *http.Request, sess *terminal.TerminalSession, who, action, details string) {
	mode, _ := screen.ModeOf(sess.Program)
	_ = s.store.RecordAudit(storage.AuditEntry{
		ID:        uuid.New().String(),
		TenantID:  sess.TenantID,
		Username:  who,
		Action:    action,
		Resource:  sess.SessionID,
		Details:   fmt.Sprintf("%s screen session on %s: %s", mode, sess.EndpointID, details),
		IPAddress: clientIP(r),
		Timestamp: time.Now().UTC(),
	})
}

// screenCreds holds launch codes, watch tokens and who minted each session's
// control token. In memory only: a hub restart drops them, and the session
// is then reattached with a fresh /attach or launch code.
var screenCreds = screen.NewCredentials()

// screenAgentName is the agent behind a request made with the hub admin key,
// as the audit names it (its control input is audited), or "" for a person.
// A self-declared X-Ominull-Agent label is named as a claim:
// `admin (agent calling itself "claude-ops", admin key)`.
func screenAgentName(r *http.Request) string {
	if isSteward(r) {
		return "steward (Nightshift's steward, steward key)"
	}
	if r.Header.Get("X-Auth-Method") != "api-key" {
		return ""
	}
	u := r.Header.Get("X-Username")
	if u == "" {
		u = "admin"
	}
	if label, ok := agentLabel(r); ok && label != "" {
		return u + " (agent calling itself \"" + label + "\", admin key)"
	}
	return u + " (agent, admin key)"
}

// screenCaller is who a request is for, as the screen audit names them.
func (s *Server) screenCaller(r *http.Request) string {
	if a := screenAgentName(r); a != "" {
		return a
	}
	return s.operatorFromRequest(r)
}

func screenSessionIDBody(w http.ResponseWriter, r *http.Request) (string, bool) {
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return "", false
	}
	var req struct {
		SessionID string `json:"session_id"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil || req.SessionID == "" {
		writeJSONError(w, http.StatusBadRequest, "missing session_id")
		return "", false
	}
	return req.SessionID, true
}

// handleScreenLaunch is POST /api/v1/screen/sessions/launch {session_id}:
// the console's "open in viewer" button. The console never holds the
// operator token; it gets a one-use, 60-second launch code bound to this
// session and this operator, which it puts in the ominull-screen:// link.
// The viewer redeems it at /api/v1/screen/launch/redeem.
func (s *Server) handleScreenLaunch(w http.ResponseWriter, r *http.Request) {
	if s.terminalMgr == nil {
		writeJSONError(w, http.StatusServiceUnavailable, "terminal manager not initialized")
		return
	}
	id, ok := screenSessionIDBody(w, r)
	if !ok {
		return
	}
	if r.Header.Get("X-Auth-Method") == "api-key" {
		writeJSONError(w, http.StatusForbidden, "launch codes are for the console; an agent uses /api/v1/screen/sessions/attach")
		return
	}
	if !screenRoleCanOpen(r) {
		writeJSONError(w, http.StatusForbidden, "insufficient role permissions to launch a screen viewer")
		return
	}
	sess, ok := s.screenSessionFor(w, r, id)
	if !ok {
		return
	}
	operator := s.operatorFromRequest(r)
	if sess.OperatorID != operator {
		writeJSONError(w, http.StatusForbidden, "only the operator who opened this screen session can control it; ask for a watch link")
		return
	}
	if !sess.IsLive() {
		writeJSONError(w, http.StatusConflict, s.screenNotLive(id, "session is no longer live"))
		return
	}
	code := screenCreds.IssueLaunchCode(id, operator, screen.AttachControl)
	s.audit(r, "SCREEN_LAUNCH_ISSUED", id, fmt.Sprintf("Issued a control launch code for screen session %s on %s to %s", id, sess.EndpointID, operator))
	writeJSON(w, http.StatusOK, map[string]interface{}{"code": code, "expires_in": int(screen.LaunchCodeTTL / time.Second)})
}

// handleScreenWatch is POST /api/v1/screen/sessions/watch {session_id}: a
// view-only attachment beside the control one (up to screen.MaxWatchers).
// The hub admin key (an agent's owner watching along via ominullctl) gets a
// one-use watch token in the body; a console caller gets a launch code for a
// watch attachment, like /launch. The session's opener or an admin may.
func (s *Server) handleScreenWatch(w http.ResponseWriter, r *http.Request) {
	if s.terminalMgr == nil {
		writeJSONError(w, http.StatusServiceUnavailable, "terminal manager not initialized")
		return
	}
	id, ok := screenSessionIDBody(w, r)
	if !ok {
		return
	}
	if !screenRoleCanOpen(r) {
		writeJSONError(w, http.StatusForbidden, "insufficient role permissions to watch a screen session")
		return
	}
	sess, ok := s.screenSessionFor(w, r, id)
	if !ok {
		return
	}
	operator := s.operatorFromRequest(r)
	if sess.OperatorID != operator && r.Header.Get("X-Role") != "admin" {
		writeJSONError(w, http.StatusForbidden, "only the session's operator or an admin can watch it")
		return
	}
	if !sess.IsLive() {
		writeJSONError(w, http.StatusConflict, s.screenNotLive(id, "session is no longer live"))
		return
	}
	if n := s.terminalMgr.WatcherCount(id); n >= screen.MaxWatchers {
		writeJSONError(w, http.StatusConflict, fmt.Sprintf("this session already has %d watchers", n))
		return
	}
	who := s.screenCaller(r)
	if r.Header.Get("X-Auth-Method") == "api-key" {
		token := screenCreds.IssueWatchToken(id, who)
		s.audit(r, "SCREEN_WATCH_ISSUED", id, fmt.Sprintf("Issued a watch token for screen session %s on %s to %s", id, sess.EndpointID, who))
		writeJSON(w, http.StatusOK, s.screenTokenBody(sess, token, response.ScreenModeView, screen.WatchTokenTTL))
		return
	}
	code := screenCreds.IssueLaunchCode(id, who, screen.AttachWatch)
	s.audit(r, "SCREEN_LAUNCH_ISSUED", id, fmt.Sprintf("Issued a watch launch code for screen session %s on %s to %s", id, sess.EndpointID, who))
	writeJSON(w, http.StatusOK, map[string]interface{}{"code": code, "expires_in": int(screen.LaunchCodeTTL / time.Second)})
}

// screenTokenBody is what a viewer needs to attach: {token, mode, host,
// expires_at}. expires_at is when the token stops working if unused.
func (s *Server) screenTokenBody(sess *terminal.TerminalSession, token, mode string, ttl time.Duration) map[string]interface{} {
	exp := sess.ExpiresAt
	if ttl > 0 {
		if t := time.Now().UTC().Add(ttl); t.Before(exp) {
			exp = t
		}
	}
	return map[string]interface{}{
		"session_id": sess.SessionID,
		"token":      token,
		"mode":       mode,
		"host":       s.endpointLabels([]string{sess.EndpointID}),
		"expires_at": exp.UTC().Format(time.RFC3339),
	}
}

// handleScreenLaunchRedeem is POST /api/v1/screen/launch/redeem
// {session_id, code}: the native viewer trades a launch code for an
// attachment token. It carries no other credential (the viewer has none), so
// it is rate limited per source address (and loosely per session), every
// code is one use, and every outcome is audited.
func (s *Server) handleScreenLaunchRedeem(w http.ResponseWriter, r *http.Request) {
	if s.terminalMgr == nil {
		writeJSONError(w, http.StatusServiceUnavailable, "terminal manager not initialized")
		return
	}
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var req struct {
		SessionID string `json:"session_id"`
		Code      string `json:"code"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil || req.SessionID == "" || req.Code == "" {
		writeJSONError(w, http.StatusBadRequest, "missing session_id or code")
		return
	}
	fail := func(status int, why string) {
		// The redeem carries no credential, so the tenant is the named
		// session's, when there is one.
		tenantID := ""
		if sess, err := s.terminalMgr.GetSession(req.SessionID); err == nil && screen.IsScreen(sess.Program) {
			tenantID = sess.TenantID
		}
		_ = s.store.RecordAudit(storage.AuditEntry{
			ID: uuid.New().String(), TenantID: tenantID, Username: "unknown", Action: "SCREEN_LAUNCH_REDEEM_FAILED",
			Resource: req.SessionID, Details: "Launch code redeem refused: " + why,
			IPAddress: clientIP(r), Timestamp: time.Now().UTC(),
		})
		writeJSONError(w, status, why)
	}
	operator, kind, err := screenCreds.RedeemLaunchCode(req.SessionID, req.Code, clientIP(r))
	if errors.Is(err, screen.ErrRedeemLimit) {
		fail(http.StatusTooManyRequests, err.Error())
		return
	}
	if err != nil {
		fail(http.StatusUnauthorized, err.Error())
		return
	}
	sess, err := s.terminalMgr.GetSession(req.SessionID)
	if err != nil || !screen.IsScreen(sess.Program) || !sess.IsLive() {
		fail(http.StatusGone, "the screen session has ended")
		return
	}
	var body map[string]interface{}
	switch kind {
	case screen.AttachControl:
		if sess.OperatorID != operator {
			fail(http.StatusForbidden, "the launch code's operator no longer owns this session")
			return
		}
		token, err := s.terminalMgr.RotateOperatorToken(req.SessionID)
		if err != nil {
			fail(http.StatusGone, "attach refused: "+err.Error())
			return
		}
		screenCreds.SetControlMinter(req.SessionID, "")
		mode, _ := screen.ModeOf(sess.Program)
		body = s.screenTokenBody(sess, token, mode, 0)
	case screen.AttachWatch:
		body = s.screenTokenBody(sess, screenCreds.IssueWatchToken(req.SessionID, operator), response.ScreenModeView, screen.WatchTokenTTL)
	default:
		fail(http.StatusUnauthorized, screen.ErrCodeInvalid.Error())
		return
	}
	s.auditScreen(r, sess, operator, "SCREEN_LAUNCH_REDEEMED", kind+" launch code redeemed by the viewer")
	writeJSON(w, http.StatusOK, body)
}

// handleScreenWSAgent attaches the endpoint agent:
// ?session_id=&endpoint_id=&token= (the agent's own connect token).
func (s *Server) handleScreenWSAgent(w http.ResponseWriter, r *http.Request) {
	if s.terminalMgr == nil {
		writeJSONError(w, http.StatusServiceUnavailable, "terminal manager not initialized")
		return
	}
	q := r.URL.Query()
	sessionID := q.Get("session_id")
	if sessionID == "" {
		writeJSONError(w, http.StatusBadRequest, "missing session_id")
		return
	}
	endpointID := q.Get("endpoint_id")
	if endpointID == "" {
		endpointID = strings.TrimSpace(r.Header.Get("X-Device-Endpoint-ID"))
	}
	if endpointID == "" {
		endpointID = strings.TrimSpace(r.Header.Get("X-Client-CN"))
	}
	if endpointID == "" {
		writeJSONError(w, http.StatusBadRequest, "missing endpoint_id")
		return
	}
	token := q.Get("token")
	if token == "" {
		token = r.Header.Get("X-Terminal-Token")
	}
	if token == "" {
		writeJSONError(w, http.StatusUnauthorized, "missing screen token")
		return
	}
	if sess, err := s.terminalMgr.GetSession(sessionID); err != nil || !screen.IsScreen(sess.Program) {
		writeJSONError(w, http.StatusUnauthorized, "screen attachment rejected: screen session not found")
		return
	}
	if err := s.terminalMgr.AttachAgent(w, r, sessionID, endpointID, token); err != nil {
		writeJSONError(w, http.StatusUnauthorized, "screen attachment rejected: "+err.Error())
	}
}

// screenOpenRequest is the body of POST /api/v1/screen/sessions.
type screenOpenRequest struct {
	EndpointID         string `json:"endpoint_id"`
	Mode               string `json:"mode"`
	MaxDurationSeconds int    `json:"max_duration_seconds"`
	// Unattended asks for a session that may open with nobody at the
	// keyboard to allow it (a machine that asks the person first declines
	// otherwise). It is audited and digested.
	Unattended bool `json:"unattended"`
	// The steward's request for a stuck run (steward.go): the run.
	StewardRun string `json:"steward_run,omitempty"`
	// Set by resolveScreen in the body it hands on, never by the caller:
	// the steward session's length and ask-first as signed.
	ResolvedSeconds  int64 `json:"resolved_seconds,omitempty"`
	ResolvedAskFirst *bool `json:"resolved_ask_first,omitempty"`
}

func (q screenOpenRequest) mode(w http.ResponseWriter) (string, bool) {
	m := strings.TrimSpace(q.Mode)
	if m == "" {
		m = response.ScreenModeControl
	}
	if !screen.ValidMode(m) {
		writeJSONError(w, http.StatusBadRequest, `mode must be "control" or "view"`)
		return "", false
	}
	return m, true
}

// screenCapable checks the endpoint can take a screen session in mode: it
// must report the screen capability (unlike the terminal there is no
// fallback for agents that report nothing) and a pinned response key, and
// for control, remote input.
func (s *Server) screenCapable(w http.ResponseWriter, r *http.Request, endpointID, mode string) bool {
	if strings.TrimSpace(endpointID) == "" {
		writeJSONError(w, http.StatusBadRequest, "missing endpoint_id")
		return false
	}
	ep, err := s.store.GetEndpoint(endpointID)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return false
	}
	if ep == nil {
		writeJSONError(w, http.StatusNotFound, "no such endpoint")
		return false
	}
	if ok, why := parseResponseCapabilities(ep.ResponseCapabilities).screenAvailable(mode == response.ScreenModeControl); !ok {
		writeJSONError(w, http.StatusConflict, why)
		return false
	}
	if why := s.screenTrustRefusal(r.Context(), ep); why != "" {
		writeJSONError(w, http.StatusConflict, why)
		return false
	}
	return true
}

// screenTrustRefusal says, before the owner is asked, why the endpoint's
// agent would drop a screen grant without a word: its signed capability
// manifest lacks screen, it has not taken the manifest that adds it yet, or
// its local ceiling forbids it. "" when nothing known stands in the way.
func (s *Server) screenTrustRefusal(ctx context.Context, ep *storage.Endpoint) string {
	m := s.endpointManifest(ctx, endpointTenant(ep), ep.ID, "", false)
	if m == nil {
		return ""
	}
	if !slices.Contains(m.Caps, response.CapScreen) {
		return fmt.Sprintf("this endpoint's capability profile (%s) does not include the remote screen; change what the host accepts first", m.Profile)
	}
	s.trust.mu.Lock()
	s.trust.init()
	seen, ok := s.trust.reports[ep.ID]
	s.trust.mu.Unlock()
	if !ok {
		return ""
	}
	if seen.report.ManifestSeq < m.Seq {
		return fmt.Sprintf("this endpoint has not taken the capability manifest that allows the remote screen yet (it holds %d, current is %d); it picks it up at its next check-in, so try again in a minute", seen.report.ManifestSeq, m.Seq)
	}
	switch seen.report.Ceiling {
	case "", "respond", "engagement":
	default:
		return fmt.Sprintf("this endpoint's local capability ceiling (%s), set on the host, does not allow the remote screen", seen.report.Ceiling)
	}
	return ""
}

// resolveScreen describes a screen request for the authority. The
// digested payload is exactly what the agent rebuilds and checks:
// {"mode":"control"}, {"mode":"view"}, plus "unattended":true when asked
// and then "ask_first":true when the endpoint's screen.ask_first is on (key
// order mode, unattended, ask_first).
func (s *Server) resolveScreen(w http.ResponseWriter, r *http.Request, body []byte) (*actionPlan, bool) {
	if !screenRoleCanOpen(r) {
		writeJSONError(w, http.StatusForbidden, "insufficient role permissions to open a screen session")
		return nil, false
	}
	if s.terminalMgr == nil {
		writeJSONError(w, http.StatusServiceUnavailable, "terminal manager not initialized")
		return nil, false
	}
	var req screenOpenRequest
	if !decodeInto(w, body, &req) || !s.endpointInScope(w, r, req.EndpointID) || s.refuseRemoteAccess(w, req.EndpointID) {
		return nil, false
	}
	mode, ok := req.mode(w)
	if !ok || !s.screenCapable(w, r, req.EndpointID, mode) {
		return nil, false
	}
	if !isSteward(r) && req.StewardRun != "" {
		writeJSONError(w, http.StatusBadRequest, "steward_run is the steward's")
		return nil, false
	}
	req.ResolvedSeconds, req.ResolvedAskFirst = 0, nil
	d := s.terminalDuration(req.MaxDurationSeconds)
	askFirst := s.screenAskFirst(req.EndpointID)
	var handOn []byte
	if isSteward(r) {
		sd, sa, ok := s.stewardScreenPlan(w, r, &req)
		if !ok {
			return nil, false
		}
		d, askFirst = sd, sa
		req.ResolvedSeconds, req.ResolvedAskFirst = int64(d/time.Second), &askFirst
		handOn, _ = json.Marshal(req)
	}
	payload, err := json.Marshal(response.ScreenSessionPayload{Mode: mode, Unattended: req.Unattended, AskFirst: askFirst})
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return nil, false
	}
	label, operator, span := s.endpointLabels([]string{req.EndpointID}), s.operatorFromRequest(r), humanDuration(d)
	action, summary := "Control screen", "See and control the screen on "+label+", up to "+span+", for "+operator
	if mode == response.ScreenModeView {
		action, summary = "Watch screen", "Watch the screen on "+label+" (no control), up to "+span+", for "+operator
	}
	if isSteward(r) {
		summary = "Nightshift's steward (steward key) will see and control the screen on " + label + ", up to " + span
		if mode == response.ScreenModeView {
			summary = "Nightshift's steward (steward key) will see the screen on " + label + ", up to " + span
		}
		summary += "; to unstick maintenance run " + req.StewardRun
	} else if r.Header.Get("X-Auth-Method") == "api-key" {
		// The authority words it the same way from the requester.
		agent, _ := agentLabel(r)
		claim := responseauth.AgentClaim(agent)
		who := strings.ToUpper(claim[:1]) + claim[1:] + " (admin key)"
		summary = who + " will see and control the screen on " + label + ", up to " + span
		if mode == response.ScreenModeView {
			summary = who + " will see the screen on " + label + ", up to " + span
		}
	}
	if askFirst {
		summary += "; the person at the keyboard is asked to allow it first"
	} else {
		summary += "; it opens without asking the person at the keyboard"
	}
	if req.Unattended {
		summary += "; if nobody is signed in to allow it, it opens anyway with nobody at the keyboard"
	}
	return &actionPlan{
		Kind: response.ActionKindScreenSession, Action: action, Summary: summary,
		Targets: []string{req.EndpointID}, Payload: payload, SessionSeconds: int64(d / time.Second),
		AskFirst: askFirst, Body: handOn,
		StewardRun: req.StewardRun,
	}, true
}

// screenNotLive adds why the session ended, so a client holding a key that
// cannot inspect sessions still learns the hub's reason.
func (s *Server) screenNotLive(sessionID, msg string) string {
	_, state, reason, _, ok := s.terminalMgr.SessionEnd(sessionID)
	switch {
	case !ok:
		return msg
	case reason != "":
		return msg + " (ended: " + reason + ")"
	case state != "":
		return msg + " (" + string(state) + ")"
	}
	return msg
}
