package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"ominull/hub/pkg/response"
	"ominull/hub/pkg/screen"
	"ominull/hub/pkg/terminal"
)

// handleTerminalSessions handles creating, listing, and showing terminal sessions.
func (s *Server) handleTerminalSessions(w http.ResponseWriter, r *http.Request) {
	tenantID := s.tenantFromRequest(r)
	if tenantID == "" {
		tenantID = "default"
	}

	if s.terminalMgr == nil {
		writeJSONError(w, http.StatusServiceUnavailable, "terminal manager not initialized")
		return
	}

	if r.Method == http.MethodGet {
		if r.Header.Get("X-Auth-Method") == "api-key" {
			writeJSONError(w, http.StatusForbidden, "static API keys cannot list or inspect terminal sessions")
			return
		}
		role := r.Header.Get("X-Role")
		if role != "admin" && role != "operator" && role != "auditor" {
			writeJSONError(w, http.StatusForbidden, "unauthorized role for terminal session inspection")
			return
		}

		id := r.URL.Query().Get("id")
		if id != "" {
			sess, err := s.terminalMgr.GetSession(id)
			if err != nil || screen.IsScreen(sess.Program) {
				writeJSONError(w, http.StatusNotFound, "session not found")
				return
			}
			if sess.TenantID != tenantID {
				writeJSONError(w, http.StatusForbidden, "session belongs to different tenant")
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(sess.Summary())
			return
		}

		sessions := s.terminalMgr.ListSessions(tenantID)
		var summaries []map[string]interface{}
		for _, sess := range sessions {
			if screen.IsScreen(sess.Program) {
				continue // screen sessions are listed by /api/v1/screen/sessions
			}
			summaries = append(summaries, sess.Summary())
		}
		if summaries == nil {
			summaries = []map[string]interface{}{}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"sessions": summaries,
		})
		return
	}

	if r.Method == http.MethodPost {
		// ownerApproved (resolveTerminal) has already checked the request,
		// asked the owner and spent the approval; the grant it produced is
		// the only authority this session runs under.
		var req struct {
			EndpointID         string `json:"endpoint_id"`
			Program            string `json:"program"`
			MaxDurationSeconds int    `json:"max_duration_seconds"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSONError(w, http.StatusBadRequest, "invalid json: "+err.Error())
			return
		}
		program, _, ok := s.terminalProgram(w, req.EndpointID, req.Program)
		if !ok {
			return
		}
		req.Program = program
		operatorID := s.operatorFromRequest(r)
		var grant *response.EndpointGrant
		for _, g := range approvalGrants(r) {
			if g.EndpointID == req.EndpointID && g.ActionKind == response.ActionKindTerminalSession {
				grant = g
			}
		}
		if grant == nil {
			writeJSONError(w, http.StatusForbidden, "a terminal session needs an owner approval")
			return
		}

		session, err := s.terminalMgr.CreateSessionFor(tenantID, req.EndpointID, operatorID, req.Program, grant, s.terminalDuration(req.MaxDurationSeconds))
		if err != nil {
			writeJSONError(w, http.StatusConflict, "failed to create terminal session: "+err.Error())
			return
		}

		// Also create a durable response job so the endpoint receives the offer in next heartbeat
		payloadJSON := fmt.Sprintf(`{"session_id":%q,"program":%q,"connect_token":%q}`, session.SessionID, session.Program, session.ConnectToken)
		if s.responseStore != nil {
			_, _ = s.responseStore.CreateJob(tenantID, req.EndpointID, response.ActionKindTerminalSession, operatorID, grant, payloadJSON, "")
		}

		// Set one-use HttpOnly attach cookie for the operator browser on this origin
		http.SetCookie(w, &http.Cookie{
			Name:     terminalCookieName(session.SessionID),
			Value:    session.OperatorToken,
			Path:     "/api/v1/terminal/ws/",
			HttpOnly: true,
			Secure:   true,
			SameSite: http.SameSiteStrictMode,
			MaxAge:   300,
		})

		s.audit(r, "TERMINAL_SESSION_CREATED", session.SessionID, fmt.Sprintf("Created shell session for %s with program %s under grant %s", req.EndpointID, req.Program, grant.GrantID))

		out := session.Summary()
		// A console browser gets the token only as the HttpOnly cookie above.
		// A non-browser caller (an agent with the admin key, after the owner
		// approved) has no cookie jar on that path, so it gets the token
		// once in the body and presents it as X-Terminal-Token.
		if r.Header.Get("X-Auth-Method") == "api-key" {
			out["connect_token"] = session.OperatorToken
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(out)
		return
	}

	if r.Method == http.MethodDelete {
		if r.Header.Get("X-Auth-Method") == "api-key" {
			writeJSONError(w, http.StatusForbidden, "static API keys cannot close terminal sessions")
			return
		}
		role := r.Header.Get("X-Role")
		if role != "admin" && role != "operator" {
			writeJSONError(w, http.StatusForbidden, "insufficient role permissions to close terminal session")
			return
		}

		id := r.URL.Query().Get("id")
		if id == "" {
			writeJSONError(w, http.StatusBadRequest, "missing session id")
			return
		}

		sess, err := s.terminalMgr.GetSession(id)
		if err != nil {
			writeJSONError(w, http.StatusNotFound, "session not found")
			return
		}
		if sess.TenantID != tenantID {
			writeJSONError(w, http.StatusForbidden, "session belongs to different tenant")
			return
		}

		if err := s.terminalMgr.CloseSession(id, "operator_closed"); err != nil {
			writeJSONError(w, http.StatusInternalServerError, "failed to close session: "+err.Error())
			return
		}

		s.audit(r, "TERMINAL_SESSION_CLOSED", id, fmt.Sprintf("Operator closed terminal session %s", id))

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "closed", "session_id": id})
		return
	}

	writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
}

// handleTerminalWSOperator handles WebSocket connections from the console operator.
func (s *Server) handleTerminalWSOperator(w http.ResponseWriter, r *http.Request) {
	if s.terminalMgr == nil {
		writeJSONError(w, http.StatusServiceUnavailable, "terminal manager not initialized")
		return
	}

	sessionID := r.URL.Query().Get("session_id")
	if sessionID == "" {
		writeJSONError(w, http.StatusBadRequest, "missing session_id")
		return
	}

	token := r.URL.Query().Get("token")
	if token == "" {
		token = r.Header.Get("X-Terminal-Token")
	}
	if token == "" {
		if cookie, err := r.Cookie(terminalCookieName(sessionID)); err == nil {
			token = cookie.Value
		} else if cookie, err := r.Cookie("ominull_terminal_token"); err == nil {
			token = cookie.Value
		}
	}

	if token == "" {
		writeJSONError(w, http.StatusUnauthorized, "missing terminal token")
		return
	}

	if s.screenSessionID(sessionID) {
		writeJSONError(w, http.StatusUnauthorized, "terminal attachment rejected: that is a screen session")
		return
	}
	if err := s.terminalMgr.AttachOperator(w, r, sessionID, token); err != nil {
		writeJSONError(w, http.StatusUnauthorized, "terminal attachment rejected: "+err.Error())
		return
	}
}

// handleTerminalWSAgent handles WebSocket connections from the remote endpoint agent.
func (s *Server) handleTerminalWSAgent(w http.ResponseWriter, r *http.Request) {
	if s.terminalMgr == nil {
		writeJSONError(w, http.StatusServiceUnavailable, "terminal manager not initialized")
		return
	}

	sessionID := r.URL.Query().Get("session_id")
	if sessionID == "" {
		writeJSONError(w, http.StatusBadRequest, "missing session_id")
		return
	}

	endpointID := r.URL.Query().Get("endpoint_id")
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

	token := r.URL.Query().Get("token")
	if token == "" {
		token = r.Header.Get("X-Terminal-Token")
	}
	if token == "" {
		writeJSONError(w, http.StatusUnauthorized, "missing terminal token")
		return
	}

	if s.screenSessionID(sessionID) {
		writeJSONError(w, http.StatusUnauthorized, "terminal attachment rejected: that is a screen session")
		return
	}
	if err := s.terminalMgr.AttachAgent(w, r, sessionID, endpointID, token); err != nil {
		writeJSONError(w, http.StatusUnauthorized, "terminal attachment rejected: "+err.Error())
		return
	}
}

// handleTerminalSessionClose handles closing a terminal session.
func (s *Server) handleTerminalSessionClose(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	if s.terminalMgr == nil {
		writeJSONError(w, http.StatusServiceUnavailable, "terminal manager not initialized")
		return
	}

	if r.Header.Get("X-Auth-Method") == "api-key" {
		writeJSONError(w, http.StatusForbidden, "static API keys cannot close terminal sessions")
		return
	}

	tenantID := s.tenantFromRequest(r)
	if tenantID == "" {
		tenantID = "default"
	}

	role := r.Header.Get("X-Role")
	if role != "admin" && role != "operator" {
		writeJSONError(w, http.StatusForbidden, "insufficient role permissions to close terminal session")
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

	sess, err := s.terminalMgr.GetSession(req.SessionID)
	if err != nil {
		writeJSONError(w, http.StatusNotFound, "session not found")
		return
	}
	if sess.TenantID != tenantID {
		writeJSONError(w, http.StatusForbidden, "session belongs to different tenant")
		return
	}

	reason := req.Reason
	if reason == "" {
		reason = "operator_close"
	}

	if err := s.terminalMgr.CloseSession(req.SessionID, reason); err != nil {
		writeJSONError(w, http.StatusInternalServerError, "close failed: "+err.Error())
		return
	}

	s.audit(r, "TERMINAL_SESSION_CLOSED", req.SessionID, fmt.Sprintf("Closed terminal session (%s)", reason))

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{"closed": true, "session_id": req.SessionID})
}

// handleTerminalFrames inspects recorded frames or rejects external frame injection.
func (s *Server) handleTerminalFrames(w http.ResponseWriter, r *http.Request) {
	if s.terminalMgr == nil {
		writeJSONError(w, http.StatusServiceUnavailable, "terminal manager not initialized")
		return
	}

	if r.Method == http.MethodGet {
		if r.Header.Get("X-Auth-Method") == "api-key" {
			writeJSONError(w, http.StatusForbidden, "static API keys cannot inspect terminal frames")
			return
		}

		role := r.Header.Get("X-Role")
		if role != "admin" && role != "operator" && role != "auditor" {
			writeJSONError(w, http.StatusForbidden, "unauthorized role for terminal frame inspection")
			return
		}

		tenantID := s.tenantFromRequest(r)
		if tenantID == "" {
			tenantID = "default"
		}

		sessionID := r.URL.Query().Get("session_id")
		if sessionID == "" {
			sessionID = r.URL.Query().Get("id")
		}
		if sessionID == "" {
			writeJSONError(w, http.StatusBadRequest, "missing session_id")
			return
		}

		frames, meta, err := s.terminalMgr.GetSessionRecording(tenantID, sessionID)
		if err != nil {
			if strings.Contains(err.Error(), "tenant mismatch") {
				writeJSONError(w, http.StatusForbidden, "session belongs to different tenant")
				return
			}
			if strings.Contains(err.Error(), "not found") {
				writeJSONError(w, http.StatusNotFound, "session not found")
				return
			}
			writeJSONError(w, http.StatusInternalServerError, "failed to read recording: "+err.Error())
			return
		}

		if frames == nil {
			frames = []terminal.TerminalFrame{}
		}
		// ?tail_bytes=N: only the newest stdout frames covering the last N
		// bytes - what a reattaching viewer needs to repaint, instead of the
		// whole recording on every phone wake-up.
		if n, err := strconv.Atoi(r.URL.Query().Get("tail_bytes")); err == nil && n > 0 {
			frames = tailStdout(frames, n)
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"metadata": meta,
			"frames":   frames,
		})
		return
	}

	if r.Method == http.MethodPost {
		writeJSONError(w, http.StatusForbidden, "external frame injection rejected: frames must stream over authenticated websocket relay")
		return
	}

	writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
}

// handleTerminalSessionAttach re-mints the operator connect cookie for a live
// session and hands back its refreshed summary, so the console can open a new
// WebSocket against a session it has detached from.
//
// It deliberately does not ask for a fresh ActionProof. The V2 proof on session
// creation authorises *spawning* a root shell on an endpoint; coming back to a
// shell this operator already spawned, inside the same response session, is not
// a second privileged action, and demanding a TOTP code to look at output you
// have already been shown teaches people to keep a shell attached rather than
// detach it. The response session is still required - the route is behind
// responseGate and authMiddleware, and a lapsed unlock fails here exactly as it
// does everywhere else.
func (s *Server) handleTerminalSessionAttach(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if s.terminalMgr == nil {
		writeJSONError(w, http.StatusServiceUnavailable, "terminal manager not initialized")
		return
	}
	if r.Header.Get("X-Auth-Method") == "api-key" {
		writeJSONError(w, http.StatusForbidden, "static API keys cannot attach to terminal sessions")
		return
	}
	role := r.Header.Get("X-Role")
	if role != "admin" && role != "operator" {
		writeJSONError(w, http.StatusForbidden, "insufficient role permissions to attach to a terminal session")
		return
	}

	tenantID := s.tenantFromRequest(r)
	if tenantID == "" {
		tenantID = "default"
	}

	var req struct {
		SessionID string `json:"session_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.SessionID == "" {
		writeJSONError(w, http.StatusBadRequest, "missing session_id")
		return
	}

	sess, err := s.terminalMgr.GetSession(req.SessionID)
	if err != nil {
		writeJSONError(w, http.StatusNotFound, "session not found")
		return
	}
	if sess.TenantID != tenantID {
		writeJSONError(w, http.StatusForbidden, "session belongs to different tenant")
		return
	}
	// The owner approved a shell for one person. Another operator in the same
	// tenant does not inherit it by reattaching.
	if sess.OperatorID != s.operatorFromRequest(r) {
		writeJSONError(w, http.StatusForbidden, "only the operator who opened this terminal can reattach to it")
		return
	}
	if screen.IsScreen(sess.Program) {
		writeJSONError(w, http.StatusNotFound, "session not found")
		return
	}
	if !sess.IsLive() {
		writeJSONError(w, http.StatusConflict, "session is no longer live and cannot be attached")
		return
	}

	token, err := s.terminalMgr.RotateOperatorToken(req.SessionID)
	if err != nil {
		writeJSONError(w, http.StatusConflict, "attach refused: "+err.Error())
		return
	}

	// The token never travels in a URL or a response body: it is an HttpOnly,
	// Secure, SameSite=Strict cookie scoped to the WebSocket path, which the
	// browser then attaches to the upgrade request by itself. MaxAge is short
	// because it is consumed immediately - the previous 300s window was the
	// only thing making it look like a long-lived credential.
	http.SetCookie(w, &http.Cookie{
		Name:     terminalCookieName(req.SessionID),
		Value:    token,
		Path:     "/api/v1/terminal/ws/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   120,
	})

	s.audit(r, "TERMINAL_SESSION_REATTACHED", req.SessionID,
		fmt.Sprintf("Operator reattached to terminal session %s on %s", req.SessionID, sess.EndpointID))

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(sess.Summary())
}

// handleTerminalSessionDetach drops the operator side of a live session and
// leaves the remote process tree running. The console normally detaches by
// closing its WebSocket; this exists for a caller that has none - a page that
// was closed, or an operator releasing a session from the Assets row.
func (s *Server) handleTerminalSessionDetach(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if s.terminalMgr == nil {
		writeJSONError(w, http.StatusServiceUnavailable, "terminal manager not initialized")
		return
	}
	if r.Header.Get("X-Auth-Method") == "api-key" {
		writeJSONError(w, http.StatusForbidden, "static API keys cannot detach terminal sessions")
		return
	}
	role := r.Header.Get("X-Role")
	if role != "admin" && role != "operator" {
		writeJSONError(w, http.StatusForbidden, "insufficient role permissions to detach a terminal session")
		return
	}

	tenantID := s.tenantFromRequest(r)
	if tenantID == "" {
		tenantID = "default"
	}

	var req struct {
		SessionID string `json:"session_id"`
		Reason    string `json:"reason"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.SessionID == "" {
		writeJSONError(w, http.StatusBadRequest, "missing session_id")
		return
	}

	sess, err := s.terminalMgr.GetSession(req.SessionID)
	if err != nil {
		writeJSONError(w, http.StatusNotFound, "session not found")
		return
	}
	if sess.TenantID != tenantID {
		writeJSONError(w, http.StatusForbidden, "session belongs to different tenant")
		return
	}

	if err := s.terminalMgr.DetachSession(req.SessionID, req.Reason); err != nil {
		writeJSONError(w, http.StatusConflict, "detach refused: "+err.Error())
		return
	}

	s.audit(r, "TERMINAL_SESSION_DETACHED", req.SessionID,
		fmt.Sprintf("Operator detached from terminal session %s on %s; remote process tree left running", req.SessionID, sess.EndpointID))

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(sess.Summary())
}

// terminalProgram picks and checks the program for a session. The hub goes by
// what the endpoint reports it can run (response capabilities), never by its
// OS name: Linux forkpty, Windows ConPTY and a later macOS backend all sit
// behind the same protocol. An agent that reports nothing (older releases)
// keeps the old behaviour: the caller's program, /bin/bash by default, and the
// agent's own allowlist decides.
func (s *Server) terminalProgram(w http.ResponseWriter, endpointID, program string) (string, []string, bool) {
	if strings.TrimSpace(endpointID) == "" {
		writeJSONError(w, http.StatusBadRequest, "missing endpoint_id")
		return "", nil, false
	}
	if screen.IsScreen(program) {
		// That prefix selects the screen session kind (no recording).
		writeJSONError(w, http.StatusBadRequest, "not a terminal program")
		return "", nil, false
	}
	ep, err := s.store.GetEndpoint(endpointID)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return "", nil, false
	}
	if ep == nil {
		writeJSONError(w, http.StatusNotFound, "no such endpoint")
		return "", nil, false
	}
	caps := parseResponseCapabilities(ep.ResponseCapabilities)
	if caps.reported {
		if caps.NoResponseKey {
			writeJSONError(w, http.StatusConflict, "this endpoint has no tenant response key pinned, so it drops every signed grant and a terminal would never open; pin the key on the endpoint first")
			return "", nil, false
		}
		if len(caps.TerminalPrograms) == 0 {
			writeJSONError(w, http.StatusConflict, "this endpoint reports no terminal capability")
			return "", nil, false
		}
		if program == "" {
			return caps.TerminalPrograms[0], caps.TerminalPrograms, true
		}
		for _, p := range caps.TerminalPrograms {
			if p == program {
				return program, caps.TerminalPrograms, true
			}
		}
		writeJSONError(w, http.StatusBadRequest, "program not offered by this endpoint; it offers: "+strings.Join(caps.TerminalPrograms, ", "))
		return "", nil, false
	}
	if program == "" {
		program = "/bin/bash"
	}
	return program, nil, true
}

// resolveTerminal describes a terminal request for the owner's approval. The
// digested payload is exactly the grant payload the agent verifies.
func (s *Server) resolveTerminal(w http.ResponseWriter, r *http.Request, body []byte) (*approvalPlan, bool) {
	role := r.Header.Get("X-Role")
	if role != "admin" && role != "operator" {
		writeJSONError(w, http.StatusForbidden, "insufficient role permissions to open a terminal")
		return nil, false
	}
	var req struct {
		EndpointID         string `json:"endpoint_id"`
		Program            string `json:"program"`
		MaxDurationSeconds int    `json:"max_duration_seconds"`
	}
	if !decodeInto(w, body, &req) || !s.endpointInScope(w, r, req.EndpointID) {
		return nil, false
	}
	program, _, ok := s.terminalProgram(w, req.EndpointID, req.Program)
	if !ok {
		return nil, false
	}
	// The digested payload stays {"program":...}: agents check a terminal
	// grant against exactly that. The session length is the hub's to
	// enforce; the authority only shows it to the owner.
	d := s.terminalDuration(req.MaxDurationSeconds)
	payload, err := json.Marshal(response.TerminalSessionPayload{Program: program})
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return nil, false
	}
	return &approvalPlan{
		Kind: response.ActionKindTerminalSession, Action: "Open terminal",
		Summary: "Interactive " + program + " on " + s.endpointLabels([]string{req.EndpointID}) + ", recorded, up to " + humanDuration(d) + ", for " + s.operatorFromRequest(r),
		Targets: []string{req.EndpointID}, Payload: payload, SessionSeconds: int64(d / time.Second),
	}, true
}

// terminalDuration is the session length a caller asked for, held to the
// hub's maximum; zero or less asks for the maximum.
func (s *Server) terminalDuration(seconds int) time.Duration {
	limit := s.terminalMgr.MaxDuration()
	d := time.Duration(seconds) * time.Second
	if d <= 0 || d > limit {
		return limit
	}
	return d
}

// tailStdout keeps the newest stdout frames whose data adds up to at most n
// bytes (at least one frame when any exists), oldest first.
func tailStdout(frames []terminal.TerminalFrame, n int) []terminal.TerminalFrame {
	total := 0
	start := len(frames)
	for i := len(frames) - 1; i >= 0; i-- {
		if frames[i].Type != terminal.FrameStdout {
			continue
		}
		if total+len(frames[i].Data) > n && start < len(frames) {
			break
		}
		total += len(frames[i].Data)
		start = i
	}
	out := make([]terminal.TerminalFrame, 0, len(frames)-start)
	for _, f := range frames[start:] {
		if f.Type == terminal.FrameStdout {
			out = append(out, f)
		}
	}
	return out
}

// screenSessionID reports whether a session id names a screen session, which
// the terminal routes never attach.
func (s *Server) screenSessionID(id string) bool {
	sess, err := s.terminalMgr.GetSession(id)
	return err == nil && screen.IsScreen(sess.Program)
}

// terminalCookieName gives every session its own attach cookie, so a browser
// can open several terminals at once without one start overwriting the token
// another tab is about to use.
func terminalCookieName(sessionID string) string {
	var b strings.Builder
	b.WriteString("ominull_terminal_token_")
	for _, c := range sessionID {
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_' {
			b.WriteRune(c)
		}
	}
	return b.String()
}
