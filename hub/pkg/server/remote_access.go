package server

// Remote access off: GET/PUT /api/v1/remote-access/settings[?endpoint_id=].
// A per-machine setting, kept as data in one settings row, that switches off
// every remote terminal and remote screen session on that machine, whoever
// asks (owner, agent or steward). Meant for the machines that must never be
// driven remotely; the hub knows them only from this setting, never from a
// hostname.
//
// Switching it on applies at once and closes the machine's open sessions.
// Switching it off loosens safety, so the authority authorizes it and the audit records it.

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"ominull/hub/pkg/responseauth"
)

const (
	remoteAccessKey   = "remote_access.off"
	remoteAccessAudit = "REMOTE_ACCESS_CHANGED"
)

var remoteAccessMu sync.Mutex

type remoteAccessSettings struct {
	// Off lists the endpoints where remote terminal and screen are off.
	Off map[string]bool `json:"off,omitempty"`
	// unreadable: the saved row could not be read, so every machine is
	// treated as off until it is rewritten (fail closed).
	unreadable bool
}

func (s *Server) loadRemoteAccess() remoteAccessSettings {
	var st remoteAccessSettings
	raw, err := s.store.GetSetting(remoteAccessKey)
	if err != nil || raw == "" {
		return st
	}
	if err := json.Unmarshal([]byte(raw), &st); err != nil {
		log.Printf("[!] Unreadable remote access settings, remote terminal and screen refused everywhere until it is rewritten: %v", err)
		return remoteAccessSettings{unreadable: true}
	}
	return st
}

// remoteAccessOff says whether remote terminal and screen are switched off on
// an endpoint.
func (s *Server) remoteAccessOff(endpointID string) bool {
	remoteAccessMu.Lock()
	defer remoteAccessMu.Unlock()
	st := s.loadRemoteAccess()
	return st.unreadable || st.Off[endpointID]
}

// refuseRemoteAccess writes the refusal when remote access is off there.
func (s *Server) refuseRemoteAccess(w http.ResponseWriter, endpointID string) bool {
	if endpointID == "" || !s.remoteAccessOff(endpointID) {
		return false
	}
	writeJSONError(w, http.StatusForbidden, "remote terminal and screen are switched off on this machine (remote access setting)")
	return true
}

func (s *Server) remoteAccessView(st remoteAccessSettings, endpointID string) map[string]interface{} {
	if endpointID != "" {
		return map[string]interface{}{"endpoint_id": endpointID, "off": st.Off[endpointID]}
	}
	ids := make([]string, 0, len(st.Off))
	for id, off := range st.Off {
		if off {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	return map[string]interface{}{"off": ids}
}

func (s *Server) handleRemoteAccess(w http.ResponseWriter, r *http.Request) {
	endpointID := strings.TrimSpace(r.URL.Query().Get("endpoint_id"))
	switch r.Method {
	case http.MethodGet:
		role := r.Header.Get("X-Role")
		if role != "admin" && role != "operator" && role != "auditor" {
			writeJSONError(w, http.StatusForbidden, "unauthorized role for remote access settings")
			return
		}
		if endpointID != "" && !s.endpointInScope(w, r, endpointID) {
			return
		}
		remoteAccessMu.Lock()
		view := s.remoteAccessView(s.loadRemoteAccess(), endpointID)
		remoteAccessMu.Unlock()
		writeJSON(w, http.StatusOK, view)
	case http.MethodPut:
		if r.Header.Get("X-Role") != "admin" {
			writeJSONError(w, http.StatusForbidden, "admin credential required to change remote access")
			return
		}
		s.putRemoteAccess(w, r, endpointID)
	default:
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

// putRemoteAccess: {"endpoint_id": "..", "off": true|false}.
func (s *Server) putRemoteAccess(w http.ResponseWriter, r *http.Request, endpointID string) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 4*1024+1))
	if err != nil || len(body) > 4*1024 {
		writeJSONError(w, http.StatusBadRequest, "request body unreadable or over 4 KiB")
		return
	}
	var req struct {
		EndpointID string `json:"endpoint_id"`
		Off        *bool  `json:"off"`
	}
	if !decodeInto(w, body, &req) {
		return
	}
	if endpointID == "" {
		endpointID = strings.TrimSpace(req.EndpointID)
	}
	if endpointID == "" || req.Off == nil {
		writeJSONError(w, http.StatusBadRequest, `send "endpoint_id" and "off": true or false`)
		return
	}
	if !s.endpointInScope(w, r, endpointID) {
		return
	}
	remoteAccessMu.Lock()
	defer remoteAccessMu.Unlock()
	before := s.loadRemoteAccess()
	was, now := before.Off[endpointID], *req.Off
	if was == now {
		view := s.remoteAccessView(before, endpointID)
		view["changed"] = false
		writeJSON(w, http.StatusOK, view)
		return
	}
	target := "remote_access:" + endpointID
	b := map[string]interface{}{"endpoint": endpointID, "off": was}
	a := map[string]interface{}{"endpoint": endpointID, "off": now}
	if host := s.endpointLabels([]string{endpointID}); host != "" && host != endpointID {
		a["host"] = host
	}
	wording, err := responseauth.RemoteAccessWording(target, b, a)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "the change could not be described: "+err.Error())
		return
	}
	c := policyChange{policy: "remote_access", op: "on", target: target, subject: "remote access", before: b, after: a, wording: wording}
	if !now {
		c.loosens = []string{"remote terminal and screen switched off"}
	}
	approvalID, ok := s.policyAuthorized(w, r, c)
	if !ok {
		return
	}
	after := remoteAccessSettings{Off: map[string]bool{}}
	for k, v := range before.Off {
		if v {
			after.Off[k] = true
		}
	}
	if now {
		after.Off[endpointID] = true
	} else {
		delete(after.Off, endpointID)
	}
	raw, _ := json.Marshal(after)
	if len(after.Off) == 0 {
		raw = nil
	}
	if err := s.store.SetSetting(remoteAccessKey, string(raw)); err != nil {
		writeJSONError(w, http.StatusInternalServerError, "the remote access setting could not be saved: "+err.Error())
		return
	}
	closed := 0
	if now {
		closed = s.closeRemoteSessions(endpointID)
	}
	how := "switched off"
	if approvalID != "" {
		how = "switched back on, authorization " + approvalID
	}
	s.audit(r, remoteAccessAudit, target, how+": "+wording+"; credential "+credentialOf(r)+" (unverified)")
	view := s.remoteAccessView(after, endpointID)
	view["changed"] = true
	if now {
		view["sessions_closed"] = closed
	}
	if approvalID != "" {
		view["approval_id"] = approvalID
	}
	writeJSON(w, http.StatusOK, view)
}

// closeRemoteSessions ends every open terminal and screen session on an
// endpoint (remote access was just switched off there).
func (s *Server) closeRemoteSessions(endpointID string) int {
	if s.terminalMgr == nil {
		return 0
	}
	n := 0
	ep, err := s.store.GetEndpoint(endpointID)
	if err != nil || ep == nil {
		return 0
	}
	for _, sess := range s.terminalMgr.ListSessions(endpointTenant(ep)) {
		if sess.EndpointID != endpointID {
			continue
		}
		if ended, _, _, _, ok := s.terminalMgr.SessionEnd(sess.SessionID); ok && !ended {
			if s.terminalMgr.CloseSession(sess.SessionID, "remote access switched off") == nil {
				n++
			}
		}
	}
	if n > 0 {
		s.reconcileSessionJobs(time.Now().UTC())
	}
	return n
}
