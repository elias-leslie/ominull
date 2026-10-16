package server

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"

	"ominull/hub/pkg/responseauth"
)

const approvalRelayKeySetting = "nightshift_approval_relay_key_sha256"

// relayKeyIssuedAudit records each issuance. The detection-policy note shows
// it: any admin-key holder can issue the key, and a closure through it is
// recorded as the owner's answer.
const relayKeyIssuedAudit = "APPROVAL_RELAY_KEY_ISSUED"

// approvalRelayAuth admits only the relay key. Unlike the findings feed there
// is no admin fallback: the relay's whole job is to carry the owner's words,
// and an admin key is exactly what the approval is meant not to be enough.
func (s *Server) approvalRelayAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		addr := clientIP(r)
		if s.throttle.blocked(addr) {
			w.Header().Set("Retry-After", "60")
			writeJSONError(w, http.StatusTooManyRequests, "too many failed authentication attempts; try again shortly")
			return
		}
		key := strings.TrimSpace(r.Header.Get("X-API-Key"))
		want, _ := s.store.GetSetting(approvalRelayKeySetting)
		if key == "" || want == "" || !secretEqual(hashFeedKey(key), want) {
			s.throttle.fail(addr)
			writeJSONError(w, http.StatusUnauthorized, "the approval relay key is required")
			return
		}
		s.throttle.succeed(addr)
		for _, h := range []string{"X-Role", "X-Tenant-ID", "X-Username", "X-User-ID", "X-Client-CN", "X-Device-Endpoint-ID", "X-Operator-ID", "X-Auth-Method", "X-Router-ID"} {
			r.Header.Del(h)
		}
		r.Header.Set("X-Role", "approval-relay")
		r.Header.Set("X-Username", "nightshift-relay")
		r.Header.Set("X-Auth-Method", "relay-key")
		next(w, r)
	}
}

// handleApprovalRelayKey issues the relay key once (reissue revokes).
func (s *Server) handleApprovalRelayKey(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if r.Header.Get("X-Role") != "admin" || r.Header.Get("X-Tenant-ID") != "" {
		writeJSONError(w, http.StatusForbidden, "only an administrator can issue the approval relay key")
		return
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		writeJSONError(w, http.StatusInternalServerError, "generating the key failed")
		return
	}
	key := "nsa_" + hex.EncodeToString(raw)
	if err := s.store.SetSetting(approvalRelayKeySetting, hashFeedKey(key)); err != nil {
		writeJSONError(w, http.StatusInternalServerError, "the key could not be saved")
		return
	}
	s.audit(r, relayKeyIssuedAudit, "nightshift", "Issued the Nightshift approval relay key; any earlier key is revoked; credential "+credentialOf(r)+" (unverified)")
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, map[string]string{"key": key, "route": "/api/v1/integrations/nightshift/approvals"})
}

// handleRelayApprovals returns pending approvals with the authority's signed
// statements. ?known=id,id&wait=N long-polls until one not in known appears.
func (s *Server) handleRelayApprovals(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if s.responseAuth == nil {
		writeJSONError(w, http.StatusServiceUnavailable, "response authority not available")
		return
	}
	known := map[string]bool{}
	for _, id := range strings.Split(r.URL.Query().Get("known"), ",") {
		if id = strings.TrimSpace(id); id != "" {
			known[id] = true
		}
	}
	deadline := time.Now().Add(parseWait(r.URL.Query().Get("wait")))
	for {
		wake := s.approvalWake.wait()
		list, err := s.responseAuth.PendingApprovals(r.Context())
		if err != nil {
			writeJSONError(w, approvalStatus(err), err.Error())
			return
		}
		fresh := false
		for _, v := range list {
			if !known[v.ID] {
				fresh = true
				break
			}
		}
		if fresh || time.Now().After(deadline) {
			if list == nil {
				list = []responseauth.ApprovalView{}
			}
			writeJSON(w, http.StatusOK, map[string]interface{}{"approvals": list})
			return
		}
		select {
		case <-wake:
		case <-time.After(time.Until(deadline)):
		case <-r.Context().Done():
			return
		}
	}
}

// handleRelayAnswer forwards the owner's answer to the authority, which
// verifies the passkey assertion itself.
func (s *Server) handleRelayAnswer(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if s.responseAuth == nil {
		writeJSONError(w, http.StatusServiceUnavailable, "response authority not available")
		return
	}
	var ans responseauth.ApprovalAnswer
	if err := json.NewDecoder(io.LimitReader(r.Body, 64*1024)).Decode(&ans); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid json body")
		return
	}
	v, err := s.responseAuth.AnswerApproval(r.Context(), &ans)
	if err != nil {
		s.audit(r, "OWNER_APPROVAL_ANSWER_REJECTED", ans.ID, err.Error())
		writeJSONError(w, approvalStatus(err), err.Error())
		return
	}
	s.approvalWake.notify()
	s.audit(r, "OWNER_APPROVAL_ANSWERED", ans.ID, string(v.State)+" by "+v.Method+" "+v.ApproverID+": "+v.Action+" - "+v.Summary)
	writeJSON(w, http.StatusOK, publicApproval(v))
}
