package server

import (
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"strings"
)

const approvalRelayKeySetting = "nightshift_approval_relay_key_sha256"

// relayKeyIssuedAudit records each issuance. The detection-policy note shows
// it: any admin-key holder can issue the key, and a closure through it is
// recorded as Nightshift's verdict.
const relayKeyIssuedAudit = "APPROVAL_RELAY_KEY_ISSUED"

// approvalRelayAuth admits only the Nightshift relay key (locks, agent builds,
// alert verdicts, routine keys). Unlike the findings feed there is no admin
// fallback. The name and the setting stay as they were so Nightshift's saved
// key keeps working.
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
			writeJSONError(w, http.StatusUnauthorized, "the Nightshift relay key is required")
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
		writeJSONError(w, http.StatusForbidden, "only an administrator can issue the Nightshift relay key")
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
	s.audit(r, relayKeyIssuedAudit, "nightshift", "Issued the Nightshift relay key; any earlier key is revoked; credential "+credentialOf(r)+" (unverified)")
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, map[string]string{"key": key, "route": "/api/v1/integrations/nightshift/locks"})
}
