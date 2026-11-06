package server

import (
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"strings"
)

// aicoRelayKeySetting holds the sha256 of the key Aico's web server sends as
// X-API-Key. The stored value is the key Aico already holds, so renaming the
// setting kept it valid (storage migration "aico_relay_key").
const aicoRelayKeySetting = "aico_relay_key_sha256"

// relayKeyIssuedAudit records each issuance. The detection-policy note shows
// it: any admin-key holder can issue the key, and a closure through it is
// recorded as the owner's verdict relayed by Aico. The action name is stored
// in older audit rows, so it keeps its original spelling.
const relayKeyIssuedAudit = "APPROVAL_RELAY_KEY_ISSUED"

// aicoRelayAuth admits only Aico's relay key (agent builds, alert verdicts).
// There is no admin fallback.
func (s *Server) aicoRelayAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		addr := clientIP(r)
		if s.throttle.blocked(addr) {
			w.Header().Set("Retry-After", "60")
			writeJSONError(w, http.StatusTooManyRequests, "too many failed authentication attempts; try again shortly")
			return
		}
		key := strings.TrimSpace(r.Header.Get("X-API-Key"))
		want, _ := s.store.GetSetting(aicoRelayKeySetting)
		if key == "" || want == "" || !secretEqual(hashFeedKey(key), want) {
			s.throttle.fail(addr)
			writeJSONError(w, http.StatusUnauthorized, "the Aico relay key is required")
			return
		}
		s.throttle.succeed(addr)
		for _, h := range []string{"X-Role", "X-Tenant-ID", "X-Username", "X-User-ID", "X-Client-CN", "X-Device-Endpoint-ID", "X-Operator-ID", "X-Auth-Method", "X-Router-ID"} {
			r.Header.Del(h)
		}
		r.Header.Set("X-Role", "approval-relay")
		r.Header.Set("X-Username", "aico-relay")
		r.Header.Set("X-Auth-Method", "relay-key")
		next(w, r)
	}
}

// handleAicoRelayKey issues the relay key once (reissue revokes).
func (s *Server) handleAicoRelayKey(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if r.Header.Get("X-Role") != "admin" || r.Header.Get("X-Tenant-ID") != "" {
		writeJSONError(w, http.StatusForbidden, "only an administrator can issue the Aico relay key")
		return
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		writeJSONError(w, http.StatusInternalServerError, "generating the key failed")
		return
	}
	key := "nsa_" + hex.EncodeToString(raw)
	if err := s.store.SetSetting(aicoRelayKeySetting, hashFeedKey(key)); err != nil {
		writeJSONError(w, http.StatusInternalServerError, "the key could not be saved")
		return
	}
	s.audit(r, relayKeyIssuedAudit, "aico", "Issued the Aico relay key; any earlier key is revoked; credential "+credentialOf(r)+" (unverified)")
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, map[string]string{"key": key, "route": "/api/v1/aico/agent-builds"})
}
