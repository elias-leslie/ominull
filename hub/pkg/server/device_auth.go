package server

import (
	"database/sql"
	"encoding/json"
	"log"
	"net/http"
	"strings"
)

const deviceCredentialHeader = "X-Ominull-Device-Credential"

// deviceOrLegacyMiddleware is the machine-route seam. New agents authenticate
// with a credential issued to exactly one endpoint. Existing 1.7.x agents may
// continue through the old shared-key middleware during a bounded migration;
// no new installer or package config emits that path.
func (s *Server) deviceOrLegacyMiddleware(next http.HandlerFunc) http.HandlerFunc {
	legacy := s.authMiddleware(next)
	return func(w http.ResponseWriter, r *http.Request) {
		credential := strings.TrimSpace(r.Header.Get(deviceCredentialHeader))
		if credential == "" {
			if !s.legacyAgentAuthEnabled() && !secureStringEqual(strings.TrimSpace(r.Header.Get("X-API-Key")), s.adminKey) {
				writeJSONError(w, http.StatusUnauthorized, "legacy agent authentication is disabled; enroll this device for a unique credential")
				return
			}
			legacy(w, r)
			return
		}
		addr := clientIP(r)
		if s.throttle.blocked(addr) {
			w.Header().Set("Retry-After", "60")
			writeJSONError(w, http.StatusTooManyRequests, "too many failed authentication attempts; try again shortly")
			return
		}
		identity, ok, err := s.store.VerifyDeviceCredential(credential)
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, "device credential could not be checked")
			return
		}
		if !ok {
			if s.throttle.fail(addr) {
				log.Printf("[!] %s has failed device authentication %d times in a minute; refusing it for the next minute.", addr, s.throttle.limit)
			}
			writeJSONError(w, http.StatusUnauthorized, "invalid or revoked device credential")
			return
		}
		s.throttle.succeed(addr)
		for _, h := range []string{"X-Role", "X-Tenant-ID", "X-Username", "X-User-ID", "X-Client-CN", "X-Device-Endpoint-ID"} {
			r.Header.Del(h)
		}
		if cn := clientCertCN(r); cn != "" {
			r.Header.Set("X-Client-CN", cn)
		}
		r.Header.Set("X-Role", "tenant")
		r.Header.Set("X-Tenant-ID", identity.TenantID)
		r.Header.Set("X-Username", "device:"+identity.EndpointID)
		r.Header.Set("X-Device-Endpoint-ID", identity.EndpointID)
		if (r.URL.Path != "/api/v1/events" || r.Method != http.MethodPost) &&
			(r.URL.Path != "/api/v1/agent/config" || r.Method != http.MethodGet) {
			writeJSONError(w, http.StatusForbidden, "device credentials may only read configuration or post telemetry")
			return
		}
		next(w, r)
	}
}

func (s *Server) legacyAgentAuthEnabled() bool {
	mode, err := s.store.GetSetting("legacy_agent_auth")
	if err != nil {
		return false
	}
	return strings.EqualFold(strings.TrimSpace(mode), "migration")
}

type legacyAgentAuthRequest struct {
	Mode string `json:"mode"`
}

func (s *Server) handleLegacyAgentAuth(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		mode, _ := s.store.GetSetting("legacy_agent_auth")
		writeJSON(w, http.StatusOK, map[string]string{"mode": strings.TrimSpace(mode)})
	case http.MethodPost:
		var req legacyAgentAuthRequest
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1024)).Decode(&req); err != nil {
			writeJSONError(w, http.StatusBadRequest, "unreadable legacy authentication body")
			return
		}
		mode := strings.ToLower(strings.TrimSpace(req.Mode))
		if mode != "migration" && mode != "disabled" {
			writeJSONError(w, http.StatusBadRequest, "mode must be migration or disabled")
			return
		}
		if err := s.store.SetSetting("legacy_agent_auth", mode); err != nil {
			writeJSONError(w, http.StatusInternalServerError, "legacy authentication mode could not be saved")
			return
		}
		s.audit(r, "LEGACY_AGENT_AUTH_CHANGED", "agent-auth", "Set legacy agent authentication mode to "+mode)
		writeJSON(w, http.StatusOK, map[string]string{"mode": mode})
	default:
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

// handleDeviceCredentials is the operator recovery surface for device
// identity. Listing never returns secret material; rotation returns the new
// credential once so an operator can deliver it through a protected channel.
func (s *Server) handleDeviceCredentials(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		items, err := s.store.ListDeviceCredentials()
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, "device credentials unavailable")
			return
		}
		writeJSON(w, http.StatusOK, map[string]interface{}{"credentials": items})
	case http.MethodPost:
		var req struct {
			EndpointID string `json:"endpoint_id"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 2048)).Decode(&req); err != nil {
			writeJSONError(w, http.StatusBadRequest, "unreadable device credential body")
			return
		}
		endpointID := strings.TrimSpace(req.EndpointID)
		if endpointID == "" {
			writeJSONError(w, http.StatusBadRequest, "endpoint_id is required")
			return
		}
		endpoint, err := s.store.GetEndpoint(endpointID)
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, "endpoint could not be read")
			return
		}
		if endpoint == nil {
			writeJSONError(w, http.StatusNotFound, "endpoint not registered")
			return
		}
		credential, record, err := s.store.IssueDeviceCredential(endpointID)
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, "device credential could not be rotated")
			return
		}
		s.audit(r, "DEVICE_CREDENTIAL_ROTATED", endpointID, "Rotated the unique device credential; the previous credential is revoked")
		w.Header().Set("Cache-Control", "no-store")
		writeJSON(w, http.StatusOK, map[string]interface{}{"credential": record, "device_credential": credential})
	case http.MethodDelete:
		endpointID := strings.TrimSpace(r.URL.Query().Get("endpoint_id"))
		if endpointID == "" {
			writeJSONError(w, http.StatusBadRequest, "endpoint_id is required")
			return
		}
		if err := s.store.RevokeDeviceCredentials(endpointID); err != nil {
			if err == sql.ErrNoRows {
				writeJSONError(w, http.StatusNotFound, "active device credential not found")
			} else {
				writeJSONError(w, http.StatusInternalServerError, "device credential could not be revoked")
			}
			return
		}
		s.audit(r, "DEVICE_CREDENTIAL_REVOKED", endpointID, "Revoked the unique device credential for this endpoint")
		writeJSON(w, http.StatusOK, map[string]string{"revoked": endpointID})
	default:
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}
