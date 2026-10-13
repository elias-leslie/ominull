package server

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"regexp"
	"strings"
	"time"
)

// Router identity.
//
// A gateway used to post telemetry over plain HTTP with the tenant key, so the
// key and every DNS query crossed the LAN in the clear. A gateway can instead
// hold its own client certificate, issued by the hub CA with the common name
// "router:<id>", and post to the agent TLS listener. The hub accepts that
// certificate only for /api/v1/router/telemetry, only for the router id it
// names, and only while its fingerprint is the one recorded at issue: issuing
// a new certificate for the same router revokes the previous one.

const routerCNPrefix = "router:"

var routerIDPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)

// routerAuth authenticates a gateway by its registered client certificate and
// otherwise falls back to the normal API credentials.
func (s *Server) routerAuth(next http.HandlerFunc) http.HandlerFunc {
	fallback := s.authMiddleware(next)
	return func(w http.ResponseWriter, r *http.Request) {
		// Only this function may assert a router identity.
		r.Header.Del("X-Router-ID")
		if id, ok := s.verifiedRouter(r); ok {
			for _, h := range []string{"X-Role", "X-Tenant-ID", "X-Username", "X-User-ID", "X-Client-CN", "X-Device-Endpoint-ID", "X-Operator-ID", "X-Auth-Method"} {
				r.Header.Del(h)
			}
			r.Header.Set("X-Router-ID", id)
			r.Header.Set("X-Role", "router")
			r.Header.Set("X-Username", routerCNPrefix+id)
			r.Header.Set("X-Auth-Method", "router-cert")
			next(w, r)
			return
		}
		fallback(w, r)
	}
}

// verifiedRouter returns the router id of a verified, currently registered
// gateway certificate.
func (s *Server) verifiedRouter(r *http.Request) (string, bool) {
	if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 || len(r.TLS.VerifiedChains[0]) == 0 {
		return "", false
	}
	leaf := r.TLS.VerifiedChains[0][0]
	id, ok := strings.CutPrefix(leaf.Subject.CommonName, routerCNPrefix)
	if !ok || !routerIDPattern.MatchString(id) {
		return "", false
	}
	registered, ok := s.store.RouterIdentity(id)
	if !ok {
		return "", false
	}
	sum := sha256.Sum256(leaf.Raw)
	if subtle.ConstantTimeCompare([]byte(hex.EncodeToString(sum[:])), []byte(registered)) != 1 {
		return "", false
	}
	return id, true
}

// handleRouterIdentity issues a gateway client certificate. Admin only: the
// response carries a private key.
func (s *Server) handleRouterIdentity(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if r.Header.Get("X-Role") != "admin" || r.Header.Get("X-Tenant-ID") != "" {
		writeJSONError(w, http.StatusForbidden, "only an administrator can issue a router identity")
		return
	}
	if s.pki == nil {
		writeJSONError(w, http.StatusServiceUnavailable, "PKI not initialized")
		return
	}
	var req struct {
		RouterID string `json:"router_id"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid json")
		return
	}
	id := strings.ToLower(strings.TrimSpace(req.RouterID))
	if !routerIDPattern.MatchString(id) {
		writeJSONError(w, http.StatusBadRequest, "router_id must be 1-64 characters of a-z, 0-9, '.', '_' or '-'")
		return
	}
	bundle, err := s.pki.IssueClientCert(routerCNPrefix+id, "")
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "issuing the router certificate failed")
		return
	}
	block, _ := pem.Decode(bundle.CertPEM)
	if block == nil {
		writeJSONError(w, http.StatusInternalServerError, "issued certificate could not be read back")
		return
	}
	sum := sha256.Sum256(block.Bytes)
	fingerprint := hex.EncodeToString(sum[:])
	if err := s.store.SetRouterIdentity(id, fingerprint, time.Now()); err != nil {
		writeJSONError(w, http.StatusInternalServerError, "router identity could not be saved")
		return
	}
	s.audit(r, "ROUTER_IDENTITY_ISSUED", id, "Issued router client certificate "+fingerprint[:16]+"…; any earlier certificate for this router is revoked")
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, map[string]string{
		"router_id":   id,
		"cert_pem":    string(bundle.CertPEM),
		"key_pem":     string(bundle.KeyPEM),
		"ca_pem":      string(bundle.CAPEM),
		"cert_sha256": fingerprint,
	})
}
