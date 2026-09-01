package server

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
	"ominull/hub/pkg/storage"
)

var enrollmentEndpointID = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$`)

func (s *Server) validateEnrollmentProfileTarget(kind, tenantID, locationID, endpointID string) error {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		tenantID = "default"
	}
	tenant, err := s.store.GetTenant(tenantID)
	if err != nil {
		return errors.New("client could not be validated")
	}
	if tenant == nil {
		return errors.New("client does not exist")
	}
	locationID = strings.TrimSpace(locationID)
	if locationID != "" {
		locations, err := s.store.ListLocations(tenantID)
		if err != nil {
			return errors.New("location could not be validated")
		}
		found := false
		for _, location := range locations {
			if location.ID == locationID {
				found = true
				break
			}
		}
		if !found {
			return errors.New("location does not belong to the selected client")
		}
	}
	endpointID = strings.TrimSpace(endpointID)
	if kind != "invitation" && endpointID != "" {
		return errors.New("a reusable enrollment profile cannot pin every install to one endpoint id")
	}
	if endpointID != "" && !enrollmentEndpointID.MatchString(endpointID) {
		return errors.New("endpoint id is invalid")
	}
	return nil
}

type enrollmentRedeemRequest struct {
	Code       string `json:"code"`
	Platform   string `json:"platform"`
	EndpointID string `json:"endpoint_id"`
	Hostname   string `json:"hostname"`
	IP         string `json:"ip"`
	MAC        string `json:"mac"`
	OS         string `json:"os"`
}

func (s *Server) handleEnrollmentProfiles(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		profiles, err := s.store.ListEnrollmentProfiles()
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, "enrollment profiles unavailable")
			return
		}
		writeJSON(w, http.StatusOK, map[string]interface{}{"profiles": profiles})
	case http.MethodPost:
		var req struct {
			Kind       string  `json:"kind"`
			Platform   string  `json:"platform"`
			TenantID   string  `json:"tenant_id"`
			LocationID string  `json:"location_id"`
			Role       string  `json:"role"`
			EndpointID string  `json:"endpoint_id"`
			Hours      float64 `json:"hours"`
			MaxUses    int     `json:"max_uses"`
			Persistent bool    `json:"persistent"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8192)).Decode(&req); err != nil {
			writeJSONError(w, http.StatusBadRequest, "unreadable enrollment profile body")
			return
		}
		kind := strings.ToLower(strings.TrimSpace(req.Kind))
		if req.Persistent {
			kind = "deployment"
		}
		if kind == "" {
			kind = "invitation"
		}
		if kind == "deployment" {
			req.Hours = 0
			req.MaxUses = 0
		} else if req.Hours <= 0 {
			req.Hours = 0.5
		}
		if kind == "invitation" && req.MaxUses == 0 {
			req.MaxUses = 1
		}
		if err := s.validateEnrollmentProfileTarget(kind, req.TenantID, req.LocationID, req.EndpointID); err != nil {
			writeJSONError(w, http.StatusBadRequest, err.Error())
			return
		}
		profile, code, err := s.store.CreateEnrollmentProfile(storage.EnrollmentProfile{
			Kind: kind, Platform: req.Platform, TenantID: req.TenantID,
			LocationID: req.LocationID, Role: req.Role, EndpointID: req.EndpointID,
			MaxUses: req.MaxUses, CreatedBy: r.Header.Get("X-Username"),
		}, time.Duration(req.Hours*float64(time.Hour)))
		if err != nil {
			writeJSONError(w, http.StatusBadRequest, err.Error())
			return
		}
		s.audit(r, "ENROLLMENT_PROFILE_CREATED", profile.ID, "Created a "+profile.Kind+" enrollment profile")
		w.Header().Set("Cache-Control", "no-store")
		writeJSON(w, http.StatusOK, map[string]interface{}{"profile": profile, "code": code})
	case http.MethodDelete:
		id := strings.TrimSpace(r.URL.Query().Get("id"))
		if id == "" {
			writeJSONError(w, http.StatusBadRequest, "id is required")
			return
		}
		if err := s.store.RevokeEnrollmentProfile(id); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				writeJSONError(w, http.StatusNotFound, "enrollment profile not found or already closed")
			} else {
				writeJSONError(w, http.StatusInternalServerError, "enrollment profile could not be revoked")
			}
			return
		}
		s.audit(r, "ENROLLMENT_PROFILE_REVOKED", id, "Revoked an enrollment profile")
		writeJSON(w, http.StatusOK, map[string]string{"revoked": id})
	default:
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

type enrollmentBundle struct {
	EndpointID       string `json:"endpoint_id"`
	AgentHubURL      string `json:"agent_hub_url"`
	DeviceCredential string `json:"device_credential"`
	CertPEM          []byte `json:"cert_pem"`
	KeyPEM           []byte `json:"key_pem"`
	CAPEM            []byte `json:"ca_pem"`
	PFXBase64        string `json:"pfx_base64,omitempty"`
}

func (s *Server) handleEnrollmentRedeem(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	addr := clientIP(r)
	if s.throttle.blocked(addr) {
		w.Header().Set("Retry-After", "60")
		writeJSONError(w, http.StatusTooManyRequests, "too many enrollment attempts; try again shortly")
		return
	}
	var req enrollmentRedeemRequest
	contentType := r.Header.Get("Content-Type")
	if strings.Contains(contentType, "application/x-www-form-urlencoded") {
		if err := r.ParseForm(); err != nil {
			writeJSONError(w, http.StatusBadRequest, "unreadable enrollment body")
			return
		}
		req.Code, req.Platform, req.EndpointID = r.PostFormValue("code"), r.PostFormValue("platform"), r.PostFormValue("endpoint_id")
		req.Hostname, req.IP, req.MAC, req.OS = r.PostFormValue("hostname"), r.PostFormValue("ip"), r.PostFormValue("mac"), r.PostFormValue("os")
	} else if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8192)).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "unreadable enrollment body")
		return
	}
	req.Platform = strings.ToLower(strings.TrimSpace(req.Platform))
	if req.Platform != "linux" && req.Platform != "windows" {
		writeJSONError(w, http.StatusBadRequest, "platform must be linux or windows")
		return
	}
	if s.pki == nil {
		writeJSONError(w, http.StatusServiceUnavailable, "hub PKI is unavailable")
		return
	}
	profile, err := s.store.RedeemEnrollmentProfile(req.Code, req.Platform)
	if err != nil {
		s.throttle.fail(addr)
		writeJSONError(w, http.StatusUnauthorized, err.Error())
		return
	}
	s.throttle.succeed(addr)
	endpointID := strings.TrimSpace(profile.EndpointID)
	if endpointID == "" {
		endpointID = enrollmentEndpointIDFor(req.Platform, req.EndpointID, req.Hostname)
	}
	if !enrollmentEndpointID.MatchString(endpointID) {
		writeJSONError(w, http.StatusBadRequest, "endpoint id is invalid")
		return
	}
	hostname := strings.TrimSpace(req.Hostname)
	if hostname == "" {
		hostname = endpointID
	}
	osName := strings.TrimSpace(req.OS)
	if osName == "" {
		osName = map[string]string{"linux": "Linux", "windows": "Windows"}[req.Platform]
	}
	tenant, err := s.store.GetTenant(profile.TenantID)
	if err != nil || tenant == nil {
		writeJSONError(w, http.StatusBadRequest, "enrollment profile names an unknown tenant")
		return
	}
	now := time.Now().UTC()
	if err := s.store.UpsertEndpoint(storage.Endpoint{
		ID: endpointID, TenantID: tenant.ID, LocationID: profile.LocationID,
		Hostname: hostname, OS: osName, IP: strings.TrimSpace(req.IP), MAC: strings.TrimSpace(req.MAC),
		RoleTag: profile.Role, DriverVersion: "enrolling", Status: "offline", CreatedAt: now, LastSeenAt: now,
	}); err != nil {
		writeJSONError(w, http.StatusInternalServerError, "endpoint could not be registered")
		return
	}
	cert, err := s.pki.IssueClientCert(endpointID, req.IP)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "endpoint certificate could not be issued")
		return
	}
	credential, _, err := s.store.IssueDeviceCredential(endpointID)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "device credential could not be issued")
		return
	}
	_ = s.store.SetEndpointCertCN(endpointID, endpointID)
	hubURL := s.agentHubURL
	if hubURL == "" {
		hubURL = s.downloadBase(r)
	}
	bundle := enrollmentBundle{EndpointID: endpointID, AgentHubURL: hubURL, DeviceCredential: credential,
		CertPEM: cert.CertPEM, KeyPEM: cert.KeyPEM, CAPEM: cert.CAPEM, PFXBase64: cert.PFXBase64}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	s.auditAs(r, "enrollment:"+endpointID, "ENROLLMENT_REDEEMED", endpointID, fmt.Sprintf("Redeemed a %s enrollment profile from %s", req.Platform, addr))
	writeJSON(w, http.StatusOK, bundle)
}

func enrollmentEndpointIDFor(platform, requested, hostname string) string {
	if requested = strings.TrimSpace(requested); requested != "" {
		return requested
	}
	value := strings.ToLower(strings.TrimSpace(hostname))
	var b strings.Builder
	for _, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' || r == '_' || r == '.' {
			b.WriteRune(r)
		} else {
			b.WriteByte('-')
		}
	}
	value = strings.Trim(b.String(), "-._")
	if value == "" {
		value = uuid.NewString()
	}
	prefix := "linux-"
	if platform == "windows" {
		prefix = "windows-"
	}
	value = prefix + value
	if len(value) > 63 {
		value = value[:63]
	}
	return strings.TrimRight(value, "-._")
}
