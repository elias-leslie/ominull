package server

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"

	"ominull/hub/pkg/response"
	"ominull/hub/pkg/storage"
)

// The host-authority courier (docs/HOST_AUTHORITY.md). On hosts that pin a
// host authority (Nightshift's keys), only grants that authority signed run
// scripts. The hub carries those grants and never signs them, and never asks
// the OmniNull authority:
//
//	POST /api/v1/endpoints/{id}/jobs/signed/reserve  {"payload":{...}}
//	  -> {"job_id","payload_json","action_digest","tenant_id","endpoint_id","expires_at"}
//	POST /api/v1/endpoints/{id}/jobs/signed          {"payload":{...},"grant":{...}}
//	  -> {"job_id","state":"queued"}
//
// The signer signs a V3 grant over action_digest (sha256 of payload_json) and
// job_id from the reserve answer. The agent checks the signature against the
// key pinned on the host; the hub checks everything it can see.

const (
	signedJobMaxBody     = 160 << 10
	signedJobMaxSource   = 64 << 10
	signedJobMaxOutput   = 5 << 20
	signedJobMaxTimeout  = 3600
	signedJobMaxLifetime = time.Hour        // expires_at - issued_at
	signedJobReportAge   = 15 * time.Minute // the trust report the route relies on
)

// handleEndpointSubroutes serves /api/v1/endpoints/{id}/... paths.
func (s *Server) handleEndpointSubroutes(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, "/api/v1/endpoints/")
	parts := strings.Split(rest, "/")
	switch {
	case len(parts) == 3 && parts[1] == "jobs" && parts[2] == "signed":
		s.handleSignedJob(w, r, parts[0])
	case len(parts) == 4 && parts[1] == "jobs" && parts[2] == "signed" && parts[3] == "reserve":
		s.handleSignedJobReserve(w, r, parts[0])
	default:
		writeJSONError(w, http.StatusNotFound, "not found")
	}
}

// canonicalScriptPayload checks a script_exec payload and returns the exact
// bytes the agent digests: Go's encoding of response.ScriptExecPayload.
func canonicalScriptPayload(raw json.RawMessage) (string, string, error) {
	if len(bytes.TrimSpace(raw)) == 0 {
		return "", "", errors.New("payload is required")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var p response.ScriptExecPayload
	if err := dec.Decode(&p); err != nil {
		return "", "", fmt.Errorf("payload: %v", err)
	}
	if dec.More() {
		return "", "", errors.New("payload: trailing data")
	}
	sum := sha256.Sum256([]byte(p.Source))
	switch {
	case p.ScriptID == "" || p.ScriptVersion <= 0:
		return "", "", errors.New("payload needs script_id and script_version")
	case p.Source == "" || len(p.Source) > signedJobMaxSource:
		return "", "", fmt.Errorf("payload source must be 1 to %d bytes", signedJobMaxSource)
	case !strings.EqualFold(p.ScriptDigest, hex.EncodeToString(sum[:])):
		return "", "", errors.New("payload script_digest is not the sha256 of its source")
	case p.Interpreter == "":
		return "", "", errors.New("payload needs an interpreter")
	case p.TimeoutSeconds < 1 || p.TimeoutSeconds > signedJobMaxTimeout:
		return "", "", fmt.Errorf("payload timeout_seconds must be 1 to %d", signedJobMaxTimeout)
	case p.MaxOutputBytes < 0 || p.MaxOutputBytes > signedJobMaxOutput:
		return "", "", fmt.Errorf("payload max_output_bytes must be 0 to %d", signedJobMaxOutput)
	}
	p.ScriptDigest = strings.ToLower(p.ScriptDigest)
	out, err := json.Marshal(p)
	if err != nil {
		return "", "", err
	}
	d := sha256.Sum256(out)
	return string(out), hex.EncodeToString(d[:]), nil
}

// hostAuthorityEndpoint returns the endpoint and its latest trust report when
// it pins a host authority; otherwise an HTTP status and reason.
func (s *Server) hostAuthorityEndpoint(id string) (*storage.Endpoint, *response.AgentTrustReport, int, string) {
	ep, err := s.store.GetEndpoint(id)
	if err != nil || ep == nil || ep.Status == "retired" {
		return nil, nil, http.StatusNotFound, "no such endpoint"
	}
	s.trust.mu.Lock()
	s.trust.init()
	seen, ok := s.trust.reports[ep.ID]
	s.trust.mu.Unlock()
	if !ok || time.Since(seen.at) > signedJobReportAge {
		return nil, nil, http.StatusConflict, "the endpoint has not reported its trust state recently"
	}
	if !seen.report.HostAuthority {
		return nil, nil, http.StatusForbidden, "the endpoint pins no host authority; signed jobs are only for hosts that do"
	}
	rep := seen.report
	return ep, &rep, 0, ""
}

func (s *Server) handleSignedJobReserve(w http.ResponseWriter, r *http.Request, endpointID string) {
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var body struct {
		Payload json.RawMessage `json:"payload"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, signedJobMaxBody)).Decode(&body); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid body")
		return
	}
	ep, _, status, why := s.hostAuthorityEndpoint(endpointID)
	if ep == nil {
		writeJSONError(w, status, why)
		return
	}
	payload, digest, err := canonicalScriptPayload(body.Payload)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	res, err := s.responseStore.ReserveJob(endpointTenant(ep), ep.ID, digest, time.Now())
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"job_id": res.JobID, "payload_json": payload, "action_digest": digest,
		"tenant_id": res.TenantID, "endpoint_id": res.EndpointID, "expires_at": res.ExpiresAt.Unix(),
	})
}

func (s *Server) handleSignedJob(w http.ResponseWriter, r *http.Request, endpointID string) {
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var body struct {
		Payload json.RawMessage         `json:"payload"`
		Grant   *response.EndpointGrant `json:"grant"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, signedJobMaxBody)).Decode(&body); err != nil || body.Grant == nil {
		writeJSONError(w, http.StatusBadRequest, "body needs payload and grant")
		return
	}
	ep, rep, status, why := s.hostAuthorityEndpoint(endpointID)
	if ep == nil {
		writeJSONError(w, status, why)
		return
	}
	payload, digest, err := canonicalScriptPayload(body.Payload)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	g := body.Grant
	tenant := endpointTenant(ep)
	now := time.Now()
	if why := signedGrantRefusal(g, ep.ID, tenant, digest, rep, now); why != "" {
		writeJSONError(w, http.StatusBadRequest, why)
		return
	}
	if err := s.responseStore.TakeReservation(g.JobID, tenant, ep.ID, digest, now); err != nil {
		writeJSONError(w, http.StatusConflict, err.Error())
		return
	}
	job, err := s.responseStore.CreateJob(tenant, ep.ID, response.ActionKindScriptExec, g.OperatorID, g, payload, "signed/"+g.JobID)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	role := strings.TrimPrefix(g.OperatorID, "nightshift:")
	_ = s.store.RecordAudit(storage.AuditEntry{ID: uuid.New().String(), Username: g.OperatorID, Action: "SIGNED_JOB_QUEUED",
		Resource: job.ID, Timestamp: now.UTC(),
		Details: fmt.Sprintf("script job signed by Nightshift (%s key %.12s) queued for %s: payload %.12s", role, g.SignerKeyID, ep.ID, digest)})
	writeJSON(w, http.StatusOK, map[string]interface{}{"job_id": job.ID, "state": string(job.State)})
}

// signedGrantRefusal is everything the hub can check about a host-authority
// grant without its key: shape, binding, time, and that its signer is a key
// the endpoint reports pinned with the role its operator claims.
func signedGrantRefusal(g *response.EndpointGrant, endpointID, tenantID, digest string, rep *response.AgentTrustReport, now time.Time) string {
	switch {
	case g.Version != response.GrantVersionJob:
		return "signed jobs need a V3 grant"
	case !g.HostAuthority():
		return "grant operator must be nightshift:tap or nightshift:auto"
	}
	if err := g.Validate(); err != nil {
		return "grant: " + err.Error()
	}
	switch {
	case g.ActionKind != response.ActionKindScriptExec:
		return "signed jobs carry script_exec grants only"
	case g.EndpointID != endpointID:
		return "grant is for another endpoint"
	case g.TenantID != tenantID:
		return "grant is for another tenant"
	case g.ResponseSessionID != "":
		return "host-authority grants carry no response_session_id"
	case !strings.EqualFold(g.ActionDigest, digest):
		return "grant action_digest does not match the payload"
	case now.Unix() < g.IssuedAt-60 || now.Unix() > g.ExpiresAt+60:
		return "grant is not valid now"
	case time.Duration(g.ExpiresAt-g.IssuedAt)*time.Second > signedJobMaxLifetime:
		return "grant lives longer than an hour"
	}
	k := rep.HostKey(g.SignerKeyID)
	if k == nil {
		return "the grant's signer is not a host-authority key this endpoint reports"
	}
	if "nightshift:"+k.Role != g.OperatorID {
		return "the grant's operator does not match its key's role"
	}
	return ""
}
