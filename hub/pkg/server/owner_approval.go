package server

// Owner approval for high-impact operations. The static admin key, a console
// session or a JWT minted from the admin key can ask for an isolation change,
// an agent update, a mesh quarantine or a terminal; none of them can make one
// happen. The first POST (no X-Approval-ID) returns 202 with an approval id,
// and the response authority's statement reaches the owner's phone as a Web
// Push through Nightshift. The owner approves with one passkey tap; the
// authority verifies that assertion itself against the approver root pinned
// on its host. The caller then repeats the identical request with
// X-Approval-ID, the authority spends the approval once and signs the grants,
// and only then does the handler run.
//
// The detector's automatic isolation is not an HTTP caller: it runs inside
// the hub (see New) and keeps working without an approval, as it must for a
// host that is attacking at 3am. Read routes and policy routes stay on the
// ordinary scoped credentials.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"ominull/hub/pkg/response"
	"ominull/hub/pkg/responseauth"
)

const approvalHeader = "X-Approval-ID"

// autoApprovedAudit is one rollout the authority approved without asking,
// under the owner's approve-all rule for owner-signed releases.
const autoApprovedAudit = "OWNER_APPROVAL_AUTO"

const rolloutRuleRemovedAudit = "OWNER_APPROVAL_RULE_REMOVED"

type grantsCtxKey struct{}

// approvalGrants returns the grants the owner approval produced for this request.
func approvalGrants(r *http.Request) []*response.EndpointGrant {
	g, _ := r.Context().Value(grantsCtxKey{}).([]*response.EndpointGrant)
	return g
}

// grantedTargets is the endpoint set the owner approved for this request, or
// nil when the request carried no grants (the in-hub automatic paths). A
// handler that resolves its targets from a scope uses this instead, so a
// fleet that changed between approval and use cannot widen the action.
func grantedTargets(r *http.Request) []string {
	g := approvalGrants(r)
	if len(g) == 0 {
		return nil
	}
	out := make([]string, 0, len(g))
	for _, x := range g {
		out = append(out, x.EndpointID)
	}
	return out
}

// approvalPlan is what one gated request would do, worked out before any
// approval is asked for, and again when it is used.
type approvalPlan struct {
	Kind    response.ActionKind
	Action  string
	Summary string
	Targets []string
	Payload []byte // the digested action; nil means route + canonical body + targets
	Body    []byte // replaces the request body (digested and handed on) when set
	// Release is the signed agent packages an agent update installs. The
	// authority approves an owner-signed rollout under the owner's
	// approve-all rule when it verifies them, and otherwise asks.
	Release []responseauth.ReleaseEvidence
	// SessionSeconds is how long a terminal may run; the authority shows it
	// to the owner (it is not part of the digest).
	SessionSeconds int64
	// OnRequested is told the approval id once one is created for this plan.
	OnRequested func(approvalID string)
}

// approvalResolver validates a request and describes it. It writes its own
// error response and returns ok=false to stop.
type approvalResolver func(w http.ResponseWriter, r *http.Request, body []byte) (*approvalPlan, bool)

// approvalNotifier wakes long-polls when an approval is created or changes.
type approvalNotifier struct {
	mu sync.Mutex
	ch chan struct{}
}

func (n *approvalNotifier) wait() <-chan struct{} {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.ch == nil {
		n.ch = make(chan struct{})
	}
	return n.ch
}

func (n *approvalNotifier) notify() {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.ch != nil {
		close(n.ch)
	}
	n.ch = make(chan struct{})
}

func canonicalJSON(body []byte) ([]byte, error) {
	if len(bytes.TrimSpace(body)) == 0 {
		return []byte("{}"), nil
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	var v interface{}
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	if dec.More() {
		return nil, errors.New("trailing data after the JSON body")
	}
	return json.Marshal(v)
}

func approvalStatus(err error) int {
	var ae *responseauth.ApprovalError
	if errors.As(err, &ae) && ae.Status != 0 {
		return ae.Status
	}
	if errors.Is(err, responseauth.ErrApprovalTooLong) {
		return http.StatusUnprocessableEntity
	}
	return http.StatusServiceUnavailable
}

// ownerApproved gates a POST route behind an owner approval. Other methods
// pass straight through (GET and DELETE on the terminal route).
func (s *Server) ownerApproved(resolve approvalResolver, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			next(w, r)
			return
		}
		if s.responseAuth == nil {
			writeJSONError(w, http.StatusServiceUnavailable, "the response authority is not available, so owner approval cannot be checked")
			return
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, 64*1024+1))
		if err != nil || len(body) > 64*1024 {
			writeJSONError(w, http.StatusBadRequest, "request body unreadable or over 64 KiB")
			return
		}
		canon, err := canonicalJSON(body)
		if err != nil {
			writeJSONError(w, http.StatusBadRequest, "invalid json body: "+err.Error())
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
		plan, ok := resolve(w, r, body)
		if !ok {
			return
		}
		if plan.Body != nil {
			body = plan.Body
			if canon, err = canonicalJSON(body); err != nil {
				writeJSONError(w, http.StatusInternalServerError, "resolved body: "+err.Error())
				return
			}
		}
		plan.Targets = sortedTargets(plan.Targets)
		if len(plan.Targets) == 0 {
			writeJSONError(w, http.StatusBadRequest, "this request names no endpoint to act on")
			return
		}
		payload := plan.Payload
		if payload == nil {
			fields := map[string]interface{}{
				"route":   r.URL.Path,
				"body":    json.RawMessage(canon),
				"targets": plan.Targets,
			}
			if r.URL.Path == "/api/v1/endpoints/isolate" || r.URL.Path == "/api/v1/endpoints/isolate-bulk" {
				// The exceptions are approved with the isolation; agents use
				// only these while isolated.
				b, err := s.isolationBaselines(plan.Targets)
				if err != nil {
					writeJSONError(w, http.StatusConflict, err.Error())
					return
				}
				if len(b) > 0 {
					fields["baselines"] = b
				}
			}
			payload, _ = json.Marshal(fields)
		}
		if _, grantRoute := grantRoutes[r.URL.Path]; grantRoute && len(payload) > maxGrantPayload {
			writeJSONError(w, http.StatusRequestEntityTooLarge, fmt.Sprintf(
				"this action's signed payload would be %d bytes; agents accept at most %d. Act on fewer hosts at once.", len(payload), maxGrantPayload))
			return
		}
		tenantID := s.tenantFromRequest(r)
		if tenantID == "" {
			tenantID = "default"
		}
		requester := s.operatorFromRequest(r)
		if m := r.Header.Get("X-Auth-Method"); m != "" {
			requester += " (" + m + ")"
		}

		id := strings.TrimSpace(r.Header.Get(approvalHeader))
		if id == "" {
			v, err := s.responseAuth.RequestApproval(r.Context(), &responseauth.ApprovalRequestInput{
				TenantID: tenantID, Requester: requester, Kind: plan.Kind, Action: plan.Action,
				Summary: plan.Summary, Targets: plan.Targets, Payload: payload, Release: plan.Release,
				SessionSeconds: plan.SessionSeconds,
			})
			if err != nil {
				s.audit(r, "OWNER_APPROVAL_UNAVAILABLE", strings.Join(plan.Targets, ","), plan.Action+": "+err.Error())
				writeJSONError(w, approvalStatus(err), "owner approval could not be requested: "+err.Error())
				return
			}
			if plan.OnRequested != nil {
				plan.OnRequested(v.ID)
			}
			s.approvalWake.notify()
			if v.State == responseauth.ApprovalApproved && v.Method == "baseline" {
				// A released maintenance package auditing with every default
				// changes nothing; the authority approves it without asking
				// and still checks it when it is spent below.
				s.audit(r, autoApprovedAudit, strings.Join(plan.Targets, ","), fmt.Sprintf("%s (approval %s) approved without asking: a default audit of released packages: %s", plan.Action, v.ID, plan.Summary))
				id = v.ID
			} else if v.State == responseauth.ApprovalApproved && v.Method == "rule" {
				// The authority approved it under the owner's approve-all rule
				// (an owner-signed agent rollout); it is spent below like any
				// approval, and the authority still checks it there.
				s.audit(r, autoApprovedAudit, strings.Join(plan.Targets, ","), fmt.Sprintf("%s (approval %s) approved without asking under the owner's approve-all rule for owner-signed rollouts: %s", plan.Action, v.ID, plan.Summary))
				id = v.ID
			} else {
				s.audit(r, "OWNER_APPROVAL_REQUESTED", strings.Join(plan.Targets, ","), fmt.Sprintf("%s (approval %s): %s", plan.Action, v.ID, plan.Summary))
				writeJSON(w, http.StatusAccepted, map[string]interface{}{
					"approval_id": v.ID,
					"state":       v.State,
					"action":      v.Action,
					"summary":     v.Summary,
					"targets":     v.Targets,
					"expires_at":  v.ExpiresAt,
					"next":        "The owner approves on their phone. Poll GET /api/v1/approvals?id=" + v.ID + "&wait=20, then repeat this request with header " + approvalHeader + ".",
				})
				return
			}
		}
		sum := sha256.Sum256(payload)
		grants, err := s.responseAuth.ConsumeApproval(r.Context(), &responseauth.ApprovalConsumeRequest{
			ID: id, TenantID: tenantID, Requester: requester, Kind: plan.Kind, Digest: hex.EncodeToString(sum[:]), Targets: plan.Targets,
		})
		if err != nil {
			s.audit(r, "OWNER_APPROVAL_REFUSED", strings.Join(plan.Targets, ","), fmt.Sprintf("%s with approval %s: %v", plan.Action, id, err))
			status := approvalStatus(err)
			if status == http.StatusNotFound {
				status = http.StatusForbidden
			}
			writeJSONError(w, status, "owner approval not valid for this request: "+err.Error())
			return
		}
		s.approvalWake.notify()
		ids := make([]string, 0, len(grants))
		for _, g := range grants {
			ids = append(ids, g.GrantID)
		}
		s.audit(r, "OWNER_APPROVAL_USED", strings.Join(plan.Targets, ","), fmt.Sprintf("%s under approval %s, grants %s", plan.Action, id, strings.Join(ids, ",")))
		r = r.WithContext(context.WithValue(r.Context(), grantsCtxKey{}, grants))
		r.Body = io.NopCloser(bytes.NewReader(body))
		// Agents verify the grants themselves. They are kept (pending) before
		// the action runs, so the hub never records an action whose grants it
		// could not keep, and released to agents only once it succeeded; a
		// failed action's grants are withdrawn and never delivered.
		kept, err := s.keepApprovalGrants(r.URL.Path, plan.Kind, payload, grants)
		if err != nil {
			s.audit(r, "OWNER_APPROVAL_UNDELIVERABLE", strings.Join(plan.Targets, ","), fmt.Sprintf("%s under approval %s: %v", plan.Action, id, err))
			writeJSONError(w, http.StatusInternalServerError, "the approved grants could not be kept for delivery; nothing was changed: "+err.Error())
			return
		}
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next(rec, r)
		if len(kept) > 0 {
			if rec.status >= 300 {
				if err := s.store.DeleteEnforcementGrants(kept); err != nil {
					log.Printf("[!] could not withdraw %d pending grant(s) of a failed %s: %v", len(kept), plan.Action, err)
				}
			} else if err := s.store.MarkGrantsDeliverable(s.withoutHeldGrants(kept)); err != nil {
				// The action ran; agents have not been told. Visible in the
				// fleet trust view (hub and agent disagree) and in the audit.
				s.audit(r, "OWNER_APPROVAL_UNDELIVERED", strings.Join(plan.Targets, ","), fmt.Sprintf("%s under approval %s ran, but its grants were not released to agents: %v", plan.Action, id, err))
			}
		}
	}
}

// withoutHeldGrants drops grants a staged rollout keeps pending until its
// canaries are healthy.
func (s *Server) withoutHeldGrants(ids []string) []string {
	held, err := s.store.HeldRolloutGrants()
	if err != nil {
		return nil // deliver nothing now; the reconcile loop settles them
	}
	out := make([]string, 0, len(ids))
	for _, id := range ids {
		if !held[id] {
			out = append(out, id)
		}
	}
	return out
}

// statusRecorder remembers the status a handler wrote.
type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (s *statusRecorder) WriteHeader(code int) {
	s.status = code
	s.ResponseWriter.WriteHeader(code)
}

// Flush keeps streaming handlers working behind the recorder.
func (s *statusRecorder) Flush() {
	if f, ok := s.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func sortedTargets(in []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, t := range in {
		t = strings.TrimSpace(t)
		if t != "" && !seen[t] {
			seen[t] = true
			out = append(out, t)
		}
	}
	sort.Strings(out)
	return out
}

// endpointLabel names an endpoint for the owner: hostname when known.
func (s *Server) endpointLabels(ids []string) string {
	const show = 6
	names := make([]string, 0, show)
	for i, id := range ids {
		if i == show {
			break
		}
		name := id
		if ep, err := s.store.GetEndpoint(id); err == nil && ep != nil && ep.Hostname != "" {
			name = ep.Hostname
		}
		names = append(names, name)
	}
	out := strings.Join(names, ", ")
	if len(ids) > show {
		out += fmt.Sprintf(" and %d more", len(ids)-show)
	}
	return out
}

func decodeInto(w http.ResponseWriter, body []byte, v interface{}) bool {
	if err := json.Unmarshal(body, v); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid json body: "+err.Error())
		return false
	}
	return true
}

// withNormalizedField returns body with one member replaced by its normalized
// value, so the owner approves, the authority signs and the handler records
// the same spelling an agent accepts (no surrounding space, no IPv4-mapped
// form).
func withNormalizedField(w http.ResponseWriter, body []byte, name string, value interface{}) ([]byte, bool) {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(body, &m); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid json body: "+err.Error())
		return nil, false
	}
	raw, err := json.Marshal(value)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, name+": "+err.Error())
		return nil, false
	}
	m[name] = raw
	out, err := json.Marshal(m)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid json body: "+err.Error())
		return nil, false
	}
	return out, true
}

// normalizedAllowIPs validates an isolation's allow list and returns the body
// carrying it normalized (nil when the request has none).
// Ranges are taken only where ranges is set (a single endpoint's isolation,
// checked against its agent afterwards).
func normalizedAllowIPs(w http.ResponseWriter, body []byte, in []string, ranges bool) ([]byte, []string, bool) {
	if len(in) == 0 {
		return nil, nil, true
	}
	out := make([]string, 0, len(in))
	for _, raw := range in {
		validate := validateIP
		if ranges {
			validate = validateAllowEntry
		}
		ip, err := validate(raw)
		if err != nil {
			writeJSONError(w, http.StatusBadRequest, "allow_ips: "+err.Error())
			return nil, nil, false
		}
		out = append(out, ip)
	}
	nb, ok := withNormalizedField(w, body, "allow_ips", out)
	return nb, out, ok
}

func (s *Server) resolveIsolate(w http.ResponseWriter, r *http.Request, body []byte) (*approvalPlan, bool) {
	var req struct {
		EndpointID string   `json:"endpoint_id"`
		AllowIPs   []string `json:"allow_ips"`
		Mode       string   `json:"mode"`
		Force      bool     `json:"force"`
	}
	if !decodeInto(w, body, &req) || !s.endpointInScope(w, r, req.EndpointID) || s.refuseMonitorOnly(w, req.EndpointID) {
		return nil, false
	}
	mode, err := parseIsolationMode(req.Mode)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return nil, false
	}
	if mode == isolationModeFull && len(req.AllowIPs) > 0 {
		writeJSONError(w, http.StatusBadRequest, "full isolation takes no allow_ips; use mode selective")
		return nil, false
	}
	nb, allow, ok := normalizedAllowIPs(w, body, req.AllowIPs, true)
	if !ok {
		return nil, false
	}
	if p := s.allowRangesProblem(req.EndpointID, allow); p != "" {
		writeJSONError(w, http.StatusBadRequest, p)
		return nil, false
	}
	req.AllowIPs = allow
	var notEnforced []string
	var onRequested func(string)
	if mode == isolationModeSelective {
		// The fabric is expanded here, before approval, so the owner approves
		// and the agent enforces the same list. The expansion is pinned to the
		// approval: when the approved request comes back it is reused, so a
		// rule changed or expired meanwhile cannot void the approval.
		approvalID := strings.TrimSpace(r.Header.Get(approvalHeader))
		pin, pinned := s.fabricPins.get(approvalID, req.EndpointID)
		if !pinned {
			p, err := s.fabricPolicyFor(req.EndpointID, time.Now().UTC())
			if err != nil {
				writeJSONError(w, http.StatusConflict, "trust fabric: "+err.Error())
				return nil, false
			}
			pin = fabricPin{endpointID: req.EndpointID, enforced: p.Enforced, notEnforced: p.NotEnforced}
			onRequested = func(id string) { s.fabricPins.put(id, pin) }
		}
		req.AllowIPs = unionAddrs(req.AllowIPs, pin.enforced)
		notEnforced = pin.notEnforced
		if nb == nil {
			nb = body
		}
		if nb, ok = withNormalizedField(w, nb, "allow_ips", req.AllowIPs); !ok {
			return nil, false
		}
	}
	summary := "Cut " + s.endpointLabels([]string{req.EndpointID}) + " off the network"
	if mode != "" {
		summary += " (" + mode + ")"
	}
	if len(req.AllowIPs) > 0 {
		summary += " except " + strings.Join(req.AllowIPs, ", ")
	}
	if len(notEnforced) > 0 {
		summary += "; trusted ranges not enforced (the agent takes single addresses, or the range is too wide): " + strings.Join(notEnforced, ", ")
	}
	if req.Force {
		summary += " (readiness gate overridden)"
	}
	return &approvalPlan{Kind: responseauth.ActionKindIsolation, Action: "Isolate host", Summary: summary, Targets: []string{req.EndpointID}, Body: nb, OnRequested: onRequested}, true
}

func (s *Server) resolveUnisolate(w http.ResponseWriter, r *http.Request, body []byte) (*approvalPlan, bool) {
	var req struct {
		EndpointID string `json:"endpoint_id"`
	}
	if !decodeInto(w, body, &req) || !s.endpointInScope(w, r, req.EndpointID) {
		return nil, false
	}
	return &approvalPlan{Kind: responseauth.ActionKindIsolation, Action: "Release isolation", Summary: "Return " + s.endpointLabels([]string{req.EndpointID}) + " to the network", Targets: []string{req.EndpointID}}, true
}

// bulkScopeProblem refuses a bulk request that does not say what it covers.
// A missing scope used to mean the whole fleet, so a client that sent its
// selection under the wrong field name isolated everything.
func bulkScopeProblem(scope string, ids []string) string {
	switch {
	case scope == "":
		return "scope is required: all, ids, client, location, platform or role"
	case scope == "ids" && len(ids) == 0:
		return "scope ids needs at least one id"
	}
	switch scope {
	case "all", "ids", "client", "location", "platform", "role":
		return ""
	}
	return "unknown scope " + strconv.Quote(scope)
}

func (s *Server) bulkTargets(w http.ResponseWriter, r *http.Request, scope, value string, ids []string) ([]string, bool) {
	if msg := bulkScopeProblem(scope, ids); msg != "" {
		writeJSONError(w, http.StatusBadRequest, msg)
		return nil, false
	}
	if scope == "ids" {
		return s.scopedEndpointIDs(w, r, ids)
	}
	tenantID := ""
	if r.Header.Get("X-Role") == "tenant" {
		tenantID = r.Header.Get("X-Tenant-ID")
	}
	out, err := s.store.BulkIsolationTargets(tenantID, scope, value)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return nil, false
	}
	return out, true
}

func (s *Server) resolveBulkIsolation(isolate bool) approvalResolver {
	return func(w http.ResponseWriter, r *http.Request, body []byte) (*approvalPlan, bool) {
		var req struct {
			Scope    string   `json:"scope"`
			Value    string   `json:"value"`
			IDs      []string `json:"ids"`
			AllowIPs []string `json:"allow_ips"`
			Force    bool     `json:"force"`
		}
		if !decodeInto(w, body, &req) {
			return nil, false
		}
		targets, ok := s.bulkTargets(w, r, req.Scope, req.Value, req.IDs)
		if !ok {
			return nil, false
		}
		if isolate {
			nb, _, ok := normalizedAllowIPs(w, body, req.AllowIPs, false)
			if !ok {
				return nil, false
			}
			// Monitor-only endpoints (hypervisors) are left out of the
			// approval, so the grants never name them.
			allowed, monitor, ok := s.splitMonitorOnly(w, targets)
			if !ok {
				return nil, false
			}
			if len(allowed) == 0 && len(monitor) > 0 {
				writeMonitorOnly(w, monitor, "")
				return nil, false
			}
			summary := fmt.Sprintf("Cut %d host(s) off the network: %s", len(allowed), s.endpointLabels(allowed))
			if len(monitor) > 0 {
				summary += fmt.Sprintf(" (%d monitor-only host(s) left out: %s)", len(monitor), s.endpointLabels(monitor))
			}
			return &approvalPlan{Kind: responseauth.ActionKindIsolation, Action: "Isolate hosts", Summary: summary, Targets: allowed, Body: nb}, true
		}
		return &approvalPlan{Kind: responseauth.ActionKindIsolation, Action: "Release isolation",
			Summary: fmt.Sprintf("Return %d host(s) to the network: %s", len(targets), s.endpointLabels(targets)), Targets: targets}, true
	}
}

func (s *Server) resolveAgentUpdate(w http.ResponseWriter, r *http.Request, body []byte) (*approvalPlan, bool) {
	if r.Header.Get("X-Role") != "admin" {
		writeJSONError(w, http.StatusForbidden, "admin role required")
		return nil, false
	}
	var req struct {
		EndpointIDs []string `json:"endpoint_ids"`
		All         bool     `json:"all"`
		Version     string   `json:"version"`
		Canary      []string `json:"canary"`
	}
	if !decodeInto(w, body, &req) {
		return nil, false
	}
	version := strings.TrimSpace(req.Version)
	var newBody []byte
	if version == "" {
		// The version the owner approves is the one installed: resolve it
		// now and carry it in the digested body, so a desired-version change
		// between approval and use refuses the approval instead.
		version = s.desiredAgentVersion()
		var m map[string]interface{}
		if err := json.Unmarshal(body, &m); err != nil || m == nil {
			m = map[string]interface{}{}
		}
		m["version"] = version
		newBody, _ = json.Marshal(m)
	}
	targets := req.EndpointIDs
	if req.All {
		eps, err := s.store.ListEndpoints("")
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, err.Error())
			return nil, false
		}
		targets = nil
		for _, ep := range eps {
			if ep.Status != "retired" {
				targets = append(targets, ep.ID)
			}
		}
	}
	scope := s.endpointLabels(sortedTargets(targets))
	if req.All {
		scope = "the whole fleet (" + scope + ")"
	}
	summary := "Install agent " + version + " on " + scope
	if canary := sortedTargets(req.Canary); len(canary) > 0 {
		if p := canaryProblem(canary, sortedTargets(targets)); p != "" {
			writeJSONError(w, http.StatusBadRequest, p)
			return nil, false
		}
		summary += fmt.Sprintf(": %s first; the other %d approved endpoint(s) only once every canary runs %s with a clean provenance check, otherwise the rollout halts (within %d minutes)",
			s.endpointLabels(canary), len(sortedTargets(targets))-len(canary), version, int(rolloutCanaryDeadline/time.Minute))
	}
	return &approvalPlan{Kind: responseauth.ActionKindAgentUpdate, Action: "Update agents",
		Summary: summary, Targets: targets, Body: newBody, Release: s.releaseEvidence(version)}, true
}

// releaseEvidence is the published agent packages of version with their
// release signatures, for the authority to verify; nil when any is missing
// (the rollout is then asked for as before).
func (s *Server) releaseEvidence(version string) []responseauth.ReleaseEvidence {
	var out []responseauth.ReleaseEvidence
	for _, pkg := range []string{"deb", "windows-native"} {
		name, sha, ok := s.signedAgentPackage(version, pkg)
		if !ok {
			return nil
		}
		sig, err := os.ReadFile(filepath.Join(s.binaryDir, name+".release.sig"))
		if err != nil || len(sig) == 0 || len(sig) > 512 {
			return nil
		}
		out = append(out, responseauth.ReleaseEvidence{Package: name, SHA256: sha, Sig: base64.StdEncoding.EncodeToString(sig)})
	}
	return out
}

func (s *Server) resolveMesh(quarantine bool) approvalResolver {
	return func(w http.ResponseWriter, r *http.Request, body []byte) (*approvalPlan, bool) {
		var req MeshQuarantineRequest
		if !decodeInto(w, body, &req) {
			return nil, false
		}
		ip, err := validateIP(req.TargetIP)
		if err != nil {
			writeJSONError(w, http.StatusBadRequest, "target_ip: "+err.Error())
			return nil, false
		}
		nb, ok := withNormalizedField(w, body, "target_ip", ip)
		if !ok {
			return nil, false
		}
		if quarantine {
			// Refused before the owner is asked: the handler would refuse it anyway.
			if why := s.hubOwnsAddress(ip); why != "" {
				writeJSONError(w, http.StatusConflict, "target_ip: "+ip+" is this hub's own address ("+why+"). Quarantining it would cut every agent off from the only host that can lift the quarantine.")
				return nil, false
			}
			return &approvalPlan{Kind: responseauth.ActionKindMesh, Action: "Quarantine address",
				Summary: "Every agent drops traffic to and from " + ip + " (" + strings.TrimSpace(req.Reason) + ")", Targets: []string{"mesh:" + ip}, Body: nb}, true
		}
		return &approvalPlan{Kind: responseauth.ActionKindMesh, Action: "Lift quarantine",
			Summary: "Agents stop dropping traffic for " + ip, Targets: []string{"mesh:" + ip}, Body: nb}, true
	}
}

// handleApprovals lets a requester follow its approval: GET ?id=&wait=N
// long-polls up to N seconds (max 25) for a change from pending. DELETE ?id=
// withdraws the caller's own pending approval (a client that stopped waiting
// must not leave the owner an ask nobody will use): the authority records a
// deny, which needs no passkey because it only refuses, and the relay closes
// the owner's notification when the approval leaves the pending list.
func (s *Server) handleApprovals(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodDelete {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if s.responseAuth == nil {
		writeJSONError(w, http.StatusServiceUnavailable, "response authority not available")
		return
	}
	id := strings.TrimSpace(r.URL.Query().Get("id"))
	if id == "" {
		writeJSONError(w, http.StatusBadRequest, "id is required")
		return
	}
	tenantID := s.tenantFromRequest(r)
	if tenantID == "" {
		tenantID = "default"
	}
	if r.Method == http.MethodDelete {
		s.withdrawApproval(w, r, id, tenantID)
		return
	}
	wait := parseWait(r.URL.Query().Get("wait"))
	deadline := time.Now().Add(wait)
	for {
		wake := s.approvalWake.wait()
		v, err := s.responseAuth.GetApproval(r.Context(), id, tenantID)
		if err != nil {
			writeJSONError(w, approvalStatus(err), err.Error())
			return
		}
		if v.State != responseauth.ApprovalPending || time.Now().After(deadline) {
			writeJSON(w, http.StatusOK, publicApproval(v))
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

func (s *Server) withdrawApproval(w http.ResponseWriter, r *http.Request, id, tenantID string) {
	v, err := s.responseAuth.GetApproval(r.Context(), id, tenantID)
	if err != nil {
		writeJSONError(w, approvalStatus(err), err.Error())
		return
	}
	requester := s.operatorFromRequest(r)
	if m := r.Header.Get("X-Auth-Method"); m != "" {
		requester += " (" + m + ")"
	}
	if v.Requester != requester {
		writeJSONError(w, http.StatusForbidden, "only the requester can withdraw an approval")
		return
	}
	if v.State != responseauth.ApprovalPending {
		writeJSONError(w, http.StatusConflict, "approval is already "+string(v.State))
		return
	}
	v, err = s.responseAuth.AnswerApproval(r.Context(), &responseauth.ApprovalAnswer{ID: id, Decision: "deny"})
	if err != nil {
		writeJSONError(w, approvalStatus(err), err.Error())
		return
	}
	s.approvalWake.notify()
	s.audit(r, "OWNER_APPROVAL_WITHDRAWN", id, "withdrawn by "+requester+": "+v.Action+" - "+v.Summary)
	writeJSON(w, http.StatusOK, publicApproval(v))
}

// handleApprovalRules shows (GET) or removes (DELETE) the owner's approve-all
// rule for owner-signed agent rollouts. Removing only narrows what runs
// without asking, so the admin credential is enough.
func (s *Server) handleApprovalRules(w http.ResponseWriter, r *http.Request) {
	if s.responseAuth == nil {
		writeJSONError(w, http.StatusServiceUnavailable, "response authority not available")
		return
	}
	tenantID := s.tenantFromRequest(r)
	if tenantID == "" {
		tenantID = "default"
	}
	switch r.Method {
	case http.MethodGet:
		rules, err := s.responseAuth.RolloutRules(r.Context(), tenantID)
		if err != nil {
			writeJSONError(w, approvalStatus(err), err.Error())
			return
		}
		pkgs, err := s.responseAuth.PackageRules(r.Context(), tenantID)
		if err != nil {
			writeJSONError(w, approvalStatus(err), err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]interface{}{"rules": rules, "package_rules": pkgs})
	case http.MethodDelete:
		if r.URL.Query().Get("kind") == "packages" {
			// One package rule (?id=) or all of them.
			id := r.URL.Query().Get("id")
			n, err := s.responseAuth.ForgetPackageRule(r.Context(), tenantID, id, s.operatorFromRequest(r))
			if err != nil {
				writeJSONError(w, approvalStatus(err), err.Error())
				return
			}
			if n > 0 {
				s.audit(r, rolloutRuleRemovedAudit, tenantID, fmt.Sprintf("Removed %d approve-all rule(s) for maintenance packages; those runs ask the owner again; credential %s", n, credentialOf(r)))
			}
			writeJSON(w, http.StatusOK, map[string]interface{}{"removed": n > 0, "count": n})
			return
		}
		had, err := s.responseAuth.ForgetRolloutRule(r.Context(), tenantID, s.operatorFromRequest(r))
		if err != nil {
			writeJSONError(w, approvalStatus(err), err.Error())
			return
		}
		if had {
			s.audit(r, rolloutRuleRemovedAudit, tenantID, "Removed the approve-all rule for owner-signed agent rollouts; rollouts ask the owner again; credential "+credentialOf(r))
		}
		writeJSON(w, http.StatusOK, map[string]bool{"removed": had})
	default:
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func parseWait(s string) time.Duration {
	var n int
	if _, err := fmt.Sscanf(s, "%d", &n); err != nil || n < 0 {
		return 0
	}
	if n > 25 {
		n = 25
	}
	return time.Duration(n) * time.Second
}

// publicApproval is what requesters see: state and words, not the signed
// statement (the relay gets that).
func publicApproval(v *responseauth.ApprovalView) map[string]interface{} {
	return map[string]interface{}{
		"id": v.ID, "state": v.State, "action": v.Action, "summary": v.Summary, "targets": v.Targets,
		"requester": v.Requester, "created_at": v.CreatedAt, "expires_at": v.ExpiresAt,
		"decided_at": v.DecidedAt, "use_by": v.UseBy,
	}
}
