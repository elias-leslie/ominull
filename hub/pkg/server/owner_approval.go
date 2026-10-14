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
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"ominull/hub/pkg/response"
	"ominull/hub/pkg/responseauth"
)

const approvalHeader = "X-Approval-ID"

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
			payload, _ = json.Marshal(map[string]interface{}{
				"route":   r.URL.Path,
				"body":    json.RawMessage(canon),
				"targets": plan.Targets,
			})
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
				Summary: plan.Summary, Targets: plan.Targets, Payload: payload,
			})
			if err != nil {
				s.audit(r, "OWNER_APPROVAL_UNAVAILABLE", strings.Join(plan.Targets, ","), plan.Action+": "+err.Error())
				writeJSONError(w, approvalStatus(err), "owner approval could not be requested: "+err.Error())
				return
			}
			s.approvalWake.notify()
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
		next(w, r)
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

func (s *Server) resolveIsolate(w http.ResponseWriter, r *http.Request, body []byte) (*approvalPlan, bool) {
	var req struct {
		EndpointID string   `json:"endpoint_id"`
		AllowIPs   []string `json:"allow_ips"`
		Force      bool     `json:"force"`
	}
	if !decodeInto(w, body, &req) || !s.endpointInScope(w, r, req.EndpointID) || s.refuseMonitorOnly(w, req.EndpointID) {
		return nil, false
	}
	summary := "Cut " + s.endpointLabels([]string{req.EndpointID}) + " off the network"
	if len(req.AllowIPs) > 0 {
		summary += " except " + strings.Join(req.AllowIPs, ", ")
	}
	if req.Force {
		summary += " (readiness gate overridden)"
	}
	return &approvalPlan{Kind: responseauth.ActionKindIsolation, Action: "Isolate host", Summary: summary, Targets: []string{req.EndpointID}}, true
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
			return &approvalPlan{Kind: responseauth.ActionKindIsolation, Action: "Isolate hosts", Summary: summary, Targets: allowed}, true
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
	return &approvalPlan{Kind: responseauth.ActionKindAgentUpdate, Action: "Update agents",
		Summary: "Install agent " + version + " on " + scope, Targets: targets, Body: newBody}, true
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
		if quarantine {
			// Refused before the owner is asked: the handler would refuse it anyway.
			if why := s.hubOwnsAddress(ip); why != "" {
				writeJSONError(w, http.StatusConflict, "target_ip: "+ip+" is this hub's own address ("+why+"). Quarantining it would cut every agent off from the only host that can lift the quarantine.")
				return nil, false
			}
			return &approvalPlan{Kind: responseauth.ActionKindMesh, Action: "Quarantine address",
				Summary: "Every agent drops traffic to and from " + ip + " (" + strings.TrimSpace(req.Reason) + ")", Targets: []string{"mesh:" + ip}}, true
		}
		return &approvalPlan{Kind: responseauth.ActionKindMesh, Action: "Lift quarantine",
			Summary: "Agents stop dropping traffic for " + ip, Targets: []string{"mesh:" + ip}}, true
	}
}

// handleApprovals lets a requester follow its approval: GET ?id=&wait=N
// long-polls up to N seconds (max 25) for a change from pending.
func (s *Server) handleApprovals(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
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
