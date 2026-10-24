package server

// Authorizing high-impact operations. The static admin key, a console session
// or a JWT minted from the admin key can ask for an isolation change, an agent
// update, a mesh quarantine, a terminal, a screen session or a package run.
// The hub works out what the request would do, hands that to the response
// authority, which checks it, puts it in its own words for the audit and signs
// the grants for each target. Then the handler runs. Nobody is asked: an
// action the authority will not sign is refused with the reason (HTTP 4xx), and
// the endpoints still accept only grants the authority signed, check them
// themselves and enforce their own locks and capability limits.
//
// The detector's automatic isolation is not an HTTP caller: it runs inside
// the hub (see New) and keeps working as it must for a host that is attacking
// at 3am. Read routes and policy routes stay on the ordinary scoped
// credentials.

import (
	"bytes"
	"context"
	"encoding/base64"
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
	"time"

	"ominull/hub/pkg/response"
	"ominull/hub/pkg/responseauth"
)

// approvalHeader carries the authorization id to the handler an authorized
// route runs. The middleware sets it itself; whatever a caller sent is dropped.
const approvalHeader = "X-Approval-ID"

type grantsCtxKey struct{}

// approvalGrants returns the grants the authorization produced for this request.
func approvalGrants(r *http.Request) []*response.EndpointGrant {
	g, _ := r.Context().Value(grantsCtxKey{}).([]*response.EndpointGrant)
	return g
}

// grantedTargets is the endpoint set the authority signed for this request, or
// nil when the request carried no grants (the in-hub automatic paths). A
// handler that resolves its targets from a scope uses this instead, so a
// fleet that changed between authorization and use cannot widen the action.
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

// actionPlan is what one gated request would do, worked out before the
// authority is asked to sign it.
type actionPlan struct {
	Kind    response.ActionKind
	Action  string
	Summary string
	Targets []string
	Payload []byte // the digested action; nil means route + canonical body + targets
	Body    []byte // replaces the request body (digested and handed on) when set
	// Release is the signed agent packages an agent update installs; the
	// authority reads it to tell a release signed with a routine key.
	Release []responseauth.ReleaseEvidence
	// RoutineKeys is the signed routine key list beside Release; the
	// authority verifies it against the pinned release key itself.
	RoutineKeys *response.RoutineKeys
	// SessionSeconds is how long a terminal or screen session may run
	// (audited, not part of the digest).
	SessionSeconds int64
	// AskFirst: a screen session asks the person at the keyboard first
	// (audited, not digested).
	AskFirst bool
	// StewardRun is the stuck maintenance run a steward screen request is for.
	StewardRun string
}

// agentLabelHeader is the name an agent calling with the shared hub admin
// key gives itself (ominullctl sends it). It is self-declared: the audit
// shows it as a claim ("an agent calling itself
// ..."), never as an identity. Per-agent keys would be the real fix.
const agentLabelHeader = "X-Ominull-Agent"

// agentLabel is the request's self-declared agent label: "" when it carries
// none or was not made with the admin key (only an admin-key caller is an
// agent); ok is false when an admin-key caller sent an unusable one.
func agentLabel(r *http.Request) (string, bool) {
	if r.Header.Get("X-Auth-Method") != "api-key" || r.Header.Get("X-Role") != "admin" {
		return "", true
	}
	vals := r.Header.Values(agentLabelHeader)
	switch len(vals) {
	case 0:
		return "", true
	case 1:
		v := strings.TrimSpace(vals[0])
		if responseauth.ValidAgentLabel(v) {
			return v, true
		}
	}
	return "", false
}

// actionResolver validates a request and describes it. It writes its own
// error response and returns ok=false to stop.
type actionResolver func(w http.ResponseWriter, r *http.Request, body []byte) (*actionPlan, bool)

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

func authorizeStatus(err error) int {
	var ae *responseauth.AuthorityError
	if errors.As(err, &ae) && ae.Status != 0 {
		return ae.Status
	}
	return http.StatusServiceUnavailable
}

// authorized has the authority sign the grants for a POST route, then runs the
// handler. Other methods pass straight through (GET and DELETE on the
// terminal route).
func (s *Server) authorized(resolve actionResolver, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			next(w, r)
			return
		}
		if s.responseAuth == nil {
			writeJSONError(w, http.StatusServiceUnavailable, "the response authority is not available, so this action cannot be signed")
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
				// The exceptions are signed with the isolation; agents use
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
		label, ok := agentLabel(r)
		if !ok {
			writeJSONError(w, http.StatusBadRequest, agentLabelHeader+" must be 1 to 64 printable characters, without quotes or backslashes")
			return
		}

		au, err := s.responseAuth.Authorize(r.Context(), &responseauth.AuthorizeInput{
			TenantID: tenantID, Requester: requester, Kind: plan.Kind, Targets: plan.Targets, Payload: payload,
			Release: plan.Release, RoutineKeys: plan.RoutineKeys, SessionSeconds: plan.SessionSeconds,
			AskFirst: plan.AskFirst, AgentLabel: label, StewardRun: plan.StewardRun,
		})
		if err != nil {
			s.audit(r, "ACTION_REFUSED", strings.Join(plan.Targets, ","), plan.Action+": "+err.Error())
			writeJSONError(w, authorizeStatus(err), "the authority did not sign this action: "+err.Error())
			return
		}
		id, grants := au.ID, au.Grants
		ids := make([]string, 0, len(grants))
		for _, g := range grants {
			ids = append(ids, g.GrantID)
		}
		s.audit(r, "ACTION_AUTHORIZED", strings.Join(plan.Targets, ","), fmt.Sprintf("%s (authorization %s), grants %s: %s", plan.Action, id, strings.Join(ids, ","), plan.Summary))
		r = r.WithContext(context.WithValue(r.Context(), grantsCtxKey{}, grants))
		r.Body = io.NopCloser(bytes.NewReader(body))
		// The handler sees the authorization it runs under (a run's id).
		r.Header.Set(approvalHeader, id)
		// Agents verify the grants themselves. They are kept (pending) before
		// the action runs, so the hub never records an action whose grants it
		// could not keep, and released to agents only once it succeeded; a
		// failed action's grants are withdrawn and never delivered.
		kept, err := s.keepApprovalGrants(r.URL.Path, plan.Kind, payload, grants)
		if err != nil {
			s.audit(r, "ACTION_UNDELIVERABLE", strings.Join(plan.Targets, ","), fmt.Sprintf("%s under authorization %s: %v", plan.Action, id, err))
			writeJSONError(w, http.StatusInternalServerError, "the signed grants could not be kept for delivery; nothing was changed: "+err.Error())
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
				s.audit(r, "ACTION_UNDELIVERED", strings.Join(plan.Targets, ","), fmt.Sprintf("%s under authorization %s ran, but its grants were not released to agents: %v", plan.Action, id, err))
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

// endpointLabels names endpoints: hostname when known.
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
// value, so the authority signs and the handler records
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

func (s *Server) resolveIsolate(w http.ResponseWriter, r *http.Request, body []byte) (*actionPlan, bool) {
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
	if mode == isolationModeSelective {
		// The fabric is expanded here, before the authority signs, so the
		// signed list and the one the agent enforces are the same.
		p, err := s.fabricPolicyFor(req.EndpointID, time.Now().UTC())
		if err != nil {
			writeJSONError(w, http.StatusConflict, "trust fabric: "+err.Error())
			return nil, false
		}
		req.AllowIPs = unionAddrs(req.AllowIPs, p.Enforced)
		notEnforced = p.NotEnforced
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
	return &actionPlan{Kind: responseauth.ActionKindIsolation, Action: "Isolate host", Summary: summary, Targets: []string{req.EndpointID}, Body: nb}, true
}

func (s *Server) resolveUnisolate(w http.ResponseWriter, r *http.Request, body []byte) (*actionPlan, bool) {
	var req struct {
		EndpointID string `json:"endpoint_id"`
	}
	if !decodeInto(w, body, &req) || !s.endpointInScope(w, r, req.EndpointID) {
		return nil, false
	}
	return &actionPlan{Kind: responseauth.ActionKindIsolation, Action: "Release isolation", Summary: "Return " + s.endpointLabels([]string{req.EndpointID}) + " to the network", Targets: []string{req.EndpointID}}, true
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

func (s *Server) resolveBulkIsolation(isolate bool) actionResolver {
	return func(w http.ResponseWriter, r *http.Request, body []byte) (*actionPlan, bool) {
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
			// authorization, so the grants never name them.
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
			return &actionPlan{Kind: responseauth.ActionKindIsolation, Action: "Isolate hosts", Summary: summary, Targets: allowed, Body: nb}, true
		}
		return &actionPlan{Kind: responseauth.ActionKindIsolation, Action: "Release isolation",
			Summary: fmt.Sprintf("Return %d host(s) to the network: %s", len(targets), s.endpointLabels(targets)), Targets: targets}, true
	}
}

func (s *Server) resolveAgentUpdate(w http.ResponseWriter, r *http.Request, body []byte) (*actionPlan, bool) {
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
	if s.agentVersionRetired(version) {
		writeJSONError(w, http.StatusConflict, "agent "+version+" was retired (rolled back); release a newer version instead")
		return nil, false
	}
	var newBody []byte
	if version == "" {
		// The version signed is the one installed: resolve it
		// now and carry it in the digested body, so a desired-version change
		// between authorization and use cannot change what was signed.
		version = s.desiredAgentVersion()
		var m map[string]interface{}
		if err := json.Unmarshal(body, &m); err != nil || m == nil {
			m = map[string]interface{}{}
		}
		m["version"] = version
		newBody, _ = json.Marshal(m)
	}
	if !releaseVersionText(version) {
		// Checked before anything else: a command line misread once sent a
		// host id as the version.
		writeJSONError(w, http.StatusBadRequest, fmt.Sprintf("version %q is not a release version (like 1.8.86)", version))
		return nil, false
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
	if !req.All {
		if len(targets) == 0 {
			writeJSONError(w, http.StatusBadRequest, "endpoint_ids or all is required")
			return nil, false
		}
		if _, ok := s.scopedEndpointIDs(w, r, append(append([]string{}, targets...), req.Canary...)); !ok {
			return nil, false
		}
	}
	scope := s.endpointLabels(sortedTargets(targets))
	if req.All {
		scope = "the whole fleet (" + scope + ")"
	}
	summary := "Install agent " + version + " on " + scope
	rk, _ := s.routineKeys()
	if len(sortedTargets(targets)) > 1 && len(sortedTargets(req.Canary)) == 0 && s.releaseSignedByRoutine(version) {
		writeJSONError(w, http.StatusConflict, "agent "+version+" was signed with a routine key, so it rolls out canaries first: name the canaries")
		return nil, false
	}
	if canary := sortedTargets(req.Canary); len(canary) > 0 {
		if p := canaryProblem(canary, sortedTargets(targets)); p != "" {
			writeJSONError(w, http.StatusBadRequest, p)
			return nil, false
		}
		summary += fmt.Sprintf(": %s first; the other %d approved endpoint(s) only once every canary runs %s with a clean provenance check, otherwise the rollout halts (within %d minutes)",
			s.endpointLabels(canary), len(sortedTargets(targets))-len(canary), version, int(rolloutCanaryDeadline/time.Minute))
	}
	return &actionPlan{Kind: responseauth.ActionKindAgentUpdate, Action: "Update agents",
		Summary: summary, Targets: targets, Body: newBody, Release: s.releaseEvidence(version), RoutineKeys: rk}, true
}

// releaseEvidence is the published agent packages of version with their
// release signatures, for the authority to verify; nil when any is missing
// (the authority then reads no release for the rollout).
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

func (s *Server) resolveMesh(quarantine bool) actionResolver {
	return func(w http.ResponseWriter, r *http.Request, body []byte) (*actionPlan, bool) {
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
			// Refused before signing: the handler would refuse it anyway.
			if why := s.hubOwnsAddress(ip); why != "" {
				writeJSONError(w, http.StatusConflict, "target_ip: "+ip+" is this hub's own address ("+why+"). Quarantining it would cut every agent off from the only host that can lift the quarantine.")
				return nil, false
			}
			return &actionPlan{Kind: responseauth.ActionKindMesh, Action: "Quarantine address",
				Summary: "Every agent drops traffic to and from " + ip + " (" + strings.TrimSpace(req.Reason) + ")", Targets: []string{"mesh:" + ip}, Body: nb}, true
		}
		return &actionPlan{Kind: responseauth.ActionKindMesh, Action: "Lift quarantine",
			Summary: "Agents stop dropping traffic for " + ip, Targets: []string{"mesh:" + ip}, Body: nb}, true
	}
}

// releaseVersionText: digits in two to four dot-separated parts, optional v.
func releaseVersionText(v string) bool {
	parts := strings.Split(strings.TrimPrefix(v, "v"), ".")
	if len(parts) < 2 || len(parts) > 4 {
		return false
	}
	for _, p := range parts {
		if p == "" || len(p) > 6 || strings.Trim(p, "0123456789") != "" {
			return false
		}
	}
	return true
}
