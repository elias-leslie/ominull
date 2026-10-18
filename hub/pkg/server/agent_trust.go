package server

// Agent trust, hub side. The hub carries the response authority's signed
// statements to agents and no longer decides what an agent does to itself:
//
//   - the three public keys an agent pins (response, auto-isolate, policy),
//     offered with the release key's signature over them (the trust bundle,
//     signed by the owner with scripts/sign-trust-bundle.sh) until the agent
//     reports them pinned; the hub cannot make that signature;
//   - the endpoint's capability manifest, offered until the agent holds it;
//   - enforcement grants (isolation, release, mesh quarantine) the owner
//     approved or the detector's narrow key signed, newest first per slot,
//     after the watermark the agent reports;
//   - the owner's grant for an agent update, next to the update descriptor.
//
// Agents from 1.8.59 verify all of it themselves (agent/include/agent_trust.h);
// is_isolated, isolation_allow_ips and quarantined_peers stay in the answer
// for older agents and for an upgraded agent's one-time bootstrap (which takes
// a hub isolation only with a dead-man; see agent_trust.h).

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"reflect"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"ominull/hub/pkg/response"
	"ominull/hub/pkg/responseauth"
	"ominull/hub/pkg/storage"
)

// grantVerifyingAgentVersion is the first agent release that verifies
// enforcement grants and update grants itself.
const grantVerifyingAgentVersion = "1.8.59"

const (
	trustKeysTTL      = 10 * time.Minute
	maxMeshGrantsSent = 4
)

type trustReportSeen struct {
	report response.AgentTrustReport
	at     time.Time
}

type agentTrustCache struct {
	mu        sync.Mutex
	keys      map[string]*response.TrustKeys
	keysAt    map[string]time.Time
	manifests map[string]*response.CapabilityManifest
	reports   map[string]trustReportSeen
	// releasePub verifies trust bundle signatures; tests swap it.
	releasePub []byte
}

func trustBundleSettingKey(tenantID string) string { return "trust_bundle:" + tenantID }

// storedBundle is the owner's signature over a tenant's trust statement.
type storedBundle struct {
	Epoch     int64  `json:"epoch"`
	Signature string `json:"signature"`
}

func (s *Server) loadBundle(tenantID string) (storedBundle, bool) {
	var b storedBundle
	raw, _ := s.store.GetSetting(trustBundleSettingKey(tenantID))
	if raw == "" || json.Unmarshal([]byte(raw), &b) != nil || b.Epoch < 1 || b.Signature == "" {
		return storedBundle{}, false
	}
	return b, true
}

func (c *agentTrustCache) init() {
	if c.keys == nil {
		c.keys = map[string]*response.TrustKeys{}
		c.keysAt = map[string]time.Time{}
		c.manifests = map[string]*response.CapabilityManifest{}
		c.reports = map[string]trustReportSeen{}
	}
}

func endpointTenant(ep *storage.Endpoint) string {
	if ep != nil && strings.TrimSpace(ep.TenantID) != "" {
		return ep.TenantID
	}
	return "default"
}

func (s *Server) trustKeys(ctx context.Context, tenantID string) *response.TrustKeys {
	if s.responseAuth == nil {
		return nil
	}
	c := &s.trust
	c.mu.Lock()
	c.init()
	if k, ok := c.keys[tenantID]; ok && time.Since(c.keysAt[tenantID]) < trustKeysTTL {
		c.mu.Unlock()
		return k
	}
	c.mu.Unlock()
	k, err := s.responseAuth.TrustKeys(ctx, tenantID)
	if err != nil {
		log.Printf("[!] trust keys for tenant %q unavailable: %v", tenantID, err)
		return nil
	}
	k.TenantID = tenantID
	// A stored signature is used only while it still covers these exact keys
	// at the authority's current epoch.
	if b, ok := s.loadBundle(tenantID); ok {
		if b.Epoch == k.Epoch && s.verifyTrustBundle(k, b.Signature) == nil {
			k.BundleSig = b.Signature
		} else {
			log.Printf("[!] the trust bundle signature for tenant %q no longer matches the authority's keys; sign it again", tenantID)
		}
	}
	c.mu.Lock()
	c.keys[tenantID] = k
	c.keysAt[tenantID] = time.Now()
	c.mu.Unlock()
	return k
}

func (s *Server) releasePublicKey() []byte {
	s.trust.mu.Lock()
	defer s.trust.mu.Unlock()
	if s.trust.releasePub != nil {
		return s.trust.releasePub
	}
	return []byte(response.ReleasePublicKeyPEM)
}

func (s *Server) verifyTrustBundle(k *response.TrustKeys, sigB64 string) error {
	der, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil || len(der) == 0 || len(der) > 80 {
		return fmt.Errorf("signature is not base64 DER")
	}
	return response.VerifyReleaseSignature(s.releasePublicKey(), []byte(response.TrustBundleStatement(k)), der)
}

// endpointManifest returns the endpoint's manifest, asking the authority on a
// cache miss. profile "" keeps whatever the authority holds; a narrower
// profile than the current one is signed without an approval.
func (s *Server) endpointManifest(ctx context.Context, tenantID, endpointID, profile string, refresh bool) *response.CapabilityManifest {
	if s.responseAuth == nil {
		return nil
	}
	c := &s.trust
	c.mu.Lock()
	c.init()
	m, ok := c.manifests[endpointID]
	c.mu.Unlock()
	if ok && !refresh && m.MatchesProfile() && (profile == "" || !response.ProfileNarrows(m.Profile, profile)) {
		return m
	}
	m, err := s.responseAuth.EndpointManifest(ctx, &responseauth.ManifestRequest{TenantID: tenantID, EndpointID: endpointID, Profile: profile})
	if err != nil {
		log.Printf("[!] capability manifest for %s unavailable: %v", endpointID, err)
		return nil
	}
	c.mu.Lock()
	c.manifests[endpointID] = m
	c.mu.Unlock()
	return m
}

func knownProfile(p string) bool {
	_, ok := response.ProfileCaps(p)
	return ok
}

// monitorOnlyClamp is the profile a monitor-only host is held to: monitor,
// unless its manifest is already a profile that adds no isolation
// (monitor-scripts, which the owner approved), which then stands.
func (s *Server) monitorOnlyClamp(endpointID, reported string) string {
	s.trust.mu.Lock()
	s.trust.init()
	m := s.trust.manifests[endpointID]
	if seen, ok := s.trust.reports[endpointID]; ok && reported == "" {
		reported = seen.report.Profile
	}
	s.trust.mu.Unlock()
	cur := reported
	if m != nil {
		cur = m.Profile
	}
	if cur != "monitor" && response.MonitorOnlyProfile(cur) {
		return cur
	}
	return "monitor"
}

// initialProfile is what an endpoint's first manifest pins: monitor for a
// monitor-only host, respond for everything else (home machines keep the
// terminal by the owner's decision; each session still needs a tap).
func initialProfile(ep *storage.Endpoint) string {
	if ep != nil && ep.MonitorOnly {
		return "monitor"
	}
	return "respond"
}

func storedToWire(g *storage.StoredGrant) (*response.EnforcementGrant, error) {
	var eg response.EndpointGrant
	if err := json.Unmarshal([]byte(g.GrantJSON), &eg); err != nil {
		return nil, err
	}
	return &response.EnforcementGrant{Grant: &eg, PayloadB64: base64.StdEncoding.EncodeToString(g.Payload)}, nil
}

// addTrustControl puts what a grant-verifying agent needs into its heartbeat
// answer. Errors here never fail the heartbeat: an agent that misses a grant
// gets it on the next beat.
func (s *Server) addTrustControl(ctx context.Context, resp map[string]interface{}, ep *storage.Endpoint, report *response.AgentTrustReport) {
	if report == nil || ep == nil || s.responseAuth == nil {
		return
	}
	tenantID := endpointTenant(ep)
	s.trust.mu.Lock()
	s.trust.init()
	s.trust.reports[ep.ID] = trustReportSeen{report: *report, at: time.Now()}
	s.trust.mu.Unlock()

	if report.Keys != "pinned" {
		// Unsigned keys are not offered: an agent would refuse them anyway.
		if k := s.trustKeys(ctx, tenantID); k != nil && k.BundleSig != "" {
			resp["trust"] = k
		}
	}
	// The release-key signed routine keys, until the agent reports pinning
	// this epoch (older agents ignore the field).
	if rk, _ := s.routineKeys(); rk != nil && report.RoutineEpoch < rk.Epoch {
		resp["routine_keys"] = rk
	}
	profile := ""
	if ep.MonitorOnly {
		profile = s.monitorOnlyClamp(ep.ID, report.Profile)
	} else if report.ManifestSeq == 0 {
		profile = initialProfile(ep)
	}
	if m := s.endpointManifest(ctx, tenantID, ep.ID, profile, false); m != nil && m.Seq != report.ManifestSeq {
		resp["capability_manifest"] = m
	}

	now := time.Now().Unix()
	var grants []*response.EnforcementGrant
	if g, err := s.store.LatestIsolationGrant(ep.ID, report.IsoSeen, now); err == nil && g != nil {
		if w, err := storedToWire(g); err == nil {
			grants = append(grants, w)
		}
	}
	if list, err := s.store.MeshGrantsAfter(report.MeshSeen, now, maxMeshGrantsSent); err == nil {
		for i := range list {
			if list[i].TenantID != tenantID {
				continue
			}
			if w, err := storedToWire(&list[i]); err == nil {
				grants = append(grants, w)
			}
		}
	}
	if len(grants) > 0 {
		resp["enforcement_grants"] = grants
	}
}

// ------------------------------------------------------------- trust bundle

// handleTrustStatement shows what the release key has to sign for a tenant's
// agents to pin its authority keys. The owner compares it with the statement
// read on the authority's own host before signing (sign-trust-bundle.sh).
func (s *Server) handleTrustStatement(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if r.Header.Get("X-Role") != "admin" {
		writeJSONError(w, http.StatusForbidden, "admin role required")
		return
	}
	tenantID := strings.TrimSpace(r.URL.Query().Get("tenant"))
	if tenantID == "" {
		tenantID = "default"
	}
	k := s.freshTrustKeys(r.Context(), tenantID)
	if k == nil {
		writeJSONError(w, http.StatusServiceUnavailable, "the response authority has no keys for this tenant")
		return
	}
	// The epoch is the authority's; the hub never chooses it.
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"tenant_id": tenantID, "epoch": k.Epoch, "statement": response.TrustBundleStatement(k), "signed": k.BundleSig != "",
	})
}

// handleTrustBundle stores the release key's signature over a tenant's trust
// statement. Anyone holding an admin key may post one; only a signature by
// the release key is kept, and only for the keys the authority holds now.
func (s *Server) handleTrustBundle(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if r.Header.Get("X-Role") != "admin" {
		writeJSONError(w, http.StatusForbidden, "admin role required")
		return
	}
	var req struct {
		TenantID  string `json:"tenant_id"`
		Epoch     int64  `json:"epoch"`
		Signature string `json:"signature"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid json body")
		return
	}
	req.TenantID = strings.TrimSpace(req.TenantID)
	if req.TenantID == "" || req.Epoch < 1 {
		writeJSONError(w, http.StatusBadRequest, "tenant_id and a positive epoch are required")
		return
	}

	k := s.freshTrustKeys(r.Context(), req.TenantID)
	if k == nil {
		writeJSONError(w, http.StatusServiceUnavailable, "the response authority has no keys for this tenant")
		return
	}
	if req.Epoch != k.Epoch {
		writeJSONError(w, http.StatusConflict, fmt.Sprintf("the authority's trust epoch is %d, not %d", k.Epoch, req.Epoch))
		return
	}
	if err := s.verifyTrustBundle(k, strings.TrimSpace(req.Signature)); err != nil {
		writeJSONError(w, http.StatusBadRequest, "the signature does not cover this tenant's keys and epoch under the release key: "+err.Error())
		return
	}
	raw, _ := json.Marshal(storedBundle{Epoch: req.Epoch, Signature: strings.TrimSpace(req.Signature)})
	if err := s.store.SetSetting(trustBundleSettingKey(req.TenantID), string(raw)); err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.dropTrustKeys(req.TenantID)
	s.audit(r, "TRUST_BUNDLE_SIGNED", req.TenantID, fmt.Sprintf("release-key signature over the tenant's authority keys stored (epoch %d)", req.Epoch))
	writeJSON(w, http.StatusOK, map[string]interface{}{"tenant_id": req.TenantID, "epoch": req.Epoch, "signed": true})
}

func (s *Server) dropTrustKeys(tenantID string) {
	s.trust.mu.Lock()
	s.trust.init()
	delete(s.trust.keys, tenantID)
	delete(s.trust.keysAt, tenantID)
	s.trust.mu.Unlock()
}

func (s *Server) freshTrustKeys(ctx context.Context, tenantID string) *response.TrustKeys {
	s.dropTrustKeys(tenantID)
	return s.trustKeys(ctx, tenantID)
}

// updateGrantFor finds the owner's grant for installing version on endpoint.
func (s *Server) updateGrantFor(endpointID, version string) *response.EnforcementGrant {
	list, err := s.store.UpdateGrants(endpointID, time.Now().Unix())
	if err != nil {
		return nil
	}
	for i := range list {
		var p struct {
			Body struct {
				Version string `json:"version"`
			} `json:"body"`
		}
		if json.Unmarshal(list[i].Payload, &p) != nil || p.Body.Version != version {
			continue
		}
		if w, err := storedToWire(&list[i]); err == nil {
			return w
		}
	}
	return nil
}

// reconcilePendingGrants settles grants whose action outcome was never
// recorded (the hub stopped between running the action and releasing its
// grants): a grant is released when the hub's state shows its action took
// effect, and withdrawn otherwise. At start (before any listener) every
// pending grant belongs to a stopped process and is settled at once; later,
// grants issued in the last two minutes may still belong to a running request
// and are left alone.
func (s *Server) reconcilePendingGrants(now time.Time) {
	s.reconcilePendingGrantsIssuedBefore(now.Add(-2*time.Minute).Unix(), now)
}

func (s *Server) reconcilePendingGrantsIssuedBefore(cutoff int64, now time.Time) {
	list, err := s.store.PendingGrants(cutoff)
	if err != nil || len(list) == 0 {
		return
	}
	held, err := s.store.HeldRolloutGrants()
	if err != nil {
		return // settle nothing rather than withdraw a staged rollout's grants
	}
	var release, withdraw []string
	expired := 0
	for _, g := range list {
		if held[g.GrantID] && g.ExpiresAt > now.Unix() {
			continue // a staged rollout releases or withdraws it
		}
		if g.ExpiresAt <= now.Unix() {
			// Too late to enforce: never released. If the hub recorded the
			// action, hub and agent now disagree, which the fleet trust view
			// and this audit show; the owner repeats the action.
			withdraw = append(withdraw, g.GrantID)
			expired++
			log.Printf("[!] pending grant %s for %s expired before it was released; the agent did not act on it (repeat the action if the hub shows it in force)", g.GrantID, g.Target)
			continue
		}
		if s.grantActionTookEffect(&g) {
			release = append(release, g.GrantID)
		} else {
			withdraw = append(withdraw, g.GrantID)
		}
	}
	if len(release) > 0 {
		if err := s.store.MarkGrantsDeliverable(release); err != nil {
			log.Printf("[!] could not release %d reconciled grant(s): %v", len(release), err)
		}
	}
	if len(withdraw) > 0 {
		if err := s.store.DeleteEnforcementGrants(withdraw); err != nil {
			log.Printf("[!] could not withdraw %d reconciled grant(s): %v", len(withdraw), err)
		}
	}
	_ = s.store.RecordAudit(storage.AuditEntry{
		ID: uuid.New().String(), Username: "hub", Action: "PENDING_GRANTS_RECONCILED", Resource: "enforcement_grants",
		Details: fmt.Sprintf("%d released (action recorded), %d withdrawn (action not recorded or, for %d, expired: hub state may not be enforced)", len(release), len(withdraw), expired), Timestamp: now.UTC(),
	})
}

func (s *Server) grantActionTookEffect(g *storage.StoredGrant) bool {
	var p struct {
		Route     string                       `json:"route"`
		Baselines []response.IsolationBaseline `json:"baselines"`
		Body      struct {
			TargetIP string   `json:"target_ip"`
			Version  string   `json:"version"`
			AllowIPs []string `json:"allow_ips"`
		} `json:"body"`
	}
	if json.Unmarshal(g.Payload, &p) != nil {
		return false
	}
	switch p.Route {
	case "/api/v1/endpoints/isolate", "/api/v1/endpoints/isolate-bulk", "/api/v1/endpoints/unisolate", "/api/v1/endpoints/unisolate-bulk":
		// The whole recorded isolation must be the grant's: on, and with
		// exactly its allow list. An isolation already in place with other
		// exceptions does not release a grant whose own change failed.
		isolated, allow, err := s.store.GetEndpointIsolation(g.Target)
		want := p.Route == "/api/v1/endpoints/isolate" || p.Route == "/api/v1/endpoints/isolate-bulk"
		if err != nil || isolated != want {
			return false
		}
		if !want {
			return true
		}
		// And its exceptions must be the ones the hub would grant now.
		if !sameAddressSet(p.Body.AllowIPs, allow) {
			return false
		}
		cur, err := s.isolationBaselines([]string{g.Target})
		return err == nil && reflect.DeepEqual(baselineRulesFor(p.Baselines, g.Target), baselineRulesFor(cur, g.Target))
	case "/api/v1/mesh/quarantine", "/api/v1/mesh/unquarantine":
		ip := strings.TrimPrefix(g.Target, "mesh:")
		return s.store.IsPeerQuarantined(ip) == (p.Route == "/api/v1/mesh/quarantine")
	case "/api/v1/agents/update":
		job, err := s.store.GetAgentUpdateJob(g.Target)
		return err == nil && job != nil && job.DesiredVersion == p.Body.Version
	}
	return false
}

// baselineRulesFor returns the rules a baseline list gives one endpoint.
func baselineRulesFor(list []response.IsolationBaseline, id string) []response.IsolationRule {
	for _, b := range list {
		for _, e := range b.Endpoints {
			if e == id {
				return b.Rules
			}
		}
	}
	return nil
}

// sameAddressSet compares allow lists as normalized address sets; an entry
// that is not an address makes them differ.
func sameAddressSet(signed, recorded []string) bool {
	norm := func(in []string) (map[string]bool, bool) {
		out := make(map[string]bool, len(in))
		for _, raw := range in {
			ip, err := validateAllowEntry(raw)
			if err != nil {
				return nil, false
			}
			out[ip] = true
		}
		return out, true
	}
	a, ok1 := norm(signed)
	b, ok2 := norm(recorded)
	if !ok1 || !ok2 || len(a) != len(b) {
		return false
	}
	for k := range a {
		if !b[k] {
			return false
		}
	}
	return true
}

func (s *Server) reconcilePendingGrantsLoop() {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for range t.C {
		s.reconcilePendingGrants(time.Now())
	}
}

// grantRoutes are the approved routes whose grants agents act on.
var grantRoutes = map[string]response.ActionKind{
	"/api/v1/endpoints/isolate":        response.ActionKindIsolationChange,
	"/api/v1/endpoints/unisolate":      response.ActionKindIsolationChange,
	"/api/v1/endpoints/isolate-bulk":   response.ActionKindIsolationChange,
	"/api/v1/endpoints/unisolate-bulk": response.ActionKindIsolationChange,
	"/api/v1/mesh/quarantine":          response.ActionKindMeshQuarantine,
	"/api/v1/mesh/unquarantine":        response.ActionKindMeshQuarantine,
	"/api/v1/agents/update":            response.ActionKindAgentUpdate,
}

// keepApprovalGrants stores the grants of an approved request as pending; the
// caller releases them once the action succeeded, and each named agent then
// receives its own on its next beat (or when it returns). It returns the
// stored grant IDs.
func (s *Server) keepApprovalGrants(route string, kind response.ActionKind, payload []byte, grants []*response.EndpointGrant) ([]string, error) {
	if want, ok := grantRoutes[route]; !ok || want != kind || len(grants) == 0 {
		return nil, nil
	}
	list := make([]storage.StoredGrant, 0, len(grants))
	for _, g := range grants {
		raw, err := json.Marshal(g)
		if err != nil {
			return nil, err
		}
		list = append(list, storage.StoredGrant{
			GrantID: g.GrantID, TenantID: g.TenantID, Target: g.EndpointID, Kind: string(g.ActionKind),
			GrantJSON: string(raw), Payload: payload, IssuedAt: g.IssuedAt, ExpiresAt: g.ExpiresAt, Pending: true,
		})
	}
	if err := s.store.SaveEnforcementGrants(list); err != nil {
		return nil, err
	}
	ids := make([]string, 0, len(list))
	for _, g := range list {
		ids = append(ids, g.GrantID)
	}
	return ids, nil
}

// signDetectorIsolation asks the authority for the detector's narrow,
// rate-limited isolation grant. Without one a grant-verifying agent stays
// connected: the hub's record says isolated, the agent's report says not,
// and the fleet trust view shows the difference.
func (s *Server) signDetectorIsolation(endpointID, reason string) {
	if s.responseAuth == nil {
		return
	}
	ep, _ := s.store.GetEndpoint(endpointID)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	baselines, err := s.isolationBaselines([]string{endpointID})
	if err != nil {
		log.Printf("[!] detector isolation of %s: %v", endpointID, err)
		baselines = nil
	}
	g, err := s.responseAuth.SignAutoIsolation(ctx, &responseauth.AutoIsolateRequest{TenantID: endpointTenant(ep), EndpointID: endpointID, Reason: reason, Baselines: baselines})
	if err != nil {
		_ = s.store.RecordAudit(storage.AuditEntry{
			ID: uuid.New().String(), Username: "detector", Action: "AUTO_ISOLATE_UNSIGNED", Resource: endpointID,
			Details: "the response authority did not sign the detector's isolation (" + err.Error() + "); agents from " +
				grantVerifyingAgentVersion + " stay connected until an owner isolates", Timestamp: time.Now().UTC(),
		})
		return
	}
	payload, err := base64.StdEncoding.DecodeString(g.PayloadB64)
	if err != nil {
		return
	}
	raw, _ := json.Marshal(g.Grant)
	if err := s.store.SaveEnforcementGrants([]storage.StoredGrant{{
		GrantID: g.Grant.GrantID, TenantID: g.Grant.TenantID, Target: endpointID, Kind: string(g.Grant.ActionKind),
		GrantJSON: string(raw), Payload: payload, IssuedAt: g.Grant.IssuedAt, ExpiresAt: g.Grant.ExpiresAt,
	}}); err != nil {
		log.Printf("[!] could not keep the detector's isolation grant for %s: %v", endpointID, err)
	}
}

// maxGrantPayload keeps a signed payload inside what an agent reads
// (TRUST_MAX_PAYLOAD 8192 in agent_trust.h, with room for the grant).
const maxGrantPayload = 7680

// isolationBaselines resolves each target's isolation exceptions into the
// form signed into an isolation: hosts with the same rules share one entry,
// rules an agent would refuse are left out (fewer holes, never a refused
// grant), entries and endpoints in a stable order.
func (s *Server) isolationBaselines(targets []string) ([]response.IsolationBaseline, error) {
	groups := map[string]*response.IsolationBaseline{}
	for _, id := range targets {
		res, err := s.store.ResolveBaseline(id)
		if err != nil {
			return nil, fmt.Errorf("isolation exceptions for %s: %w", id, err)
		}
		wire, trimmed := storage.CapBaselineWireRules(storage.BaselineWireRules(res.Rules))
		if trimmed && res.ReadinessReported && len(res.Uncovered) == 0 {
			return nil, fmt.Errorf("the isolation exceptions for %s exceed what an agent holds (%d rules)", id, storage.BaselineWireLimit)
		}
		rules := make([]response.IsolationRule, 0, len(wire))
		for _, w := range wire {
			r := response.IsolationRule{Destination: w.Destination, Port: w.Port, Protocol: w.Protocol, Service: w.Service}
			if r.Valid() && len(rules) < response.MaxIsolationRules {
				rules = append(rules, r)
			}
		}
		if len(rules) == 0 {
			continue
		}
		sort.Slice(rules, func(i, j int) bool {
			a, b := rules[i], rules[j]
			return fmt.Sprintf("%s|%s|%s|%05d", a.Destination, a.Protocol, a.Service, a.Port) < fmt.Sprintf("%s|%s|%s|%05d", b.Destination, b.Protocol, b.Service, b.Port)
		})
		key, _ := json.Marshal(rules)
		g, ok := groups[string(key)]
		if !ok {
			g = &response.IsolationBaseline{Rules: rules}
			groups[string(key)] = g
		}
		g.Endpoints = append(g.Endpoints, id)
	}
	out := make([]response.IsolationBaseline, 0, len(groups))
	for _, g := range groups {
		sort.Strings(g.Endpoints)
		out = append(out, *g)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Endpoints[0] < out[j].Endpoints[0] })
	return out, nil
}

// --------------------------------------------------------- capability changes

type capabilityRequest struct {
	EndpointID string `json:"endpoint_id"`
	Profile    string `json:"profile"`
	Reason     string `json:"reason"`
}

func decodeCapabilityRequest(w http.ResponseWriter, body []byte) (capabilityRequest, bool) {
	var req capabilityRequest
	if err := json.Unmarshal(body, &req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid json body: "+err.Error())
		return req, false
	}
	req.EndpointID = strings.TrimSpace(req.EndpointID)
	req.Reason = strings.TrimSpace(req.Reason)
	switch {
	case req.EndpointID == "":
		writeJSONError(w, http.StatusBadRequest, "endpoint_id is required")
		return req, false
	case !knownProfile(req.Profile):
		writeJSONError(w, http.StatusBadRequest, "profile must be monitor, monitor-scripts, respond or engagement")
		return req, false
	case req.Reason == "" || len(req.Reason) > 300:
		writeJSONError(w, http.StatusBadRequest, "reason is required (at most 300 characters)")
		return req, false
	}
	return req, true
}

// resolveCapabilities describes a manifest change for the owner's approval.
func (s *Server) resolveCapabilities(w http.ResponseWriter, r *http.Request, body []byte) (*approvalPlan, bool) {
	if r.Header.Get("X-Role") != "admin" {
		writeJSONError(w, http.StatusForbidden, "admin role required")
		return nil, false
	}
	req, ok := decodeCapabilityRequest(w, body)
	if !ok || !s.endpointInScope(w, r, req.EndpointID) {
		return nil, false
	}
	caps, _ := response.ProfileCaps(req.Profile)
	return &approvalPlan{Kind: response.ActionKindCapability, Action: "Change what a host accepts",
		Summary: fmt.Sprintf("%s accepts %s (%s)", s.endpointLabels([]string{req.EndpointID}), req.Profile, strings.Join(caps, ", ")),
		Targets: []string{req.EndpointID}}, true
}

// handleEndpointCapabilities runs after the owner approved: the authority has
// already signed the new manifest while consuming the approval.
func (s *Server) handleEndpointCapabilities(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var req capabilityRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	req.EndpointID = strings.TrimSpace(req.EndpointID)
	if ids := grantedTargets(r); len(ids) != 1 || ids[0] != req.EndpointID {
		writeJSONError(w, http.StatusForbidden, "the approval covers a different endpoint")
		return
	}
	ep, err := s.store.GetEndpoint(req.EndpointID)
	if err != nil || ep == nil {
		writeJSONError(w, http.StatusNotFound, "no such endpoint")
		return
	}
	// The authority signed the new manifest when the approval was consumed.
	// The hub's monitor-only setting is lifted only through allow-isolation (at
	// its revision), so while it stands it narrows the manifest straight back.
	m := s.endpointManifest(r.Context(), endpointTenant(ep), req.EndpointID, "", true)
	s.audit(r, "ENDPOINT_CAPABILITIES_CHANGED", req.EndpointID, "profile "+req.Profile+": "+req.Reason)
	out := map[string]interface{}{"endpoint_id": req.EndpointID, "profile": req.Profile}
	if ep.MonitorOnly && !response.MonitorOnlyProfile(req.Profile) {
		m = s.endpointManifest(r.Context(), endpointTenant(ep), req.EndpointID, "monitor", true)
		out["profile"] = "monitor"
		out["still_monitor_only"] = "lift monitor-only with allow-isolation first: " + ep.MonitorOnlyReason()
	}
	if m != nil {
		out["manifest_seq"] = m.Seq
		out["caps"] = m.Caps
	}
	writeJSON(w, http.StatusOK, out)
}

// afterProfileChange keeps the manifest in step with the hub's monitor-only
// verdict: narrowing is signed at once; a raise was signed by the authority
// when the owner's approval was consumed and only needs re-reading.
func (s *Server) afterProfileChange(ctx context.Context, endpointID string) {
	ep, err := s.store.GetEndpoint(endpointID)
	if err != nil || ep == nil {
		return
	}
	profile := ""
	if ep.MonitorOnly {
		profile = s.monitorOnlyClamp(endpointID, "")
	}
	s.endpointManifest(ctx, endpointTenant(ep), endpointID, profile, true)
}

// ------------------------------------------------------------- fleet view

type fleetTrustRow struct {
	EndpointID   string   `json:"endpoint_id"`
	Hostname     string   `json:"hostname"`
	AgentVersion string   `json:"agent_version"`
	Verification string   `json:"verification"` // agent | hub-only | unknown
	Keys         string   `json:"keys,omitempty"`
	TrustBundle  string   `json:"trust_bundle"` // signed | unsigned | unavailable (the tenant's)
	MissingKeys  []string `json:"missing_keys,omitempty"`
	Profile      string   `json:"profile,omitempty"`
	Ceiling      string   `json:"ceiling,omitempty"`
	// Host authority: keys pinned on the host (ids and roles), the auto
	// allow-list, and why a host file was not used.
	HostAuthority   *bool                      `json:"host_authority,omitempty"` // set whenever the agent reported: false shows as false
	HostKeys        []response.HostKeyReport   `json:"host_keys,omitempty"`
	HostAllow       []response.HostAllowReport `json:"host_allow,omitempty"`
	HostError       string                     `json:"host_error,omitempty"`
	ManifestSeq     int64                      `json:"manifest_seq,omitempty"`
	HubIsolated     bool                       `json:"hub_isolated"`
	AgentIsolated   *bool                      `json:"agent_isolated,omitempty"`
	IsolationSource string                     `json:"isolation_source,omitempty"`
	Disagrees       bool                       `json:"disagrees,omitempty"`
	Refused         string                     `json:"refused,omitempty"`
	RefusedAt       int64                      `json:"refused_at,omitempty"`
	ReportedAt      string                     `json:"reported_at,omitempty"`
	// Routine release keys the agent has pinned (agents from 1.8.89): the
	// epoch of the signed list (0: none) and how many keys it holds. Set
	// whenever the agent reported, so 0 shows as 0.
	RoutineEpoch *int64 `json:"routine_epoch,omitempty"`
	RoutineKeys  *int   `json:"routine_keys,omitempty"`
}

// handleFleetTrust is the fleet's trust report: which agents verify grants
// themselves, which keys each has pinned, its manifest, and the last thing it
// refused. Hub isolation that an agent does not hold shows as disagrees.
func (s *Server) handleFleetTrust(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	tenantID := ""
	if r.Header.Get("X-Role") == "tenant" {
		tenantID = r.Header.Get("X-Tenant-ID")
	}
	eps, err := s.store.ListEndpoints(tenantID)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.trust.mu.Lock()
	s.trust.init()
	reports := make(map[string]trustReportSeen, len(s.trust.reports))
	for k, v := range s.trust.reports {
		reports[k] = v
	}
	s.trust.mu.Unlock()
	rows := []fleetTrustRow{}
	counts := map[string]int{}
	bundles := map[string]string{}
	for _, ep := range eps {
		if ep.Status == "retired" {
			continue
		}
		row := fleetTrustRow{EndpointID: ep.ID, Hostname: ep.Hostname, AgentVersion: ep.DriverVersion, HubIsolated: ep.IsIsolated}
		tenant := endpointTenant(&ep)
		if _, ok := bundles[tenant]; !ok {
			switch k := s.trustKeys(r.Context(), tenant); {
			case k == nil:
				bundles[tenant] = "unavailable"
			case k.BundleSig == "":
				bundles[tenant] = "unsigned"
			default:
				bundles[tenant] = "signed"
			}
		}
		row.TrustBundle = bundles[tenant]
		if seen, ok := reports[ep.ID]; ok {
			rep := seen.report
			row.Verification = "agent"
			row.Keys = rep.Keys
			if !rep.ResponseKey {
				row.MissingKeys = append(row.MissingKeys, "response")
			}
			if !rep.AutoIsolateKey {
				row.MissingKeys = append(row.MissingKeys, "auto_isolate")
			}
			if !rep.PolicyKey {
				row.MissingKeys = append(row.MissingKeys, "policy")
			}
			row.Profile, row.ManifestSeq, row.Ceiling = rep.Profile, rep.ManifestSeq, rep.Ceiling
			hostAuth := rep.HostAuthority
			row.HostAuthority, row.HostKeys, row.HostAllow, row.HostError = &hostAuth, rep.HostKeys, rep.HostAllow, rep.HostError
			iso := rep.Isolated
			row.AgentIsolated = &iso
			row.IsolationSource = rep.IsolationSource
			row.Disagrees = iso != ep.IsIsolated
			row.Refused, row.RefusedAt = rep.Refused, rep.RefusedAt
			row.ReportedAt = seen.at.UTC().Format(time.RFC3339)
			routineEpoch, routineKeys := rep.RoutineEpoch, rep.RoutineKeys
			row.RoutineEpoch, row.RoutineKeys = &routineEpoch, &routineKeys
		} else if ep.DriverVersion != "" && compareVersions(ep.DriverVersion, grantVerifyingAgentVersion) < 0 {
			row.Verification = "hub-only"
		} else {
			row.Verification = "unknown"
		}
		counts[row.Verification]++
		rows = append(rows, row)
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].Hostname+rows[i].EndpointID < rows[j].Hostname+rows[j].EndpointID })
	writeJSON(w, http.StatusOK, map[string]interface{}{"endpoints": rows, "counts": counts})
}
