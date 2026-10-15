package responseauth

// Agent trust, authority side: the two narrow keys next to the tenant
// response key, the detector's rate-limited isolation grants, and capability
// manifests. Agents pin all three public keys and verify everything here
// themselves (agent/include/agent_trust.h), so code running on the hub can
// carry these statements but cannot make them.

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"ominull/hub/pkg/response"
)

const (
	keySlotAutoIsolate = "#auto-isolate"
	keySlotPolicy      = "#policy"

	// The detector's isolation: short-lived, isolate only, bounded.
	autoIsolateTTL          = 10 * time.Minute
	autoIsolatePerHour      = 6                // per tenant
	autoIsolatePerEndpoint  = 10 * time.Minute // one per endpoint in this window
	autoIsolateMaxReasonLen = 200

	// How long an owner-approved enforcement grant may wait for an endpoint
	// that is offline when it is approved.
	enforcementGrantTTL = 24 * time.Hour
	updateGrantTTL      = 7 * 24 * time.Hour
)

// ErrAutoIsolateRateLimit is returned when the detector asks too often.
var ErrAutoIsolateRateLimit = errors.New("automatic isolation rate limit reached; an owner must isolate further hosts")

// ErrManifestNeedsApproval is returned when a manifest request would raise or
// replace an endpoint's pinned capabilities without an owner approval.
var ErrManifestNeedsApproval = errors.New("this capability change needs an owner approval")

// enforcementClock hands out issue times for enforcement grants (isolation,
// detector isolation, mesh). Agents keep one watermark per slot and skip any
// grant not newer than it, so two grants in the same second must still be
// ordered: each one gets max(now, last+1). The last value is kept on disk so
// a restart right after a burst cannot reuse a second.
type enforcementClock struct {
	mu   sync.Mutex
	path string
	last map[string]int64
	// broken is set when the persisted clock could not be read: nothing is
	// signed until it is repaired, as a reset clock could reissue times
	// agents already passed.
	broken error
}

func newEnforcementClock(stateDir string) *enforcementClock {
	c := &enforcementClock{last: map[string]int64{}}
	if stateDir == "" {
		return c
	}
	c.path = filepath.Join(stateDir, "enforcement_clock.json")
	raw, err := os.ReadFile(c.path)
	switch {
	case errors.Is(err, os.ErrNotExist):
	case err != nil:
		c.broken = fmt.Errorf("enforcement clock unreadable: %w", err)
	default:
		if err := json.Unmarshal(raw, &c.last); err != nil || c.last == nil {
			c.broken = fmt.Errorf("enforcement clock %s is corrupt", c.path)
			c.last = map[string]int64{}
		}
	}
	return c
}

// maxClockLead bounds how far a tenant's clock may run ahead of real time.
// Grants are rationed (owner taps, the detector's 6 per hour), so a lead this
// large means something is wrong; agents would refuse such grants anyway.
const maxClockLead = 5 * time.Minute

// next returns a strictly increasing issue time for one tenant, durable
// before it is used: written to a temporary file, fsynced, renamed over,
// directory fsynced. A time that could not be made durable is never handed
// out. Tenants have their own clocks, so one tenant's grants never push
// another's ahead.
func (c *enforcementClock) next(tenantID string, now time.Time) (int64, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.broken != nil {
		return 0, c.broken
	}
	t := now.Unix()
	if last := c.last[tenantID]; t <= last {
		t = last + 1
	}
	if time.Unix(t, 0).Sub(now) > maxClockLead {
		return 0, fmt.Errorf("the enforcement clock for tenant %q is more than %s ahead of real time", tenantID, maxClockLead)
	}
	if c.path != "" {
		next := make(map[string]int64, len(c.last)+1)
		for k, v := range c.last {
			next[k] = v
		}
		next[tenantID] = t
		raw, _ := json.Marshal(next)
		if err := writeDurable(c.path, raw); err != nil {
			return 0, fmt.Errorf("enforcement clock not persisted: %w", err)
		}
	}
	c.last[tenantID] = t
	return t, nil
}

func writeDurable(path string, data []byte) error {
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	d, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

// enforcementKind reports whether grants of this kind move an agent's
// enforcement slots (and so need strictly ordered issue times).
func enforcementKind(k response.ActionKind) bool {
	switch k {
	case response.ActionKindIsolationChange, response.ActionKindMeshQuarantine, response.ActionKindAutoIsolate:
		return true
	}
	return false
}

func validTenant(t string) bool {
	return t != "" && !strings.ContainsAny(t, "#/\\\x00")
}

func (a *Authority) slotKey(tenantID, slot string) (ed25519.PrivateKey, string, error) {
	if !validTenant(tenantID) {
		return nil, "", errors.New("invalid tenant ID")
	}
	id := tenantID + slot
	if _, _, err := a.getOrCreateKey(id); err != nil {
		return nil, "", err
	}
	a.mu.RLock()
	priv, ok := a.tenantKeys[id]
	a.mu.RUnlock()
	if !ok {
		return nil, "", fmt.Errorf("no %s key for tenant %q", slot, tenantID)
	}
	pub := priv.Public().(ed25519.PublicKey)
	fp := sha256.Sum256(pub)
	return priv, hex.EncodeToString(fp[:]), nil
}

// trustEpochs is the authority's own record of each tenant's trust bundle
// epoch: it moves up by one whenever the tenant's three public keys change,
// and nothing outside the authority sets it, so a hub cannot make the owner
// sign an old or an exhausted epoch.
type trustEpochs struct {
	mu    sync.Mutex
	path  string
	items map[string]trustEpoch
	floor int64
	err   error
}

type trustEpoch struct {
	Epoch int64  `json:"epoch"`
	Keys  string `json:"keys"` // sha256 over the three public keys
}

func newTrustEpochs(stateDir string, floor int64) *trustEpochs {
	e := &trustEpochs{items: map[string]trustEpoch{}, floor: floor}
	if stateDir == "" {
		return e
	}
	e.path = filepath.Join(stateDir, "trust_epochs.json")
	raw, err := os.ReadFile(e.path)
	switch {
	case errors.Is(err, os.ErrNotExist):
	case err != nil:
		e.err = fmt.Errorf("trust epochs unreadable: %w", err)
	default:
		if json.Unmarshal(raw, &e.items) != nil || e.items == nil {
			e.err = fmt.Errorf("trust epochs file %s is corrupt", e.path)
			e.items = map[string]trustEpoch{}
		}
	}
	return e
}

func (e *trustEpochs) epochFor(tenantID string, k *response.TrustKeys) (int64, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.err != nil {
		return 0, e.err
	}
	sum := sha256.Sum256([]byte(strings.ToLower(k.ResponseKey + "|" + k.AutoIsolateKey + "|" + k.PolicyKey)))
	fp := hex.EncodeToString(sum[:])
	cur, ok := e.items[tenantID]
	if ok && cur.Keys == fp && cur.Epoch >= e.floor {
		return cur.Epoch, nil
	}
	next := trustEpoch{Epoch: cur.Epoch + 1, Keys: fp}
	if ok && cur.Keys == fp {
		next.Epoch = cur.Epoch // only the floor moves it
	}
	if next.Epoch < e.floor {
		next.Epoch = e.floor
	}
	if e.path != "" {
		all := make(map[string]trustEpoch, len(e.items)+1)
		for t, v := range e.items {
			all[t] = v
		}
		all[tenantID] = next
		raw, _ := json.Marshal(all)
		if err := writeDurable(e.path, raw); err != nil {
			return 0, fmt.Errorf("trust epoch not persisted: %w", err)
		}
	}
	e.items[tenantID] = next
	return next.Epoch, nil
}

// hasTenantKey reports whether the tenant already has an active response key.
func (a *Authority) hasTenantKey(tenantID string) bool {
	a.mu.RLock()
	_, ok := a.tenantKeys[tenantID]
	a.mu.RUnlock()
	if ok {
		return true
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	rec, err := a.store.GetTenantKey(ctx, tenantID)
	return err == nil && rec != nil && rec.Status == "active"
}

// TrustKeys returns the three public keys an agent of this tenant pins.
func (a *Authority) TrustKeys(tenantID string) (*response.TrustKeys, error) {
	if !validTenant(tenantID) {
		return nil, errors.New("invalid tenant ID")
	}
	resp, _, err := a.GetOrCreateTenantKey(tenantID)
	if err != nil {
		return nil, err
	}
	autoPriv, _, err := a.slotKey(tenantID, keySlotAutoIsolate)
	if err != nil {
		return nil, err
	}
	polPriv, _, err := a.slotKey(tenantID, keySlotPolicy)
	if err != nil {
		return nil, err
	}
	k := &response.TrustKeys{
		TenantID:       tenantID,
		ResponseKey:    hex.EncodeToString(resp),
		AutoIsolateKey: hex.EncodeToString(autoPriv.Public().(ed25519.PublicKey)),
		PolicyKey:      hex.EncodeToString(polPriv.Public().(ed25519.PublicKey)),
	}
	if k.Epoch, err = a.trustEpochs.epochFor(tenantID, k); err != nil {
		return nil, err
	}
	return k, nil
}

// AutoIsolateRequest is the detector asking to contain one host.
type AutoIsolateRequest struct {
	TenantID   string `json:"tenant_id"`
	EndpointID string `json:"endpoint_id"`
	Reason     string `json:"reason"`
	// Baselines are the host's isolation exceptions (at most one entry,
	// naming only this endpoint), signed into the grant.
	Baselines []response.IsolationBaseline `json:"baselines,omitempty"`
}

type autoIsolateBook struct {
	mu         sync.Mutex
	byTenant   map[string][]time.Time
	byEndpoint map[string]time.Time
}

// SignAutoIsolation signs the detector's isolation of one endpoint with the
// auto-isolation key. The grant can only isolate (agents refuse it for
// anything else), lives ten minutes, and the authority rations it: at most
// six per tenant per hour and one per endpoint per ten minutes, each audited.
func (a *Authority) SignAutoIsolation(req *AutoIsolateRequest) (*response.EnforcementGrant, error) {
	if req == nil || !validTenant(req.TenantID) {
		return nil, errors.New("invalid tenant ID")
	}
	ep := strings.TrimSpace(req.EndpointID)
	if ep == "" || len(ep) > 128 || cleanText(ep, 128) != ep || strings.HasPrefix(ep, "mesh:") {
		return nil, errors.New("invalid endpoint ID")
	}
	if len(req.Baselines) > 1 {
		return nil, errors.New("an automatic isolation carries one host's exceptions")
	}
	if !a.hasTenantKey(req.TenantID) {
		// The detector never brings a tenant into being.
		return nil, fmt.Errorf("tenant %q has no response key", req.TenantID)
	}
	if _, err := checkBaselines(req.Baselines, []string{ep}); err != nil {
		return nil, err
	}
	now := time.Now()
	b := a.autoIso
	b.mu.Lock()
	recent := b.byTenant[req.TenantID][:0:0]
	for _, at := range b.byTenant[req.TenantID] {
		if now.Sub(at) < time.Hour {
			recent = append(recent, at)
		}
	}
	key := req.TenantID + "\x00" + ep
	if last, ok := b.byEndpoint[key]; ok && now.Sub(last) < autoIsolatePerEndpoint {
		b.mu.Unlock()
		a.auditApproval(req.TenantID, "detector", "auto_isolate_refused", string(response.ActionKindAutoIsolate), ep, "", "denied", "one automatic isolation per endpoint per 10 minutes")
		return nil, ErrAutoIsolateRateLimit
	}
	if len(recent) >= autoIsolatePerHour {
		b.byTenant[req.TenantID] = recent
		b.mu.Unlock()
		a.auditApproval(req.TenantID, "detector", "auto_isolate_refused", string(response.ActionKindAutoIsolate), ep, "", "denied", ErrAutoIsolateRateLimit.Error())
		return nil, ErrAutoIsolateRateLimit
	}
	b.byTenant[req.TenantID] = append(recent, now)
	b.byEndpoint[key] = now
	for k, at := range b.byEndpoint {
		if now.Sub(at) > time.Hour {
			delete(b.byEndpoint, k)
		}
	}
	b.mu.Unlock()

	priv, keyID, err := a.slotKey(req.TenantID, keySlotAutoIsolate)
	if err != nil {
		return nil, err
	}
	fields := map[string]interface{}{
		"route":   response.AutoIsolateRoute,
		"body":    map[string]string{"endpoint_id": ep, "reason": cleanText(req.Reason, autoIsolateMaxReasonLen)},
		"targets": []string{ep},
	}
	if len(req.Baselines) > 0 {
		fields["baselines"] = req.Baselines
	}
	payload, _ := json.Marshal(fields)
	digest := sha256.Sum256(payload)
	issued, err := a.enfClock.next(req.TenantID, now)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	g := &response.EndpointGrant{
		Version:           response.GrantVersion,
		GrantID:           uuid.New().String(),
		TenantID:          req.TenantID,
		EndpointID:        ep,
		ActionKind:        response.ActionKindAutoIsolate,
		ActionDigest:      hex.EncodeToString(digest[:]),
		OperatorID:        "detector",
		ResponseSessionID: "auto-isolate",
		IssuedAt:          issued,
		ExpiresAt:         issued + int64(autoIsolateTTL/time.Second),
		Nonce:             hex.EncodeToString(nonce),
		SignerKeyID:       keyID,
	}
	g.Signature = hex.EncodeToString(ed25519.Sign(priv, g.CanonicalBytes()))
	a.auditApproval(req.TenantID, "detector", "auto_isolate_signed", string(response.ActionKindAutoIsolate), ep, g.GrantID, "success", cleanText(req.Reason, autoIsolateMaxReasonLen))
	return &response.EnforcementGrant{Grant: g, PayloadB64: b64(payload)}, nil
}

// ---------------------------------------------------------------- manifests

type manifestBook struct {
	mu    sync.Mutex
	path  string
	items map[string]*response.CapabilityManifest // tenant \x00 endpoint
}

func newManifestBook(stateDir string) *manifestBook {
	b := &manifestBook{items: map[string]*response.CapabilityManifest{}}
	if stateDir == "" {
		return b
	}
	b.path = filepath.Join(stateDir, "manifests.json")
	if raw, err := os.ReadFile(b.path); err == nil {
		var list []*response.CapabilityManifest
		if json.Unmarshal(raw, &list) == nil {
			for _, m := range list {
				b.items[m.TenantID+"\x00"+m.EndpointID] = m
			}
		}
	}
	return b
}

func (b *manifestBook) saveLocked() error {
	if b.path == "" {
		return nil
	}
	list := make([]*response.CapabilityManifest, 0, len(b.items))
	for _, m := range b.items {
		list = append(list, m)
	}
	sort.Slice(list, func(i, j int) bool {
		return list[i].TenantID+list[i].EndpointID < list[j].TenantID+list[j].EndpointID
	})
	raw, err := json.MarshalIndent(list, "", " ")
	if err != nil {
		return err
	}
	tmp := b.path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, b.path)
}

// ManifestRequest asks for an endpoint's manifest.
type ManifestRequest struct {
	TenantID   string `json:"tenant_id"`
	EndpointID string `json:"endpoint_id"`
	Profile    string `json:"profile"`
}

// EndpointManifest returns the endpoint's current manifest. When it has none,
// the first one is signed now, at most "respond": the initial manifest
// pins what the endpoint already does, and engagement (hub-pushed scripts)
// is always an owner's decision. Any later change goes through an owner
// approval (capability_change).
func (a *Authority) EndpointManifest(req *ManifestRequest) (*response.CapabilityManifest, error) {
	if req == nil || !validTenant(req.TenantID) {
		return nil, errors.New("invalid tenant ID")
	}
	ep := strings.TrimSpace(req.EndpointID)
	if ep == "" || len(ep) > 128 || cleanText(ep, 128) != ep || strings.HasPrefix(ep, "mesh:") {
		return nil, errors.New("invalid endpoint ID")
	}
	b := a.manifests
	b.mu.Lock()
	defer b.mu.Unlock()
	profile := req.Profile
	if m, ok := b.items[req.TenantID+"\x00"+ep]; ok {
		// A manifest signed by a retired policy key is re-signed, same
		// profile, next seq, so agents that pinned the new key take it.
		if _, keyID, err := a.slotKey(req.TenantID, keySlotPolicy); err == nil && m.SignerKeyID != keyID {
			n, err := a.signManifestLocked(req.TenantID, ep, m.Profile, m.Seq+1)
			if err != nil {
				return nil, err
			}
			a.auditApproval(req.TenantID, "authority", "manifest_resigned", string(response.ActionKindCapability), ep, "", "success",
				fmt.Sprintf("profile %s under the current policy key, seq %d", n.Profile, n.Seq))
			m = n
		}
		// Narrowing needs no approval: it can only take capabilities away.
		if profile != "" && response.ProfileRank(profile) > 0 && response.ProfileRank(profile) < response.ProfileRank(m.Profile) {
			n, err := a.signManifestLocked(req.TenantID, ep, profile, m.Seq+1)
			if err != nil {
				return nil, err
			}
			a.auditApproval(req.TenantID, "hub", "manifest_narrowed", string(response.ActionKindCapability), ep, "", "success",
				fmt.Sprintf("profile %s -> %s, seq %d", m.Profile, profile, n.Seq))
			c := *n
			return &c, nil
		}
		c := *m
		return &c, nil
	}
	if profile == "" {
		profile = "respond"
	}
	if !ProfileInitialAllowed(profile) {
		return nil, ErrManifestNeedsApproval
	}
	m, err := a.signManifestLocked(req.TenantID, ep, profile, 1)
	if err != nil {
		return nil, err
	}
	a.auditApproval(req.TenantID, "hub", "manifest_initial", string(response.ActionKindCapability), ep, "", "success", "profile "+profile)
	c := *m
	return &c, nil
}

// ProfileInitialAllowed reports whether a profile may be pinned without an
// owner approval as an endpoint's first manifest.
func ProfileInitialAllowed(profile string) bool {
	return profile == "monitor" || profile == "respond"
}

func (a *Authority) signManifestLocked(tenantID, ep, profile string, seq int64) (*response.CapabilityManifest, error) {
	caps, ok := response.ProfileCaps(profile)
	if !ok {
		return nil, fmt.Errorf("unknown profile %q", profile)
	}
	priv, _, err := a.slotKey(tenantID, keySlotPolicy)
	if err != nil {
		return nil, err
	}
	m := &response.CapabilityManifest{V: 1, TenantID: tenantID, EndpointID: ep, Profile: profile, Caps: caps, Seq: seq, IssuedAt: time.Now().Unix()}
	m.Sign(priv)
	b := a.manifests
	prev := b.items[tenantID+"\x00"+ep]
	b.items[tenantID+"\x00"+ep] = m
	if err := b.saveLocked(); err != nil {
		if prev == nil {
			delete(b.items, tenantID+"\x00"+ep)
		} else {
			b.items[tenantID+"\x00"+ep] = prev
		}
		return nil, fmt.Errorf("persist manifest: %w", err)
	}
	return m, nil
}

// allowIsolationRoute lifts monitor-only (an isolation_change approval); the
// authority raises the endpoint's manifest to respond when it is consumed.
const allowIsolationRoute = "/api/v1/endpoints/allow-isolation"

// manifestApproval reports whether consuming this approval changes a manifest.
func manifestApproval(kind response.ActionKind, payload []byte) bool {
	if kind == response.ActionKindCapability {
		return true
	}
	if kind != response.ActionKindIsolationChange {
		return false
	}
	var p routedPayload
	return decodeJSON(payload, &p) == nil && p.Route == allowIsolationRoute
}

// capabilityPayload is the body of an owner-approved capability change.
type capabilityPayload struct {
	EndpointID string `json:"endpoint_id"`
	Profile    string `json:"profile"`
	Reason     string `json:"reason"`
}

// applyCapabilityApproval signs the next manifest once an owner approved it.
func (a *Authority) applyCapabilityApproval(tenantID string, stmt ApprovalStatement, payload []byte) error {
	var p routedPayload
	if err := decodeJSON(payload, &p); err != nil {
		return err
	}
	var body capabilityPayload
	if err := decodeJSON(p.Body, &body); err != nil {
		return err
	}
	if len(stmt.Targets) != 1 || body.EndpointID != stmt.Targets[0] {
		return errors.New("capability change names another endpoint")
	}
	b := a.manifests
	b.mu.Lock()
	defer b.mu.Unlock()
	var seq int64 = 1
	cur, have := b.items[tenantID+"\x00"+body.EndpointID]
	if have {
		seq = cur.Seq + 1
	}
	if p.Route == allowIsolationRoute {
		// Lifting monitor-only is the owner's raise to "respond"; a host
		// already at respond or above keeps its manifest.
		if have && response.ProfileRank(cur.Profile) >= response.ProfileRank("respond") {
			return nil
		}
		body.Profile = "respond"
	}
	m, err := a.signManifestLocked(tenantID, body.EndpointID, body.Profile, seq)
	if err != nil {
		return err
	}
	a.auditApproval(tenantID, stmt.Requester, "manifest_changed", string(response.ActionKindCapability), body.EndpointID, stmt.ID, "success",
		fmt.Sprintf("profile %s, seq %d", m.Profile, m.Seq))
	return nil
}

// ------------------------------------------------------------ strict payloads

// strictPayload refuses a payload two readers could read differently: it
// must be the canonical encoding of itself (no duplicate keys, nothing
// escaped that need not be), and no object may hold two keys that differ only
// in case (Go matches struct fields case-insensitively; the agent does not).
func strictPayload(raw []byte) error {
	var v interface{}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&v); err != nil {
		return err
	}
	if dec.More() {
		return errors.New("trailing data")
	}
	var walk func(x interface{}) error
	walk = func(x interface{}) error {
		switch t := x.(type) {
		case map[string]interface{}:
			seen := map[string]bool{}
			for k, sub := range t {
				lk := strings.ToLower(k)
				if lk != k {
					return fmt.Errorf("key %q is not lower case", k)
				}
				if seen[lk] {
					return fmt.Errorf("keys differ only in case: %q", k)
				}
				seen[lk] = true
				if err := walk(sub); err != nil {
					return err
				}
			}
		case []interface{}:
			for _, sub := range t {
				if err := walk(sub); err != nil {
					return err
				}
			}
		}
		return nil
	}
	if err := walk(v); err != nil {
		return err
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(true)
	if err := enc.Encode(v); err != nil {
		return err
	}
	if !bytes.Equal(bytes.TrimRight(buf.Bytes(), "\n"), raw) {
		return errors.New("payload is not in canonical form")
	}
	return nil
}

// grantTTL is how long an approved grant of this kind stays usable.
func grantTTL(kind response.ActionKind, requested int64) int64 {
	switch kind {
	case response.ActionKindIsolationChange, response.ActionKindMeshQuarantine:
		return int64(enforcementGrantTTL / time.Second)
	case response.ActionKindAgentUpdate:
		return int64(updateGrantTTL / time.Second)
	}
	if requested <= 0 || requested > 3600 {
		return 300
	}
	return requested
}

func b64(raw []byte) string { return base64.StdEncoding.EncodeToString(raw) }
