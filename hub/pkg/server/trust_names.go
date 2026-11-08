package server

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"ominull/hub/pkg/grants"
	"ominull/hub/pkg/response"
	"ominull/hub/pkg/storage"
	"ominull/hub/pkg/trustfabric"
)

// Name rules: the hub resolves a rule's name and signs the addresses, so the
// agent's firewall never holds or trusts a name. An isolation in force is
// frozen against rule changes, but not against DNS: a selective isolation that
// carries a name keeps the fabric it was granted under, and when the name's
// addresses move the hub signs a new grant for the same rules.
const (
	trustNameRefreshSetting = "trust_name_refresh_seconds"
	trustNameRefreshDefault = 300
	trustNameRefreshMin     = 60
	trustNameRefreshMax     = 3600
	// An endpoint may hold an answer from an earlier lookup, and a pool hands
	// out a different part of itself each time.
	trustNameRetainSetting = "trust_name_retain_minutes"
	trustNameRetainDefault = 60
	trustNameRetainMax     = 24 * 60
	// trustNameMaxAddrs bounds one name's share of an agent's 32-entry list.
	trustNameMaxAddrs     = 16
	trustNameLookupBudget = 4 * time.Second
	// Containment does not wait on DNS: a slower name stays closed and the
	// loop's next grant opens it.
	trustNameIsolateBudget = 3 * time.Second
	trustNameParallel      = 8
)

func (s *Server) intSetting(key string, def, lo, hi int) int {
	if v, err := s.store.GetSetting(key); err == nil && strings.TrimSpace(v) != "" {
		if n, err := strconv.Atoi(strings.TrimSpace(v)); err == nil {
			return min(max(n, lo), hi)
		}
	}
	return def
}

// answerAddrs is the answers as trustfabric takes them.
func answerAddrs(answers map[string]storage.TrustNameAnswer) map[string][]netip.Addr {
	out := make(map[string][]netip.Addr, len(answers))
	for name, a := range answers {
		for _, entry := range a.Addrs {
			if addr, err := netip.ParseAddr(entry.Addr); err == nil {
				out[name] = append(out[name], addr)
			}
		}
	}
	return out
}

// usableTrustAnswer refuses what could never be a destination: a filtering
// resolver answers 0.0.0.0 for a blocked name, and loopback or link-local is
// this machine or its own link, not the name.
func usableTrustAnswer(a netip.Addr) bool {
	a = a.Unmap()
	return a.IsValid() && !a.IsUnspecified() && !a.IsLoopback() && !a.IsMulticast() &&
		!a.IsLinkLocalUnicast() && !a.IsLinkLocalMulticast()
}

// lookupTrustName resolves one name through the hub's resolver and stores it.
func (s *Server) lookupTrustName(ctx context.Context, name string, now time.Time) {
	lookup := s.trustNameLookup
	if lookup == nil {
		lookup = func(ctx context.Context, name string) ([]netip.Addr, error) {
			return net.DefaultResolver.LookupNetIP(ctx, "ip", name)
		}
	}
	ctx, cancel := context.WithTimeout(ctx, trustNameLookupBudget)
	defer cancel()
	addrs, err := lookup(ctx, name)
	usable := make([]netip.Addr, 0, len(addrs))
	for _, a := range addrs {
		if usableTrustAnswer(a) {
			usable = append(usable, a.Unmap())
		}
	}
	problem := ""
	switch {
	case err != nil:
		problem = err.Error()
	case len(usable) == 0:
		problem = "no usable address in the answer"
	}
	retain := time.Duration(s.intSetting(trustNameRetainSetting, trustNameRetainDefault, 0, trustNameRetainMax)) * time.Minute
	if err := s.store.SaveTrustNameAnswer(name, usable, problem, now, retain, trustNameMaxAddrs); err != nil {
		log.Printf("[!] trust name %s: %v", name, err)
	}
}

// lookupTrustNames resolves names side by side.
func (s *Server) lookupTrustNames(ctx context.Context, names map[string]bool, now time.Time) {
	var wg sync.WaitGroup
	slots := make(chan struct{}, trustNameParallel)
	for name := range names {
		slots <- struct{}{}
		wg.Add(1)
		go func(name string) {
			defer wg.Done()
			defer func() { <-slots }()
			s.lookupTrustName(ctx, name, now)
		}(name)
	}
	wg.Wait()
}

// lookupUnresolvedTrustNames gives a name nobody has resolved yet one chance
// before an isolation is signed. The loop keeps resolved names fresh.
func (s *Server) lookupUnresolvedTrustNames(ctx context.Context, endpointID string, now time.Time) {
	ep, err := s.store.GetEndpoint(endpointID)
	if err != nil || ep == nil {
		return
	}
	rules, err := s.store.TrustRules()
	if err != nil {
		return
	}
	answers, err := s.store.TrustNameAnswers()
	if err != nil {
		return
	}
	fe := fabricEndpoint(ep)
	unresolved := map[string]bool{}
	for _, r := range rules {
		if r.Kind == trustfabric.KindFQDN && r.Active(now) && r.AppliesTo(fe) && len(answers[r.Value].Addrs) == 0 {
			unresolved[r.Value] = true
		}
	}
	ctx, cancel := context.WithTimeout(ctx, trustNameIsolateBudget)
	defer cancel()
	s.lookupTrustNames(ctx, unresolved, now)
}

// isolationFabric is everything a selective isolation carrying names was
// granted under. Following a name changes one input, the name's addresses; the
// endpoint's scope and capabilities are what it reported then, because a host
// under containment reports its own, and the exceptions are the ones signed then.
type isolationFabric struct {
	At          time.Time                    `json:"at"`
	Own         []string                     `json:"own"`
	Rules       []trustfabric.Rule           `json:"rules"`
	Endpoint    trustfabric.Endpoint         `json:"endpoint"`
	TakesRanges bool                         `json:"takes_ranges"`
	Baselines   []response.IsolationBaseline `json:"baselines,omitempty"`
}

// freezeIsolationFabric returns what records the fabric once the isolation has
// succeeded. Without a name in it there is nothing to follow.
func (s *Server) freezeIsolationFabric(endpointID string, own []string, now time.Time) func() {
	ep, err := s.store.GetEndpoint(endpointID)
	if err != nil || ep == nil {
		return nil
	}
	rules, err := s.store.TrustRules()
	if err != nil {
		return nil
	}
	fe := fabricEndpoint(ep)
	f := isolationFabric{At: now, Own: own, Endpoint: fe, TakesRanges: agentTakesAllowRanges(ep)}
	names := false
	for _, r := range rules {
		if r.Active(now) && r.AppliesTo(fe) {
			f.Rules = append(f.Rules, r)
			names = names || r.Kind == trustfabric.KindFQDN
		}
	}
	if !names {
		return nil
	}
	if f.Baselines, err = s.isolationBaselines([]string{endpointID}); err != nil {
		return nil
	}
	raw, err := json.Marshal(f)
	if err != nil {
		return nil
	}
	return func() {
		if err := s.store.SetIsolationFabric(endpointID, string(raw)); err != nil {
			log.Printf("[!] isolation of %s will not follow its names: %v", endpointID, err)
		}
	}
}

// followedAllowList is the list a frozen fabric comes to under these answers,
// and what stays closed. An agent that has since lost range support only ever
// narrows it: a grant naming a range would be refused whole.
func followedAllowList(f isolationFabric, ep *storage.Endpoint, answers map[string]storage.TrustNameAnswer) (want, closed []string) {
	ranges := f.TakesRanges && agentTakesAllowRanges(ep)
	own := f.Own
	if !ranges {
		var pol trustfabric.Policy
		for _, entry := range f.Own {
			if pre, err := netip.ParsePrefix(entry); err == nil {
				pol.Allow = append(pol.Allow, pre)
			} else if a, err := netip.ParseAddr(entry); err == nil {
				pol.Addresses = append(pol.Addresses, a)
			}
		}
		own, closed = allowEntries(pol, false, nil)
	}
	p := compileFabricFor(f.Endpoint, ranges, f.Rules, answers, f.At)
	want, over := capAllowList(unionAddrs(own, p.Enforced))
	return want, append(append(closed, p.NotEnforced...), over...)
}

func (s *Server) trustNameLoop() {
	for {
		s.refreshTrustNames(context.Background(), time.Now().UTC())
		time.Sleep(time.Duration(s.intSetting(trustNameRefreshSetting, trustNameRefreshDefault, trustNameRefreshMin, trustNameRefreshMax)) * time.Second)
	}
}

// refreshTrustNames resolves every name a rule or an isolation in force uses,
// and re-signs the isolations whose addresses moved.
func (s *Server) refreshTrustNames(ctx context.Context, now time.Time) {
	rules, err := s.store.TrustRules()
	if err != nil {
		log.Printf("[!] trust names: %v", err)
		return
	}
	isolated, err := s.store.IsolatedEndpoints()
	if err != nil {
		log.Printf("[!] trust names: %v", err)
		return
	}
	names := map[string]bool{}
	for _, r := range rules {
		if r.Kind == trustfabric.KindFQDN && r.Active(now) {
			names[r.Value] = true
		}
	}
	type carried struct {
		rec storage.IsolationRecord
		f   isolationFabric
	}
	var live []carried
	for _, rec := range isolated {
		var f isolationFabric
		if rec.Fabric == "" || json.Unmarshal([]byte(rec.Fabric), &f) != nil {
			continue
		}
		live = append(live, carried{rec, f})
		for _, r := range f.Rules {
			if r.Kind == trustfabric.KindFQDN {
				names[r.Value] = true
			}
		}
	}
	s.lookupTrustNames(ctx, names, now)
	// A rule written during the lookups keeps the answer its creation fetched.
	keep := names
	if fresh, err := s.store.TrustRules(); err != nil {
		log.Printf("[!] trust names: %v", err)
		keep = nil
	} else {
		for _, r := range fresh {
			if r.Kind == trustfabric.KindFQDN {
				keep[r.Value] = true
			}
		}
	}
	if keep != nil {
		if err := s.store.ForgetTrustNameAnswers(keep); err != nil {
			log.Printf("[!] trust names: %v", err)
		}
	}
	if len(live) == 0 {
		return
	}
	answers, err := s.store.TrustNameAnswers()
	if err != nil {
		log.Printf("[!] trust names: %v", err)
		return
	}
	for _, c := range live {
		ep, err := s.store.GetEndpoint(c.rec.EndpointID)
		if err != nil || ep == nil {
			continue
		}
		want, closed := followedAllowList(c.f, ep, answers)
		if sameAddressSet(c.rec.AllowIPs, want) {
			continue
		}
		if err := s.regrantIsolation(ctx, ep, c.rec, c.f, want, closed); err != nil {
			log.Printf("[!] isolation of %s could not follow its names: %v", c.rec.EndpointID, err)
			s.recordTrustNameAudit(c.rec, "TRUST_NAME_REGRANT_FAILED", err.Error())
		}
	}
}

// regrantIsolation signs and delivers one isolation's new address list, as a
// request to the isolate route would, keeping the isolation's id, fabric and
// signed exceptions. rec may be stale: if that isolation is no longer the one in
// force, nothing is recorded and the grant is withdrawn before any agent sees it.
func (s *Server) regrantIsolation(ctx context.Context, ep *storage.Endpoint, rec storage.IsolationRecord, f isolationFabric, allow, closed []string) error {
	if s.responseAuth == nil {
		return fmt.Errorf("the grant signer is not available")
	}
	s.isolationMu.Lock()
	defer s.isolationMu.Unlock()
	const route = "/api/v1/endpoints/isolate"
	body, err := json.Marshal(map[string]any{"endpoint_id": rec.EndpointID, "mode": isolationModeSelective, "allow_ips": allow})
	if err != nil {
		return err
	}
	canon, err := canonicalJSON(body)
	if err != nil {
		return err
	}
	fields := map[string]any{"route": route, "body": json.RawMessage(canon), "targets": []string{rec.EndpointID}}
	if len(f.Baselines) > 0 {
		fields["baselines"] = f.Baselines
	}
	payload, err := json.Marshal(fields)
	if err != nil {
		return err
	}
	if len(payload) > maxGrantPayload {
		return fmt.Errorf("the signed payload would be %d bytes; agents accept at most %d", len(payload), maxGrantPayload)
	}
	au, err := s.responseAuth.Authorize(ctx, &grants.AuthorizeInput{
		TenantID: endpointTenant(ep), Requester: "hub (a trusted name's addresses moved)",
		Kind: grants.ActionKindIsolation, Targets: []string{rec.EndpointID}, Payload: payload,
	})
	if err != nil {
		return err
	}
	kept, err := s.keepApprovalGrants(route, grants.ActionKindIsolation, payload, au.Grants)
	if err != nil {
		return err
	}
	current, err := s.store.UpdateIsolationAllowList(rec.EndpointID, rec.ID, rec.Fabric, allow)
	if err != nil || !current {
		if derr := s.store.DeleteEnforcementGrants(kept); derr != nil {
			log.Printf("[!] could not withdraw the grant of a superseded isolation of %s: %v", rec.EndpointID, derr)
		}
		return err
	}
	if err := s.store.MarkGrantsDeliverable(s.withoutHeldGrants(kept)); err != nil {
		return fmt.Errorf("signed but not released to the agent: %w", err)
	}
	details := fmt.Sprintf("isolation %s, authorization %s: a trusted name's addresses moved; now %s (was %s)",
		rec.ID, au.ID, strings.Join(allow, ", "), strings.Join(rec.AllowIPs, ", "))
	if len(closed) > 0 {
		details += "; not enforced: " + strings.Join(closed, ", ")
	}
	s.recordTrustNameAudit(rec, "TRUST_NAME_REGRANTED", details)
	return nil
}

func (s *Server) recordTrustNameAudit(rec storage.IsolationRecord, action, details string) {
	if err := s.store.RecordAudit(storage.AuditEntry{
		ID: uuid.New().String(), TenantID: rec.TenantID, Username: "hub", Action: action,
		Resource: rec.EndpointID, Details: details, Timestamp: time.Now().UTC(),
	}); err != nil {
		log.Printf("[!] audit %s: %v", action, err)
	}
}
