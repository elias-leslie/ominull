package server

// The maintenance schedule. Every few minutes the hub walks each package
// (maintenance and security alike) and each Windows host that is online now,
// and works out the effective settings (fleet default, endpoint override,
// category switch). A package is due on a host when it is enabled there and
// its last successful run is older than its interval, so a laptop that was off
// catches up the next time it is online. Hosts with the same settings share
// one run.
//
// Each due run goes to the response authority like a hand-made one. A
// baseline run (a safe package auditing with its default settings) or one the
// owner's package rule covers is approved at once and dispatched; grants are
// signed now, for hosts online now. Anything else (enforce, a careful package,
// changed settings) files one owner ask (a Nightshift push, one tap) and waits
// for it; the run is dispatched once approved. An ask the owner declines or
// lets expire is not filed again for the same settings for a day. Disabling a
// package or switching it to audit never asks.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"ominull/hub/pkg/response"
	"ominull/hub/pkg/responseauth"
	"ominull/hub/pkg/scripts"
	"ominull/hub/pkg/storage"
)

const (
	maintenanceTick = 5 * time.Minute
	// A run that did not succeed (skipped because someone was using the
	// machine, failed, no result) is tried again after this long.
	maintenanceRetry = time.Hour
	// endpointOnline matches the endpoints list: seen within 30 s.
	endpointOnline = 30 * time.Second
	// maintenanceReask: a declined or expired ask is not filed again for
	// the same run sooner than this.
	maintenanceMaxTargets = 50 // the authority's limit for one approval
	maintenanceReask      = 24 * time.Hour
	schedulerName         = "maintenance schedule"
)

// scheduleBlock is why a due run is not running (Nightshift feed).
type scheduleBlock struct {
	Package   string    `json:"package"`
	Endpoints []string  `json:"endpoints"`
	Reason    string    `json:"reason"`
	Since     time.Time `json:"since"`
}

// pendingAsk is an owner ask the schedule filed and waits on.
type pendingAsk struct {
	ID      string
	Tenant  string
	Payload []byte
	Items   []packageRunItem
	Targets []string
	Label   string
	Since   time.Time
}

type maintenanceBlocks struct {
	run      sync.Mutex     // one pass at a time
	kicks    sync.WaitGroup // passes started by a settings change
	mu       sync.Mutex
	items    map[string]scheduleBlock // run key
	asks     map[string]*pendingAsk   // run key
	declined map[string]time.Time     // run key -> when
}

func (b *maintenanceBlocks) set(key string, blk scheduleBlock) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.items == nil {
		b.items = map[string]scheduleBlock{}
	}
	if old, ok := b.items[key]; ok && old.Reason == blk.Reason {
		blk.Since = old.Since
	}
	b.items[key] = blk
}

func (b *maintenanceBlocks) clear(key string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.items, key)
}

func (b *maintenanceBlocks) list() []scheduleBlock {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make([]scheduleBlock, 0, len(b.items))
	for _, v := range b.items {
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Package < out[j].Package })
	return out
}

func (s *Server) maintenanceScheduleLoop() {
	t := time.NewTicker(maintenanceTick)
	defer t.Stop()
	for range t.C {
		s.runMaintenanceSchedules(time.Now().UTC())
	}
}

// packageRunDue says whether a package should run on a host now, from its
// newest jobs there (newest first).
func packageRunDue(jobs []*response.JobRecord, interval time.Duration, now time.Time) bool {
	var lastSuccess, lastAttempt time.Time
	for _, j := range jobs {
		run := derivePackageRun(j, now)
		switch run.State {
		case "waiting", "running":
			return false // one at a time
		case "ok", "fixed", "drift":
			if lastSuccess.IsZero() {
				lastSuccess = j.RequestedAt
			}
		}
		if lastAttempt.IsZero() {
			lastAttempt = j.RequestedAt
		}
	}
	if !lastSuccess.IsZero() && now.Sub(lastSuccess) < interval {
		return false
	}
	return lastAttempt.IsZero() || now.Sub(lastAttempt) >= maintenanceRetry
}

func (s *Server) runMaintenanceSchedules(now time.Time) {
	if s.scriptsStore == nil || s.responseStore == nil || s.responseAuth == nil {
		return
	}
	s.maintBlocks.run.Lock()
	defer s.maintBlocks.run.Unlock()
	eps, err := s.store.ListEndpoints("")
	if err != nil {
		log.Printf("[!] maintenance schedule: %v", err)
		return
	}
	tenants := map[string][]*storage.Endpoint{}
	for i := range eps {
		ep := eps[i]
		if ep.Status == "retired" || !strings.Contains(strings.ToLower(ep.OS), "windows") {
			continue
		}
		t := ep.TenantID
		if t == "" {
			t = "default"
		}
		tenants[t] = append(tenants[t], &ep)
	}
	live := map[string]bool{}
	for tenant, list := range tenants {
		if err := s.runTenantMaintenance(tenant, list, now, live); err != nil {
			log.Printf("[!] maintenance schedule (%s): %v", tenant, err)
		}
	}
	// Forget blocks and asks for runs that are no longer due or wanted.
	b := &s.maintBlocks
	b.mu.Lock()
	for k := range b.items {
		if !live[k] {
			delete(b.items, k)
		}
	}
	// An ask outlives a pass where its hosts are offline, so a laptop that
	// drops off for a while picks up the same ask when it is back instead of
	// putting a second one on the owner's phone.
	for k, a := range b.asks {
		if !live[k] && now.Sub(a.Since) >= maintenanceReask {
			delete(b.asks, k)
		}
	}
	for k, at := range b.declined {
		if now.Sub(at) >= maintenanceReask {
			delete(b.declined, k)
		}
	}
	b.mu.Unlock()
}

func (s *Server) runTenantMaintenance(tenant string, eps []*storage.Endpoint, now time.Time, live map[string]bool) error {
	defs, err := s.packageDefs(tenant)
	if err != nil {
		return err
	}
	st, err := s.maintenanceSettings(tenant)
	if err != nil {
		return err
	}
	for _, d := range defs {
		if !windowsInterpreter(d.Script.Interpreter) {
			continue
		}
		groups := map[string]*pendingAsk{} // item digest -> run
		for _, ep := range eps {
			eff := st.Effective(d.Header, ep.ID)
			if !eff.Enabled || now.Sub(ep.LastSeenAt) >= endpointOnline {
				continue
			}
			interval, ok := scripts.RecurrenceInterval(eff.Interval)
			if !ok {
				continue
			}
			jobs, err := s.responseStore.ScriptJobs(tenant, ep.ID, d.Script.ID, 20)
			if err != nil {
				return err
			}
			if !packageRunDue(jobs, interval, now) {
				continue
			}
			params := eff.RunParams("")
			if d.Header.CheckRun(params) != nil {
				continue
			}
			raw, err := packageItem(d.Script, d.Version, params, d.Header.Timeout, packageMaxOutput)
			if err != nil {
				return err
			}
			dg := responseauth.ItemDigest(raw)
			g := groups[dg]
			if g == nil {
				g = &pendingAsk{Tenant: tenant, Items: []packageRunItem{{Raw: raw, Digest: dg, Script: d.Script, Version: d.Version.Version}},
					Label: d.Header.Name + " (" + params["mode"] + ")"}
				groups[dg] = g
			}
			g.Targets = append(g.Targets, ep.ID)
		}
		for dg, g := range groups {
			g.Targets = sortedTargets(g.Targets)
			// One ask per run payload, whatever hosts are due: a host going
			// offline or coming back must not file a second ask or dodge a
			// decline. An ask covers at most the authority's target limit;
			// the rest wait for the next one.
			if len(g.Targets) > maintenanceMaxTargets {
				g.Targets = g.Targets[:maintenanceMaxTargets]
			}
			key := tenant + "|" + dg
			live[key] = true
			s.runScheduledPackage(key, g, now)
		}
	}
	return nil
}

func (s *Server) runScheduledPackage(key string, run *pendingAsk, now time.Time) {
	b := &s.maintBlocks
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	block := func(reason string) {
		b.set(key, scheduleBlock{Package: run.Label, Endpoints: run.Targets, Reason: reason, Since: now})
	}
	b.mu.Lock()
	ask := b.asks[key]
	declinedAt, declined := b.declined[key]
	b.mu.Unlock()
	if ask == nil && declined && now.Sub(declinedAt) < maintenanceReask {
		block("you declined this run or let the ask expire; asking again a day later or when its settings change")
		return
	}
	if ask != nil {
		v, err := s.responseAuth.GetApproval(ctx, ask.ID, ask.Tenant)
		if err != nil {
			if errors.Is(err, responseauth.ErrApprovalNotFound) || now.Sub(ask.Since) >= maintenanceReask {
				// The authority no longer has it (restarted, or long gone):
				// ask afresh on the next pass instead of waiting forever.
				b.mu.Lock()
				delete(b.asks, key)
				b.mu.Unlock()
			}
			block("could not read the owner ask: " + err.Error())
			return
		}
		switch v.State {
		case responseauth.ApprovalPending:
			b.set(key, scheduleBlock{Package: run.Label, Endpoints: ask.Targets, Reason: "waiting for your approval", Since: now})
			return
		case responseauth.ApprovalApproved:
			s.dispatchScheduled(ctx, key, ask, v.ID, run.Targets, now)
		default:
			b.mu.Lock()
			delete(b.asks, key)
			if b.declined == nil {
				b.declined = map[string]time.Time{}
			}
			b.declined[key] = now
			b.mu.Unlock()
			block("you declined this run or let the ask expire; asking again a day later or when its settings change")
		}
		return
	}
	run.Payload = packageRunPayload(run.Items, run.Targets)
	run.Since = now
	v, err := s.responseAuth.RequestApproval(ctx, &responseauth.ApprovalRequestInput{
		TenantID: run.Tenant, Requester: schedulerName, Kind: response.ActionKindScriptExec,
		Action: "Run maintenance", Summary: run.Label, Targets: run.Targets, Payload: run.Payload,
	})
	if err != nil {
		block("the owner could not be asked: " + err.Error())
		return
	}
	run.ID = v.ID
	if v.State == responseauth.ApprovalApproved {
		s.dispatchScheduled(ctx, key, run, v.ID, run.Targets, now)
		return
	}
	b.mu.Lock()
	if b.asks == nil {
		b.asks = map[string]*pendingAsk{}
	}
	b.asks[key] = run
	b.mu.Unlock()
	block("waiting for your approval")
}

// dispatchScheduled spends an approval (for exactly the hosts it named) and
// creates jobs only on the hosts that are due and online now: a grant lives a
// few minutes, so a host that went offline since the ask is asked for again
// when it is back.
func (s *Server) dispatchScheduled(ctx context.Context, key string, run *pendingAsk, approvalID string, due []string, now time.Time) {
	b := &s.maintBlocks
	b.mu.Lock()
	delete(b.asks, key)
	b.mu.Unlock()
	sum := sha256.Sum256(run.Payload)
	grants, err := s.responseAuth.ConsumeApproval(ctx, &responseauth.ApprovalConsumeRequest{
		ID: approvalID, TenantID: run.Tenant, Requester: schedulerName, Kind: response.ActionKindScriptExec,
		Digest: hex.EncodeToString(sum[:]), Targets: run.Targets,
	})
	if err != nil {
		b.set(key, scheduleBlock{Package: run.Label, Endpoints: run.Targets, Reason: "approval could not be used: " + err.Error(), Since: now})
		return
	}
	b.clear(key)
	dueNow := map[string]bool{}
	for _, ep := range due {
		dueNow[ep] = true
	}
	use := grants[:0]
	for _, g := range grants {
		if dueNow[g.EndpointID] {
			use = append(use, g)
		}
	}
	jobs, err := s.dispatchPackageGrants(run.Tenant, schedulerName, run.Items, use)
	if err != nil {
		log.Printf("[!] maintenance schedule: %s: %v", run.Label, err)
	}
	if len(jobs) == 0 {
		return
	}
	ids := make([]string, 0, len(jobs))
	for _, j := range jobs {
		ids = append(ids, j.JobID)
	}
	_ = s.store.RecordAudit(storage.AuditEntry{
		ID: uuid.New().String(), TenantID: run.Tenant, Username: "schedule", Action: "SCRIPT_RUN_DISPATCHED",
		Resource: run.Items[0].Script.ID, Timestamp: now,
		Details: fmt.Sprintf("Scheduled package %s v%d on %s (approval %s); jobs %s",
			run.Label, run.Items[0].Version, strings.Join(run.Targets, ", "), approvalID, strings.Join(ids, ",")),
	})
}
