package server

// The maintenance schedule. Every few minutes the hub walks each package
// (maintenance and security alike) and each Windows host that is online now,
// and works out the effective settings (fleet default, endpoint override,
// category switch). A package is due on a host when it is enabled there and
// its last successful run is older than its interval, so a laptop that was off
// catches up the next time it is online. Hosts with the same settings share
// one run.
//
// Each due run goes to the response authority like a hand-made one: the
// authority checks it and signs the grants now, for hosts online now, and the
// run is dispatched at once. Nobody is asked; a run the authority will not
// sign shows up as a schedule block (Nightshift feed, console) with its
// reason, and is tried again on the next pass.
//
// Audit-then-enforce: a safe package whose setting on_drift is "enforce"
// (mode audit) keeps auditing on its interval; when a host's newest run is a
// scheduled audit that found drift, the next pass runs one enforce run there,
// inside the host's maintenance window.

import (
	"context"
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
	endpointOnline        = 30 * time.Second
	maintenanceMaxTargets = 50 // the authority's limit for one authorization
	schedulerName         = "maintenance schedule"
)

// scheduleBlock is why a due run is not running (Nightshift feed).
type scheduleBlock struct {
	Package   string    `json:"package"`
	Endpoints []string  `json:"endpoints"`
	Reason    string    `json:"reason"`
	Since     time.Time `json:"since"`
}

// scheduledRun is one due run: a package's item on the hosts it is due on.
type scheduledRun struct {
	ID      string
	Tenant  string
	Payload []byte
	Items   []packageRunItem
	Targets []string
	Label   string
	Since   time.Time
}

type maintenanceBlocks struct {
	run   sync.Mutex     // one pass at a time
	kicks sync.WaitGroup // passes started by a settings change
	mu    sync.Mutex
	items map[string]scheduleBlock // run key
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
	go s.playbookLoop()
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

// driftNeedsFix: the host's newest run of the package (jobs newest first) is
// a scheduled audit that finished with drift, and nothing ran after it. One
// fix per drifting audit: if the fix fails or is declined, the next scheduled
// audit decides again.
func driftNeedsFix(jobs []*response.JobRecord, accepted map[string]acceptedRisk) bool {
	if len(jobs) == 0 || jobs[0].RequestedBy != schedulerName {
		return false
	}
	run := derivePackageRun(jobs[0], time.Now())
	applyAcceptedRisks(run, accepted) // drift the owner accepted needs no fix
	return run.State == "drift" && run.Mode == "audit" && run.CompletedAt != nil
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
		if ep.Status == "retired" {
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
	// Forget blocks for runs that are no longer due or wanted.
	b := &s.maintBlocks
	b.mu.Lock()
	for k := range b.items {
		if !live[k] {
			delete(b.items, k)
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
	acceptedAll := s.allAcceptedRisks()
	busy := s.playbookBusyHosts() // a playbook running there has the machine
	for _, d := range defs {
		// Maintenance mode is switched on for a while and a restart is a
		// playbook step; neither runs on a schedule.
		if d.Script.Interpreter != d.Header.Interpreter() || d.Header.Role != "" {
			continue
		}
		groups := map[string]*scheduledRun{} // item digest -> run
		for _, ep := range eps {
			if !d.Header.RunsOn(ep.OS) || busy[ep.ID] {
				continue
			}
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
			mode := ""
			if !packageRunDue(jobs, interval, now) {
				if eff.OnDrift != "enforce" || eff.Mode != "audit" || !driftNeedsFix(jobs, acceptedAll[ep.ID]) {
					continue
				}
				mode = "enforce" // audit-then-enforce: the scheduled audit found drift
			}
			params := eff.RunParams(mode)
			addWindow(d.Header, params, s.windowParams([]string{ep.ID})[ep.ID])
			if params["window"] != "" && !s.windowOpenOrUnknown(params["window"], ep.ID, now) {
				continue // enforce waits for the machine's window
			}
			if s.fillCatalogParams(d.Header, params) != nil || d.Header.CheckRun(params) != nil {
				continue
			}
			raw, err := packageItem(d.Script, d.Version, params, d.Header.Timeout, packageMaxOutput)
			if err != nil {
				return err
			}
			dg := responseauth.ItemDigest(raw)
			g := groups[dg]
			if g == nil {
				label := d.Header.Name + " (" + params["mode"] + ")"
				if mode == "enforce" {
					label = d.Header.Name + " (enforce: the scheduled audit found drift)"
				}
				g = &scheduledRun{Tenant: tenant, Items: []packageRunItem{{Raw: raw, Digest: dg, Script: d.Script, Version: d.Version.Version}},
					Label: label}
				groups[dg] = g
			}
			g.Targets = append(g.Targets, ep.ID)
		}
		for dg, g := range groups {
			g.Targets = sortedTargets(g.Targets)
			// One run per payload, whatever hosts are due. A run covers at
			// most the authority's target limit; the rest wait for the next
			// pass.
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

func (s *Server) runScheduledPackage(key string, run *scheduledRun, now time.Time) {
	b := &s.maintBlocks
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	block := func(reason string) {
		b.set(key, scheduleBlock{Package: run.Label, Endpoints: run.Targets, Reason: reason, Since: now})
	}
	if s.responseAuth == nil {
		block("the response authority is not available")
		return
	}
	run.Payload = packageRunPayload(run.Items, run.Targets)
	run.Since = now
	au, err := s.responseAuth.Authorize(ctx, &responseauth.AuthorizeInput{
		TenantID: run.Tenant, Requester: schedulerName, Kind: response.ActionKindScriptExec,
		Targets: run.Targets, Payload: run.Payload,
	})
	if err != nil {
		block("the authority did not sign this run: " + err.Error())
		return
	}
	run.ID = au.ID
	b.clear(key)
	jobs, err := s.dispatchPackageGrants(run.Tenant, schedulerName, run.ID, run.Items, au.Grants)
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
		Details: fmt.Sprintf("Scheduled package %s v%d on %s (authorization %s); jobs %s",
			run.Label, run.Items[0].Version, strings.Join(run.Targets, ", "), au.ID, strings.Join(ids, ",")),
	})
}
