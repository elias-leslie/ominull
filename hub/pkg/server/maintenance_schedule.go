package server

// The package schedule: a loop over script_schedules that runs a scheduled
// package on a host when its last successful run there is older than the
// schedule's interval (so a laptop that was off catches up the next time it
// is online). Only runs the owner's package rule covers are dispatched: the
// loop asks the authority rule-only, so nothing is ever pushed to the owner
// from here, and a schedule the rule does not cover (a new script version,
// another host) waits and is reported in the Nightshift feed instead.
// Grants are signed at dispatch, only for hosts online at that moment.

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
)

// scheduleBlock is why a schedule could not run on its last due pass.
type scheduleBlock struct {
	Package   string    `json:"package"`
	Endpoints []string  `json:"endpoints"`
	Reason    string    `json:"reason"`
	Since     time.Time `json:"since"`
}

type maintenanceBlocks struct {
	mu    sync.Mutex
	items map[string]scheduleBlock // schedule id
}

func (b *maintenanceBlocks) set(id string, blk scheduleBlock) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.items == nil {
		b.items = map[string]scheduleBlock{}
	}
	if old, ok := b.items[id]; ok && old.Reason == blk.Reason {
		blk.Since = old.Since
	}
	b.items[id] = blk
}

func (b *maintenanceBlocks) clear(id string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.items, id)
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
	list, err := s.scriptsStore.ActiveSchedules()
	if err != nil {
		log.Printf("[!] maintenance schedule: %v", err)
		return
	}
	for _, sched := range list {
		if err := s.runMaintenanceSchedule(sched, now); err != nil {
			log.Printf("[!] maintenance schedule %s: %v", sched.ID, err)
		}
	}
}

func (s *Server) runMaintenanceSchedule(sched *scripts.ScriptSchedule, now time.Time) error {
	interval, ok := scripts.RecurrenceInterval(sched.Recurrence)
	if !ok || now.Before(sched.StartTime) || (sched.EndTime != nil && !now.Before(*sched.EndTime)) ||
		(sched.MaxRuns > 0 && sched.RunsCount >= sched.MaxRuns) {
		return nil
	}
	sc, err := s.scriptsStore.GetScript(sched.TenantID, sched.ScriptID)
	if err != nil {
		return err
	}
	if sc.Package() == nil || sc.Retired {
		return nil // only packages run unattended
	}
	sv, err := s.scriptsStore.GetScriptVersion(sched.TenantID, sched.ScriptID, sched.Version)
	if err != nil {
		return err
	}
	if sv.DigestSHA256 != sched.ScriptDigest {
		return fmt.Errorf("version %d no longer has the frozen digest", sched.Version)
	}
	var due []string
	for _, epID := range sched.TargetEndpoints {
		ep, err := s.store.GetEndpoint(epID)
		if err != nil || ep == nil || ep.Status == "retired" || now.Sub(ep.LastSeenAt) >= endpointOnline {
			continue
		}
		jobs, err := s.responseStore.ScriptJobs(sched.TenantID, epID, sched.ScriptID, 20)
		if err != nil {
			return err
		}
		if packageRunDue(jobs, interval, now) {
			due = append(due, epID)
		}
	}
	if len(due) == 0 {
		return nil
	}
	due = sortedTargets(due)
	raw, err := packageItem(sc, sv, sched.Parameters, sched.TimeoutSeconds, sched.MaxOutputBytes)
	if err != nil {
		return err
	}
	items := []packageRunItem{{Raw: raw, Digest: responseauth.ItemDigest(raw), Script: sc, Version: sv.Version}}
	payload := packageRunPayload(items, due)
	requester := "schedule " + sched.ID
	label := sc.Name
	if m := sched.Parameters["mode"]; m != "" {
		label += " (" + m + ")"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	v, err := s.responseAuth.RequestApproval(ctx, &responseauth.ApprovalRequestInput{
		TenantID: sched.TenantID, Requester: requester, Kind: response.ActionKindScriptExec,
		Action: "Run maintenance", Summary: label, Targets: due, Payload: payload, RuleOnly: true,
	})
	if err != nil {
		reason := err.Error()
		var ae *responseauth.ApprovalError
		if errors.Is(err, responseauth.ErrRuleNotCovered) || (errors.As(err, &ae) && ae.Message == responseauth.ErrRuleNotCovered.Error()) {
			reason = "no approve-all rule covers this exact script on these hosts"
		}
		s.maintBlocks.set(sched.ID, scheduleBlock{Package: label, Endpoints: due, Reason: reason, Since: now})
		return nil
	}
	sum := sha256.Sum256(payload)
	grants, err := s.responseAuth.ConsumeApproval(ctx, &responseauth.ApprovalConsumeRequest{
		ID: v.ID, TenantID: sched.TenantID, Requester: requester, Kind: response.ActionKindScriptExec,
		Digest: hex.EncodeToString(sum[:]), Targets: due,
	})
	if err != nil {
		s.maintBlocks.set(sched.ID, scheduleBlock{Package: label, Endpoints: due, Reason: "approval could not be used: " + err.Error(), Since: now})
		return nil
	}
	s.maintBlocks.clear(sched.ID)
	jobs, err := s.dispatchPackageGrants(sched.TenantID, requester, items, grants)
	if n := len(jobs); n > 0 {
		_ = s.scriptsStore.CountScheduleRuns(sched.TenantID, sched.ID, n)
		ids := make([]string, 0, n)
		for _, j := range jobs {
			ids = append(ids, j.JobID)
		}
		_ = s.store.RecordAudit(storage.AuditEntry{
			ID: uuid.New().String(), TenantID: sched.TenantID, Username: "schedule", Action: "SCRIPT_RUN_DISPATCHED",
			Resource: sched.ID, Timestamp: now,
			Details: fmt.Sprintf("Scheduled package %s v%d on %s under the owner's package rule (approval %s); jobs %s",
				label, sv.Version, strings.Join(due, ", "), v.ID, strings.Join(ids, ",")),
		})
	}
	return err
}
