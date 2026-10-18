package server

import (
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"ominull/hub/pkg/response"
	"ominull/hub/pkg/storage"
	"ominull/hub/pkg/terminal"
)

// Terminal and screen jobs carry a session offer. The agent starts the
// session and never posts a result (the session is the work), so the hub
// ends the job when the session ends: succeeded once it ran, failed when it
// never started, cancelled when no agent took the offer.

const (
	sessionJobTick = time.Minute
	// A job whose session the hub no longer knows ends after this long.
	sessionJobOrphanAfter = 24 * time.Hour
)

func (s *Server) sessionJobsLoop() {
	t := time.NewTicker(sessionJobTick)
	defer t.Stop()
	for {
		s.reconcileSessionJobs(time.Now().UTC())
		<-t.C
	}
}

// reconcileSessionJobs ends the session jobs whose sessions have ended.
func (s *Server) reconcileSessionJobs(now time.Time) int {
	if s.responseStore == nil || s.terminalMgr == nil {
		return 0
	}
	open, err := s.responseStore.OpenSessionJobs()
	if err != nil {
		return 0
	}
	n := 0
	for _, j := range open {
		code, detail, end := sessionJobOutcome(s.terminalMgr, j, now)
		if !end {
			continue
		}
		if s.responseStore.EndSessionJob(j.JobID, code, detail) == nil {
			n++
			s.auditSessionJobEnd(j, detail, now)
		}
	}
	if n > 0 {
		s.jobWake.notify()
	}
	return n
}

func sessionJobOutcome(m *terminal.Manager, j response.OpenSessionJob, now time.Time) (code, detail string, end bool) {
	if j.SessionID != "" {
		ended, state, reason, started, ok := m.SessionEnd(j.SessionID)
		if ok {
			if !ended {
				return "", "", false
			}
			if reason == "" {
				reason = string(state)
			}
			switch {
			case started && state != terminal.StateFailed:
				return "", "session ended: " + reason, true
			case started:
				return "session_failed", "session failed: " + reason, true
			default:
				return "session_never_started", "the agent never joined the session: " + reason, true
			}
		}
	}
	if now.Sub(j.RequestedAt) < sessionJobOrphanAfter {
		return "", "", false
	}
	return "session_unknown", "the hub no longer knows this session", true
}

// auditSessionJobEnd leaves a SCREEN_SESSION_ENDED row for a screen session
// the hub ended on its own (an agent frame it refuses, the agent leaving, a
// time limit), so its reason is in the audit log and not only in the job.
// A session the operator closed already has SCREEN_SESSION_CLOSED.
func (s *Server) auditSessionJobEnd(j response.OpenSessionJob, detail string, now time.Time) {
	if j.Kind != response.ActionKindScreenSession || strings.HasSuffix(detail, ": operator_closed") {
		return
	}
	resource := j.SessionID
	if resource == "" {
		resource = j.JobID
	}
	_ = s.store.RecordAudit(storage.AuditEntry{
		ID:        uuid.New().String(),
		TenantID:  j.TenantID,
		Username:  "hub",
		Action:    "SCREEN_SESSION_ENDED",
		Resource:  resource,
		Details:   fmt.Sprintf("The screen session on %s ended without the operator closing it (%s)", j.EndpointID, detail),
		Timestamp: now,
	})
}
