package server

import (
	"time"

	"ominull/hub/pkg/response"
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
