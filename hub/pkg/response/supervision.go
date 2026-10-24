package response

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// The endpoint supervises every script_exec job it runs and posts a heartbeat
// (POST /api/v1/response/jobs/progress) every 30 s and whenever its phase or
// progress line changes. The latest heartbeat per job is kept here, beside
// response_jobs, so nothing else about a job's record changes: running is
// still the job state, and the phase says how the run is going.

// Supervision phases an endpoint reports.
const (
	PhaseRunning    = "running"
	PhaseStalled    = "stalled"     // no output, CPU or IO for a while, no window waiting
	PhaseNeedsHands = "needs_hands" // stalled with a visible window waiting for a click
)

// SupervisedWindow is the window a needs_hands job is waiting on.
type SupervisedWindow struct {
	Title   string `json:"title"`
	Process string `json:"process"`
	PID     int    `json:"pid,omitempty"`
	Session int    `json:"session"`
}

// JobHeartbeat is what an endpoint posts while a job runs.
type JobHeartbeat struct {
	JobID       string            `json:"job_id"`
	LeaseID     string            `json:"lease_id"`
	Phase       string            `json:"phase"`
	ProgressPct *int              `json:"progress_pct,omitempty"`
	Message     string            `json:"message,omitempty"`
	CPUms       int64             `json:"cpu_ms,omitempty"`
	IOBytes     int64             `json:"io_bytes,omitempty"`
	IdleSeconds int               `json:"idle_seconds,omitempty"`
	Processes   int               `json:"processes,omitempty"`
	Window      *SupervisedWindow `json:"window,omitempty"`
}

// JobSupervision is the latest heartbeat of a job, as the hub keeps it.
type JobSupervision struct {
	JobID       string            `json:"job_id"`
	EndpointID  string            `json:"endpoint_id"`
	Phase       string            `json:"phase"`
	PhaseSince  time.Time         `json:"phase_since"`
	HeartbeatAt time.Time         `json:"heartbeat_at"`
	Heartbeats  int               `json:"heartbeats"`
	ProgressPct int               `json:"progress_pct"` // -1 when the run has not said
	Message     string            `json:"message,omitempty"`
	CPUms       int64             `json:"cpu_ms"`
	IOBytes     int64             `json:"io_bytes"`
	IdleSeconds int               `json:"idle_seconds"`
	Processes   int               `json:"processes"`
	Window      *SupervisedWindow `json:"window,omitempty"`
}

// Limits on what an endpoint may put in a heartbeat.
const (
	maxHeartbeatText = 200
)

// cleanHeartbeatText keeps endpoint text printable and short.
func cleanHeartbeatText(s string) string {
	s = strings.ToValidUTF8(s, "")
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || r == utf8.RuneError {
			return ' '
		}
		return r
	}, s)
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > maxHeartbeatText {
		cut := maxHeartbeatText
		for cut > 0 && !utf8.RuneStart(s[cut]) {
			cut--
		}
		s = s[:cut]
	}
	return s
}

// clean validates and normalises a heartbeat in place.
func (hb *JobHeartbeat) clean() error {
	switch hb.Phase {
	case PhaseRunning, PhaseStalled, PhaseNeedsHands:
	case "":
		hb.Phase = PhaseRunning
	default:
		return fmt.Errorf("unknown phase %q", hb.Phase)
	}
	hb.Message = cleanHeartbeatText(hb.Message)
	if hb.ProgressPct != nil && (*hb.ProgressPct < 0 || *hb.ProgressPct > 100) {
		hb.ProgressPct = nil
	}
	clamp := func(v int64) int64 {
		if v < 0 {
			return 0
		}
		return v
	}
	hb.CPUms, hb.IOBytes = clamp(hb.CPUms), clamp(hb.IOBytes)
	if hb.IdleSeconds < 0 {
		hb.IdleSeconds = 0
	}
	if hb.Processes < 0 {
		hb.Processes = 0
	}
	if hb.Window != nil {
		hb.Window.Title = cleanHeartbeatText(hb.Window.Title)
		hb.Window.Process = cleanHeartbeatText(hb.Window.Process)
		if len(hb.Window.Process) > 64 {
			hb.Window.Process = hb.Window.Process[:64]
		}
	}
	// A window only means something while the run waits on it.
	if hb.Phase != PhaseNeedsHands {
		hb.Window = nil
	}
	return nil
}

func (s *Store) migrateSupervision() error {
	_, err := s.db.Exec(`
	CREATE TABLE IF NOT EXISTS response_job_progress (
		job_id TEXT PRIMARY KEY,
		tenant_id TEXT NOT NULL,
		endpoint_id TEXT NOT NULL,
		phase TEXT NOT NULL,
		phase_since TIMESTAMP NOT NULL,
		heartbeat_at TIMESTAMP NOT NULL,
		heartbeats INTEGER NOT NULL DEFAULT 0,
		body TEXT NOT NULL
	);
	CREATE INDEX IF NOT EXISTS idx_response_job_progress_endpoint ON response_job_progress(endpoint_id);
	`)
	return err
}

// ErrJobNotRunning is returned for a heartbeat on a job that is not running.
var ErrJobNotRunning = errors.New("job is not running")

// HeartbeatOutcome says what a heartbeat changed and whether the endpoint
// should stop the job.
type HeartbeatOutcome struct {
	Cancel  bool // the job has a cancel request: kill it and report cancelled
	Changed bool // first heartbeat, a new phase, or a new progress line
	Phase   string
	Prior   string // the phase before this heartbeat ("" for the first)
}

// RecordHeartbeat stores an endpoint's heartbeat for a job it is running. The
// lease must match; its expiry does not matter once the job was acknowledged
// (a run outlives the two-minute offer lease). The first heartbeat moves an
// acknowledged job to running. Phase changes are audited; plain heartbeats
// are not.
func (s *Store) RecordHeartbeat(tenantID, endpointID string, hb *JobHeartbeat) (HeartbeatOutcome, error) {
	var out HeartbeatOutcome
	if hb == nil || hb.JobID == "" || hb.LeaseID == "" {
		return out, errors.New("heartbeat needs job_id and lease_id")
	}
	if err := hb.clean(); err != nil {
		return out, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now().UTC()
	var curTenant, curEndpoint, state, lease, grantID string
	err := s.db.QueryRow(`SELECT tenant_id, endpoint_id, state, lease_id, authorization_grant_id FROM response_jobs WHERE id = ?`,
		hb.JobID).Scan(&curTenant, &curEndpoint, &state, &lease, &grantID)
	if errors.Is(err, sql.ErrNoRows) {
		return out, ErrJobNotFound
	} else if err != nil {
		return out, err
	}
	if tenantID != "" && curTenant != tenantID {
		return out, ErrTenantMismatch
	}
	if endpointID != "" && curEndpoint != endpointID {
		return out, ErrEndpointMismatch
	}
	if lease != hb.LeaseID {
		return out, ErrLeaseMismatch
	}
	switch JobState(state) {
	case StateAcknowledged, StateRunning, StateCancelRequested:
	default:
		return out, ErrJobNotRunning
	}
	out.Cancel = JobState(state) == StateCancelRequested
	out.Phase = hb.Phase

	var prior JobSupervision
	var priorBody string
	var priorSince time.Time
	var beats int
	err = s.db.QueryRow(`SELECT phase, phase_since, heartbeats, body FROM response_job_progress WHERE job_id = ?`, hb.JobID).
		Scan(&prior.Phase, &priorSince, &beats, &priorBody)
	first := errors.Is(err, sql.ErrNoRows)
	if err != nil && !first {
		return out, err
	}
	if !first {
		_ = json.Unmarshal([]byte(priorBody), &prior)
	}
	out.Prior = prior.Phase

	sup := JobSupervision{
		JobID: hb.JobID, EndpointID: curEndpoint, Phase: hb.Phase, PhaseSince: now, HeartbeatAt: now, Heartbeats: beats + 1,
		ProgressPct: -1, Message: hb.Message, CPUms: hb.CPUms, IOBytes: hb.IOBytes, IdleSeconds: hb.IdleSeconds,
		Processes: hb.Processes, Window: hb.Window,
	}
	if !first {
		sup.ProgressPct = prior.ProgressPct
		if prior.Phase == hb.Phase {
			sup.PhaseSince = priorSince
		}
		if sup.Message == "" {
			sup.Message = prior.Message
		}
	}
	if hb.ProgressPct != nil {
		sup.ProgressPct = *hb.ProgressPct
	}
	out.Changed = first || prior.Phase != hb.Phase || prior.Message != sup.Message || prior.ProgressPct != sup.ProgressPct
	body, _ := json.Marshal(sup)
	if _, err := s.db.Exec(`
		INSERT INTO response_job_progress (job_id, tenant_id, endpoint_id, phase, phase_since, heartbeat_at, heartbeats, body)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(job_id) DO UPDATE SET phase = excluded.phase, phase_since = excluded.phase_since,
			heartbeat_at = excluded.heartbeat_at, heartbeats = excluded.heartbeats, body = excluded.body`,
		hb.JobID, curTenant, curEndpoint, sup.Phase, sup.PhaseSince, now, sup.Heartbeats, string(body)); err != nil {
		return out, err
	}

	actor := "endpoint:" + curEndpoint
	if JobState(state) == StateAcknowledged {
		if _, err := s.db.Exec(`UPDATE response_jobs SET state = ?, updated_at = ? WHERE id = ?`, string(StateRunning), now, hb.JobID); err != nil {
			return out, err
		}
		_ = s.recordAudit(curTenant, curEndpoint, hb.JobID, grantID, StateAcknowledged, StateRunning, actor, "supervised: "+hb.Phase)
	} else if !first && prior.Phase != hb.Phase {
		detail := "supervised: " + prior.Phase + " -> " + hb.Phase
		if hb.Window != nil {
			detail += fmt.Sprintf(" (window %q of %s, session %d)", hb.Window.Title, hb.Window.Process, hb.Window.Session)
		}
		_ = s.recordAudit(curTenant, curEndpoint, hb.JobID, grantID, JobState(state), JobState(state), actor, detail)
	}
	return out, nil
}

// Supervision returns the latest heartbeat of each job that has one.
func (s *Store) Supervision(tenantID string, jobIDs []string) (map[string]*JobSupervision, error) {
	out := map[string]*JobSupervision{}
	if len(jobIDs) == 0 {
		return out, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for start := 0; start < len(jobIDs); start += 400 {
		end := start + 400
		if end > len(jobIDs) {
			end = len(jobIDs)
		}
		chunk := jobIDs[start:end]
		args := make([]interface{}, 0, len(chunk)+1)
		args = append(args, tenantID, tenantID)
		for _, id := range chunk {
			args = append(args, id)
		}
		rows, err := s.db.Query(`SELECT body FROM response_job_progress WHERE (? = '' OR tenant_id = ?) AND job_id IN (?`+strings.Repeat(",?", len(chunk)-1)+`)`, args...)
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			var body string
			if err := rows.Scan(&body); err != nil {
				rows.Close()
				return nil, err
			}
			var sup JobSupervision
			if json.Unmarshal([]byte(body), &sup) == nil && sup.JobID != "" {
				out[sup.JobID] = &sup
			}
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// RunKeyPrefix makes the idempotency key of a job dispatched for a run (the
// authorization id): runID + "/" + grant id. JobsForRun finds them again.
func RunKeyPrefix(runID string) string { return runID + "/" }

// JobsForRun returns the jobs dispatched for a run, oldest first.
func (s *Store) JobsForRun(tenantID, runID string) ([]*JobRecord, error) {
	if runID == "" || strings.ContainsAny(runID, "%_/") {
		return nil, nil
	}
	s.mu.Lock()
	rows, err := s.db.Query(`SELECT id FROM response_jobs WHERE (? = '' OR tenant_id = ?) AND idempotency_key LIKE ? ORDER BY created_at, id`,
		tenantID, tenantID, RunKeyPrefix(runID)+"%")
	if err != nil {
		s.mu.Unlock()
		return nil, err
	}
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			s.mu.Unlock()
			return nil, err
		}
		ids = append(ids, id)
	}
	rows.Close()
	s.mu.Unlock()
	var out []*JobRecord
	for _, id := range ids {
		if j, err := s.GetJob(tenantID, id); err == nil && j != nil {
			out = append(out, j)
		}
	}
	return out, nil
}
