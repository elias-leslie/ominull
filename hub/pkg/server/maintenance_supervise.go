package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"ominull/hub/pkg/response"
)

// Supervised runs. The endpoint wraps every script_exec job in a supervisor
// that posts a heartbeat (POST /api/v1/response/jobs/progress) every 30 s and
// whenever the run's phase or progress line changes: running, stalled (no
// output, CPU or disk activity for a while) or needs_hands (stalled with a
// visible window waiting for a click; the heartbeat names the window). The
// reply carries a pending cancel, so a cancel reaches a running job within a
// heartbeat. Everything that shows a run (Maintenance page, asset card, jobs
// page, playbooks, the Nightshift feed) and ominullctl maint wait read the
// run's live state from here.

const (
	// heartbeatLost: a run that had heartbeats and then none for this long
	// reads stalled (the machine went quiet mid-run).
	heartbeatLost = 3 * time.Minute
	// waitRecheck bounds how long a wait sleeps between looks even without an
	// event, so heartbeat loss and time limits are noticed.
	waitRecheck = 15 * time.Second
)

type runProgress struct {
	Pct         int       `json:"pct"` // -1 unknown
	Message     string    `json:"message,omitempty"`
	HeartbeatAt time.Time `json:"heartbeat_at"`
	PhaseSince  time.Time `json:"phase_since"`
	IdleSeconds int       `json:"idle_seconds"`
	Processes   int       `json:"processes"`
}

// runAttention: states that wait on someone (a steward or the owner).
func runAttention(state string) bool {
	return state == "stalled" || state == "needs_hands" || state == "no_result"
}

// runFinal: states of a run that ended.
func runFinal(state string) bool {
	switch state {
	case "waiting", "running", "stalled", "needs_hands", "no_result":
		return false
	}
	return true
}

// runFailed: final states that did not do the job.
func runFailed(state string) bool {
	return state == "failed" || state == "cancelled" || state == "not_run"
}

// applySupervision adds the latest heartbeat to a run that is still running.
func applySupervision(run *packageRun, sup *response.JobSupervision, now time.Time) {
	if sup == nil || run.State != "running" {
		return
	}
	run.Phase = sup.Phase
	run.Progress = &runProgress{Pct: sup.ProgressPct, Message: sup.Message, HeartbeatAt: sup.HeartbeatAt,
		PhaseSince: sup.PhaseSince, IdleSeconds: sup.IdleSeconds, Processes: sup.Processes}
	if quiet := now.Sub(sup.HeartbeatAt); quiet > heartbeatLost {
		run.State = "stalled"
		run.Reason = fmt.Sprintf("no word from the machine for %d min", int(quiet/time.Minute))
		return
	}
	switch sup.Phase {
	case response.PhaseStalled:
		run.State = "stalled"
		run.Reason = fmt.Sprintf("no output, CPU or disk activity for %s", minutesText(sup.IdleSeconds))
	case response.PhaseNeedsHands:
		run.State = "needs_hands"
		run.Window = sup.Window
		run.Reason = "waiting on a window"
		if sup.Window != nil {
			run.Reason = fmt.Sprintf("waiting on a window: %q (%s, session %d)", sup.Window.Title, sup.Window.Process, sup.Window.Session)
		}
	}
}

func minutesText(secs int) string {
	if secs < 120 {
		return fmt.Sprintf("%d s", secs)
	}
	return fmt.Sprintf("%d min", secs/60)
}

// liveRuns derives each job's run with its latest heartbeat.
func (s *Server) liveRuns(tenantID string, jobs []*response.JobRecord, now time.Time) map[string]*packageRun {
	out := make(map[string]*packageRun, len(jobs))
	accepted := s.allAcceptedRisks()
	var open []string
	for _, j := range jobs {
		if j == nil {
			continue
		}
		out[j.ID] = derivePackageRun(j, now)
		applyAcceptedRisks(out[j.ID], accepted[j.EndpointID])
		if out[j.ID].State == "running" {
			open = append(open, j.ID)
		}
	}
	if len(open) > 0 && s.responseStore != nil {
		sups, err := s.responseStore.Supervision(tenantID, open)
		if err == nil {
			for _, id := range open {
				applySupervision(out[id], sups[id], now)
			}
		}
	}
	return out
}

// liveRun is liveRuns for one job.
func (s *Server) liveRun(job *response.JobRecord, now time.Time) *packageRun {
	return s.liveRuns(job.TenantID, []*response.JobRecord{job}, now)[job.ID]
}

// handleResponseProgress takes an endpoint's heartbeat for a job it runs.
func (s *Server) handleResponseProgress(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if s.responseStore == nil {
		writeJSONError(w, http.StatusServiceUnavailable, "response store not initialized")
		return
	}
	var hb response.JobHeartbeat
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16*1024)).Decode(&hb); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid progress payload")
		return
	}
	endpointID := r.Header.Get("X-Client-CN")
	if endpointID == "" {
		endpointID = r.Header.Get("X-Device-Endpoint-ID")
	}
	out, err := s.responseStore.RecordHeartbeat(s.tenantFromRequest(r), endpointID, &hb)
	if err != nil {
		code := http.StatusBadRequest
		if errors.Is(err, response.ErrJobNotRunning) {
			code = http.StatusConflict
		}
		writeJSONError(w, code, "progress not recorded: "+err.Error())
		return
	}
	if out.Changed {
		s.jobWake.notify()
		if out.Prior != out.Phase && out.Phase != response.PhaseRunning {
			s.audit(r, "SCRIPT_RUN_ATTENTION", hb.JobID, fmt.Sprintf("Run %s on %s is %s", hb.JobID, endpointID, out.Phase))
		}
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"ok": true, "cancel": out.Cancel})
}

// ---- waiting on runs ----------------------------------------------------------

// waitEntry is one line of ominullctl maint wait: a job, or one machine's
// progress through a playbook run.
type waitEntry struct {
	ID         string                     `json:"id"` // the job, or playbook run id + "/" + machine
	JobID      string                     `json:"job_id,omitempty"`
	RunID      string                     `json:"run_id,omitempty"`
	EndpointID string                     `json:"endpoint_id"`
	Host       string                     `json:"host,omitempty"`
	Package    string                     `json:"package,omitempty"`
	Step       string                     `json:"step,omitempty"` // "2/3 windows-cleanup (enforce)"
	State      string                     `json:"state"`
	Final      bool                       `json:"final"`
	Attention  bool                       `json:"attention"`
	Failed     bool                       `json:"failed"`
	Reason     string                     `json:"reason,omitempty"`
	Line       string                     `json:"line,omitempty"`
	Progress   *runProgress               `json:"progress,omitempty"`
	Window     *response.SupervisedWindow `json:"window,omitempty"`
}

type waitView struct {
	Entries   []waitEntry `json:"entries"`
	Unknown   []string    `json:"unknown,omitempty"`
	AnyFinal  bool        `json:"any_final"`
	AllFinal  bool        `json:"all_final"`
	Attention bool        `json:"attention"`
	Failed    bool        `json:"failed"`
}

func (s *Server) jobEntry(job *response.JobRecord, run *packageRun) waitEntry {
	e := waitEntry{ID: job.ID, JobID: job.ID, EndpointID: job.EndpointID, State: run.State, Reason: run.Reason,
		Line: run.Line, Progress: run.Progress, Window: run.Window}
	if p, ok := scriptJobPayload(job); ok {
		e.Package = p.ScriptID
		if isOneOffScript(p.ScriptID) {
			if rec := s.oneOffForJob(job.ID); rec != nil {
				e.Package = "one-off: " + rec.Name
			}
		} else if s.scriptsStore != nil {
			if sc, err := s.scriptsStore.GetScript(job.TenantID, p.ScriptID); err == nil && sc != nil {
				e.Package = sc.Name
			}
		}
	}
	return e
}

// waitLook reads the current state of everything ids name: job ids, run ids
// (a maintenance run's approval) and playbook run ids.
func (s *Server) waitLook(tenantID string, ids []string, now time.Time) waitView {
	var v waitView
	var jobs []*response.JobRecord
	seen := map[string]bool{}
	addJob := func(j *response.JobRecord) {
		if j != nil && !seen[j.ID] && j.Kind == response.ActionKindScriptExec {
			seen[j.ID] = true
			jobs = append(jobs, j)
		}
	}
	runs := s.playbookRuns()
	for _, id := range ids {
		if j, err := s.responseStore.GetJob(tenantID, id); err == nil && j != nil {
			addJob(j)
			continue
		}
		if list, err := s.responseStore.JobsForRun(tenantID, id); err == nil && len(list) > 0 {
			for _, j := range list {
				addJob(j)
			}
			continue
		}
		var pb *playbookRun
		for _, r := range runs {
			if r.ID == id && r.Tenant == tenantID {
				pb = r
			}
		}
		if pb == nil {
			v.Unknown = append(v.Unknown, id)
			continue
		}
		v.Entries = append(v.Entries, s.playbookEntries(pb, now)...)
	}
	live := s.liveRuns(tenantID, jobs, now)
	for _, j := range jobs {
		v.Entries = append(v.Entries, s.jobEntry(j, live[j.ID]))
	}
	labels := s.endpointHostnames()
	v.AllFinal = len(v.Entries) > 0
	for i := range v.Entries {
		e := &v.Entries[i]
		if e.Host == "" {
			e.Host = labels[e.EndpointID]
		}
		if e.ID == e.JobID || e.RunID == "" {
			e.Final, e.Attention = runFinal(e.State), runAttention(e.State)
			e.Failed = e.Final && runFailed(e.State)
		}
		v.AnyFinal = v.AnyFinal || e.Final
		v.AllFinal = v.AllFinal && e.Final
		v.Attention = v.Attention || e.Attention
		v.Failed = v.Failed || e.Failed
	}
	sort.SliceStable(v.Entries, func(i, j int) bool {
		if v.Entries[i].EndpointID != v.Entries[j].EndpointID {
			return v.Entries[i].EndpointID < v.Entries[j].EndpointID
		}
		return v.Entries[i].ID < v.Entries[j].ID
	})
	return v
}

// playbookEntries: one entry per machine of a playbook run, final once the
// machine has no step left to start, in attention while its current step is.
func (s *Server) playbookEntries(pb *playbookRun, now time.Time) []waitEntry {
	var out []waitEntry
	eps := make([]string, 0, len(pb.Hosts))
	for ep := range pb.Hosts {
		eps = append(eps, ep)
	}
	sort.Strings(eps)
	for _, ep := range eps {
		steps := pb.Hosts[ep]
		e := waitEntry{ID: pb.ID + "/" + ep, RunID: pb.ID, EndpointID: ep, Package: pb.Name, State: "waiting"}
		final, failed := true, false
	steps:
		for i, st := range steps {
			label := ""
			if i < len(pb.Steps) {
				label = pb.Steps[i].Label
			}
			stepText := fmt.Sprintf("%d/%d %s", i+1, len(steps), label)
			switch st.State {
			case "done", "not_started":
				res := st.Result
				if st.State == "not_started" {
					res = "not_run"
				}
				if runFailed(res) || res == "no_result" {
					failed = true
				}
				e.Step, e.State = stepText, res
				continue
			case "started":
				final = false
				e.Step, e.JobID = stepText, st.JobID
				if job, err := s.responseStore.GetJob(pb.Tenant, st.JobID); err == nil && job != nil {
					run := s.liveRun(job, now)
					e.State, e.Reason, e.Progress, e.Window, e.Line = run.State, run.Reason, run.Progress, run.Window, run.Line
					e.Attention = runAttention(run.State)
				}
			default: // pending
				final = false
				if e.JobID == "" {
					e.Step, e.State = stepText, "waiting"
				}
			}
			break steps
		}
		if pb.Done {
			final = true
		}
		e.Final, e.Failed = final, final && failed
		if final && !failed {
			e.State = "done"
		} else if final {
			e.State = "failed"
		}
		out = append(out, e)
	}
	return out
}

// endpointHostnames maps endpoint ids to hostnames for display.
func (s *Server) endpointHostnames() map[string]string {
	out := map[string]string{}
	if eps, err := s.store.ListEndpoints(""); err == nil {
		for _, ep := range eps {
			out[ep.ID] = ep.Hostname
		}
	}
	return out
}

// handleMaintenanceWait answers GET /api/v1/maintenance/wait?ids=a,b&wait=25
// [&all=1]: a long-poll that returns as soon as any named run ends or needs
// attention (with all=1: once every run has ended, or any needs attention),
// or when wait seconds pass. Waking comes from job events (ack, heartbeat
// phase or progress change, result, cancel), not from client polling.
func (s *Server) handleMaintenanceWait(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if s.responseStore == nil {
		writeJSONError(w, http.StatusServiceUnavailable, "response store not initialized")
		return
	}
	tenantID := tenantOr(s.tenantFromRequest(r))
	var ids []string
	for _, id := range strings.Split(r.URL.Query().Get("ids"), ",") {
		if id = strings.TrimSpace(id); id != "" && len(id) <= 128 {
			ids = append(ids, id)
		}
	}
	if len(ids) == 0 || len(ids) > 100 {
		writeJSONError(w, http.StatusBadRequest, "ids names 1 to 100 job, run or playbook run ids")
		return
	}
	all := r.URL.Query().Get("all") == "1"
	deadline := time.Now().Add(parseWait(r.URL.Query().Get("wait")))
	for {
		wake := s.jobWake.wait()
		v := s.waitLook(tenantID, ids, time.Now().UTC())
		done := v.Attention || (all && v.AllFinal) || (!all && v.AnyFinal) || len(v.Entries) == 0
		if done || !time.Now().Before(deadline) {
			writeJSON(w, http.StatusOK, v)
			return
		}
		sleep := time.Until(deadline)
		if sleep > waitRecheck {
			sleep = waitRecheck
		}
		select {
		case <-wake:
		case <-time.After(sleep):
		case <-r.Context().Done():
			return
		}
	}
}
