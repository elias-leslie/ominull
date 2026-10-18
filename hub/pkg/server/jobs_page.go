package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"ominull/hub/pkg/response"
	"ominull/hub/pkg/scripts"
)

// /console/jobs lists the response jobs the hub has dispatched to agents
// (evidence collections, scripts, isolation changes, updates), still in flight
// or finished; ?id= is one job with what the agent sent back. The hub renders
// both; web/jobs.js (built from web-src/jobs.ts) cancels a job, copies output,
// and reloads the page when an open job changes state.

const jobsListLimit = 100

type jobRow struct {
	ID, Short, HostID, Host, Action, Who, When string
	Label, Tone                                string
	ErrorCode                                  string
	Attempt                                    int
}

type jobMeta struct{ Label, Value string }

type jobStep struct {
	When, What, Who, Detail string
}

type jobView struct {
	ID, HostID, Host, Action, Label, Tone string
	Open, CanCancel, TakenUp              bool
	State                                 string
	Updated                               string
	Meta                                  []jobMeta
	HasResult                             bool
	Stdout, Stderr                        string
	Steps                                 []jobStep
	Controls                              []jobControl // a package run's per-control results
}

// jobControl is one control a package run checked, as the page shows it.
type jobControl struct {
	ID, CIS, Expected, Actual, Label, Tone string
	Careful                                bool
}

type jobsPageBody struct {
	Off      bool
	History  bool
	Rows     []jobRow
	Open     int
	Done     int
	Zone     string
	CanAct   bool
	View     *jobView
	Gone     string
	Problems []string
}

// jobStateLabel says a job's state in words and the tone it is drawn in.
func jobStateLabel(state response.JobState) (string, string) {
	switch state {
	case response.StateQueued:
		return "Waiting for the agent", "idle"
	case response.StateOffered:
		return "Offered to the agent", "info"
	case response.StateAcknowledged:
		return "Taken by the agent", "info"
	case response.StateRunning:
		return "Running", "warn"
	case response.StateSucceeded:
		return "Done", "ok"
	case response.StateFailed:
		return "Failed", "crit"
	case response.StateCancelRequested:
		return "Asked to stop", "warn"
	case response.StateCancelled:
		return "Cancelled", "idle"
	}
	return string(state), "idle"
}

// jobInFlight is true until the job reaches an end state. A job asked to stop
// is still in flight: the agent has not said it stopped.
func jobInFlight(state response.JobState) bool {
	switch state {
	case response.StateSucceeded, response.StateFailed, response.StateCancelled:
		return false
	}
	return true
}

func jobCancellable(state response.JobState) bool {
	return jobInFlight(state) && state != response.StateCancelRequested
}

var jobActionNames = map[response.ActionKind]string{
	response.ActionKindForensicCollect: "Evidence collection",
	response.ActionKindScriptExec:      "Script",
	response.ActionKindTerminalSession: "Terminal",
	response.ActionKindScreenSession:   "Screen",
	response.ActionKindIsolationChange: "Isolation change",
	response.ActionKindAgentUpdate:     "Agent update",
	response.ActionKindMeshQuarantine:  "Mesh quarantine",
	response.ActionKindAutoIsolate:     "Automatic isolation",
	response.ActionKindCapability:      "Capability change",
	response.ActionKindDetectionPolicy: "Detection policy change",
}

func jobActionName(kind response.ActionKind) string {
	if name, ok := jobActionNames[kind]; ok {
		return name
	}
	return strings.ReplaceAll(string(kind), "_", " ")
}

func shortJobID(id string) string {
	if len(id) > 8 {
		return id[:8]
	}
	return id
}

func (s *Server) handleJobsPage(w http.ResponseWriter, r *http.Request) {
	viewer, ok := s.requirePageViewer(w, r)
	if !ok {
		return
	}
	q := r.URL.Query()
	body := s.buildJobsPage(viewer, q.Get("id"), q.Get("view") == "history", time.Now())
	data := pageData{Title: "Response jobs", Operator: viewer.Email, Role: viewer.Role, Back: "response", Body: body}
	if body.View != nil && body.Gone == "" {
		data.Script = "jobs.js"
	}
	s.servePage(w, r, "jobs", data)
}

func (s *Server) buildJobsPage(viewer accessOperator, jobID string, history bool, now time.Time) jobsPageBody {
	body := jobsPageBody{History: history}
	if !s.responseEnabled || s.responseStore == nil {
		body.Off = true
		return body
	}
	// The hub refuses writes from read-only roles; the page offers what it allows.
	body.CanAct = roleAllows(viewer.Role, http.MethodPost)
	loc := s.store.GetDetectionTuning().Location()
	body.Zone = loc.String()
	if body.Zone == "Local" {
		body.Zone = now.In(loc).Format("MST")
	}
	names := map[string]string{}
	if endpoints, err := s.store.ListEndpoints(""); err == nil {
		for _, ep := range endpoints {
			names[ep.ID] = ep.Hostname
		}
	}
	host := func(id string) string {
		if name := names[id]; name != "" {
			return name
		}
		return id
	}
	stamp := func(t time.Time) string { return pageStamp(t, now, loc) }

	if jobID != "" {
		job, err := s.responseStore.GetJob("default", jobID)
		if err != nil {
			if errors.Is(err, response.ErrJobNotFound) || errors.Is(err, response.ErrTenantMismatch) {
				body.Gone = "No response job with ID “" + jobID + "”."
			} else {
				body.Gone = "The job could not be read: " + err.Error()
			}
			body.View = &jobView{ID: jobID}
			return body
		}
		body.View = s.buildJobView(job, host(job.EndpointID), stamp, body.CanAct)
		if meta := s.packageForJob(job); meta != nil {
			addPackageResult(body.View, job, meta, s.liveRun(job, now))
		}
		return body
	}

	jobs, err := s.responseStore.ListJobs("default", "", jobsListLimit)
	if err != nil {
		body.Problems = append(body.Problems, "Response jobs could not be read: "+err.Error())
	}
	// Package runs are named by their package, not just "Script".
	packages := map[string]string{}
	if s.scriptsStore != nil {
		if list, err := s.scriptsStore.ListScripts("default"); err == nil {
			for _, sc := range list {
				if meta := sc.Package(); meta != nil {
					packages[sc.ID] = meta.Title
					if meta.Title == "" {
						packages[sc.ID] = sc.Name
					}
				}
			}
		}
	}
	for _, j := range jobs {
		if jobInFlight(j.State) {
			body.Open++
		} else {
			body.Done++
		}
		if jobInFlight(j.State) == history {
			continue
		}
		label, tone := jobStateLabel(j.State)
		action := jobActionName(j.Kind)
		if j.Kind == response.ActionKindScriptExec && len(packages) > 0 {
			if p, ok := scriptJobPayload(j); ok && packages[p.ScriptID] != "" {
				action = packages[p.ScriptID] + " package"
				if run := s.liveRun(j, now); !jobInFlight(j.State) || runAttention(run.State) {
					label, tone = packageStateLabel(run.State)
				}
			}
		}
		body.Rows = append(body.Rows, jobRow{
			ID: j.ID, Short: shortJobID(j.ID), HostID: j.EndpointID, Host: host(j.EndpointID),
			Action: action, Who: requesterLabel(j.RequestedBy), When: stamp(j.RequestedAt),
			Label: label, Tone: tone, ErrorCode: j.ErrorCode, Attempt: j.Attempt,
		})
	}
	return body
}

func (s *Server) buildJobView(job *response.JobRecord, hostName string, stamp func(time.Time) string, canAct bool) *jobView {
	label, tone := jobStateLabel(job.State)
	v := &jobView{
		ID: job.ID, HostID: job.EndpointID, Host: hostName, Action: jobActionName(job.Kind),
		Label: label, Tone: tone, State: string(job.State), Updated: job.UpdatedAt.UTC().Format(time.RFC3339Nano),
		Open:      jobInFlight(job.State),
		CanCancel: canAct && jobCancellable(job.State),
		// Until the agent's ack is accepted the job is withdrawn outright.
		TakenUp: job.State == response.StateAcknowledged || job.State == response.StateRunning,
	}
	add := func(label, value string) {
		if value != "" {
			v.Meta = append(v.Meta, jobMeta{label, value})
		}
	}
	add("Host", hostName)
	add("Action", v.Action)
	add("Requested by", requesterLabel(job.RequestedBy))
	add("Requested", stamp(job.RequestedAt))
	if job.StartedAt != nil {
		add("Started", stamp(*job.StartedAt))
	}
	if job.CompletedAt != nil {
		add("Finished", stamp(*job.CompletedAt))
	}
	// Only an offered job's lease does anything: when it lapses unacked, the
	// job is offered again.
	if job.LeaseExpiresAt != nil && job.State == response.StateOffered {
		add("Offered again at", stamp(*job.LeaseExpiresAt))
	}
	if job.Attempt > 1 {
		add("Attempt", strconv.Itoa(job.Attempt))
	}
	add("Error", job.ErrorCode)
	add("Approval", job.AuthorizationGrantID)

	if job.ResultJSON != "" {
		// The hub stores the agent's whole report (response.JobResult).
		var res response.JobResult
		if json.Unmarshal([]byte(job.ResultJSON), &res) == nil {
			v.HasResult = true
			if job.Kind == response.ActionKindScriptExec {
				add("Exit code", strconv.Itoa(res.ExitCode))
			}
			if res.DurationMs > 0 {
				add("Took", (time.Duration(res.DurationMs) * time.Millisecond).String())
			}
			v.Stdout, v.Stderr = res.Stdout, strings.TrimRight(res.Stderr, "\n")
			if res.Truncated {
				add("Output", "cut at the size limit")
			}
		}
	}

	if steps, err := s.responseStore.GetJobAuditLog("default", job.ID, 50); err == nil {
		for _, e := range steps {
			to, _ := jobStateLabel(response.JobState(e.ToState))
			v.Steps = append(v.Steps, jobStep{When: stamp(e.Timestamp), What: to, Who: jobActor(e.Actor, job.EndpointID, hostName), Detail: jobStepDetail(e.Details)})
		}
	}
	return v
}

// jobActor names who moved a job: the agent on its host, the hub's scheduler,
// or the operator.
// requesterLabel names who asked for a job. Jobs from the host-authority
// courier were signed by Nightshift: a tap key (the owner approved this
// script) or the auto key (an allow-listed package).
func requesterLabel(by string) string {
	switch by {
	case response.OperatorNightshiftTap:
		return "signed by Nightshift (owner tap)"
	case response.OperatorNightshiftAuto:
		return "signed by Nightshift (allow-listed package)"
	}
	return by
}

func jobActor(actor, endpointID, hostName string) string {
	switch actor {
	case "endpoint:" + endpointID:
		return "agent on " + hostName
	case "scheduler":
		return "hub"
	}
	return actor
}

var jobLeaseDetail = regexp.MustCompile(`^leased to \S+ attempt (\d+)$`)

// jobStepDetail keeps what a history step's note adds (a rejection reason, a
// progress message) and drops notes that only restate the step.
func jobStepDetail(details string) string {
	if m := jobLeaseDetail.FindStringSubmatch(details); m != nil {
		if m[1] == "1" {
			return ""
		}
		return "try " + m[1]
	}
	switch {
	case details == "job created", details == "job accepted by endpoint", details == "cancellation requested",
		strings.HasPrefix(details, "completed state="):
		return ""
	}
	return details
}

// addPackageResult names a package run and puts what its result line says
// (state, reboot, changes) at the top of the job's details.
func addPackageResult(v *jobView, job *response.JobRecord, meta *scripts.PackageMeta, run *packageRun) {
	v.Action = meta.Title + " package"
	var meta2 []jobMeta
	if run.Mode != "" {
		meta2 = append(meta2, jobMeta{"Mode", run.Mode})
	}
	if jobInFlight(job.State) && run.Progress != nil {
		if runAttention(run.State) {
			v.Label, v.Tone = packageStateLabel(run.State)
			meta2 = append(meta2, jobMeta{"Why", run.Reason})
		}
		if p := run.Progress; p.Message != "" || p.Pct >= 0 {
			text := p.Message
			if p.Pct >= 0 {
				text = strings.TrimSpace(fmt.Sprintf("%d%% %s", p.Pct, p.Message))
			}
			meta2 = append(meta2, jobMeta{"Progress", text})
		}
		meta2 = append(meta2, jobMeta{"Last heartbeat", run.Progress.HeartbeatAt.Format("15:04:05 MST")})
	}
	if !jobInFlight(job.State) {
		v.Label, v.Tone = packageStateLabel(run.State)
		meta2 = append(meta2, jobMeta{"Result", v.Label})
		if run.Reason != "" {
			meta2 = append(meta2, jobMeta{"Why", run.Reason})
		}
		reboot := "No"
		if run.Reboot {
			reboot = "Yes"
		}
		meta2 = append(meta2, jobMeta{"Reboot needed", reboot})
		if len(run.Changed) > 0 {
			changed := run.Changed
			more := ""
			if len(changed) > 12 {
				more = fmt.Sprintf(" and %d more", len(changed)-12)
				changed = changed[:12]
			}
			meta2 = append(meta2, jobMeta{"Changed", strings.Join(changed, ", ") + more})
		}
		if run.Pass+run.Fail > 0 {
			meta2 = append(meta2, jobMeta{"Compliance", fmt.Sprintf("%d%% (%d of %d controls pass)", 100*run.Pass/(run.Pass+run.Fail), run.Pass, run.Pass+run.Fail)})
		}
		for _, c := range run.Controls {
			jc := jobControl{ID: c.ID, CIS: c.CIS, Expected: c.Expected, Actual: c.Actual, Careful: c.Risk == "careful"}
			switch c.State {
			case "pass":
				jc.Label, jc.Tone = "Pass", "ok"
			case "fixed":
				jc.Label, jc.Tone = "Fixed", "ok"
			case "fail":
				jc.Label, jc.Tone = "Fail", "crit"
			default:
				jc.Label, jc.Tone = "Not applicable", "idle"
			}
			v.Controls = append(v.Controls, jc)
		}
	}
	// After Host and Action.
	n := 2
	if len(v.Meta) < n {
		n = len(v.Meta)
	}
	v.Meta = append(append(append([]jobMeta{}, v.Meta[:n]...), meta2...), v.Meta[n:]...)
}
