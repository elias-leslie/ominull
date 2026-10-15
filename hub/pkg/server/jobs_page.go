package server

import (
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"ominull/hub/pkg/response"
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
	response.ActionKindIsolationChange: "Isolation change",
	response.ActionKindAgentUpdate:     "Agent update",
	response.ActionKindMeshQuarantine:  "Mesh quarantine",
	response.ActionKindAutoIsolate:     "Automatic isolation",
	response.ActionKindCapability:      "Capability change",
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
	body.CanAct = viewer.Role == "admin" || viewer.Role == "operator"
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
		return body
	}

	jobs, err := s.responseStore.ListJobs("default", "", jobsListLimit)
	if err != nil {
		body.Problems = append(body.Problems, "Response jobs could not be read: "+err.Error())
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
		body.Rows = append(body.Rows, jobRow{
			ID: j.ID, Short: shortJobID(j.ID), HostID: j.EndpointID, Host: host(j.EndpointID),
			Action: jobActionName(j.Kind), Who: j.RequestedBy, When: stamp(j.RequestedAt),
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
	add("Requested by", job.RequestedBy)
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
