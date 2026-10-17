package server

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"ominull/hub/pkg/response"
	"ominull/hub/pkg/scripts"
)

// Maintenance packages are library scripts with package metadata; a run is a
// script_exec job. Nothing is stored per (host, package): the latest job is the
// current state, derived here on read.

// packageRunGrace is how long past its own timeout an open job may stay
// unanswered before the console says no result came back (the agent restarted
// or lost the hub mid-run).
const packageRunGrace = 10 * time.Minute

type packageRun struct {
	JobID       string     `json:"job_id"`
	JobState    string     `json:"job_state"`
	State       string     `json:"state"` // ok|fixed|drift|failed|skipped, or running|waiting|cancelled|no_result
	Reboot      bool       `json:"reboot"`
	Changed     []string   `json:"changed,omitempty"`
	Reason      string     `json:"reason,omitempty"` // a skipped or failed package's own reason
	Mode        string     `json:"mode,omitempty"`
	Version     int        `json:"version,omitempty"`
	RequestedAt time.Time  `json:"requested_at"`
	CompletedAt *time.Time `json:"completed_at,omitempty"`
}

type packageStatus struct {
	ScriptID       string      `json:"script_id"`
	Name           string      `json:"name"`
	Title          string      `json:"title"`
	Description    string      `json:"description"`
	Interpreter    string      `json:"interpreter"`
	Risk           string      `json:"risk"`
	RebootPossible bool        `json:"reboot_possible"`
	Timeout        int         `json:"timeout"`
	LatestVersion  int         `json:"latest_version"`
	Last           *packageRun `json:"last"`
}

// scriptJobPayload decodes the signed script payload out of a job's request_json.
func scriptJobPayload(job *response.JobRecord) (response.ScriptExecPayload, bool) {
	var p response.ScriptExecPayload
	var wrapped struct {
		Payload string `json:"payload"`
	}
	if json.Unmarshal([]byte(job.RequestJSON), &wrapped) != nil || json.Unmarshal([]byte(wrapped.Payload), &p) != nil {
		return p, false
	}
	return p, p.ScriptID != ""
}

// derivePackageRun says what one package job amounts to. A finished job whose
// last stdout line is not a package result counts as failed.
func derivePackageRun(job *response.JobRecord, now time.Time) *packageRun {
	run := &packageRun{JobID: job.ID, JobState: string(job.State), RequestedAt: job.RequestedAt, CompletedAt: job.CompletedAt}
	timeout := scripts.DefaultTimeoutSeconds
	if p, ok := scriptJobPayload(job); ok {
		run.Mode, run.Version, timeout = p.Parameters["mode"], p.ScriptVersion, p.TimeoutSeconds
	}
	switch job.State {
	case response.StateQueued, response.StateOffered:
		run.State = "waiting"
	case response.StateAcknowledged, response.StateRunning, response.StateCancelRequested:
		run.State = "running"
		started := job.RequestedAt
		if job.StartedAt != nil {
			started = *job.StartedAt
		}
		if now.Sub(started) > time.Duration(timeout)*time.Second+packageRunGrace {
			run.State = "no_result"
		}
	case response.StateCancelled:
		run.State = "cancelled"
	default:
		run.State = "failed"
		var res response.JobResult
		if json.Unmarshal([]byte(job.ResultJSON), &res) == nil {
			if pr, ok := scripts.ParsePackageResult(res.Stdout); ok {
				run.State, run.Reboot, run.Changed = pr.State, pr.Reboot, pr.Changed
				var d struct{ Reason, Error string }
				if json.Unmarshal(pr.Detail, &d) == nil {
					run.Reason = d.Reason
					if run.Reason == "" {
						run.Reason = d.Error
					}
				}
			} else if res.ErrorCode == "TIMED_OUT" {
				run.Reason = "stopped at its time limit"
			} else {
				run.Reason = "no result line in its output"
			}
		}
	}
	if run.State == "failed" && run.Reason == "" {
		run.Reason = job.ErrorCode
	}
	return run
}

// packageForJob returns the package a script job ran, or nil.
func (s *Server) packageForJob(job *response.JobRecord) *scripts.PackageMeta {
	if job.Kind != response.ActionKindScriptExec || s.scriptsStore == nil {
		return nil
	}
	p, ok := scriptJobPayload(job)
	if !ok {
		return nil
	}
	sc, err := s.scriptsStore.GetScript(job.TenantID, p.ScriptID)
	if err != nil {
		return nil
	}
	meta := sc.Package()
	if meta != nil && meta.Title == "" {
		meta.Title = sc.Name
	}
	return meta
}

// handleMaintenance answers GET /api/v1/maintenance?endpoint_id=: every
// package that fits the host and its latest run there.
func (s *Server) handleMaintenance(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if s.scriptsStore == nil || s.responseStore == nil {
		writeJSONError(w, http.StatusServiceUnavailable, "scripts or response engine not initialized")
		return
	}
	tenantID := s.tenantFromRequest(r)
	if tenantID == "" {
		tenantID = "default"
	}
	epID := r.URL.Query().Get("endpoint_id")
	ep, err := s.store.GetEndpoint(epID)
	if epID == "" || err != nil || ep == nil {
		writeJSONError(w, http.StatusNotFound, "endpoint not found")
		return
	}
	list, err := s.scriptsStore.ListScripts(tenantID)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "failed to list scripts: "+err.Error())
		return
	}
	latest, err := s.responseStore.LatestScriptJobs(tenantID, epID)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "failed to read jobs: "+err.Error())
		return
	}
	windows := strings.Contains(strings.ToLower(ep.OS), "windows")
	now := time.Now().UTC()
	out := []packageStatus{}
	for _, sc := range list {
		meta := sc.Package()
		if meta == nil || sc.Retired || windowsInterpreter(sc.Interpreter) != windows {
			continue
		}
		st := packageStatus{
			ScriptID: sc.ID, Name: sc.Name, Title: meta.Title, Description: sc.Description, Interpreter: sc.Interpreter,
			Risk: meta.Risk, RebootPossible: meta.Reboot, Timeout: meta.Timeout, LatestVersion: sc.LatestVersion,
		}
		if st.Title == "" {
			st.Title = sc.Name
		}
		if job := latest[sc.ID]; job != nil {
			st.Last = derivePackageRun(job, now)
		}
		out = append(out, st)
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{"packages": out})
}

// packageStateLabel says a package run's state in words and its tone.
func packageStateLabel(state string) (string, string) {
	switch state {
	case "ok":
		return "Nothing to change", "ok"
	case "fixed":
		return "Fixed", "ok"
	case "drift":
		return "Needs changes", "warn"
	case "skipped":
		return "Skipped", "idle"
	case "running":
		return "Running", "warn"
	case "waiting":
		return "Waiting for the agent", "idle"
	case "cancelled":
		return "Cancelled", "idle"
	case "no_result":
		return "No result came back", "crit"
	}
	return "Failed", "crit"
}

func windowsInterpreter(interp string) bool {
	switch strings.ToLower(interp) {
	case "powershell.exe", "pwsh.exe", "cmd.exe":
		return true
	}
	return false
}
