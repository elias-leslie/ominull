package server

import (
	"encoding/json"
	"fmt"
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
	JobID    string   `json:"job_id"`
	JobState string   `json:"job_state"`
	State    string   `json:"state"` // ok|fixed|drift|failed|skipped|na, or running|waiting|cancelled|no_result
	Reboot   bool     `json:"reboot"`
	Changed  []string `json:"changed,omitempty"`
	Reason   string   `json:"reason,omitempty"` // a skipped or failed package's own reason
	Mode     string   `json:"mode,omitempty"`
	Version  int      `json:"version,omitempty"`
	// Controls is the run's per-control results (detail.controls); Pass and
	// Fail count them for compliance (pass/(pass+fail); na counts for neither).
	Controls    []scripts.Control `json:"controls,omitempty"`
	Pass        int               `json:"pass,omitempty"`
	Fail        int               `json:"fail,omitempty"`
	RequestedAt time.Time         `json:"requested_at"`
	CompletedAt *time.Time        `json:"completed_at,omitempty"`
	// RestartIn is a restart package's warning time (detail.restart_in_seconds).
	RestartIn int `json:"restart_in_seconds,omitempty"`
	// NeedsOwner is what the run left for the owner to decide
	// (detail.needs_owner), cleaned of anything an endpoint could abuse.
	NeedsOwner []ownerItem `json:"needs_owner,omitempty"`
	// Line is the last line of a finished run's output (capped).
	Line string `json:"line,omitempty"`
	// Live supervision of a running job (applySupervision): the phase the
	// endpoint reports, its progress line, and the window a needs_hands run
	// waits on.
	Phase    string                     `json:"phase,omitempty"`
	Progress *runProgress               `json:"progress,omitempty"`
	Window   *response.SupervisedWindow `json:"window,omitempty"`
	// OneOff marks an agent's or operator's one-off script (not a package).
	OneOff bool `json:"one_off,omitempty"`
}

type packageStatus struct {
	ScriptID       string      `json:"script_id"`
	Name           string      `json:"name"`
	Title          string      `json:"title"`
	Description    string      `json:"description"`
	Interpreter    string      `json:"interpreter"`
	Risk           string      `json:"risk"`
	Category       string      `json:"category"` // maintenance | security
	Role           string      `json:"role,omitempty"`
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
		run.OneOff = isOneOffScript(p.ScriptID)
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
			run.Line = lastLine(res.Stdout)
			if run.OneOff {
				// A one-off script has no result contract: its exit code says.
				switch {
				case job.State == response.StateSucceeded:
					run.State = "ok"
				case res.ErrorCode == "TIMED_OUT":
					run.Reason = "stopped at its time limit"
				default:
					run.Reason = fmt.Sprintf("exit code %d", res.ExitCode)
					if res.ErrorCode != "" {
						run.Reason += " (" + res.ErrorCode + ")"
					}
				}
			} else if pr, ok := scripts.ParsePackageResult(res.Stdout); ok {
				run.State, run.Reboot, run.Changed = pr.State, pr.Reboot, pr.Changed
				run.Controls = pr.Controls()
				run.Pass, run.Fail = scripts.Compliance(run.Controls)
				var d struct {
					Reason, Error string
					RestartIn     int             `json:"restart_in_seconds"`
					NeedsOwner    json.RawMessage `json:"needs_owner"`
				}
				if json.Unmarshal(pr.Detail, &d) == nil {
					run.Reason, run.RestartIn, run.NeedsOwner = d.Reason, d.RestartIn, cleanOwnerItems(d.NeedsOwner)
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

// lastLine is the last non-empty line of a run's output, capped.
func lastLine(out string) string {
	lines := strings.Split(strings.TrimRight(out, "\r\n\t "), "\n")
	l := strings.TrimSpace(lines[len(lines)-1])
	if len(l) > 300 {
		l = l[:300]
	}
	return strings.ToValidUTF8(l, "")
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
			Risk: meta.Risk, Category: packageCategory(meta.Category), Role: meta.Role, RebootPossible: meta.Reboot, Timeout: meta.Timeout, LatestVersion: sc.LatestVersion,
		}
		if st.Title == "" {
			st.Title = sc.Name
		}
		if job := latest[sc.ID]; job != nil {
			st.Last = s.liveRun(job, now)
		}
		out = append(out, st)
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{"packages": out,
		"maintenance_mode": s.maintenanceModeFor(tenantID, epID, ep.OS, latest, now)})
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
	case "na":
		return "Not applicable", "idle"
	case "running":
		return "Running", "warn"
	case "waiting":
		return "Waiting for the agent", "idle"
	case "cancelled":
		return "Cancelled", "idle"
	case "no_result":
		return "No result came back", "crit"
	case "stalled":
		return "Stalled", "crit"
	case "needs_hands":
		return "Waiting on a window", "crit"
	case "not_run":
		return "Not run", "idle"
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

// maintenanceFindings is the Nightshift feed's maintenance record. A package
// whose latest run on a host failed or never answered needs the owner: that
// is the one finding raised to critical (Nightshift pushes it). A schedule
// waiting for an approve-all tap is a medium finding on the board; reboots
// needed and changes waiting in audit runs are counts in the resolved record.
func (s *Server) maintenanceFindings(now time.Time) ([]feedFinding, error) {
	const uid, title = "ominull.maintenance", "Maintenance packages"
	const schedUID, schedTitle = "ominull.maintenance.schedule", "Scheduled maintenance"
	if s.scriptsStore == nil || s.responseStore == nil {
		return []feedFinding{s.feedFinding(now, uid, title, ocsfSevInformational, ocsfStatusResolved, "Maintenance packages are not set up", nil, nil)}, nil
	}
	eps, err := s.store.ListEndpoints("")
	if err != nil {
		return nil, err
	}
	type failure struct {
		Endpoint string    `json:"endpoint"`
		Package  string    `json:"package"`
		State    string    `json:"state"`
		Reason   string    `json:"reason,omitempty"`
		At       time.Time `json:"at"`
	}
	var failures []failure
	var failed []feedResource
	reboot := []string{}
	drift, runs := 0, 0
	compliance := map[string]map[string]int{} // category -> pass/fail
	libraries := map[string][]*scripts.Script{}
	acceptedAll := s.allAcceptedRisks()
	for _, ep := range eps {
		if ep.Status == "retired" {
			continue
		}
		list, ok := libraries[ep.TenantID]
		if !ok {
			if list, err = s.scriptsStore.ListScripts(ep.TenantID); err != nil {
				return nil, err
			}
			libraries[ep.TenantID] = list
		}
		latest, err := s.responseStore.LatestScriptJobs(ep.TenantID, ep.ID)
		if err != nil {
			return nil, err
		}
		hostFailed := false
		for _, sc := range list {
			job := latest[sc.ID]
			if sc.Package() == nil || job == nil {
				continue
			}
			run := derivePackageRun(job, now)
			applyAcceptedRisks(run, acceptedAll[ep.ID])
			runs++
			switch run.State {
			case "failed", "no_result":
				failures = append(failures, failure{Endpoint: ep.Hostname, Package: sc.Name, State: run.State, Reason: run.Reason, At: job.RequestedAt})
				hostFailed = true
			case "drift":
				drift++
			}
			if len(run.Controls) > 0 {
				cat := packageCategory(sc.Package().Category)
				if compliance[cat] == nil {
					compliance[cat] = map[string]int{}
				}
				compliance[cat]["pass"] += run.Pass
				compliance[cat]["fail"] += run.Fail
			}
			if run.Reboot && run.CompletedAt != nil {
				reboot = append(reboot, ep.Hostname+": "+sc.Name)
			}
		}
		if hostFailed {
			failed = append(failed, feedResource{Type: "endpoint", Name: ep.Hostname, UID: ep.ID})
		}
	}
	unmapped := map[string]any{"latest_runs": runs, "needs_changes": drift, "reboot_needed": reboot, "compliance": compliance}
	var out []feedFinding
	if len(failures) > 0 {
		if len(failures) > 20 {
			failures = failures[:20]
		}
		unmapped["failures"] = failures
		out = append(out, s.feedFinding(now, uid, title, ocsfSevCritical, ocsfStatusNew,
			fmt.Sprintf("%s failed on %s", plural(len(failures), "maintenance package run", "maintenance package runs"), plural(len(failed), "host", "hosts")), failed, unmapped))
	} else {
		out = append(out, s.feedFinding(now, uid, title, ocsfSevInformational, ocsfStatusResolved,
			fmt.Sprintf("No failed maintenance runs (%d latest, %d need a reboot)", runs, len(reboot)), nil, unmapped))
	}
	if blocks := s.maintBlocks.list(); len(blocks) > 0 {
		out = append(out, s.feedFinding(now, schedUID, schedTitle, ocsfSevMedium, ocsfStatusNew,
			plural(len(blocks), "scheduled package run is", "scheduled package runs are")+" waiting (approval or a declined ask)", nil, map[string]any{"waiting": blocks}))
	} else {
		out = append(out, s.feedFinding(now, schedUID, schedTitle, ocsfSevInformational, ocsfStatusResolved, "No scheduled package is waiting", nil, nil))
	}
	return out, nil
}

// packageCategory reads a package's category; packages synced before
// categories existed are maintenance.
func packageCategory(c string) string {
	if c == "security" {
		return c
	}
	return "maintenance"
}
