package server

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"ominull/hub/pkg/response"
	"ominull/hub/pkg/responseauth"
	"ominull/hub/pkg/scripts"
)

// One-off scripts: an agent or the operator submits a script (PowerShell,
// bash or sh) to run once on named machines. It is a real run: the authority signs
// a grant bound to the exact script, the agent runs it under the same
// supervisor, result contract and audit as a package, and the run record keeps
// the script text (the job's signed payload) with its name, reason and
// requester. POST /api/v1/maintenance/script/promote turns a one-off script
// that carries a package header into a library package.

const (
	oneOffRunsSetting = "maintenance.oneoff_runs"
	oneOffRunsKept    = 200
	oneOffMaxSource   = 64 * 1024
	oneOffMaxOutput   = 1024 * 1024
	oneOffDefaultTime = 600
	promoteMaxSource  = 32 * 1024 // the library's package bound (ominullctl scripts sync)
)

var oneOffMu sync.Mutex

// oneOffInterpreters maps the shell a request names to the interpreter the
// agent runs and whether it is a Windows shell.
var oneOffInterpreters = map[string]struct {
	path    string
	windows bool
}{
	"powershell": {"powershell.exe", true},
	"bash":       {"/bin/bash", false},
	"sh":         {"/bin/sh", false},
}

func isOneOffScript(scriptID string) bool {
	return strings.HasPrefix(scriptID, responseauth.OneOffPrefix)
}

type oneOffRequest struct {
	EndpointIDs    []string `json:"endpoint_ids"`
	Name           string   `json:"name"`
	Shell          string   `json:"shell"` // powershell | bash | sh
	Source         string   `json:"source"`
	TimeoutSeconds int      `json:"timeout_seconds,omitempty"`
	Reason         string   `json:"reason"`
}

// oneOffRun is the record of one one-off script run.
type oneOffRun struct {
	RunID     string    `json:"run_id"` // the authorization id
	Tenant    string    `json:"tenant"`
	Name      string    `json:"name"`
	Reason    string    `json:"reason"`
	Shell     string    `json:"shell"`
	Digest    string    `json:"digest"`
	Lines     int       `json:"lines"`
	Requester string    `json:"requester"`
	At        time.Time `json:"at"`
	Jobs      []string  `json:"jobs"`
	Promoted  string    `json:"promoted,omitempty"` // the package it became
}

// oneOffPlan validates a request and builds its signed payload.
func (s *Server) oneOffPlan(tenantID string, body []byte) (*oneOffRequest, string, []byte, error) {
	var req oneOffRequest
	if err := json.Unmarshal(body, &req); err != nil {
		return nil, "", nil, errors.New("invalid json body: " + err.Error())
	}
	req.EndpointIDs = sortedTargets(req.EndpointIDs)
	req.Name, req.Reason = strings.TrimSpace(req.Name), strings.TrimSpace(req.Reason)
	if len(req.EndpointIDs) == 0 || len(req.EndpointIDs) > 20 {
		return nil, "", nil, errors.New("name 1 to 20 endpoints")
	}
	if req.Name == "" || len(req.Name) > 60 || ownerText(req.Name, 60) != req.Name {
		return nil, "", nil, errors.New("name the script in up to 60 plain characters")
	}
	if req.Reason == "" || len(req.Reason) > 160 || ownerText(req.Reason, 160) != req.Reason {
		return nil, "", nil, errors.New("say why it runs in up to 160 plain characters (reason)")
	}
	shell, ok := oneOffInterpreters[req.Shell]
	if !ok {
		return nil, "", nil, errors.New("shell must be powershell, bash or sh")
	}
	if strings.TrimSpace(req.Source) == "" || len(req.Source) > oneOffMaxSource {
		return nil, "", nil, fmt.Errorf("the script must be 1 byte to %d KiB", oneOffMaxSource/1024)
	}
	if req.TimeoutSeconds == 0 {
		req.TimeoutSeconds = oneOffDefaultTime
	}
	if req.TimeoutSeconds < 30 || req.TimeoutSeconds > 3600 {
		return nil, "", nil, errors.New("timeout_seconds must be 30 to 3600")
	}
	windows, err := s.packageHosts(tenantID, req.EndpointIDs)
	if err != nil {
		return nil, "", nil, err
	}
	for _, id := range req.EndpointIDs {
		if windows[id] != shell.windows {
			return nil, "", nil, fmt.Errorf("a %s script does not run on %s", req.Shell, id)
		}
	}
	sum := sha256.Sum256([]byte(req.Source))
	digest := hex.EncodeToString(sum[:])
	raw, err := json.Marshal(response.ScriptExecPayload{
		ScriptID: responseauth.OneOffID(digest), ScriptVersion: 1, ScriptDigest: digest, Interpreter: shell.path,
		Source: req.Source, TimeoutSeconds: req.TimeoutSeconds, MaxOutputBytes: oneOffMaxOutput,
	})
	if err != nil {
		return nil, "", nil, err
	}
	payload, _ := json.Marshal(responseauth.PackageRunPayload{
		Route: responseauth.OneOffScriptRoute, Items: []string{string(raw)}, Targets: req.EndpointIDs,
		OneOff: &responseauth.OneOffScript{Name: req.Name, Reason: req.Reason},
	})
	return &req, string(raw), payload, nil
}

func (s *Server) resolveOneOffScript(w http.ResponseWriter, r *http.Request, body []byte) (*actionPlan, bool) {
	if s.responseStore == nil {
		writeJSONError(w, http.StatusServiceUnavailable, "response engine not initialized")
		return nil, false
	}
	req, _, payload, err := s.oneOffPlan(tenantOr(s.tenantFromRequest(r)), body)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return nil, false
	}
	if _, ok := s.scopedEndpointIDs(w, r, req.EndpointIDs); !ok || s.refuseLocked(w, "script", req.EndpointIDs...) {
		return nil, false
	}
	return &actionPlan{
		Kind:    response.ActionKindScriptExec,
		Action:  "Run a one-off script",
		Summary: fmt.Sprintf("One-off script %q on %s: %s", req.Name, s.endpointLabels(req.EndpointIDs), req.Reason),
		Targets: req.EndpointIDs,
		Payload: payload,
	}, true
}

// handleOneOffScript runs once the authority has authorized it: one job per machine.
func (s *Server) handleOneOffScript(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	tenantID := tenantOr(s.tenantFromRequest(r))
	var body json.RawMessage
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 2*oneOffMaxSource)).Decode(&body); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid json body")
		return
	}
	req, raw, _, err := s.oneOffPlan(tenantID, body)
	if err != nil {
		writeJSONError(w, http.StatusConflict, err.Error())
		return
	}
	grants := approvalGrants(r)
	if len(grants) == 0 {
		writeJSONError(w, http.StatusForbidden, "a one-off script was not authorized")
		return
	}
	requestedBy := s.operatorFromRequest(r)
	if requestedBy == "" {
		requestedBy = "operator"
	}
	runID := r.Header.Get(approvalHeader)
	digest := responseauth.ItemDigest(raw)
	var p response.ScriptExecPayload
	_ = json.Unmarshal([]byte(raw), &p)
	rec := oneOffRun{RunID: runID, Tenant: tenantID, Name: req.Name, Reason: req.Reason, Shell: req.Shell, Digest: p.ScriptDigest,
		Lines: strings.Count(strings.TrimRight(req.Source, "\n"), "\n") + 1, Requester: requestedBy, At: time.Now().UTC()}
	var jobs []packageRunJob
	for _, g := range grants {
		if g.ActionDigest != digest || g.ActionKind != response.ActionKindScriptExec {
			writeJSONError(w, http.StatusConflict, "a grant does not match this script")
			return
		}
		key := ""
		if runID != "" {
			key = response.RunKeyPrefix(runID) + g.GrantID
		}
		job, err := s.responseStore.CreateJob(tenantID, g.EndpointID, response.ActionKindScriptExec, requestedBy, g, raw, key)
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, fmt.Sprintf("created %d of %d jobs: %v", len(jobs), len(grants), err))
			return
		}
		jobs = append(jobs, packageRunJob{JobID: job.ID, EndpointID: g.EndpointID, Package: req.Name, Version: 1})
		rec.Jobs = append(rec.Jobs, job.ID)
		s.audit(r, "SCRIPT_RUN_DISPATCHED", job.ID, fmt.Sprintf("Dispatched one-off script %q (sha256 %s, %s) to %s authorized by the response authority: %s",
			req.Name, p.ScriptDigest[:12], req.Shell, g.EndpointID, req.Reason))
	}
	if err := s.saveOneOffRun(rec); err != nil {
		log.Printf("[!] one-off run %s not recorded: %v", runID, err)
	}
	writeJSON(w, http.StatusCreated, map[string]interface{}{"run_id": runID, "jobs": jobs})
}

func (s *Server) oneOffRuns() []oneOffRun {
	var out []oneOffRun
	if raw, err := s.store.GetSetting(oneOffRunsSetting); err == nil && raw != "" {
		_ = json.Unmarshal([]byte(raw), &out)
	}
	return out
}

func (s *Server) saveOneOffRun(rec oneOffRun) error {
	oneOffMu.Lock()
	defer oneOffMu.Unlock()
	runs := s.oneOffRuns()
	replaced := false
	for i := range runs {
		if runs[i].RunID == rec.RunID && rec.RunID != "" {
			runs[i], replaced = rec, true
		}
	}
	if !replaced {
		runs = append(runs, rec)
	}
	if len(runs) > oneOffRunsKept {
		runs = runs[len(runs)-oneOffRunsKept:]
	}
	raw, err := json.Marshal(runs)
	if err != nil {
		return err
	}
	return s.store.SetSetting(oneOffRunsSetting, string(raw))
}

// oneOffForJob returns the record of the one-off run a job belongs to.
func (s *Server) oneOffForJob(jobID string) *oneOffRun {
	for _, r := range s.oneOffRuns() {
		for _, j := range r.Jobs {
			if j == jobID {
				rr := r
				return &rr
			}
		}
	}
	return nil
}

// handleOneOffScripts lists recent one-off runs with each machine's state
// (GET /api/v1/maintenance/script) .
func (s *Server) handleOneOffScripts(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	tenantID := tenantOr(s.tenantFromRequest(r))
	now := time.Now().UTC()
	type machine struct {
		JobID      string      `json:"job_id"`
		EndpointID string      `json:"endpoint_id"`
		Run        *packageRun `json:"run"`
	}
	type view struct {
		oneOffRun
		Machines []machine `json:"machines"`
	}
	runs := s.oneOffRuns()
	out := []view{}
	for i := len(runs) - 1; i >= 0 && len(out) < 30; i-- {
		rec := runs[i]
		if rec.Tenant != tenantID {
			continue
		}
		v := view{oneOffRun: rec}
		var jobs []*response.JobRecord
		for _, id := range rec.Jobs {
			if j, err := s.responseStore.GetJob(tenantID, id); err == nil && j != nil {
				jobs = append(jobs, j)
			}
		}
		live := s.liveRuns(tenantID, jobs, now)
		for _, j := range jobs {
			v.Machines = append(v.Machines, machine{JobID: j.ID, EndpointID: j.EndpointID, Run: live[j.ID]})
		}
		out = append(out, v)
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"runs": out})
}

// handlePromoteScript turns a script into a library package: {"job_id"} (a
// one-off run's script) or {"source"}. The script must carry a valid package
// header and its name must be new to the library. A promoted package is not
// a released one, so each run is authorized one by one until a hub release
// ships it.
func (s *Server) handlePromoteScript(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if s.scriptsStore == nil {
		writeJSONError(w, http.StatusServiceUnavailable, "scripts not initialized")
		return
	}
	tenantID := tenantOr(s.tenantFromRequest(r))
	var req struct {
		JobID  string `json:"job_id"`
		Source string `json:"source"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 2*oneOffMaxSource)).Decode(&req); err != nil || (req.JobID == "") == (req.Source == "") {
		writeJSONError(w, http.StatusBadRequest, "send job_id (a one-off run) or source")
		return
	}
	source := req.Source
	if req.JobID != "" {
		job, err := s.responseStore.GetJob(tenantID, req.JobID)
		if err != nil || job == nil {
			writeJSONError(w, http.StatusNotFound, "no such job")
			return
		}
		p, ok := scriptJobPayload(job)
		if !ok || !isOneOffScript(p.ScriptID) {
			writeJSONError(w, http.StatusBadRequest, "that job is not a one-off script run")
			return
		}
		source = p.Source
	}
	if len(source) > promoteMaxSource {
		writeJSONError(w, http.StatusBadRequest, fmt.Sprintf("a package is at most %d KiB", promoteMaxSource/1024))
		return
	}
	h, err := scripts.ParsePackageHeader(source)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "the script needs a package header on its first line (docs/MAINTENANCE_PACKAGES.md): "+err.Error())
		return
	}
	if list, err := s.scriptsStore.ListScripts(tenantID); err == nil {
		for _, sc := range list {
			if sc.Name == h.Name {
				writeJSONError(w, http.StatusConflict, h.Name+" is already in the library; change it in the repository and sync it")
				return
			}
		}
	}
	meta, _ := json.Marshal(map[string]interface{}{
		"package": h.Name, "title": h.Title, "category": h.Category, "interval": h.Interval, "risk": h.Risk,
		"reboot": h.Reboot, "timeout": h.Timeout, "platform": h.PlatformName(), "role": h.Role,
	})
	schema, _ := json.Marshal(h.Schema())
	operatorID := s.operatorFromRequest(r)
	sc, sv, _, err := s.scriptsStore.SyncScript(tenantID, h.Name, h.Description, h.Interpreter(), source, string(schema), string(meta), operatorID)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "not added: "+err.Error())
		return
	}
	if req.JobID != "" {
		if rec := s.oneOffForJob(req.JobID); rec != nil {
			rec.Promoted = h.Name
			_ = s.saveOneOffRun(*rec)
		}
	}
	s.audit(r, "SCRIPT_PROMOTED", sc.ID, fmt.Sprintf("Promoted a script to package %s v%d (digest %s); not a released package, so each run is authorized one by one", h.Name, sv.Version, sv.DigestSHA256))
	writeJSON(w, http.StatusCreated, map[string]interface{}{"package": h.Name, "script_id": sc.ID, "version": sv.Version, "digest": sv.DigestSHA256})
}

// handleOneOffScriptRoute: GET lists runs; POST asks for and starts one.
func (s *Server) handleOneOffScriptRoute() http.HandlerFunc {
	run := requireAdmin(s.authorized(s.resolveOneOffScript, s.handleOneOffScript))
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			s.handleOneOffScripts(w, r)
			return
		}
		run(w, r)
	}
}
