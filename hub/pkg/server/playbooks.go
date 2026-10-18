package server

// Playbooks: named, ordered package runs (GET/PUT/DELETE
// /api/v1/maintenance/playbooks) and running one on chosen machines
// (POST /api/v1/maintenance/playbooks/run). A run asks the owner once for
// every step on every machine: the approval binds each step's exact payload.
// With maintenance mode on, the run starts by keeping the machines awake for
// the run's window and ends by letting them sleep again.
//
// The agent starts every job it is offered at once, so the hub holds each
// machine's next step back until the one before it has ended (finished,
// failed, or gone quiet past its time limit). The grants live for the window
// the owner approved (responseauth.PlaybookRun); a step that has not started
// by then is not started at all. A step that fails does not stop the ones
// after it: each package checks and skips by itself, and maintenance mode
// still ends. Scheduled package runs leave a machine alone while a playbook
// runs on it.

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"

	"ominull/hub/pkg/response"
	"ominull/hub/pkg/responseauth"
	"ominull/hub/pkg/scripts"
)

const (
	playbooksSetting    = "maintenance.playbooks"
	playbookRunsSetting = "maintenance.playbook_runs"
	playbooksAudit      = "PLAYBOOK_CHANGED"
	playbookMaxSteps    = 8 // with maintenance mode on and off, the authority's 10 scripts
	playbookMaxCount    = 50
	playbookRunsKept    = 20
	playbookStepSlack   = 10 * time.Minute // per step, for an agent that polls late
	// A restart step's warning (at most 60 min) and the machine coming back.
	playbookRestartSlack  = 75 * time.Minute
	playbookRestartSettle = 2 * time.Minute
	playbookTick          = 30 * time.Second
)

var (
	playbookMu   sync.Mutex // playbooks and runs: read-modify-write
	playbookIDRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,47}$`)
)

type playbookStep struct {
	Package string `json:"package"`
	Mode    string `json:"mode"`
}

type playbook struct {
	ID              string         `json:"id"`
	Name            string         `json:"name"`
	Steps           []playbookStep `json:"steps"`
	MaintenanceMode bool           `json:"maintenance_mode"`
	Note            string         `json:"note,omitempty"`
}

// plainText: 1..max characters, no control characters, quotes, backslashes
// or angle brackets, no leading or trailing space.
func plainText(s string, max int) bool {
	if s == "" || len([]rune(s)) > max || strings.TrimSpace(s) != s || strings.ContainsAny(s, "\"\\<>") {
		return false
	}
	for _, r := range s {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return false
		}
	}
	return true
}

func (p *playbook) validate() error {
	switch {
	case !playbookIDRe.MatchString(p.ID):
		return errors.New("id: 2-48 lower-case letters, digits and -")
	case !plainText(p.Name, 80):
		return errors.New("name: 1-80 characters, no quotes, backslashes or angle brackets")
	case len(p.Steps) == 0 || len(p.Steps) > playbookMaxSteps:
		return fmt.Errorf("a playbook has 1-%d steps", playbookMaxSteps)
	case p.Note != "" && !plainText(p.Note, 200):
		return errors.New("note: up to 200 characters, no quotes, backslashes or angle brackets")
	}
	seen := map[playbookStep]bool{}
	for i, st := range p.Steps {
		if strings.TrimSpace(st.Package) == "" {
			return fmt.Errorf("step %d names no package", i+1)
		}
		if !scripts.RunModes[st.Mode] {
			return fmt.Errorf("step %d: mode must be audit, enforce or revert", i+1)
		}
		if seen[st] {
			return fmt.Errorf("step %d repeats %s (%s)", i+1, st.Package, st.Mode)
		}
		seen[st] = true
	}
	return nil
}

func (s *Server) playbooks() []playbook {
	var out []playbook
	if raw, err := s.store.GetSetting(playbooksSetting); err == nil && raw != "" {
		if err := json.Unmarshal([]byte(raw), &out); err != nil {
			log.Printf("[!] Ignoring unreadable saved playbooks: %v", err)
			return nil
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func (s *Server) savePlaybooks(list []playbook) error {
	if list == nil {
		list = []playbook{}
	}
	raw, err := json.Marshal(list)
	if err != nil {
		return err
	}
	return s.store.SetSetting(playbooksSetting, string(raw))
}

// checkPlaybookPackages: every step is a live package other than maintenance
// mode (the playbook switches that itself), and all steps run on one platform.
func (s *Server) checkPlaybookPackages(tenantID string, p *playbook) error {
	platform := ""
	for i, st := range p.Steps {
		sc, err := s.findPackage(tenantID, st.Package)
		if err != nil {
			return fmt.Errorf("step %d: %v", i+1, err)
		}
		if m := sc.Package(); m != nil && m.Role == scripts.RoleMaintenanceMode {
			return fmt.Errorf("step %d: %s is switched by the playbook itself, not run as a step", i+1, sc.Name)
		}
		pl := "linux"
		if windowsInterpreter(sc.Interpreter) {
			pl = "windows"
		}
		if platform != "" && pl != platform {
			return errors.New("all steps of a playbook run on the same platform (Windows or Linux)")
		}
		platform = pl
	}
	return nil
}

// ---- runs ------------------------------------------------------------------

type playbookRunStep struct {
	Label string `json:"label"`          // "windows-cleanup (enforce)"
	Item  string `json:"item,omitempty"` // the exact payload; dropped when the run ends
	// Reboot marks a restart step: the next step waits for the machine to
	// come back from it.
	Reboot bool `json:"reboot,omitempty"`
}

type playbookHostStep struct {
	State  string                  `json:"state"` // pending | started | done | not_started
	JobID  string                  `json:"job_id,omitempty"`
	Result string                  `json:"result,omitempty"` // the package run's state once done
	Grant  *response.EndpointGrant `json:"grant,omitempty"`  // until the step starts
	// HoldUntil: after a restart step, the next step waits until then and
	// until the machine has checked in since.
	HoldUntil *time.Time `json:"hold_until,omitempty"`
}

type playbookRun struct {
	ID         string                         `json:"id"` // the owner's approval
	Tenant     string                         `json:"tenant"`
	PlaybookID string                         `json:"playbook_id"`
	Name       string                         `json:"name"`
	Requester  string                         `json:"requester"`
	Started    time.Time                      `json:"started"`
	Deadline   time.Time                      `json:"deadline"`
	Done       bool                           `json:"done"`
	Steps      []playbookRunStep              `json:"steps"`
	Hosts      map[string][]*playbookHostStep `json:"hosts"`
}

func (s *Server) playbookRuns() []*playbookRun {
	var out []*playbookRun
	if raw, err := s.store.GetSetting(playbookRunsSetting); err == nil && raw != "" {
		if err := json.Unmarshal([]byte(raw), &out); err != nil {
			log.Printf("[!] Ignoring unreadable playbook runs: %v", err)
			return nil
		}
	}
	return out
}

func (s *Server) savePlaybookRuns(runs []*playbookRun) error {
	// Newest first; finished runs beyond the kept count are forgotten.
	sort.SliceStable(runs, func(i, j int) bool { return runs[i].Started.After(runs[j].Started) })
	kept := runs[:0]
	for i, r := range runs {
		if !r.Done || i < playbookRunsKept {
			kept = append(kept, r)
		}
	}
	raw, err := json.Marshal(kept)
	if err != nil {
		return err
	}
	return s.store.SetSetting(playbookRunsSetting, string(raw))
}

// playbookBusyHosts are the machines a playbook is running on now.
func (s *Server) playbookBusyHosts() map[string]bool {
	playbookMu.Lock()
	defer playbookMu.Unlock()
	busy := map[string]bool{}
	for _, r := range s.playbookRuns() {
		if !r.Done {
			for ep := range r.Hosts {
				busy[ep] = true
			}
		}
	}
	return busy
}

type playbookRunRequest struct {
	PlaybookID  string   `json:"playbook_id"`
	EndpointIDs []string `json:"endpoint_ids"`
	// DontWait: steps that change something run even when someone is using
	// the machine or a game is open (by default they wait).
	DontWait bool `json:"dont_wait"`
}

type playbookPlan struct {
	req    playbookRunRequest
	book   playbook
	items  []packageRunItem
	labels []string
	reboot []bool
	window int64 // seconds
}

// playbookRunPlan works out a run the same way each time: maintenance mode on
// (for the whole window), the steps, maintenance mode off.
func (s *Server) playbookRunPlan(tenantID string, body []byte) (*playbookPlan, error) {
	var req playbookRunRequest
	if err := json.Unmarshal(body, &req); err != nil {
		return nil, errors.New("invalid json body: " + err.Error())
	}
	req.EndpointIDs = sortedTargets(req.EndpointIDs)
	if len(req.EndpointIDs) == 0 || req.PlaybookID == "" {
		return nil, errors.New("name a playbook and at least one endpoint")
	}
	var book *playbook
	for _, p := range s.playbooks() {
		if p.ID == req.PlaybookID {
			p := p
			book = &p
		}
	}
	if book == nil {
		return nil, fmt.Errorf("no playbook %s", req.PlaybookID)
	}
	if err := s.checkPlaybookPackages(tenantID, book); err != nil {
		return nil, err
	}
	windows, err := s.packageHosts(tenantID, req.EndpointIDs)
	if err != nil {
		return nil, err
	}
	settings, err := s.maintenanceSettings(tenantID)
	if err != nil {
		return nil, err
	}
	plan := &playbookPlan{req: req, book: *book}
	var total time.Duration
	add := func(it packageRunItem, h *scripts.PackageHeader, mode string) {
		plan.items = append(plan.items, it)
		plan.labels = append(plan.labels, h.Name+" ("+mode+")")
		plan.reboot = append(plan.reboot, h.Role == scripts.RoleReboot && mode == "enforce")
		total += time.Duration(scripts.ClampTimeout(h.Timeout))*time.Second + playbookStepSlack
		if h.Role == scripts.RoleReboot && mode == "enforce" {
			total += playbookRestartSlack
		}
	}
	// Steps that change something wait while someone is using the machine,
	// unless the run says not to.
	opts := map[string]string{"when_busy": "wait"}
	if req.DontWait {
		opts["when_busy"] = "run"
	}
	for _, st := range book.Steps {
		sc, err := s.findPackage(tenantID, st.Package)
		if err != nil {
			return nil, err
		}
		var over map[string]string
		if st.Mode != "audit" {
			over = opts
		}
		it, h, err := s.buildPackageItem(tenantID, sc, st.Mode, req.EndpointIDs, windows, settings, over)
		if err != nil {
			return nil, err
		}
		add(it, h, st.Mode)
	}
	var mm *scripts.Script
	if book.MaintenanceMode {
		if mm, err = s.maintenanceModePackage(tenantID, windows[req.EndpointIDs[0]]); err != nil {
			return nil, err
		}
		total += 2 * playbookStepSlack // its own two short runs
	}
	hours := int64((total + time.Hour - 1) / time.Hour)
	if hours*3600 > responseauth.PlaybookMaxWindow {
		return nil, fmt.Errorf("this playbook can take up to %d hours on a machine; a run takes at most 24, so split it", hours)
	}
	plan.window = hours * 3600
	if mm != nil {
		on, h, err := s.buildPackageItem(tenantID, mm, "enforce", req.EndpointIDs, windows, settings, map[string]string{"hours": strconv.FormatInt(hours, 10)})
		if err != nil {
			return nil, err
		}
		off, _, err := s.buildPackageItem(tenantID, mm, "revert", req.EndpointIDs, windows, settings, nil)
		if err != nil {
			return nil, err
		}
		plan.items = append(append([]packageRunItem{on}, plan.items...), off)
		plan.reboot = append(append([]bool{false}, plan.reboot...), false)
		plan.labels = append(append([]string{h.Name + " (enforce)"}, plan.labels...), h.Name+" (revert)")
	}
	return plan, nil
}

// maintenanceModePackage is the maintenance mode package for a platform.
func (s *Server) maintenanceModePackage(tenantID string, windows bool) (*scripts.Script, error) {
	defs, err := s.packageDefs(tenantID)
	if err != nil {
		return nil, err
	}
	for _, d := range defs {
		if d.Header.Role == scripts.RoleMaintenanceMode && windowsInterpreter(d.Script.Interpreter) == windows {
			return d.Script, nil
		}
	}
	return nil, errors.New("this playbook turns on maintenance mode, but no maintenance mode package for these machines is in the script library")
}

func (p *playbookPlan) payload() []byte {
	pr := responseauth.PackageRunPayload{Route: responseauth.PlaybookRunRoute, Targets: p.req.EndpointIDs,
		Playbook: &responseauth.PlaybookRun{Name: p.book.Name, WindowSeconds: p.window}}
	for _, it := range p.items {
		pr.Items = append(pr.Items, it.Raw)
	}
	raw, _ := json.Marshal(pr)
	return raw
}

func (s *Server) resolvePlaybookRun(w http.ResponseWriter, r *http.Request, body []byte) (*approvalPlan, bool) {
	if s.scriptsStore == nil || s.responseStore == nil {
		writeJSONError(w, http.StatusServiceUnavailable, "scripts or response engine not initialized")
		return nil, false
	}
	plan, err := s.playbookRunPlan(tenantOr(s.tenantFromRequest(r)), body)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return nil, false
	}
	if _, ok := s.scopedEndpointIDs(w, r, plan.req.EndpointIDs); !ok {
		return nil, false
	}
	return &approvalPlan{
		Kind:    response.ActionKindScriptExec,
		Action:  "Run playbook",
		Summary: fmt.Sprintf("%s (%s) on %s", plan.book.Name, strings.Join(plan.labels, ", "), s.endpointLabels(plan.req.EndpointIDs)),
		Targets: plan.req.EndpointIDs,
		Payload: plan.payload(),
	}, true
}

func tenantOr(t string) string {
	if t == "" {
		return "default"
	}
	return t
}

// handlePlaybookRun runs once the owner approved: it records the run with
// every step's grant and starts the first step on each machine.
func (s *Server) handlePlaybookRun(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	tenantID := tenantOr(s.tenantFromRequest(r))
	body, err := io.ReadAll(io.LimitReader(r.Body, 64*1024))
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "request body unreadable")
		return
	}
	plan, err := s.playbookRunPlan(tenantID, body)
	if err != nil {
		writeJSONError(w, http.StatusConflict, err.Error())
		return
	}
	grants := approvalGrants(r)
	if len(grants) == 0 {
		writeJSONError(w, http.StatusForbidden, "a playbook run needs the owner's approval")
		return
	}
	requestedBy := s.operatorFromRequest(r)
	if requestedBy == "" {
		requestedBy = "operator"
	}
	now := time.Now().UTC()
	run := &playbookRun{ID: r.Header.Get(approvalHeader), Tenant: tenantID, PlaybookID: plan.book.ID, Name: plan.book.Name,
		Requester: requestedBy, Started: now, Deadline: now.Add(time.Duration(plan.window) * time.Second), Hosts: map[string][]*playbookHostStep{}}
	if run.ID == "" {
		run.ID = "run-" + strconv.FormatInt(now.UnixNano(), 36)
	}
	byKey := map[string]*response.EndpointGrant{}
	for _, g := range grants {
		if g.ActionKind == response.ActionKindScriptExec {
			byKey[g.EndpointID+"|"+g.ActionDigest] = g
		}
	}
	for i, it := range plan.items {
		run.Steps = append(run.Steps, playbookRunStep{Label: plan.labels[i], Item: it.Raw, Reboot: plan.reboot[i]})
	}
	for _, ep := range plan.req.EndpointIDs {
		for _, it := range plan.items {
			g := byKey[ep+"|"+it.Digest]
			if g == nil {
				writeJSONError(w, http.StatusConflict, "the approval does not cover every step on every machine; ask again")
				return
			}
			run.Hosts[ep] = append(run.Hosts[ep], &playbookHostStep{State: "pending", Grant: g})
		}
	}
	playbookMu.Lock()
	runs := append(s.playbookRuns(), run)
	err = s.savePlaybookRuns(runs)
	playbookMu.Unlock()
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "the run could not be saved: "+err.Error())
		return
	}
	s.audit(r, "PLAYBOOK_RUN_STARTED", run.ID, fmt.Sprintf("Playbook %s (%s) on %s under owner approval, within %s",
		plan.book.Name, strings.Join(plan.labels, ", "), strings.Join(plan.req.EndpointIDs, ", "), time.Duration(plan.window)*time.Second))
	s.advancePlaybookRuns(now)
	writeJSON(w, http.StatusCreated, map[string]interface{}{"run": s.playbookRunView(run.ID)})
}

// advancePlaybookRuns starts each machine's next step once the one before it
// has ended, and closes runs whose steps have all ended.
func (s *Server) advancePlaybookRuns(now time.Time) {
	if s.responseStore == nil {
		return
	}
	playbookMu.Lock()
	defer playbookMu.Unlock()
	runs := s.playbookRuns()
	changed := false
	for _, run := range runs {
		if run.Done {
			continue
		}
		open := false
		for ep, steps := range run.Hosts {
			if s.advancePlaybookHost(run, ep, steps, now, &changed) {
				open = true
			}
		}
		if !open {
			run.Done, changed = true, true
			for i := range run.Steps {
				run.Steps[i].Item = ""
			}
			log.Printf("[+] Playbook run %s (%s) has ended on every machine.", run.ID, run.Name)
		}
	}
	if changed {
		if err := s.savePlaybookRuns(runs); err != nil {
			log.Printf("[!] playbook runs: %v", err)
		}
	}
}

// advancePlaybookHost moves one machine along; true while it has a step left.
func (s *Server) advancePlaybookHost(run *playbookRun, ep string, steps []*playbookHostStep, now time.Time, changed *bool) bool {
	for i, st := range steps {
		switch st.State {
		case "done", "not_started":
			continue
		case "started":
			job, err := s.responseStore.GetJob(run.Tenant, st.JobID)
			if err != nil || job == nil {
				st.State, st.Result, *changed = "done", "failed", true
				continue
			}
			pr := derivePackageRun(job, now)
			if pr.State == "running" || pr.State == "waiting" && now.Before(run.Deadline.Add(packageRunGrace)) {
				return true
			}
			if pr.State == "waiting" {
				pr.State = "not_run" // offline past the window: its grant has expired
			}
			st.State, st.Result, *changed = "done", pr.State, true
			if run.Steps[i].Reboot && pr.State == "fixed" {
				end := now
				if pr.CompletedAt != nil {
					end = *pr.CompletedAt
				}
				hold := end.Add(time.Duration(pr.RestartIn)*time.Second + playbookRestartSettle)
				st.HoldUntil = &hold
			}
			continue
		}
		// pending: start it while the grants still live.
		if !now.Before(run.Deadline) {
			for _, rest := range steps[i:] {
				rest.State, rest.Grant = "not_started", nil
			}
			*changed = true
			return false
		}
		if i > 0 && steps[i-1].HoldUntil != nil && !s.backFromRestart(ep, *steps[i-1].HoldUntil, now) {
			return true
		}
		job, err := s.responseStore.CreateJob(run.Tenant, ep, response.ActionKindScriptExec, run.Requester, st.Grant, run.Steps[i].Item, "")
		if err != nil {
			log.Printf("[!] playbook run %s: step %d on %s not started: %v", run.ID, i+1, ep, err)
			return true // tried again next tick
		}
		st.State, st.JobID, st.Grant, *changed = "started", job.ID, nil, true
		log.Printf("[*] Playbook run %s: step %d (%s) started on %s.", run.ID, i+1, run.Steps[i].Label, ep)
		return true
	}
	return false
}

// backFromRestart: the hold after a restart step has passed and the machine
// has checked in since, so a next step is not handed to a machine going down.
func (s *Server) backFromRestart(ep string, hold, now time.Time) bool {
	if now.Before(hold) {
		return false
	}
	e, err := s.store.GetEndpoint(ep)
	return err == nil && e != nil && e.LastSeenAt.After(hold)
}

func (s *Server) playbookLoop() {
	t := time.NewTicker(playbookTick)
	defer t.Stop()
	for range t.C {
		s.advancePlaybookRuns(time.Now().UTC())
	}
}

// ---- views and the API -------------------------------------------------------

type playbookRunView struct {
	ID         string                            `json:"id"`
	PlaybookID string                            `json:"playbook_id"`
	Name       string                            `json:"name"`
	Requester  string                            `json:"requester"`
	Started    time.Time                         `json:"started"`
	Deadline   time.Time                         `json:"deadline"`
	Done       bool                              `json:"done"`
	Steps      []string                          `json:"steps"`
	Hosts      map[string][]playbookHostStepView `json:"hosts"`
}

type playbookHostStepView struct {
	State  string `json:"state"`
	JobID  string `json:"job_id,omitempty"`
	Result string `json:"result,omitempty"`
	// Live is a started step's run as it goes (stalled, needs_hands,
	// progress line).
	Live *packageRun `json:"live,omitempty"`
}

// withLive adds each started step's live run to a view.
func (s *Server) withLive(v playbookRunView, tenant string, now time.Time) playbookRunView {
	if s.responseStore == nil {
		return v
	}
	for _, steps := range v.Hosts {
		for i := range steps {
			if steps[i].State != "started" || steps[i].JobID == "" {
				continue
			}
			if job, err := s.responseStore.GetJob(tenant, steps[i].JobID); err == nil && job != nil {
				steps[i].Live = s.liveRun(job, now)
			}
		}
	}
	return v
}

func viewPlaybookRun(r *playbookRun) playbookRunView {
	v := playbookRunView{ID: r.ID, PlaybookID: r.PlaybookID, Name: r.Name, Requester: r.Requester, Started: r.Started,
		Deadline: r.Deadline, Done: r.Done, Hosts: map[string][]playbookHostStepView{}}
	for _, st := range r.Steps {
		v.Steps = append(v.Steps, st.Label)
	}
	for ep, steps := range r.Hosts {
		for _, st := range steps {
			v.Hosts[ep] = append(v.Hosts[ep], playbookHostStepView{State: st.State, JobID: st.JobID, Result: st.Result})
		}
	}
	return v
}

func (s *Server) playbookRunView(id string) *playbookRunView {
	playbookMu.Lock()
	defer playbookMu.Unlock()
	for _, r := range s.playbookRuns() {
		if r.ID == id {
			v := s.withLive(viewPlaybookRun(r), r.Tenant, time.Now().UTC())
			return &v
		}
	}
	return nil
}

func (s *Server) playbooksView() map[string]interface{} {
	playbookMu.Lock()
	defer playbookMu.Unlock()
	books := s.playbooks()
	if books == nil {
		books = []playbook{}
	}
	runs := []playbookRunView{}
	now := time.Now().UTC()
	for _, r := range s.playbookRuns() {
		runs = append(runs, s.withLive(viewPlaybookRun(r), r.Tenant, now))
	}
	return map[string]interface{}{"playbooks": books, "runs": runs, "max_steps": playbookMaxSteps}
}

// handlePlaybooks: GET (any role) the playbooks and recent runs; PUT
// {"playbook":{...}} (admin) adds or replaces one; DELETE ?id= removes one.
// Saving runs nothing and asks nobody: every run asks the owner.
func (s *Server) handlePlaybooks(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, s.playbooksView())
		return
	case http.MethodPut, http.MethodDelete:
	default:
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if r.Header.Get("X-Role") != "admin" {
		writeJSONError(w, http.StatusForbidden, "admin credential required to change playbooks")
		return
	}
	if s.scriptsStore == nil {
		writeJSONError(w, http.StatusServiceUnavailable, "the script library is not initialized")
		return
	}
	tenantID := tenantOr(s.tenantFromRequest(r))
	playbookMu.Lock()
	list := s.playbooks()
	if r.Method == http.MethodDelete {
		id := strings.TrimSpace(r.URL.Query().Get("id"))
		next := []playbook{}
		for _, p := range list {
			if p.ID != id {
				next = append(next, p)
			}
		}
		if len(next) == len(list) {
			playbookMu.Unlock()
			writeJSONError(w, http.StatusNotFound, "no playbook "+id)
			return
		}
		err := s.savePlaybooks(next)
		playbookMu.Unlock()
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, "the playbooks could not be saved: "+err.Error())
			return
		}
		s.audit(r, playbooksAudit, "playbook:"+id, "removed "+id+"; credential "+credentialOf(r)+" (unverified)")
		writeJSON(w, http.StatusOK, s.playbooksView())
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 16*1024+1))
	if err != nil || len(body) > 16*1024 {
		playbookMu.Unlock()
		writeJSONError(w, http.StatusBadRequest, "request body unreadable or over 16 KiB")
		return
	}
	var req struct {
		Playbook playbook `json:"playbook"`
	}
	if !decodeInto(w, body, &req) {
		playbookMu.Unlock()
		return
	}
	p := req.Playbook
	err = p.validate()
	if err == nil {
		err = s.checkPlaybookPackages(tenantID, &p)
	}
	if err != nil {
		playbookMu.Unlock()
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	next, how := []playbook{}, "added"
	for _, x := range list {
		if x.ID == p.ID {
			how = "changed"
			continue
		}
		next = append(next, x)
	}
	if len(next) >= playbookMaxCount {
		playbookMu.Unlock()
		writeJSONError(w, http.StatusBadRequest, fmt.Sprintf("at most %d playbooks", playbookMaxCount))
		return
	}
	err = s.savePlaybooks(append(next, p))
	playbookMu.Unlock()
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "the playbooks could not be saved: "+err.Error())
		return
	}
	steps := make([]string, 0, len(p.Steps))
	for _, st := range p.Steps {
		steps = append(steps, st.Package+" ("+st.Mode+")")
	}
	mm := ""
	if p.MaintenanceMode {
		mm = ", maintenance mode on for the run"
	}
	s.audit(r, playbooksAudit, "playbook:"+p.ID, how+" "+p.Name+": "+strings.Join(steps, ", ")+mm+"; credential "+credentialOf(r)+" (unverified)")
	writeJSON(w, http.StatusOK, s.playbooksView())
}
