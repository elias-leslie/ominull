package server

// Package runs authorized by the response authority: POST /api/v1/maintenance/run has the
// authority sign grants for named packages on named hosts and dispatches them
// at once. Each run is an ordinary script_exec
// job, so its result lands on the Maintenance card and the jobs page.

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"

	"ominull/hub/pkg/response"
	"ominull/hub/pkg/responseauth"
	"ominull/hub/pkg/scripts"
)

// packageMaxOutput is the output bound of every package run. The console,
// the run route and schedules use the same value, so the same package run
// is the same bytes (and so the same digest a package rule names).
const packageMaxOutput = 1 << 20

type packageRunRequest struct {
	EndpointIDs []string `json:"endpoint_ids"`
	Packages    []string `json:"packages"`
	Mode        string   `json:"mode"`
}

type packageRunItem struct {
	Raw     string
	Digest  string
	Script  *scripts.Script
	Version int
}

// packageItem is the exact script payload an agent receives for one run.
func packageItem(sc *scripts.Script, sv *scripts.ScriptVersion, params map[string]string, timeout int, maxOutput int64) (string, error) {
	raw, err := json.Marshal(response.ScriptExecPayload{
		ScriptID:       sc.ID,
		ScriptVersion:  sv.Version,
		ScriptDigest:   sv.DigestSHA256,
		Interpreter:    sc.Interpreter,
		Source:         sv.Source,
		Parameters:     params,
		TimeoutSeconds: scripts.ClampTimeout(timeout),
		MaxOutputBytes: maxOutput,
	})
	return string(raw), err
}

// findPackage resolves a package by its package or script name.
func (s *Server) findPackage(tenantID, name string) (*scripts.Script, error) {
	list, err := s.scriptsStore.ListScripts(tenantID)
	if err != nil {
		return nil, err
	}
	for _, sc := range list {
		if m := sc.Package(); m != nil && !sc.Retired && (sc.Name == name || m.Package == name) {
			return sc, nil
		}
	}
	return nil, fmt.Errorf("no package called %q in the script library", name)
}

// packageRunItems works out the run a request names, the same way each time.
func (s *Server) packageRunItems(tenantID string, body []byte) (*packageRunRequest, []packageRunItem, error) {
	var req packageRunRequest
	if err := json.Unmarshal(body, &req); err != nil {
		return nil, nil, errors.New("invalid json body: " + err.Error())
	}
	req.EndpointIDs = sortedTargets(req.EndpointIDs)
	if len(req.EndpointIDs) == 0 || len(req.Packages) == 0 {
		return nil, nil, errors.New("name at least one endpoint and one package")
	}
	if !scripts.RunModes[req.Mode] {
		return nil, nil, errors.New("mode must be audit, enforce or revert")
	}
	windows, err := s.packageHosts(tenantID, req.EndpointIDs)
	if err != nil {
		return nil, nil, err
	}
	settings, err := s.maintenanceSettings(tenantID)
	if err != nil {
		return nil, nil, err
	}
	seen := map[string]bool{}
	var items []packageRunItem
	for _, name := range req.Packages {
		sc, err := s.findPackage(tenantID, strings.TrimSpace(name))
		if err != nil {
			return nil, nil, err
		}
		if seen[sc.ID] {
			continue
		}
		seen[sc.ID] = true
		it, _, err := s.buildPackageItem(tenantID, sc, req.Mode, req.EndpointIDs, windows, settings, nil)
		if err != nil {
			return nil, nil, err
		}
		items = append(items, it)
	}
	return &req, items, nil
}

// packageHosts checks the named endpoints and says which run Windows.
func (s *Server) packageHosts(tenantID string, ids []string) (map[string]bool, error) {
	windows := map[string]bool{}
	for _, id := range ids {
		ep, err := s.store.GetEndpoint(id)
		if err != nil || ep == nil || ep.Status == "retired" || (ep.TenantID != tenantID && tenantID != "default") {
			return nil, fmt.Errorf("endpoint %s not found", id)
		}
		windows[id] = strings.Contains(strings.ToLower(ep.OS), "windows")
	}
	return windows, nil
}

// buildPackageItem is one package's run payload for hosts that share its
// effective settings (windows says which hosts run Windows). override sets
// parameters over the settings (a playbook's maintenance mode length, its
// run options).
func (s *Server) buildPackageItem(tenantID string, sc *scripts.Script, mode string, endpointIDs []string, windows map[string]bool,
	settings scripts.Settings, override map[string]string) (packageRunItem, *scripts.PackageHeader, error) {
	for _, id := range endpointIDs {
		if windows[id] != windowsInterpreter(sc.Interpreter) {
			return packageRunItem{}, nil, fmt.Errorf("%s does not run on %s", sc.Name, id)
		}
	}
	sv, err := s.scriptsStore.GetScriptVersion(tenantID, sc.ID, sc.LatestVersion)
	if err != nil {
		return packageRunItem{}, nil, err
	}
	h, err := scripts.ParsePackageHeader(sv.Source)
	if err != nil {
		return packageRunItem{}, nil, fmt.Errorf("%s: %v", sc.Name, err)
	}
	// One run is one payload on every named host, so the hosts must
	// share the package's effective settings.
	var params map[string]string
	winParams := s.windowParams(endpointIDs)
	for _, id := range endpointIDs {
		p := settings.Effective(h, id).RunParams(mode)
		addWindow(h, p, winParams[id])
		for k, v := range override {
			p[k] = v
		}
		if err := s.fillCatalogParams(h, p); err != nil {
			return packageRunItem{}, nil, err
		}
		if params != nil && !sameParams(params, p) {
			return packageRunItem{}, nil, fmt.Errorf("%s has different settings on these hosts; run them separately", sc.Name)
		}
		params = p
	}
	if err := h.CheckRun(params); err != nil {
		return packageRunItem{}, nil, fmt.Errorf("%s: %w", sc.Name, err)
	}
	raw, err := packageItem(sc, sv, params, h.Timeout, packageMaxOutput)
	if err != nil {
		return packageRunItem{}, nil, err
	}
	return packageRunItem{Raw: raw, Digest: responseauth.ItemDigest(raw), Script: sc, Version: sv.Version}, h, nil
}

func sameParams(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if bv, ok := b[k]; !ok || bv != v {
			return false
		}
	}
	return true
}

func packageRunPayload(items []packageRunItem, targets []string) []byte {
	p := responseauth.PackageRunPayload{Route: responseauth.PackageRunRoute, Targets: targets}
	for _, it := range items {
		p.Items = append(p.Items, it.Raw)
	}
	raw, _ := json.Marshal(p)
	return raw
}

func (s *Server) resolveMaintenanceRun(w http.ResponseWriter, r *http.Request, body []byte) (*actionPlan, bool) {
	if s.scriptsStore == nil || s.responseStore == nil {
		writeJSONError(w, http.StatusServiceUnavailable, "scripts or response engine not initialized")
		return nil, false
	}
	tenantID := s.tenantFromRequest(r)
	if tenantID == "" {
		tenantID = "default"
	}
	req, items, err := s.packageRunItems(tenantID, body)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return nil, false
	}
	if _, ok := s.scopedEndpointIDs(w, r, req.EndpointIDs); !ok || s.refuseLocked(w, "script", req.EndpointIDs...) {
		return nil, false
	}
	names := make([]string, 0, len(items))
	for _, it := range items {
		names = append(names, it.Script.Name)
	}
	return &actionPlan{
		Kind:    response.ActionKindScriptExec,
		Action:  "Run maintenance",
		Summary: fmt.Sprintf("%s (%s) on %s", strings.Join(names, ", "), req.Mode, s.endpointLabels(req.EndpointIDs)),
		Targets: req.EndpointIDs,
		Payload: packageRunPayload(items, req.EndpointIDs),
	}, true
}

type packageRunJob struct {
	JobID      string `json:"job_id"`
	EndpointID string `json:"endpoint_id"`
	Package    string `json:"package"`
	Version    int    `json:"version"`
}

// dispatchPackageGrants creates one script_exec job per grant. runID (the
// authorization id, when there is one) is kept in each job's idempotency key
// so the run's jobs can be found again (ominullctl maint wait RUN).
func (s *Server) dispatchPackageGrants(tenantID, requestedBy, runID string, items []packageRunItem, grants []*response.EndpointGrant) ([]packageRunJob, error) {
	byDigest := map[string]packageRunItem{}
	for _, it := range items {
		byDigest[it.Digest] = it
	}
	var out []packageRunJob
	for _, g := range grants {
		it, ok := byDigest[g.ActionDigest]
		if !ok || g.ActionKind != response.ActionKindScriptExec {
			return out, fmt.Errorf("grant %s matches no script of this run", g.GrantID)
		}
		key := ""
		if runID != "" {
			key = response.RunKeyPrefix(runID) + g.GrantID
		}
		job, err := s.responseStore.CreateJob(tenantID, g.EndpointID, response.ActionKindScriptExec, requestedBy, g, it.Raw, key)
		if err != nil {
			return out, err
		}
		out = append(out, packageRunJob{JobID: job.ID, EndpointID: g.EndpointID, Package: it.Script.Name, Version: it.Version})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].EndpointID != out[j].EndpointID {
			return out[i].EndpointID < out[j].EndpointID
		}
		return out[i].Package < out[j].Package
	})
	return out, nil
}

// handleMaintenanceRun runs once the authority has authorized it: it
// creates the jobs the authority's grants allow.
func (s *Server) handleMaintenanceRun(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	tenantID := s.tenantFromRequest(r)
	if tenantID == "" {
		tenantID = "default"
	}
	var body json.RawMessage
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid json body")
		return
	}
	_, items, err := s.packageRunItems(tenantID, body)
	if err != nil {
		writeJSONError(w, http.StatusConflict, err.Error())
		return
	}
	grants := approvalGrants(r)
	if len(grants) == 0 {
		writeJSONError(w, http.StatusForbidden, "a package run was not authorized")
		return
	}
	requestedBy := s.operatorFromRequest(r)
	if requestedBy == "" {
		requestedBy = "operator"
	}
	runID := r.Header.Get(approvalHeader)
	jobs, err := s.dispatchPackageGrants(tenantID, requestedBy, runID, items, grants)
	for _, j := range jobs {
		s.audit(r, "SCRIPT_RUN_DISPATCHED", j.JobID, fmt.Sprintf("Dispatched package %s v%d to %s authorized by the response authority", j.Package, j.Version, j.EndpointID))
	}
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, fmt.Sprintf("created %d of %d jobs: %v", len(jobs), len(grants), err))
		return
	}
	writeJSON(w, http.StatusCreated, map[string]interface{}{"run_id": runID, "jobs": jobs})
}
