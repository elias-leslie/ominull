package server

// Posture: the control packs (hub/pkg/posture) scored from what is already
// here. A pack control's answer comes from a package's latest control result,
// from something the hub knows about itself, or from a person's confirmation;
// no result is stored apart from the run records and two settings rows (the
// packs when replaced on this hub, and the confirmations).
//
//	GET    /api/v1/posture[?endpoint_id=][&download=1]  the packs, scored, with the evidence
//	GET    /api/v1/posture/packs                        the packs in force
//	PUT    /api/v1/posture/packs                        replace them (admin, audited)
//	DELETE /api/v1/posture/packs                        back to the shipped ones (admin, audited)
//	POST   /api/v1/posture/attest                       confirm what the hub cannot see (admin, audited)
//	POST   /api/v1/maintenance/host-run                 record a run done over root access (admin, audited)

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"ominull/hub/pkg/posture"
	"ominull/hub/pkg/response"
	"ominull/hub/pkg/scripts"
	"ominull/hub/pkg/storage"
)

const (
	posturePacksSetting  = "posture.packs"
	postureAttestSetting = "posture.attestations"
	postureBodyMax       = 256 << 10
	attestNoteMax        = 300
	attestDaysMax        = 365
	postureFindingMax    = 10
)

// postureSettingsMu serializes changes to the two settings rows.
var postureSettingsMu sync.Mutex

// postureCatalog is the catalog in force and whether it was saved on this hub.
func (s *Server) postureCatalog() (posture.Catalog, bool) {
	if raw, err := s.store.GetSetting(posturePacksSetting); err == nil && raw != "" {
		var c posture.Catalog
		if err := json.Unmarshal([]byte(raw), &c); err == nil && c.Validate() == nil {
			return c, true
		}
		log.Printf("[!] Ignoring unreadable or invalid saved posture packs; using the shipped ones.")
	}
	c, err := posture.Seed()
	if err != nil {
		log.Printf("[!] The shipped posture packs are invalid: %v", err)
	}
	return c, false
}

// postureAttestation is someone's word on a control the hub cannot see. It
// lapses, so an old statement reads as unknown rather than as still true.
type postureAttestation struct {
	State   string    `json:"state"`
	Note    string    `json:"note"`
	By      string    `json:"by"`
	At      time.Time `json:"at"`
	Expires time.Time `json:"expires"`
}

func (s *Server) postureAttestations() map[string]postureAttestation {
	out := map[string]postureAttestation{}
	if raw, err := s.store.GetSetting(postureAttestSetting); err == nil && raw != "" {
		if json.Unmarshal([]byte(raw), &out) != nil {
			log.Printf("[!] Ignoring unreadable posture confirmations.")
			return map[string]postureAttestation{}
		}
	}
	return out
}

// postureResult is one answer: a machine's, or the whole hub's when EndpointID
// is empty. Key is what accepting the risk of a failing answer is set against.
type postureResult struct {
	EndpointID string     `json:"endpoint_id,omitempty"`
	Host       string     `json:"host,omitempty"`
	State      string     `json:"state"`
	Key        string     `json:"key,omitempty"`
	Expected   string     `json:"expected,omitempty"`
	Actual     string     `json:"actual,omitempty"`
	At         *time.Time `json:"at,omitempty"`
	Expires    *time.Time `json:"expires,omitempty"`
	JobID      string     `json:"job_id,omitempty"`
	By         string     `json:"by,omitempty"`
	Reason     string     `json:"reason,omitempty"` // why it was accepted
	Stale      bool       `json:"stale,omitempty"`
}

type postureControlView struct {
	ID       string             `json:"id"`
	Title    string             `json:"title"`
	Why      string             `json:"why,omitempty"`
	Severity string             `json:"severity"`
	Refs     []string           `json:"refs,omitempty"`
	From     []string           `json:"from,omitempty"`
	Fleet    bool               `json:"fleet,omitempty"`
	Attest   bool               `json:"attest,omitempty"`
	Score    posture.Score      `json:"score"`
	Results  []postureResult    `json:"results"`
	Evidence []posture.Evidence `json:"evidence"`
}

type posturePackView struct {
	ID            string               `json:"id"`
	Title         string               `json:"title"`
	SourceName    string               `json:"source_name,omitempty"`
	SourceVersion string               `json:"source_version,omitempty"`
	SourceURL     string               `json:"source_url,omitempty"`
	Score         posture.Score        `json:"score"`
	Controls      []postureControlView `json:"controls"`
}

type postureView struct {
	GeneratedAt time.Time         `json:"generated_at"`
	Saved       bool              `json:"saved"`
	StaleDays   int               `json:"stale_days"`
	Packs       []posturePackView `json:"packs"`
}

// postureEval holds what one report reads, so each machine's runs are read once.
type postureEval struct {
	s        *Server
	now      time.Time
	catalog  posture.Catalog
	accepted map[string]map[string]acceptedRisk
	attest   map[string]postureAttestation
	newest   map[string]string
	fleet    storage.AicoFleet
	cfg      storage.DetectionTuning
	scripts  map[string][]*scripts.Script
	latest   map[string]map[string]*response.JobRecord
	runs     map[string]*packageRun // endpoint|package
}

func endpointPlatform(ep storage.Endpoint) string {
	os := strings.ToLower(ep.OS)
	switch {
	case strings.Contains(os, "windows"):
		return "windows"
	case strings.Contains(os, "linux"):
		return "linux"
	}
	return ""
}

// packageRunFor is the machine's latest finished run of a package that reported
// controls, or nil.
func (e *postureEval) packageRunFor(ep storage.Endpoint, name string) (*packageRun, error) {
	key := ep.ID + "|" + name
	if run, ok := e.runs[key]; ok {
		return run, nil
	}
	tenant := tenantOr(ep.TenantID)
	list, ok := e.scripts[tenant]
	var err error
	if !ok {
		if list, err = e.s.scriptsStore.ListScripts(tenant); err != nil {
			return nil, err
		}
		e.scripts[tenant] = list
	}
	latest, ok := e.latest[ep.ID]
	if !ok {
		if latest, err = e.s.responseStore.LatestScriptJobs(tenant, ep.ID); err != nil {
			return nil, err
		}
		e.latest[ep.ID] = latest
	}
	var run *packageRun
	for _, sc := range list {
		if m := sc.Package(); m != nil && !sc.Retired && (sc.Name == name || m.Package == name) && latest[sc.ID] != nil {
			if run, err = e.s.latestControlsRun(ep, sc, latest[sc.ID], e.now, e.accepted[ep.ID]); err != nil {
				return nil, err
			}
			break
		}
	}
	e.runs[key] = run
	return run, nil
}

// packageResult reads one control out of the machine's latest run.
func (e *postureEval) packageResult(ep storage.Endpoint, ev posture.Evidence) (postureResult, error) {
	res := postureResult{State: posture.Unknown, Key: ev.Control}
	run, err := e.packageRunFor(ep, ev.Package)
	if err != nil || run == nil {
		res.Actual = "no result yet"
		return res, err
	}
	res.At, res.JobID = run.CompletedAt, run.JobID
	for _, c := range run.Controls {
		if c.ID != ev.Control {
			continue
		}
		res.Expected, res.Actual = c.Expected, c.Actual
		switch c.State {
		case "pass", "fixed":
			res.State = posture.Pass
		case "fail":
			res.State = posture.Fail
		case "accepted":
			res.State = posture.Accepted
			if c.Accepted != nil {
				res.Reason = c.Accepted.Reason
			}
		case "na":
			res.State = posture.NA
		}
		return res, nil
	}
	res.Actual = "the latest run did not report this"
	return res, nil
}

// reportingResult: is the agent reporting when it should be.
func (e *postureEval) reportingResult(ep storage.Endpoint) postureResult {
	allowance, age, watched := agentWatch(ep, e.now, e.newest, e.fleet, e.cfg)
	res := postureResult{Expected: "reporting, or off on purpose", State: posture.Pass, Actual: "reporting"}
	seen := ep.LastSeenAt
	res.At = &seen
	switch {
	case !watched:
		res.State, res.Actual = posture.NA, "off on purpose, so not watched"
	case age >= allowance:
		res.State, res.Actual = posture.Fail, "quiet for "+quietWords(age)
	}
	return res
}

func quietWords(d time.Duration) string {
	if d >= 48*time.Hour {
		return fmt.Sprintf("%d days", int(d.Hours()/24))
	}
	if d >= time.Hour {
		return fmt.Sprintf("%d hours", int(d.Hours()))
	}
	return fmt.Sprintf("%d minutes", int(d.Minutes()))
}

// isolationResult: could the console cut this machine off, from what its agent
// last said about its keys, its profile and any lock set on the machine.
func (e *postureEval) isolationResult(ep storage.Endpoint) postureResult {
	res := postureResult{Expected: "keys pinned and isolation allowed", State: posture.Unknown, Actual: "the agent has not reported since the hub started"}
	srv := e.s
	srv.trust.mu.Lock()
	srv.trust.init()
	seen, ok := srv.trust.reports[ep.ID]
	srv.trust.mu.Unlock()
	if !ok {
		return res
	}
	at := seen.at
	res.At = &at
	rep := seen.report
	caps, _ := response.ProfileCaps(rep.Profile)
	switch {
	case !ceilingAllowsIsolation(rep.Ceiling):
		res.State, res.Actual = posture.NA, "locked on the machine to "+rep.Ceiling+", so it is never isolated"
	case ep.MonitorOnly:
		res.State, res.Actual = posture.NA, "monitor only on purpose: "+ep.MonitorOnlyReason()
	case rep.Keys != "pinned":
		res.State, res.Actual = posture.Fail, "keys "+rep.Keys
	case !slices.Contains(caps, response.CapIsolate):
		res.State, res.Actual = posture.Fail, "profile "+rep.Profile+" has no isolation"
	default:
		res.State, res.Actual = posture.Pass, "keys pinned, profile "+rep.Profile
	}
	return res
}

// ceilingAllowsIsolation mirrors Trust_CeilingHas on the agent: no lock, or a
// level that holds isolation. Anything else, unknown levels too, reads as a lock.
func ceilingAllowsIsolation(ceiling string) bool {
	switch ceiling {
	case "", "engagement", "respond", "isolate", "signed-scripts":
		return true
	}
	return false
}

// baselineResult: has every package the packs read for this platform reported
// lately. The oldest one decides, and one that never ran is never checked. A
// machine off on purpose or offline cannot answer, so an old answer is not a
// failure of its own.
func (e *postureEval) baselineResult(ep storage.Endpoint, ev posture.Evidence) (postureResult, error) {
	maxAge := ev.Params["max_age_days"]
	res := postureResult{Expected: fmt.Sprintf("every check run in the last %d days", maxAge)}
	platform := endpointPlatform(ep)
	if platform == "" {
		res.State, res.Actual = posture.Unknown, "the agent has not said which system it runs"
		return res, nil
	}
	var oldest *packageRun
	var never []string
	seen := map[string]bool{}
	for _, p := range e.catalog.Packs {
		for _, c := range p.Controls {
			evi, ok := c.EvidenceFor(platform)
			if !ok || evi.Package == "" || seen[evi.Package] {
				continue
			}
			seen[evi.Package] = true
			run, err := e.packageRunFor(ep, evi.Package)
			if err != nil {
				return res, err
			}
			switch {
			case run == nil || run.CompletedAt == nil:
				never = append(never, evi.Package)
			case oldest == nil || run.CompletedAt.Before(*oldest.CompletedAt):
				oldest = run
			}
		}
	}
	if oldest != nil {
		res.At, res.JobID = oldest.CompletedAt, oldest.JobID
	}
	days := -1
	if oldest != nil {
		days = int(e.now.Sub(*oldest.CompletedAt).Hours() / 24)
	}
	stale := len(never) > 0 || days >= maxAge
	switch {
	case len(never) > 0:
		slices.Sort(never)
		res.Actual = "never ran: " + strings.Join(never, ", ")
	case oldest == nil:
		res.State, res.Actual = posture.NA, "no check here applies to this machine"
		return res, nil
	default:
		res.Actual = fmt.Sprintf("oldest check is %d days old", days)
	}
	if !stale {
		res.State = posture.Pass
		return res, nil
	}
	_, _, watched := agentWatch(ep, e.now, e.newest, e.fleet, e.cfg)
	switch {
	case !watched:
		res.State = posture.NA
		res.Actual += "; off on purpose"
	case e.now.Sub(ep.LastSeenAt) >= endpointOnline:
		res.State = posture.Unknown
		res.Actual += "; offline"
	default:
		res.State = posture.Fail
	}
	return res, nil
}

func (e *postureEval) retentionResult(ev posture.Evidence) postureResult {
	res := postureResult{State: posture.Unknown, Actual: "the retention sweep has not started",
		Expected: fmt.Sprintf("alerts %d days, flow rollups %d days, audit %d days", ev.Params["alerts_days"], ev.Params["flows_days"], ev.Params["audit_days"])}
	p := e.s.store.RetentionInForce()
	if p == nil {
		return res
	}
	words := func(d time.Duration) string {
		if d <= 0 {
			return "kept forever"
		}
		return fmt.Sprintf("%d days", int(d.Hours()/24))
	}
	short := func(d time.Duration, wantDays int) bool { return d > 0 && int(d.Hours()/24) < wantDays }
	res.Actual = fmt.Sprintf("alerts %s, flow rollups %s, audit %s", words(p.AnomalyAlerts), words(p.FlowRollups), words(p.AuditLogs))
	res.State = posture.Pass
	if short(p.AnomalyAlerts, ev.Params["alerts_days"]) || short(p.FlowRollups, ev.Params["flows_days"]) || short(p.AuditLogs, ev.Params["audit_days"]) {
		res.State = posture.Fail
	}
	return res
}

func (e *postureEval) drillResult(ev posture.Evidence) postureResult {
	maxAge := ev.Params["max_age_days"]
	res := postureResult{Expected: fmt.Sprintf("every floor case raised, in the last %d days", maxAge), State: posture.Fail, Actual: "never ran"}
	rec, ok := e.s.lastFloorDrill()
	if !ok {
		return res
	}
	at := rec.RanAt
	res.At = &at
	switch {
	case len(rec.Missed) > 0:
		res.Actual = fmt.Sprintf("missed %d of %d cases", len(rec.Missed), rec.Cases)
	case int(e.now.Sub(rec.RanAt).Hours()/24) >= maxAge:
		res.Actual = fmt.Sprintf("last ran %s ago", quietWords(e.now.Sub(rec.RanAt)))
	default:
		res.State, res.Actual = posture.Pass, fmt.Sprintf("all %d cases raised", rec.Cases)
	}
	return res
}

func (e *postureEval) attestResult(id string) postureResult {
	res := postureResult{State: posture.Unknown, Actual: "nobody has confirmed this"}
	a, ok := e.attest[id]
	if !ok {
		return res
	}
	at := a.At
	res.At, res.By = &at, a.By
	if !e.now.Before(a.Expires) {
		res.Actual = "the last confirmation lapsed: " + a.Note
		return res
	}
	expires := a.Expires
	res.State, res.Actual, res.Expires = a.State, a.Note, &expires
	return res
}

// endpointResult answers a per-machine control. ok is false when no evidence
// fits this machine's platform: the control does not apply here at all.
func (e *postureEval) endpointResult(ep storage.Endpoint, c posture.Control) (postureResult, bool, error) {
	// An unrecognized OS still gets the answers that fit every platform.
	ev, ok := c.EvidenceFor(endpointPlatform(ep))
	if !ok {
		return postureResult{}, false, nil
	}
	var res postureResult
	var err error
	switch ev.Hub {
	case "":
		res, err = e.packageResult(ep, ev)
	case posture.HubAgentReporting:
		res = e.reportingResult(ep)
	case posture.HubIsolationReady:
		res = e.isolationResult(ep)
	case posture.HubBaselineRecent:
		res, err = e.baselineResult(ep, ev)
	}
	if err != nil {
		return res, false, err
	}
	if ev.Hub != "" {
		res.Key = "hub." + ev.Hub
		if a, ok := e.accepted[ep.ID][res.Key]; ok && res.State == posture.Fail {
			res.State, res.Reason = posture.Accepted, a.Reason
		}
	}
	res.EndpointID, res.Host = ep.ID, ep.Hostname
	if res.At != nil && e.catalog.StaleDays > 0 && e.now.Sub(*res.At) >= time.Duration(e.catalog.StaleDays)*24*time.Hour {
		res.Stale = true
	}
	return res, true, nil
}

func (e *postureEval) fleetResult(c posture.Control) postureResult {
	ev := c.Evidence[0]
	switch ev.Hub {
	case posture.HubEvidenceRetention:
		return e.retentionResult(ev)
	case posture.HubFloorDrill:
		return e.drillResult(ev)
	}
	return e.attestResult(c.ID)
}

// postureReport scores every pack, for one machine when endpointID is set.
func (s *Server) postureReport(tenant, endpointID string, now time.Time) (postureView, error) {
	catalog, saved := s.postureCatalog()
	view := postureView{GeneratedAt: now, Saved: saved, StaleDays: catalog.StaleDays, Packs: []posturePackView{}}
	eps, err := s.store.ListEndpoints(tenant)
	if err != nil {
		return view, err
	}
	fleet, _ := s.store.AicoFleet()
	e := &postureEval{s: s, now: now, catalog: catalog, accepted: s.allAcceptedRisks(), attest: s.postureAttestations(),
		newest: storage.NewestEndpoints(eps), fleet: fleet, cfg: s.store.GetDetectionTuning(),
		scripts: map[string][]*scripts.Script{}, latest: map[string]map[string]*response.JobRecord{}, runs: map[string]*packageRun{}}
	active := eps[:0:0]
	for _, ep := range eps {
		if ep.Status != "retired" && (endpointID == "" || ep.ID == endpointID) {
			active = append(active, ep)
		}
	}
	for _, p := range catalog.Packs {
		pv := posturePackView{ID: p.ID, Title: p.Title, SourceName: p.SourceName, SourceVersion: p.SourceVersion, SourceURL: p.SourceURL, Controls: []postureControlView{}}
		for _, c := range p.Controls {
			cv := postureControlView{ID: c.ID, Title: c.Title, Why: c.Why, Severity: c.Severity, Refs: c.Refs, From: c.From,
				Fleet: c.Fleet(), Evidence: c.Evidence, Results: []postureResult{}}
			cv.Attest = c.Evidence[0].Attest
			if cv.Fleet {
				if endpointID != "" {
					continue // one machine's view holds only that machine's answers
				}
				cv.Results = append(cv.Results, e.fleetResult(c))
			} else {
				for _, ep := range active {
					res, ok, err := e.endpointResult(ep, c)
					if err != nil {
						return view, err
					}
					if ok {
						cv.Results = append(cv.Results, res)
					}
				}
			}
			if len(cv.Results) == 0 {
				continue // nothing here this control applies to
			}
			for _, r := range cv.Results {
				cv.Score.Add(r.State, c.Severity)
				pv.Score.Add(r.State, c.Severity)
			}
			pv.Controls = append(pv.Controls, cv)
		}
		if len(pv.Controls) > 0 {
			view.Packs = append(view.Packs, pv)
		}
	}
	return view, nil
}

// postureFinding: one Status row. It stays a note unless a critical control
// fails somewhere; even then it never pages.
func (s *Server) postureFinding(now time.Time) (feedFinding, error) {
	const uid, title = "ominull.posture", "Security posture"
	sev, status := ocsfSevInformational, ocsfStatusResolved
	if s.scriptsStore == nil || s.responseStore == nil {
		return s.feedFinding(now, uid, title, sev, status, "Posture is not available on this hub", nil, nil), nil
	}
	view, err := s.postureReport("", "", now)
	if err != nil {
		return feedFinding{}, err
	}
	var parts, critical []string
	packs := map[string]any{}
	for _, p := range view.Packs {
		word := p.Title + " no answers yet"
		if p.Score.Percent != nil {
			word = fmt.Sprintf("%s %d%%", p.Title, *p.Score.Percent)
		}
		parts = append(parts, word)
		packs[p.ID] = map[string]any{"percent": p.Score.Percent, "fail": p.Score.Fail, "unknown": p.Score.Unknown}
		for _, c := range p.Controls {
			if c.Severity != "critical" {
				continue
			}
			for _, r := range c.Results {
				name := c.Title
				if r.Host != "" {
					name += " on " + r.Host
				}
				if r.State == posture.Fail && !slices.Contains(critical, name) {
					critical = append(critical, name)
				}
			}
		}
	}
	msg := strings.Join(parts, ", ")
	if len(critical) > 0 {
		sev, status = ocsfSevMedium, ocsfStatusNew
		msg = plural(len(critical), "critical control fails", "critical controls fail") + ": " + strings.Join(critical[:min(3, len(critical))], "; ") + ". " + msg
	}
	if len(critical) > postureFindingMax {
		critical = critical[:postureFindingMax]
	}
	return s.feedFinding(now, uid, title, sev, status, msg, nil, map[string]any{"packs": packs, "critical": critical}), nil
}

func (s *Server) handlePosture(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if s.scriptsStore == nil || s.responseStore == nil {
		writeJSONError(w, http.StatusServiceUnavailable, "scripts or response engine not initialized")
		return
	}
	// The report lists every machine's weak points; the tenant key ships on every endpoint.
	if r.Header.Get("X-Role") == "tenant" {
		writeJSONError(w, http.StatusForbidden, "posture is not available to this credential")
		return
	}
	now := time.Now().UTC()
	view, err := s.postureReport(s.tenantFromRequest(r), r.URL.Query().Get("endpoint_id"), now)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "failed to read posture: "+err.Error())
		return
	}
	if r.URL.Query().Get("download") == "1" {
		w.Header().Set("Content-Disposition", `attachment; filename="ominull-posture-`+now.Format("20060102")+`.json"`)
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, view)
}

func (s *Server) handlePosturePacks(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("X-Role") == "tenant" {
		writeJSONError(w, http.StatusForbidden, "posture is not available to this credential")
		return
	}
	switch r.Method {
	case http.MethodGet:
		c, saved := s.postureCatalog()
		writeJSON(w, http.StatusOK, map[string]any{"catalog": c, "saved": saved})
		return
	case http.MethodPut, http.MethodDelete:
	default:
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if r.Header.Get("X-Role") != "admin" {
		writeJSONError(w, http.StatusForbidden, "admin credential required to change the posture packs")
		return
	}
	postureSettingsMu.Lock()
	defer postureSettingsMu.Unlock()
	if r.Method == http.MethodDelete {
		if err := s.store.SetSetting(posturePacksSetting, ""); err != nil {
			writeJSONError(w, http.StatusInternalServerError, "failed to save: "+err.Error())
			return
		}
		s.audit(r, "POSTURE_PACKS_CHANGED", "posture:packs", "back to the shipped packs; credential "+credentialOf(r)+" (unverified)")
		c, _ := s.postureCatalog()
		writeJSON(w, http.StatusOK, map[string]any{"catalog": c, "saved": false})
		return
	}
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, postureBodyMax))
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "body too large or unreadable")
		return
	}
	var c posture.Catalog
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		writeJSONError(w, http.StatusBadRequest, "not a posture catalog: "+err.Error())
		return
	}
	if err := c.Validate(); err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	saved, _ := json.Marshal(c)
	if err := s.store.SetSetting(posturePacksSetting, string(saved)); err != nil {
		writeJSONError(w, http.StatusInternalServerError, "failed to save: "+err.Error())
		return
	}
	s.audit(r, "POSTURE_PACKS_CHANGED", "posture:packs", fmt.Sprintf("replaced with %d packs; credential %s (unverified)", len(c.Packs), credentialOf(r)))
	writeJSON(w, http.StatusOK, map[string]any{"catalog": c, "saved": true})
}

// handlePostureAttest records someone's word on a control the hub cannot see.
// {"control","state":"pass"|"fail"|"clear","note","days"}
func (s *Server) handlePostureAttest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var req struct {
		Control string `json:"control"`
		State   string `json:"state"`
		Note    string `json:"note"`
		Days    int    `json:"days"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid body")
		return
	}
	catalog, _ := s.postureCatalog()
	c := catalog.Find(req.Control)
	if c == nil || !c.Evidence[0].Attest {
		writeJSONError(w, http.StatusNotFound, "no control "+req.Control+" that takes a confirmation")
		return
	}
	req.Note = strings.TrimSpace(req.Note)
	if req.State != "clear" {
		if req.State != posture.Pass && req.State != posture.Fail {
			writeJSONError(w, http.StatusBadRequest, "state must be pass, fail or clear")
			return
		}
		if req.Note == "" || len(req.Note) > attestNoteMax {
			writeJSONError(w, http.StatusBadRequest, fmt.Sprintf("say what shows it, in at most %d characters", attestNoteMax))
			return
		}
		if req.Days < 1 || req.Days > attestDaysMax {
			writeJSONError(w, http.StatusBadRequest, fmt.Sprintf("days must be from 1 to %d", attestDaysMax))
			return
		}
	}
	postureSettingsMu.Lock()
	defer postureSettingsMu.Unlock()
	all := s.postureAttestations()
	now := time.Now().UTC()
	by := r.Header.Get("X-Username")
	if req.State == "clear" {
		delete(all, req.Control)
	} else {
		all[req.Control] = postureAttestation{State: req.State, Note: req.Note, By: by, At: now, Expires: now.AddDate(0, 0, req.Days)}
	}
	raw, _ := json.Marshal(all)
	if err := s.store.SetSetting(postureAttestSetting, string(raw)); err != nil {
		writeJSONError(w, http.StatusInternalServerError, "failed to save: "+err.Error())
		return
	}
	s.audit(r, "POSTURE_ATTESTED", "posture:"+req.Control, fmt.Sprintf("%s for %d days: %s; credential %s (unverified)", req.State, req.Days, req.Note, credentialOf(r)))
	writeJSON(w, http.StatusOK, map[string]any{"control": req.Control, "state": req.State})
}

// handleHostRun records a package run done over root access on a machine that
// takes no hub-signed scripts, as an ordinary finished job. The source must be
// a version in this hub's library, so the record says exactly what ran.
// {"endpoint_id","package","sha256","mode","stdout","exit_code"}
func (s *Server) handleHostRun(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if s.scriptsStore == nil || s.responseStore == nil {
		writeJSONError(w, http.StatusServiceUnavailable, "scripts or response engine not initialized")
		return
	}
	var req struct {
		EndpointID string `json:"endpoint_id"`
		Package    string `json:"package"`
		SHA256     string `json:"sha256"`
		Mode       string `json:"mode"`
		Stdout     string `json:"stdout"`
		ExitCode   int    `json:"exit_code"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, packageMaxOutput+4096)).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid body")
		return
	}
	ep, err := s.store.GetEndpoint(req.EndpointID)
	if err != nil || ep == nil || ep.Status == "retired" {
		writeJSONError(w, http.StatusNotFound, "endpoint not found")
		return
	}
	tenant := tenantOr(ep.TenantID)
	if t := s.tenantFromRequest(r); t != "" && t != tenant {
		writeJSONError(w, http.StatusNotFound, "endpoint not found")
		return
	}
	sc, err := s.findPackage(tenant, req.Package)
	if err != nil || sc == nil {
		writeJSONError(w, http.StatusNotFound, "no package "+req.Package+" in the library; sync it first")
		return
	}
	version, err := s.scriptsStore.GetScriptVersion(tenant, sc.ID, sc.LatestVersion)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "failed to read the package")
		return
	}
	header, err := scripts.ParsePackageHeader(version.Source)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "package has no readable header")
		return
	}
	if !header.RunsOn(ep.OS) {
		writeJSONError(w, http.StatusBadRequest, req.Package+" does not run on "+ep.OS)
		return
	}
	if req.Mode != "audit" {
		writeJSONError(w, http.StatusBadRequest, "only audit runs are recorded this way")
		return
	}
	if version.DigestSHA256 != strings.ToLower(req.SHA256) {
		writeJSONError(w, http.StatusConflict, "this is not the library's current "+req.Package+"; sync the library or run the current one")
		return
	}
	payload, err := json.Marshal(response.ScriptExecPayload{
		ScriptID: sc.ID, ScriptVersion: version.Version, ScriptDigest: version.DigestSHA256, Interpreter: sc.Interpreter,
		Parameters: map[string]string{"mode": req.Mode}, TimeoutSeconds: scripts.ClampTimeout(header.Timeout), MaxOutputBytes: packageMaxOutput,
	})
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "failed to record the run")
		return
	}
	who := r.Header.Get("X-Username")
	job, err := s.responseStore.RecordFinishedScriptJob(tenant, ep.ID, "root access: "+who, string(payload), &response.JobResult{Stdout: req.Stdout, ExitCode: req.ExitCode})
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "failed to record the run: "+err.Error())
		return
	}
	s.audit(r, "MAINTENANCE_HOST_RUN", "endpoint:"+ep.ID, fmt.Sprintf("%s (%s) v%d, exit %d, job %s; credential %s (unverified)", req.Package, req.Mode, version.Version, req.ExitCode, job.ID, credentialOf(r)))
	writeJSON(w, http.StatusOK, derivePackageRun(job, time.Now().UTC()))
}
