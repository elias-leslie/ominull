package server

// Owner decisions: what a package run could not settle by itself (a program
// whose uninstaller needs someone at the screen, one left open) comes back as
// detail.needs_owner items: {"id","name","reason","keep"}. The hub groups the
// open ones per run (a playbook run, or one package's latest runs) into one
// Nightshift feed record each, and the owner answers from the Maintenance page
// or POST /api/v1/maintenance/decisions:
//
//   keep:    leave it on that machine. When the item names a list setting
//            ("keep"), its id is added to that machine's override of the
//            setting, with the owner's reason, so later runs skip it.
//   handled: the owner dealt with it (removed it by hand, or does not care).
//
// Answers are a settings row; an answered item opens again only when a run
// that finished after the answer reports it again.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode"

	"ominull/hub/pkg/scripts"
)

const (
	decisionsSetting    = "maintenance.decisions"
	decisionsKept       = 500                // answers remembered
	decisionResolvedFor = 7 * 24 * time.Hour // a fully answered run stays in the feed as resolved this long
	ownerItemsMax       = 40                 // items read from one run
)

// ownerItem is one needs_owner entry from a package result.
type ownerItem struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Reason string `json:"reason"`
	Keep   string `json:"keep,omitempty"` // list setting a keep answer adds ID to
}

var ownerParamRe = regexp.MustCompile(`^[a-z][a-z0-9_]{0,39}$`)

// ownerText keeps an endpoint-supplied string printable and short.
func ownerText(v string, max int) string {
	v = strings.TrimSpace(strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return ' '
		}
		return r
	}, v))
	if r := []rune(v); len(r) > max {
		v = string(r[:max])
	}
	return v
}

// cleanOwnerItems reads a needs_owner list leniently: entries that are not
// objects with an id or name are dropped, text is cut short.
func cleanOwnerItems(raw json.RawMessage) []ownerItem {
	if len(raw) == 0 {
		return nil
	}
	var list []json.RawMessage
	if json.Unmarshal(raw, &list) != nil {
		return nil
	}
	var out []ownerItem
	for _, e := range list {
		var it ownerItem
		if json.Unmarshal(e, &it) != nil {
			continue
		}
		it.ID, it.Name, it.Reason = ownerText(it.ID, 128), ownerText(it.Name, 160), ownerText(it.Reason, 200)
		if it.ID == "" {
			it.ID = it.Name
		}
		if it.ID == "" {
			continue
		}
		if !ownerParamRe.MatchString(it.Keep) {
			it.Keep = ""
		}
		out = append(out, it)
		if len(out) == ownerItemsMax {
			break
		}
	}
	return out
}

// ownerDecision is one open item, or one answered (Answer set).
type ownerDecision struct {
	Key        string    `json:"key"`
	Group      string    `json:"group"`       // playbook:<run id> or package:<name>
	GroupTitle string    `json:"group_title"` // what the owner sees
	Tenant     string    `json:"tenant"`
	EndpointID string    `json:"endpoint_id"`
	Endpoint   string    `json:"endpoint"`
	Package    string    `json:"package"`
	Item       ownerItem `json:"item"`
	JobID      string    `json:"job_id,omitempty"`
	Seen       time.Time `json:"seen"`              // when the run that reported it finished
	Answers    []string  `json:"answers,omitempty"` // what the owner may answer
	Answer     string    `json:"answer,omitempty"`
	Reason     string    `json:"reason,omitempty"`
	By         string    `json:"by,omitempty"`
	At         time.Time `json:"at,omitempty"`
}

func decisionKey(tenant, ep, pkg, id string) string {
	sum := sha256.Sum256([]byte(tenant + "\x00" + ep + "\x00" + pkg + "\x00" + id))
	return hex.EncodeToString(sum[:12])
}

func (s *Server) decisionAnswers() map[string]ownerDecision {
	out := map[string]ownerDecision{}
	if raw, err := s.store.GetSetting(decisionsSetting); err == nil && raw != "" {
		_ = json.Unmarshal([]byte(raw), &out)
	}
	return out
}

func (s *Server) saveDecisionAnswers(m map[string]ownerDecision) error {
	if len(m) > decisionsKept {
		list := make([]ownerDecision, 0, len(m))
		for _, d := range m {
			list = append(list, d)
		}
		sort.Slice(list, func(i, j int) bool { return list[i].At.After(list[j].At) })
		m = map[string]ownerDecision{}
		for _, d := range list[:decisionsKept] {
			m[d.Key] = d
		}
	}
	raw, err := json.Marshal(m)
	if err != nil {
		return err
	}
	return s.store.SetSetting(decisionsSetting, string(raw))
}

// playbookJobs maps a job to the playbook run that started it.
func (s *Server) playbookJobs() map[string]*playbookRun {
	playbookMu.Lock()
	defer playbookMu.Unlock()
	out := map[string]*playbookRun{}
	for _, r := range s.playbookRuns() {
		for _, steps := range r.Hosts {
			for _, st := range steps {
				if st.JobID != "" {
					out[st.JobID] = r
				}
			}
		}
	}
	return out
}

// openDecisions lists every item the latest package runs left for the owner
// that has no answer newer than the run.
func (s *Server) openDecisions(now time.Time) ([]ownerDecision, error) {
	if s.scriptsStore == nil || s.responseStore == nil {
		return nil, nil
	}
	eps, err := s.store.ListEndpoints("")
	if err != nil {
		return nil, err
	}
	answers := s.decisionAnswers()
	byJob := s.playbookJobs()
	libraries := map[string][]*scripts.Script{}
	var out []ownerDecision
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
		for _, sc := range list {
			job := latest[sc.ID]
			m := sc.Package()
			if m == nil || job == nil {
				continue
			}
			run := derivePackageRun(job, now)
			if len(run.NeedsOwner) == 0 || run.CompletedAt == nil {
				continue
			}
			name := m.Package
			if name == "" {
				name = sc.Name
			}
			group, title := "package:"+name, name
			if r := byJob[job.ID]; r != nil {
				group, title = "playbook:"+r.ID, "Playbook "+r.Name
			}
			for _, it := range run.NeedsOwner {
				k := decisionKey(ep.TenantID, ep.ID, name, it.ID)
				if a, ok := answers[k]; ok && !a.At.Before(*run.CompletedAt) {
					continue
				}
				d := ownerDecision{Key: k, Group: group, GroupTitle: title, Tenant: ep.TenantID, EndpointID: ep.ID, Endpoint: ep.Hostname,
					Package: name, Item: it, JobID: job.ID, Seen: *run.CompletedAt, Answers: []string{"handled"}}
				if it.Keep != "" {
					d.Answers = []string{"keep", "handled"}
				}
				out = append(out, d)
			}
		}
	}
	hosts := map[string]string{}
	for _, ep := range eps {
		hosts[ep.ID] = ep.Hostname
	}
	out = append(out, s.escalatedDecisions(answers, hosts)...)
	sort.Slice(out, func(i, j int) bool {
		if out[i].Group != out[j].Group {
			return out[i].Group < out[j].Group
		}
		if out[i].Endpoint != out[j].Endpoint {
			return out[i].Endpoint < out[j].Endpoint
		}
		return out[i].Item.Name < out[j].Item.Name
	})
	return out, nil
}

// decisionFindings: one feed record per run with open items (medium: the
// board, no push), and a resolved one for a run answered in the last week.
func (s *Server) decisionFindings(now time.Time) ([]feedFinding, error) {
	open, err := s.openDecisions(now)
	if err != nil {
		return nil, err
	}
	type group struct {
		title string
		items []ownerDecision
		hosts map[string]bool
	}
	groups := map[string]*group{}
	var order []string
	for _, d := range open {
		g := groups[d.Group]
		if g == nil {
			g = &group{title: d.GroupTitle, hosts: map[string]bool{}}
			groups[d.Group] = g
			order = append(order, d.Group)
		}
		g.items = append(g.items, d)
		g.hosts[d.EndpointID] = true
	}
	var out []feedFinding
	for _, key := range order {
		g := groups[key]
		var res []feedResource
		var items []map[string]any
		for _, d := range g.items {
			items = append(items, map[string]any{"key": d.Key, "endpoint": d.Endpoint, "package": d.Package, "name": d.Item.Name,
				"reason": d.Item.Reason, "answers": d.Answers})
		}
		for ep := range g.hosts {
			res = append(res, feedResource{Type: "endpoint", UID: ep})
		}
		sort.Slice(res, func(i, j int) bool { return res[i].UID < res[j].UID })
		msg := fmt.Sprintf("%s: %s waiting for your decision on %s", g.title,
			plural(len(g.items), "item", "items"), plural(len(g.hosts), "machine", "machines"))
		out = append(out, s.feedFinding(now, decisionUID(key), "Maintenance decisions", ocsfSevMedium, ocsfStatusNew, msg, res,
			map[string]any{"run": key, "decisions": items, "answer_in": "OmniNull console"}))
	}
	resolved := map[string]string{}
	for _, a := range s.decisionAnswers() {
		if groups[a.Group] == nil && now.Sub(a.At) < decisionResolvedFor {
			resolved[a.Group] = a.GroupTitle
		}
	}
	keys := make([]string, 0, len(resolved))
	for k := range resolved {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		out = append(out, s.feedFinding(now, decisionUID(k), "Maintenance decisions", ocsfSevInformational, ocsfStatusResolved,
			resolved[k]+": every item answered", nil, map[string]any{"run": k}))
	}
	return out, nil
}

// decisionUID: ominull.decisions.<run>, with only feed-safe characters.
func decisionUID(group string) string {
	return "ominull.decisions." + strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' || r == '_' {
			return r
		}
		return '.'
	}, strings.ToLower(group))
}

type decisionAnswer struct {
	Key    string `json:"key"`
	Answer string `json:"answer"`
	Reason string `json:"reason"`
}

func (s *Server) handleDecisions(w http.ResponseWriter, r *http.Request) {
	now := time.Now().UTC()
	switch r.Method {
	case http.MethodGet:
		open, err := s.openDecisions(now)
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, err.Error())
			return
		}
		var answered []ownerDecision
		for _, a := range s.decisionAnswers() {
			answered = append(answered, a)
		}
		sort.Slice(answered, func(i, j int) bool { return answered[i].At.After(answered[j].At) })
		if len(answered) > 20 {
			answered = answered[:20]
		}
		if open == nil {
			open = []ownerDecision{}
		}
		writeJSON(w, http.StatusOK, map[string]any{"open": open, "answered": answered})
	case http.MethodPost:
		if r.Header.Get("X-Role") != "admin" {
			writeJSONError(w, http.StatusForbidden, "admin credential required to answer a maintenance decision")
			return
		}
		var a decisionAnswer
		dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8*1024))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&a); err != nil {
			writeJSONError(w, http.StatusBadRequest, "invalid json body: "+err.Error())
			return
		}
		d, status, err := s.answerDecision(r, a, now)
		if err != nil {
			writeJSONError(w, status, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"answered": d})
	default:
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (s *Server) answerDecision(r *http.Request, a decisionAnswer, now time.Time) (*ownerDecision, int, error) {
	a.Reason = ownerText(a.Reason, 200)
	if a.Answer != "keep" && a.Answer != "handled" {
		return nil, http.StatusBadRequest, errors.New("answer is keep or handled")
	}
	open, err := s.openDecisions(now)
	if err != nil {
		return nil, http.StatusInternalServerError, err
	}
	var d *ownerDecision
	for i := range open {
		if open[i].Key == a.Key {
			d = &open[i]
		}
	}
	if d == nil {
		return nil, http.StatusNotFound, errors.New("no open decision with that key (answered already, or a newer run settled it)")
	}
	if a.Answer == "keep" {
		if d.Item.Keep == "" {
			return nil, http.StatusBadRequest, fmt.Errorf("%s has no setting to keep %s with; answer handled", d.Package, d.Item.Name)
		}
		if a.Reason == "" {
			return nil, http.StatusBadRequest, errors.New("say why this machine keeps it (reason); it becomes the machine's override reason")
		}
		if err := s.keepOnMachine(d, a.Reason, s.operatorFromRequest(r)); err != nil {
			return nil, http.StatusConflict, err
		}
	}
	d.Answer, d.Reason, d.By, d.At = a.Answer, a.Reason, s.operatorFromRequest(r), now
	d.Answers = nil
	playbookMu.Lock() // answers and playbook runs share the settings table; keep writes in order
	answers := s.decisionAnswers()
	answers[d.Key] = *d
	err = s.saveDecisionAnswers(answers)
	playbookMu.Unlock()
	if err != nil {
		return nil, http.StatusInternalServerError, err
	}
	what := "handled"
	if a.Answer == "keep" {
		what = "kept on the machine (" + d.Item.Keep + " += " + d.Item.ID + ")"
	}
	s.audit(r, "MAINTENANCE_DECISION", d.Key, fmt.Sprintf("%s on %s, %s: %s; reason: %s", d.Item.Name, d.Endpoint, d.Package, what, a.Reason))
	return d, http.StatusOK, nil
}

// keepOnMachine adds the item to the machine's override of the package's list
// setting, keeping the rest of the override and saying why in its reason.
func (s *Server) keepOnMachine(d *ownerDecision, reason, by string) error {
	defs, err := s.packageDefs(d.Tenant)
	if err != nil {
		return err
	}
	var h *scripts.PackageHeader
	for _, def := range defs {
		if def.Header.Name == d.Package {
			h = def.Header
		}
	}
	if h == nil {
		return fmt.Errorf("package %s is no longer in the library", d.Package)
	}
	p := h.Param(d.Item.Keep)
	if p == nil || p.Type != "list" {
		return fmt.Errorf("%s has no list setting %q", d.Package, d.Item.Keep)
	}
	eff, err := s.maintenanceSettings(d.Tenant)
	if err != nil {
		return err
	}
	cur := scripts.SplitList(eff.Effective(h, d.EndpointID).Params[p.Name])
	for _, v := range cur {
		if strings.EqualFold(v, d.Item.ID) {
			return nil // already kept there
		}
	}
	next := scripts.JoinList(append(cur, d.Item.ID))
	if err := p.Check(next); err != nil {
		return fmt.Errorf("%s cannot keep %s: %v", d.Package, d.Item.ID, err)
	}
	all, err := s.maintenanceRows(d.Tenant)
	if err != nil {
		return err
	}
	row := scripts.PackageSetting{Package: h.Name, EndpointID: d.EndpointID}
	if r, ok := all[h.Name][d.EndpointID]; ok && !r.Expired(time.Now()) {
		row = r
	}
	params := map[string]string{}
	for k, v := range row.Params {
		params[k] = v
	}
	params[p.Name] = next
	row.Params = params
	note := "keeps " + d.Item.Name + ": " + reason
	if row.Reason != "" {
		note = row.Reason + "; " + note
	}
	if r := []rune(note); len(r) > 300 {
		note = string(r[len(r)-300:])
	}
	row.Reason, row.UpdatedBy = note, by
	return s.scriptsStore.PutSetting(d.Tenant, row)
}
