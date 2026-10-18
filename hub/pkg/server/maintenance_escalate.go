package server

// Escalation: a steward (or an operator) that cannot settle a run hands it to
// the owner. POST /api/v1/maintenance/escalate {"job_id","reason"} (admin)
// puts the run on the owner's decisions card, and in Nightshift's inbox, as
// one item (group job:<id>, answer handled). Answering it closes it like any
// decision; escalating the same job again replaces the reason.

import (
	"encoding/json"
	"errors"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	escalationsSetting = "maintenance.escalations"
	escalationsMax     = 50
)

var escalationsMu sync.Mutex

type escalation struct {
	JobID      string    `json:"job_id"`
	Tenant     string    `json:"tenant"`
	EndpointID string    `json:"endpoint_id"`
	Package    string    `json:"package"`
	Reason     string    `json:"reason"`
	By         string    `json:"by"`
	At         time.Time `json:"at"`
}

func (s *Server) escalations() map[string]escalation {
	out := map[string]escalation{}
	if raw, err := s.store.GetSetting(escalationsSetting); err == nil && raw != "" {
		_ = json.Unmarshal([]byte(raw), &out)
	}
	return out
}

// escalatedDecisions are the open escalations as owner decisions.
func (s *Server) escalatedDecisions(answers map[string]ownerDecision, hosts map[string]string) []ownerDecision {
	var out []ownerDecision
	for _, e := range s.escalations() {
		k := decisionKey(e.Tenant, e.EndpointID, "job:"+e.JobID, e.JobID)
		if a, ok := answers[k]; ok && !a.At.Before(e.At) {
			continue
		}
		host := hosts[e.EndpointID]
		if host == "" {
			host = e.EndpointID
		}
		out = append(out, ownerDecision{Key: k, Group: "job:" + e.JobID, GroupTitle: "Escalated run: " + e.Package + " on " + host,
			Tenant: e.Tenant, EndpointID: e.EndpointID, Endpoint: host, Package: e.Package,
			Item:  ownerItem{ID: e.JobID, Name: e.Package + " (run " + e.JobID + ")", Reason: e.Reason + " (escalated by " + e.By + ")"},
			JobID: e.JobID, Seen: e.At, Answers: []string{"handled"}})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Seen.Before(out[j].Seen) })
	return out
}

func (s *Server) handleMaintenanceEscalate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if r.Header.Get("X-Role") != "admin" {
		writeJSONError(w, http.StatusForbidden, "admin credential required to escalate a run")
		return
	}
	var req struct {
		JobID  string `json:"job_id"`
		Reason string `json:"reason"`
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8*1024))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid json body: "+err.Error())
		return
	}
	req.JobID, req.Reason = strings.TrimSpace(req.JobID), ownerText(req.Reason, 200)
	if req.JobID == "" || req.Reason == "" {
		writeJSONError(w, http.StatusBadRequest, "job_id and reason are required: say what the owner needs to do")
		return
	}
	e, status, err := s.escalate(req.JobID, req.Reason, s.operatorFromRequest(r), time.Now().UTC())
	if err != nil {
		writeJSONError(w, status, err.Error())
		return
	}
	s.audit(r, "MAINTENANCE_ESCALATED", req.JobID, e.Package+" on "+e.EndpointID+": "+req.Reason)
	writeJSON(w, http.StatusOK, map[string]any{"escalated": e})
}

func (s *Server) escalate(jobID, reason, by string, now time.Time) (*escalation, int, error) {
	if s.responseStore == nil {
		return nil, http.StatusServiceUnavailable, errors.New("response engine not initialized")
	}
	job, err := s.responseStore.GetJob("", jobID)
	if err != nil || job == nil {
		job, err = s.responseStore.GetJob("default", jobID)
	}
	if err != nil || job == nil {
		return nil, http.StatusNotFound, errors.New("no such job")
	}
	p, ok := scriptJobPayload(job)
	if !ok {
		return nil, http.StatusBadRequest, errors.New("only a script or package run can be escalated")
	}
	name := p.ScriptID
	if s.scriptsStore != nil {
		if sc, err := s.scriptsStore.GetScript(job.TenantID, p.ScriptID); err == nil && sc != nil {
			name = sc.Name
			if m := sc.Package(); m != nil && m.Package != "" {
				name = m.Package
			}
		}
	}
	e := escalation{JobID: job.ID, Tenant: job.TenantID, EndpointID: job.EndpointID, Package: name, Reason: reason, By: by, At: now}
	escalationsMu.Lock()
	defer escalationsMu.Unlock()
	all := s.escalations()
	all[job.ID] = e
	if len(all) > escalationsMax {
		list := make([]escalation, 0, len(all))
		for _, v := range all {
			list = append(list, v)
		}
		sort.Slice(list, func(i, j int) bool { return list[i].At.After(list[j].At) })
		all = map[string]escalation{}
		for _, v := range list[:escalationsMax] {
			all[v.JobID] = v
		}
	}
	raw, _ := json.Marshal(all)
	if err := s.store.SetSetting(escalationsSetting, string(raw)); err != nil {
		return nil, http.StatusInternalServerError, err
	}
	return &e, http.StatusOK, nil
}
