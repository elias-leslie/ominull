package server

// Accepted risks: the owner decides a failing check is fine on one machine
// (e.g. no disk encryption on a kids' laptop) and the decision lives here, as
// data on that machine, not in anyone's memory. An accepted control reads
// "accepted" instead of "fail" in every view of a package run: the device
// page, the compliance counts, the score Nightshift builds from them, the
// drift that asks for a fix, and so nothing about it is recommended or asked.
// Un-accepting removes the row and the control reads as the agent reported it.
//
// Set with PUT /api/v1/maintenance/settings {"endpoint_id","accept_risk":
// "<control id>","accepted":true|false,"reason":"..."} (admin). The control
// does not need a result yet: a machine that is offline can be set now.

import (
	"net/http"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"encoding/json"

	"ominull/hub/pkg/scripts"
)

const (
	acceptedRisksSetting = "maintenance.accepted_risks"
	acceptedReasonMax    = 160
	acceptedPerEndpoint  = 40
)

var (
	acceptedRisksMu sync.Mutex
	controlIDRe     = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9 ._:*()\\/\-]{0,119}$`)
)

type acceptedRisk struct {
	Reason string    `json:"reason,omitempty"`
	By     string    `json:"by,omitempty"`
	At     time.Time `json:"at"`
}

// allAcceptedRisks: endpoint id -> control id -> decision.
func (s *Server) allAcceptedRisks() map[string]map[string]acceptedRisk {
	out := map[string]map[string]acceptedRisk{}
	if s.store == nil {
		return out
	}
	if raw, err := s.store.GetSetting(acceptedRisksSetting); err == nil && raw != "" {
		_ = json.Unmarshal([]byte(raw), &out)
	}
	return out
}

// applyAcceptedRisks turns the run's accepted failing controls into
// "accepted", recounts, and clears a drift that only they caused.
func applyAcceptedRisks(run *packageRun, accepted map[string]acceptedRisk) {
	if run == nil || len(accepted) == 0 || len(run.Controls) == 0 {
		return
	}
	cs := make([]scripts.Control, len(run.Controls))
	copy(cs, run.Controls)
	changed := false
	for i := range cs {
		if a, ok := accepted[cs[i].ID]; ok && cs[i].State == "fail" {
			cs[i].State = "accepted"
			cs[i].Accepted = &scripts.AcceptedNote{Reason: a.Reason, By: a.By, At: a.At}
			changed = true
		}
	}
	if !changed {
		return
	}
	run.Controls = cs
	run.Pass, run.Fail = scripts.Compliance(cs)
	if run.State == "drift" && run.Fail == 0 {
		run.State = "ok"
	}
}

// setAcceptedRisk accepts or un-accepts one control on one endpoint.
func (s *Server) setAcceptedRisk(endpointID, control string, accept bool, reason, by string, now time.Time) error {
	acceptedRisksMu.Lock()
	defer acceptedRisksMu.Unlock()
	all := s.allAcceptedRisks()
	if accept {
		if all[endpointID] == nil {
			all[endpointID] = map[string]acceptedRisk{}
		}
		all[endpointID][control] = acceptedRisk{Reason: reason, By: by, At: now.UTC()}
	} else if all[endpointID] != nil {
		delete(all[endpointID], control)
		if len(all[endpointID]) == 0 {
			delete(all, endpointID)
		}
	}
	raw := ""
	if len(all) > 0 {
		b, _ := json.Marshal(all)
		raw = string(b)
	}
	return s.store.SetSetting(acceptedRisksSetting, raw)
}

type acceptedRiskView struct {
	Control string `json:"control"`
	acceptedRisk
}

// acceptedRiskList is one endpoint's decisions for the settings answer.
func (s *Server) acceptedRiskList(endpointID string) []acceptedRiskView {
	out := []acceptedRiskView{}
	for c, a := range s.allAcceptedRisks()[endpointID] {
		out = append(out, acceptedRiskView{Control: c, acceptedRisk: a})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Control < out[j].Control })
	return out
}

// putAcceptedRisk handles the accept_risk form of a settings PUT.
func (s *Server) putAcceptedRisk(w http.ResponseWriter, r *http.Request, tenantID string, c settingsChange) {
	control := strings.TrimSpace(*c.AcceptRisk)
	switch {
	case c.EndpointID == "":
		writeJSONError(w, http.StatusBadRequest, "name the machine (endpoint_id) whose risk this is")
		return
	case !controlIDRe.MatchString(control):
		writeJSONError(w, http.StatusBadRequest, "accept_risk is the id of a check, like bitlocker")
		return
	case c.Accepted == nil:
		writeJSONError(w, http.StatusBadRequest, "say accepted: true to accept the risk or false to stop accepting it")
		return
	case c.Package != "" || c.Category != "":
		writeJSONError(w, http.StatusBadRequest, "an accepted risk is its own change; send it without a package or category")
		return
	}
	reason := ""
	if c.Reason != nil {
		reason = ownerText(*c.Reason, acceptedReasonMax)
	}
	if *c.Accepted && len(s.allAcceptedRisks()[c.EndpointID]) >= acceptedPerEndpoint {
		if _, again := s.allAcceptedRisks()[c.EndpointID][control]; !again {
			writeJSONError(w, http.StatusBadRequest, "this machine already has the most accepted risks allowed")
			return
		}
	}
	if err := s.setAcceptedRisk(c.EndpointID, control, *c.Accepted, reason, s.operatorFromRequest(r), time.Now()); err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if *c.Accepted {
		s.audit(r, "RISK_ACCEPTED", c.EndpointID, control+": "+reason)
	} else {
		s.audit(r, "RISK_ACCEPTANCE_REMOVED", c.EndpointID, control)
	}
	r.URL.RawQuery = "endpoint_id=" + c.EndpointID
	s.getMaintenanceSettings(w, r, tenantID)
}
