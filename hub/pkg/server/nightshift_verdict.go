package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"ominull/hub/pkg/storage"
)

// Owner verdicts from Nightshift.
//
// Nightshift asks the owner about a paging alert it lists ("Was this you?").
// When the owner answers "That was me", Nightshift sends the alert ids here
// and the hub records the verdict the console's Confirm benign records, so the
// owner answers once. "Not me" sends nothing: the alert stays open here and
// Nightshift escalates it.
//
// The relay key carries it, like the approvals it already carries. With it the
// relay can confirm benign only what Nightshift asks about: an open, high or
// critical paging alert of the last 24 hours that the hub does not explain,
// never a held or older one, a threat-list or beacon match (those the owner
// closes in the console), or a malicious verdict. Each confirmation is
// audited with the ids.

const verdictMaxIDs = 2 * feedAlertMax

// consoleOnly are alerts a relayed answer never closes.
var consoleOnly = map[string]bool{"THREAT_INTEL_MATCH": true, "C2_BEACONING": true}

func (s *Server) handleRelayAlertVerdict(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var req struct {
		IDs []string `json:"ids"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "body must be {\"ids\": [...]}")
		return
	}
	if len(req.IDs) == 0 || len(req.IDs) > verdictMaxIDs {
		writeJSONError(w, http.StatusBadRequest, fmt.Sprintf("name 1 to %d alerts", verdictMaxIDs))
		return
	}
	open, err := s.store.NewOpenAlerts(time.Now().UTC().Add(-feedAnomalyWindow), feedAlertScan)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "the open alerts could not be read")
		return
	}
	tuning := s.store.GetDetectionTuning()
	listed := map[string]bool{}
	for _, a := range open {
		if (a.Severity == "HIGH" || a.Severity == "CRITICAL") && !consoleOnly[a.AnomalyType] && describeAlert(a, tuning).Expected == "" {
			listed[a.ID] = true
		}
	}
	var ids, skipped []string
	seen := map[string]bool{}
	for _, id := range req.IDs {
		id = strings.TrimSpace(id)
		if id == "" || seen[id] {
			continue
		}
		seen[id] = true
		if listed[id] {
			ids = append(ids, id)
		} else {
			skipped = append(skipped, id)
		}
	}
	n := 0
	if len(ids) > 0 {
		var closed storage.Dismissal
		n, closed, err = s.store.ResolveAnomalies("", ids, storage.Resolution{Reason: "Owner answered on Nightshift: that was me",
			By: "owner via Nightshift", Verdict: storage.VerdictBenign, Method: storage.MethodOperator})
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, "the verdict could not be saved")
			return
		}
		s.audit(r, "NIGHTSHIFT_OWNER_BENIGN", "anomalies", "Owner confirmed benign on Nightshift: "+strings.Join(ids, ", "))
		s.auditDismissal(r, findingsAcknowledgedAudit, "acknowledged", closed)
	}
	writeJSON(w, http.StatusOK, map[string]any{"confirmed": n, "skipped": skipped})
}
