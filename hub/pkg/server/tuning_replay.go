package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"ominull/hub/pkg/detector"
	"ominull/hub/pkg/storage"
)

const (
	replayDefaultSpan  = 7 * 24 * time.Hour
	replayMaxSpan      = 92 * 24 * time.Hour
	replayTopSignature = 100
	resolveMaxIDs      = 10000
)

// replayWindow reads from/to (a date or an RFC 3339 time) with a default of
// the last `def` and a ceiling of replayMaxSpan.
func replayWindow(from, to string, def time.Duration) (time.Time, time.Time, error) {
	parse := func(v string) (time.Time, error) {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			return t.UTC(), nil
		}
		return time.Parse("2006-01-02", v)
	}
	end := time.Now().UTC()
	if to != "" {
		t, err := parse(to)
		if err != nil {
			return time.Time{}, time.Time{}, fmt.Errorf("to: %v", err)
		}
		end = t
	}
	start := end.Add(-def)
	if from != "" {
		t, err := parse(from)
		if err != nil {
			return time.Time{}, time.Time{}, fmt.Errorf("from: %v", err)
		}
		start = t
	}
	if !start.Before(end) {
		return time.Time{}, time.Time{}, errors.New("from must be before to")
	}
	if end.Sub(start) > replayMaxSpan {
		return time.Time{}, time.Time{}, fmt.Errorf("window is longer than %d days", int(replayMaxSpan.Hours()/24))
	}
	return start, end, nil
}

// handleTuningReplay answers "what would this tuning have raised?" from the
// findings already recorded. GET judges the saved tuning; POST {"tuning": ...}
// judges a draft without saving it, so an exclusion can be argued with numbers
// before it exists.
func (s *Server) handleTuningReplay(w http.ResponseWriter, r *http.Request) {
	tuning := s.store.GetDetectionTuning()
	switch r.Method {
	case http.MethodGet:
	case http.MethodPost:
		var req struct {
			Tuning *storage.DetectionTuning `json:"tuning"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
			writeJSONError(w, http.StatusBadRequest, err.Error())
			return
		}
		if req.Tuning != nil {
			draft, err := storage.PrepareDetectionTuning(*req.Tuning)
			if err != nil {
				writeJSONError(w, http.StatusBadRequest, err.Error())
				return
			}
			tuning = draft
		}
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	q := r.URL.Query()
	from, to, err := replayWindow(q.Get("from"), q.Get("to"), replayDefaultSpan)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	alerts, err := s.store.ListAnomalyAlertsBetween(s.tenantFromRequest(r), from, to, false)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	res := detector.Replay(alerts, tuning)
	sigs := res.Signatures
	if len(sigs) > replayTopSignature {
		sigs = sigs[:replayTopSignature]
	}
	// cut is the best case and worst_cut the worst: see ReplayResult.MaySurface.
	cut, worst := 0.0, 0.0
	if res.Before > 0 {
		cut = float64(res.Before-res.After) / float64(res.Before)
		worst = max(0, float64(res.Before-res.After-res.MaySurface)/float64(res.Before))
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"from": from, "to": to,
		"before": res.Before, "after": res.After, "cut": cut,
		"may_surface": res.MaySurface, "worst_cut": worst,
		"by_type":    res.ByType,
		"paging":     res.Paging,
		"signatures": sigs,
		"truncated":  len(alerts) >= storage.MaxReplayAlerts,
	})
}

// handleResolveAnomalies closes findings with a recorded reason. Either name
// them ({"ids": [...], "reason": "..."}), or ask for every open finding in a
// window that the saved tuning would no longer raise ({"covered": true}), each
// resolved with the rule that now covers it. Administrator only: closing a
// finding in bulk is a decision about the whole estate.
func (s *Server) handleResolveAnomalies(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		IDs     []string `json:"ids"`
		Covered bool     `json:"covered"`
		Reason  string   `json:"reason"`
		// Verdict is what the operator concluded: benign, malicious, or
		// nothing. Only a verdict makes the outcome a training label.
		Verdict string `json:"verdict"`
		From    string `json:"from"`
		To      string `json:"to"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	tenant := s.tenantFromRequest(r)
	by := s.operatorFromRequest(r)
	reason := strings.TrimSpace(req.Reason)
	byReason := map[string]int{}
	truncated := false

	switch {
	case req.Covered == (len(req.IDs) > 0):
		writeJSONError(w, http.StatusBadRequest, "name the findings (ids) or ask for those the tuning covers (covered), not both")
		return
	case len(req.IDs) > 0:
		if reason == "" {
			writeJSONError(w, http.StatusBadRequest, "a resolution needs a reason")
			return
		}
		if len(req.IDs) > resolveMaxIDs {
			writeJSONError(w, http.StatusBadRequest, fmt.Sprintf("at most %d findings per request", resolveMaxIDs))
			return
		}
		switch req.Verdict {
		case "", storage.VerdictBenign, storage.VerdictMalicious:
		default:
			writeJSONError(w, http.StatusBadRequest, "verdict is benign, malicious, or omitted")
			return
		}
		n, err := s.store.ResolveAnomalies(tenant, req.IDs, storage.Resolution{Reason: reason, By: by, Verdict: req.Verdict, Method: storage.MethodOperator})
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, err.Error())
			return
		}
		byReason[reason] = n
	default:
		from, to, err := replayWindow(req.From, req.To, replayMaxSpan)
		if err != nil {
			writeJSONError(w, http.StatusBadRequest, err.Error())
			return
		}
		// Every finding in the window, not only the open ones, so the
		// off-hours folding is judged against the same history the detector
		// would have had.
		alerts, err := s.store.ListAnomalyAlertsBetween(tenant, from, to, false)
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, err.Error())
			return
		}
		truncated = len(alerts) >= storage.MaxReplayAlerts
		open := map[string]bool{}
		for _, a := range alerts {
			if !a.Acknowledged {
				open[a.ID] = true
			}
		}
		groups := map[string][]string{}
		for _, d := range detector.Replay(alerts, s.store.GetDetectionTuning()).Decisions {
			if !d.Kept && open[d.ID] {
				why := "covered by tuning: " + d.Reason
				if reason != "" {
					why += " (" + reason + ")"
				}
				groups[why] = append(groups[why], d.ID)
			}
		}
		keys := make([]string, 0, len(groups))
		for k := range groups {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, why := range keys {
			n, err := s.store.ResolveAnomalies(tenant, groups[why], storage.Resolution{Reason: why, By: by, Verdict: storage.VerdictBenign, Method: storage.MethodTuning})
			byReason[why] = n
			if err != nil {
				s.audit(r, "ANOMALIES_RESOLVED", "anomalies", fmt.Sprintf("resolved %d findings before an error", n))
				writeJSONError(w, http.StatusInternalServerError, err.Error())
				return
			}
		}
	}
	total := 0
	for _, n := range byReason {
		total += n
	}
	s.audit(r, "ANOMALIES_RESOLVED", "anomalies", fmt.Sprintf("resolved %d findings under %d reasons", total, len(byReason)))
	writeJSON(w, http.StatusOK, map[string]any{"resolved": total, "by_reason": byReason, "truncated": truncated})
}
