package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"ominull/hub/pkg/storage"
)

// The learning API.
//
// Reading is open to any authenticated operator - an analyst who cannot see
// that a window is holding findings will misread a quiet console. Opening,
// closing and applying are administrator actions, because each one changes what
// the fleet will report, and applying a proposal is a suppression by another
// name.

// handleLearningWindows lists and opens windows.
func (s *Server) handleLearningWindows(w http.ResponseWriter, r *http.Request) {
	role := r.Header.Get("X-Role")
	tenantID := ""
	if role == "tenant" {
		tenantID = r.Header.Get("X-Tenant-ID")
	}

	switch r.Method {
	case http.MethodGet:
		windows, err := s.store.ListLearningWindows(tenantID, r.URL.Query().Get("open") == "true")
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, err.Error())
			return
		}
		now := time.Now().UTC()
		out := make([]map[string]interface{}, 0, len(windows))
		for _, win := range windows {
			row := map[string]interface{}{
				"window": win,
				"open":   win.Open(now),
			}
			if win.Open(now) {
				row["remaining_minutes"] = int(win.EndsAt.Sub(now).Minutes())
			}
			out = append(out, row)
		}
		writeJSON(w, http.StatusOK, map[string]interface{}{"windows": out})

	case http.MethodPost:
		if role != "admin" {
			writeJSONError(w, http.StatusForbidden, "opening a learning window is an administrator action")
			return
		}
		var req struct {
			ScopeType string `json:"scope_type"`
			ScopeID   string `json:"scope_id"`
			Hours     int    `json:"hours"`
			Days      int    `json:"days"`
			Note      string `json:"note"`
			TenantID  string `json:"tenant_id"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSONError(w, http.StatusBadRequest, err.Error())
			return
		}

		window := storage.LearningWindow{
			ScopeType: strings.TrimSpace(req.ScopeType),
			ScopeID:   strings.TrimSpace(req.ScopeID),
			Note:      strings.TrimSpace(req.Note),
			TenantID:  strings.TrimSpace(req.TenantID),
			StartedBy: operatorName(r),
		}
		if window.TenantID == "" {
			window.TenantID = tenantID
		}
		if window.ScopeType == "" {
			window.ScopeType = storage.LearningScopeEndpoint
		}
		// Seven days is the low end of what every new-terms and dry-run
		// allowlisting guide recommends, and it is what an operator who gave no
		// duration almost certainly meant.
		switch {
		case req.Hours > 0:
			window.EndsAt = time.Now().UTC().Add(time.Duration(req.Hours) * time.Hour)
		case req.Days > 0:
			window.EndsAt = time.Now().UTC().Add(time.Duration(req.Days) * 24 * time.Hour)
		}
		window.ScopeLabel = s.describeScope(window)

		saved, err := s.store.CreateLearningWindow(window)
		if err != nil {
			writeJSONError(w, http.StatusBadRequest, err.Error())
			return
		}
		s.audit(r, "LEARNING_WINDOW_OPENED", "detection",
			fmt.Sprintf("opened a learning window over %s %s until %s",
				saved.ScopeType, saved.ScopeLabel, saved.EndsAt.Format(time.RFC3339)))
		writeJSON(w, http.StatusOK, map[string]interface{}{"window": saved, "open": true})

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleCloseLearningWindow ends a window: completed if it did its job,
// cancelled if it was a mistake. Both stop the holding at once.
func (s *Server) handleCloseLearningWindow(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if r.Header.Get("X-Role") != "admin" {
		writeJSONError(w, http.StatusForbidden, "closing a learning window is an administrator action")
		return
	}
	var req struct {
		ID     string `json:"id"`
		Cancel bool   `json:"cancel"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	status := storage.LearningCompleted
	if req.Cancel {
		status = storage.LearningCancelled
	}
	if err := s.store.CloseLearningWindow(strings.TrimSpace(req.ID), status); err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	s.audit(r, "LEARNING_WINDOW_CLOSED", "detection",
		fmt.Sprintf("closed learning window %s as %s", req.ID, status))
	writeJSON(w, http.StatusOK, map[string]interface{}{"id": req.ID, "status": status})
}

// handleLearningProposals returns what a window learned, as candidate changes.
func (s *Server) handleLearningProposals(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	windowID := strings.TrimSpace(r.URL.Query().Get("window"))
	if windowID == "" {
		writeJSONError(w, http.StatusBadRequest, "which window?")
		return
	}
	proposals, err := s.store.ComputeLearningProposals(windowID)
	if err != nil {
		writeJSONError(w, http.StatusNotFound, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"window": windowID, "proposals": proposals})
}

// handleApplyLearningProposals applies an explicit list of proposal ids.
//
// Nothing applies itself and nothing applies in bulk by wildcard: the ids are
// named, they are re-computed from the observations before anything is written,
// and a proposal that no longer stands is refused rather than guessed at.
func (s *Server) handleApplyLearningProposals(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if r.Header.Get("X-Role") != "admin" {
		writeJSONError(w, http.StatusForbidden, "applying a learning proposal is an administrator action")
		return
	}
	var req struct {
		Window string   `json:"window"`
		IDs    []string `json:"ids"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	if strings.TrimSpace(req.Window) == "" || len(req.IDs) == 0 {
		writeJSONError(w, http.StatusBadRequest, "name the window and the proposals to apply")
		return
	}

	proposals, err := s.store.ComputeLearningProposals(strings.TrimSpace(req.Window))
	if err != nil {
		writeJSONError(w, http.StatusNotFound, err.Error())
		return
	}
	byID := map[string]storage.LearningProposal{}
	for _, p := range proposals {
		byID[p.ID] = p
	}

	tuning := s.store.GetDetectionTuning()
	applied := []string{}
	skipped := map[string]string{}
	for _, id := range req.IDs {
		p, ok := byID[strings.TrimSpace(id)]
		if !ok {
			skipped[id] = "the window no longer proposes this; it may already be applied"
			continue
		}
		switch p.Kind {
		case storage.ProposeQuietPair:
			tuning.QuietPairs = append(tuning.QuietPairs, p.Subject)
		case storage.ProposeQuietProcess:
			tuning.QuietClients = append(tuning.QuietClients, p.Subject)
		case storage.ProposeOffHours:
			start, end, err := parseHourRange(p.Subject)
			if err != nil {
				skipped[id] = err.Error()
				continue
			}
			tuning.OffHoursStart, tuning.OffHoursEnd = start, end
		default:
			skipped[id] = "unknown proposal kind " + p.Kind
			continue
		}
		applied = append(applied, p.ID)
	}

	if len(applied) == 0 {
		writeJSON(w, http.StatusOK, map[string]interface{}{"applied": applied, "skipped": skipped})
		return
	}

	saved, err := s.store.SaveDetectionTuning(tuning, operatorName(r))
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if s.detector != nil {
		s.detector.InvalidateTuning()
	}
	sort.Strings(applied)
	s.audit(r, "LEARNING_PROPOSALS_APPLIED", "detection",
		fmt.Sprintf("applied %d proposal(s) from learning window %s: %s",
			len(applied), req.Window, strings.Join(applied, ", ")))
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"applied": applied,
		"skipped": skipped,
		"tuning":  saved,
	})
}

// parseHourRange reads the "HH:00-HH:00" subject an active-hours proposal
// carries back into the two integers the tuning holds.
func parseHourRange(subject string) (int, int, error) {
	var start, end int
	if _, err := fmt.Sscanf(strings.TrimSpace(subject), "%d:00-%d:00", &start, &end); err != nil {
		return 0, 0, fmt.Errorf("%q is not an hour range", subject)
	}
	if start < 0 || start > 23 || end < 0 || end > 23 {
		return 0, 0, fmt.Errorf("%q is not an hour range", subject)
	}
	return start, end, nil
}

// describeScope names what a window covers, so the console and the audit log
// can say "the workstations at Primary Home LAN" rather than a UUID.
func (s *Server) describeScope(w storage.LearningWindow) string {
	switch w.ScopeType {
	case storage.LearningScopeEndpoint:
		if ep, err := s.store.GetEndpoint(w.ScopeID); err == nil && ep != nil && ep.Hostname != "" {
			return ep.Hostname
		}
	case storage.LearningScopeLocation:
		if locs, err := s.store.ListLocations(w.TenantID); err == nil {
			for _, l := range locs {
				if l.ID == w.ScopeID {
					return l.Name
				}
			}
		}
	case storage.LearningScopeTenant:
		if w.ScopeID == "" {
			return "the whole estate"
		}
		return w.ScopeID
	}
	return w.ScopeID
}

func operatorName(r *http.Request) string {
	if by := strings.TrimSpace(r.Header.Get("X-Username")); by != "" {
		return by
	}
	return "admin"
}
