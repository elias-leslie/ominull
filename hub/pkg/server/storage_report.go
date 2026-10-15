package server

import (
	"fmt"
	"net/http"
	"strings"
	"time"
)

// Storage report: how much data the hub keeps per endpoint-day and per
// router-client-day, hot versus retained, against the retention budgets. The
// store rebuilds it on every retention sweep; this only reads the cached copy.

func (s *Server) handleStorageReport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	// Hub-wide numbers name every tenant's endpoints.
	if r.Header.Get("X-Tenant-ID") != "" {
		writeJSONError(w, http.StatusForbidden, "the storage report is for hub operators")
		return
	}
	rep := s.store.DataReport()
	if rep == nil {
		writeJSON(w, http.StatusOK, map[string]any{"pending": true})
		return
	}
	segments, err := s.store.ColdSegments()
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "reading cold segments failed")
		return
	}
	// Agent uploads per endpoint and day (wire and decoded bytes), the last
	// week: read live, not from the cached report.
	uploads, err := s.store.UploadsSince(time.Now().UTC().AddDate(0, 0, -7).Format("2006-01-02"))
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "reading upload counts failed")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, map[string]any{"report": rep, "cold_segments": segments, "uploads": uploads})
}

// storageFinding is the Nightshift "Data per endpoint" row: informational
// within budget, a warning naming what is over it otherwise.
func (s *Server) storageFinding(now time.Time) ([]feedFinding, error) {
	rep := s.store.DataReport()
	if rep == nil {
		return nil, nil
	}
	if rep.Error != "" {
		return nil, fmt.Errorf("data report: %s", rep.Error)
	}
	unmapped := map[string]any{
		"hot_busy_mb_per_day":          rep.HotBusyMBPerDay,
		"hot_typical_mb_per_day":       rep.HotTypicalMBPerDay,
		"hot_mb_per_endpoint_day":      rep.HotMBPerEPDay,
		"retained_mb_per_endpoint_day": rep.RetainedMBPerEPDay,
		"router_mb_per_client_day":     rep.RouterMBPerClient,
		"db_mb":                        roundMB(rep.DBBytes),
		"db_growth_mb_per_day":         rep.DBGrowthMBPerDay,
		"hub_rss_mb":                   roundMB(rep.HubRSSBytes),
		"over_budget":                  rep.OverBudget,
		"generated_at":                 rep.GeneratedAt.Format(time.RFC3339),
	}
	msg := fmt.Sprintf("Busiest endpoint %.1f MB/day hot, typical %.2f; retained %.2f MB per endpoint-day; router %.2f MB per client-day; database %d MB",
		rep.HotBusyMBPerDay, rep.HotTypicalMBPerDay, rep.RetainedMBPerEPDay, rep.RouterMBPerClient, int64(roundMB(rep.DBBytes)))
	sev, status := ocsfSevInformational, ocsfStatusResolved
	if len(rep.OverBudget) > 0 {
		sev, status = ocsfSevMedium, ocsfStatusNew
		msg = "Over the data budget: " + strings.Join(rep.OverBudget, "; ") + ". " + msg
	}
	return []feedFinding{s.feedFinding(now, "ominull.storage.data_per_endpoint", "Data per endpoint", sev, status, msg, nil, unmapped)}, nil
}

func roundMB(b int64) float64 { return float64(b*10/(1<<20)) / 10 }
