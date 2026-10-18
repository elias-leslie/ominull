package server

import (
	"strings"
	"time"

	"ominull/hub/pkg/response"
	"ominull/hub/pkg/scripts"
	"ominull/hub/pkg/storage"
)

// Per-machine compliance for Nightshift's posture score: one informational
// record per endpoint, ominull.compliance.<endpoint>, from the latest
// finished run of each package that reported controls. An endpoint with no
// such run gets no record; retired endpoints are skipped. Kept flat because
// the feed cuts unmapped data at depth 4 and 4 KB per record.

const (
	complianceFailedMax = 10
	// complianceLookback is how many of a package's newest runs are read to
	// find the latest finished one with controls (a run in flight, or one that
	// was skipped, does not hide the last real answer).
	complianceLookback = 10
)

type complianceRun struct {
	Category string
	Run      *packageRun
}

type complianceCount struct {
	Pass int `json:"pass"`
	Fail int `json:"fail"`
}

// complianceUID: ominull.compliance.<endpoint>, feed-safe like runUID.
func complianceUID(endpointID string) string { return "ominull.compliance." + feedSafe(endpointID) }

// controlTitle names a failing control in plain words: its benchmark
// reference when it has one, and the setting it checks (the last part of
// its id, e.g. a registry value name).
func controlTitle(c scripts.Control) string {
	leaf := c.ID
	if i := strings.LastIndexAny(leaf, `\/`); i >= 0 && i+1 < len(leaf) {
		leaf = leaf[i+1:]
	}
	if c.CIS != "" {
		return c.CIS + ": " + leaf
	}
	return leaf
}

// complianceRecord builds one endpoint's unmapped data, or nil when no run
// reported controls.
func complianceRecord(ep storage.Endpoint, runs []complianceRun) map[string]any {
	sec, maint := complianceCount{}, complianceCount{}
	var newest time.Time
	var failedSec, failedMaint []string
	accepted := []map[string]string{} // owner-accepted failures: listed, never counted
	seen := false
	for _, r := range runs {
		if r.Run == nil || len(r.Run.Controls) == 0 || r.Run.CompletedAt == nil {
			continue
		}
		seen = true
		if r.Run.CompletedAt.After(newest) {
			newest = *r.Run.CompletedAt
		}
		count, failed := &maint, &failedMaint
		if r.Category == "security" {
			count, failed = &sec, &failedSec
		}
		count.Pass += r.Run.Pass
		count.Fail += r.Run.Fail
		for _, c := range r.Run.Controls {
			if c.State == "fail" {
				*failed = append(*failed, controlTitle(c))
			}
			if c.State == "accepted" && len(accepted) < complianceFailedMax {
				a := map[string]string{"title": controlTitle(c)}
				if c.Accepted != nil && c.Accepted.Reason != "" {
					a["reason"] = c.Accepted.Reason
				}
				accepted = append(accepted, a)
			}
		}
	}
	if !seen {
		return nil
	}
	failed := append(failedSec, failedMaint...)
	if len(failed) > complianceFailedMax {
		failed = failed[:complianceFailedMax]
	}
	if failed == nil {
		failed = []string{}
	}
	return map[string]any{
		"endpoint_id": ep.ID, "hostname": ep.Hostname, "at": newest.UTC().Format(time.RFC3339),
		"security": sec, "maintenance": maint, "failed": failed, "accepted": accepted,
	}
}

// latestControlsRun is the newest finished run of a package that reported
// controls, among its last few.
func (s *Server) latestControlsRun(ep storage.Endpoint, sc *scripts.Script, latest *response.JobRecord, now time.Time, accepted map[string]acceptedRisk) (*packageRun, error) {
	if latest != nil {
		run := derivePackageRun(latest, now)
		applyAcceptedRisks(run, accepted)
		if run.CompletedAt != nil && len(run.Controls) > 0 {
			return run, nil
		}
	}
	jobs, err := s.responseStore.ScriptJobs(ep.TenantID, ep.ID, sc.ID, complianceLookback)
	if err != nil {
		return nil, err
	}
	for _, j := range jobs {
		run := derivePackageRun(j, now)
		applyAcceptedRisks(run, accepted)
		if run.CompletedAt != nil && len(run.Controls) > 0 {
			return run, nil
		}
	}
	return nil, nil
}

// complianceFindings: one resolved record per endpoint with controls.
func (s *Server) complianceFindings(now time.Time) ([]feedFinding, error) {
	if s.scriptsStore == nil || s.responseStore == nil {
		return nil, nil
	}
	eps, err := s.store.ListEndpoints("")
	if err != nil {
		return nil, err
	}
	libraries := map[string][]*scripts.Script{}
	acceptedAll := s.allAcceptedRisks()
	var out []feedFinding
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
		var runs []complianceRun
		for _, sc := range list {
			if sc.Package() == nil || latest[sc.ID] == nil {
				continue
			}
			run, err := s.latestControlsRun(ep, sc, latest[sc.ID], now, acceptedAll[ep.ID])
			if err != nil {
				return nil, err
			}
			if run != nil {
				runs = append(runs, complianceRun{Category: packageCategory(sc.Package().Category), Run: run})
			}
		}
		rec := complianceRecord(ep, runs)
		if rec == nil {
			continue
		}
		sec, maint := rec["security"].(complianceCount), rec["maintenance"].(complianceCount)
		msg := ep.Hostname + ": " + plural(sec.Pass+maint.Pass, "control passes", "controls pass") + ", " + plural(sec.Fail+maint.Fail, "control fails", "controls fail")
		out = append(out, s.feedFinding(now, complianceUID(ep.ID), "Machine compliance", ocsfSevInformational, ocsfStatusResolved, msg,
			[]feedResource{{Type: "endpoint", Name: ep.Hostname, UID: ep.ID}}, rec))
	}
	return out, nil
}
