package storage

import (
	"strings"
	"time"
)

// Detection tiers.
//
// A finding is either paging or a hunt lead. Paging findings come only from
// deterministic, explainable rules - a canary or decoy touched, an always-on
// host gone silent, a sweep, a threat-intelligence match, a policy broken -
// and they are what the open alert list, the counts and the Nightshift summary
// describe. Hunt leads come from the behavioural detectors (first-seen
// destinations, interpreters reaching out, off-hours activity): on a machine
// where AI agents start programs and open connections all day those describe
// ordinary work, so they are kept as data an analyst can hunt through and are
// never raised as alerts.
//
// A hunt lead is stored like a learning-held finding: written in full, with its
// evidence, kept out of every open count and off the default list, one filter
// away. It is bounded by the same retention as every other finding.
const (
	TierPage = "page"
	TierHunt = "hunt"

	// HeldHunt is the held reason of a hunt lead.
	HeldHunt = "hunt"

	// HeldHuntOnly is the Hunt leads view of QueryAnomalyAlerts.
	HeldHuntOnly = "hunt"

	// MutedAgentHeavy marks a hunt lead from an agent-heavy endpoint, whose
	// severity is lowered to LOW; the detector's own severity stays in the
	// evidence as detector_severity.
	MutedAgentHeavy = "agent_heavy"
)

// TierOf names a finding's tier from its held reason.
func TierOf(a AnomalyAlert) string {
	if a.HeldReason == HeldHunt {
		return TierHunt
	}
	return TierPage
}

// heldClause is the SQL filter for one held view.
func heldClause(held string) string {
	switch held {
	case HeldOnly:
		return " AND held_reason != '' AND held_reason != '" + HeldHunt + "'"
	case HeldHuntOnly:
		return " AND held_reason = '" + HeldHunt + "'"
	case HeldAny:
		return ""
	default:
		return " AND held_reason = ''"
	}
}

// IsAgentHeavy reports whether the tuning names this endpoint, by id or by
// role tag, as one where agents run programs and open connections as a matter
// of course. The detector also counts an endpoint whose telemetry has shown an
// agent runtime when AgentHeavyObserved is on. The operating system is never
// consulted.
func (t DetectionTuning) IsAgentHeavy(ep Endpoint) bool {
	id := strings.ToLower(strings.TrimSpace(ep.ID))
	role := strings.ToLower(strings.TrimSpace(ep.RoleTag))
	for _, v := range t.AgentHeavyEndpoints {
		if id != "" && v == id {
			return true
		}
	}
	for _, v := range t.AgentHeavyRoles {
		if role != "" && v == role {
			return true
		}
	}
	return false
}

// RunsAgentRuntimes reports whether the endpoint's own telemetry has shown a
// configured AI agent runtime (agent_egress_runtimes): the capability the
// agent reports, whatever its operating system.
func (s *Store) RunsAgentRuntimes(tenantID, endpointID string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var one int
	return s.db.QueryRow(`SELECT 1 FROM agent_egress_runtimes WHERE tenant_id = ? AND endpoint_id = ? LIMIT 1`,
		tenantID, endpointID).Scan(&one) == nil
}

const huntBackfillSetting = "anomaly_hunt_tier_backfill_v1"

// BackfillHuntTier moves the findings of the given types recorded before
// detection tiers existed into the hunt tier, once. Findings a learning window
// holds keep their reason, and so do the subnet sweep's new-device findings
// (ids alert-disc-*), which share the NOVEL_DESTINATION type but are not
// behavioural. It reports how many rows it moved; a second call
// moves nothing.
func (s *Store) BackfillHuntTier(types []string) (int64, error) {
	if len(types) == 0 {
		return 0, nil
	}
	if done, err := s.GetSetting(huntBackfillSetting); err != nil || done != "" {
		return 0, err
	}
	args := make([]any, 0, len(types))
	for _, t := range types {
		args = append(args, t)
	}
	stmt := `UPDATE anomaly_alerts SET held_reason = ? WHERE rowid IN (
		SELECT rowid FROM anomaly_alerts WHERE held_reason = '' AND id NOT LIKE 'alert-disc-%' AND anomaly_type IN (?` +
		strings.Repeat(", ?", len(types)-1) + `) LIMIT ?)`
	args = append(append([]any{HeldHunt}, args...), pruneBatch)
	var moved int64
	for {
		// Batches give the lock up between them, like retention.
		n, err := s.execBatch(stmt, args)
		if err != nil {
			return moved, err
		}
		moved += n
		if n < pruneBatch {
			break
		}
	}
	return moved, s.SetSetting(huntBackfillSetting, time.Now().UTC().Format(time.RFC3339))
}

func (s *Store) execBatch(stmt string, args []any) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	res, err := s.db.Exec(stmt, args...)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// HuntWindow counts the hunt leads raised since a point in time.
type HuntWindow struct {
	Total  int            `json:"total"`
	Muted  int            `json:"muted"`
	ByType map[string]int `json:"by_type"`
	ByHost map[string]int `json:"by_host"`
}

// SummariseHuntLeads returns the hunt-lead counts the Nightshift feed reports.
func (s *Store) SummariseHuntLeads(since time.Time) (HuntWindow, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := HuntWindow{ByType: map[string]int{}, ByHost: map[string]int{}}
	rows, err := s.db.Query(`SELECT anomaly_type, hostname,
			SUM(CASE WHEN json_valid(evidence) AND json_extract(evidence, '$.muted') = ? THEN 1 ELSE 0 END), COUNT(*)
		FROM anomaly_alerts WHERE held_reason = ? AND timestamp >= ?
		GROUP BY anomaly_type, hostname`, MutedAgentHeavy, HeldHunt, since.UTC())
	if err != nil {
		return out, err
	}
	defer rows.Close()
	for rows.Next() {
		var typ, host string
		var muted, n int
		if err := rows.Scan(&typ, &host, &muted, &n); err != nil {
			return out, err
		}
		out.Total += n
		out.Muted += muted
		out.ByType[typ] += n
		out.ByHost[host] += n
	}
	return out, rows.Err()
}
