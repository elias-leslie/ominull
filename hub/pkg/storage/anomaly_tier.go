package storage

import (
	"database/sql"
	"encoding/json"
	"errors"
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

	// HeldIncident is the held reason of a page that joined an incident
	// already open (same device, rule family and counterparty within
	// page_incident_hours) without raising its severity: it is kept with the
	// incident, not pushed again.
	HeldIncident = "incident"

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
	return s.db.QueryRow(`SELECT 1 FROM agent_egress_runtimes WHERE tenant_id = ? AND endpoint_id = ? AND runtime != '*' LIMIT 1`,
		tenantID, endpointID).Scan(&one) == nil
}

// HuntWindow counts the hunt leads raised since a point in time.
type HuntWindow struct {
	Total   int            `json:"total"`
	Muted   int            `json:"muted"`
	ByType  map[string]int `json:"by_type"`
	ByHost  map[string]int `json:"by_host"`
	ByClass map[string]int `json:"by_class"`
}

// SummariseHuntLeads returns the hunt-lead counts the Aico push reports.
func (s *Store) SummariseHuntLeads(since time.Time) (HuntWindow, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := HuntWindow{ByType: map[string]int{}, ByHost: map[string]int{}, ByClass: map[string]int{}}
	rows, err := s.db.Query(`SELECT anomaly_type, hostname,
			CASE WHEN json_valid(evidence) AND json_extract(evidence, '$.class') = ? THEN ? ELSE ? END,
			SUM(CASE WHEN json_valid(evidence) AND json_extract(evidence, '$.muted') = ? THEN 1 ELSE 0 END), COUNT(*)
		FROM anomaly_alerts WHERE held_reason = ? AND timestamp >= ?
		GROUP BY 1, 2, 3`, ClassDigest, ClassDigest, ClassRecord, MutedAgentHeavy, HeldHunt, since.UTC())
	if err != nil {
		return out, err
	}
	defer rows.Close()
	for rows.Next() {
		var typ, host, class string
		var muted, n int
		if err := rows.Scan(&typ, &host, &class, &muted, &n); err != nil {
			return out, err
		}
		out.Total += n
		out.Muted += muted
		out.ByClass[class] += n
		out.ByType[typ] += n
		out.ByHost[host] += n
	}
	return out, rows.Err()
}

// Alert classes (detector/class.go). A page is pushed and asked about, once
// per incident; a record is stored with its evidence and only counted; a
// digest is one daily line per group. Record and digest findings are held
// like hunt leads (held_reason hunt), so only pages are open alerts.
const (
	ClassPage   = "page"
	ClassRecord = "record"
	ClassDigest = "digest"
)

// SetAlertClassifier installs the function that stamps a finding's class,
// reason and incident before CreateAnomalyAlert writes it. The detector
// installs it; nil removes it.
func (s *Store) SetAlertClassifier(f func(*AnomalyAlert)) {
	if f == nil {
		s.classifier.Store(nil)
		return
	}
	s.classifier.Store(&f)
}

// AlertClass is a finding's stamped class: the evidence's class field, or for
// a finding written before classes, page unless it is held as a hunt lead.
func AlertClass(a AnomalyAlert) string {
	var f struct {
		Class string `json:"class"`
	}
	if strings.TrimSpace(a.Evidence) != "" && json.Unmarshal([]byte(a.Evidence), &f) == nil {
		switch f.Class {
		case ClassPage, ClassRecord, ClassDigest:
			return f.Class
		}
	}
	if a.HeldReason == HeldHunt {
		return ClassRecord
	}
	return ClassPage
}

// OpenIncident finds the incident a page with this key joins: the newest
// paging finding carrying the key since a point in time. It returns the
// incident id ("" when none is open) and the worst severity it has paged at.
func (s *Store) OpenIncident(tenantID, endpointID, key string, since time.Time) (id, worst string, err error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	// The window runs from the incident's first page, not its newest member:
	// activity that goes on for days asks again each window.
	err = s.db.QueryRow(`SELECT json_extract(evidence, '$.incident') FROM anomaly_alerts
		WHERE tenant_id = ? AND endpoint_id = ? AND timestamp >= ? AND json_valid(evidence)
			AND json_extract(evidence, '$.incident_key') = ? AND json_extract(evidence, '$.incident') = 'inc-' || id
		ORDER BY timestamp DESC LIMIT 1`, tenantID, endpointID, since.UTC(), key).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return "", "", nil
	}
	if err != nil {
		return "", "", err
	}
	rows, err := s.db.Query(`SELECT severity FROM anomaly_alerts
		WHERE tenant_id = ? AND endpoint_id = ? AND timestamp >= ? AND json_valid(evidence)
			AND json_extract(evidence, '$.incident') = ?`, tenantID, endpointID, since.UTC(), id)
	if err != nil {
		return "", "", err
	}
	defer rows.Close()
	rank := map[string]int{"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
	for rows.Next() {
		var sev string
		if err := rows.Scan(&sev); err != nil {
			return "", "", err
		}
		if rank[sev] > rank[worst] {
			worst = sev
		}
	}
	return id, worst, rows.Err()
}

// RecordedAlerts returns the newest record and digest findings (held as
// hunt leads) raised since a point in time, at most limit of them.
func (s *Store) RecordedAlerts(since time.Time, limit int) ([]AnomalyAlert, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	rows, err := s.db.Query(`SELECT id, tenant_id, endpoint_id, hostname, anomaly_type, severity, title, description,
		COALESCE(evidence, ''), held_reason, process_path, dst_ip, dst_port, timestamp FROM anomaly_alerts
		WHERE held_reason = ? AND timestamp >= ?
		ORDER BY timestamp DESC LIMIT ?`, HeldHunt, since.UTC(), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AnomalyAlert
	for rows.Next() {
		var a AnomalyAlert
		if err := rows.Scan(&a.ID, &a.TenantID, &a.EndpointID, &a.Hostname, &a.AnomalyType, &a.Severity, &a.Title,
			&a.Description, &a.Evidence, &a.HeldReason, &a.ProcessPath, &a.DstIP, &a.DstPort, &a.Timestamp); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// DestinationPrevalence counts the devices that have reached an address
// (or, when named, the name) in their communication profiles.
func (s *Store) DestinationPrevalence(tenantID, dstIP, domain string) (int, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var n int
	err := s.db.QueryRow(`SELECT COUNT(DISTINCT endpoint_id) FROM comm_profiles
		WHERE tenant_id = ? AND (dst_ip = ? OR (? != '' AND domain = ?))`, tenantID, dstIP, domain, domain).Scan(&n)
	return n, err
}
