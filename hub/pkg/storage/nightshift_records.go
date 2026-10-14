package storage

import (
	"strings"
	"time"
)

// AnomalyOutcomeDay is one endpoint's findings of one type on one UTC day, as
// the Nightshift record feed counts them. It carries no hostname, title or
// other text from the findings.
type AnomalyOutcomeDay struct {
	EndpointID  string
	AnomalyType string
	First, Last time.Time
	Count       int
	Open        int // not acknowledged
	Tuning      int // closed by a tuning rule
	Benign      int // closed by an operator with the verdict benign
	Malicious   int // closed by an operator with the verdict malicious
	Hunt        int // hunt leads (anomaly_tier.go) among Count
}

// IsolationActions are the audit actions written only once an endpoint has
// actually been cut off: the evidence of an incident on it. The guard's
// FORCED and UNVERIFIED entries are written before the attempt, and a bulk
// isolation's own entry names a scope, so neither counts; a bulk isolation
// writes an ISOLATE_HOST per endpoint once it has succeeded.
var IsolationActions = []string{"ISOLATE_HOST", "AUTO_ISOLATE_HOST"}

// IsolationEvent is one isolation of the endpoint Resource at At.
type IsolationEvent struct {
	Resource string
	At       time.Time
}

// ListAnomalyOutcomeDays returns findings raised since `since`, counted per
// endpoint, type and day, newest day first, at most limit groups; truncated
// says the limit cut older days off. Findings held by a learning window are
// left out: nobody was shown them, so they have no outcome. Hunt leads are
// counted, and Hunt says how many: they were findings before the tiers
// existed, and the learner still reads them.
func (s *Store) ListAnomalyOutcomeDays(since time.Time, limit int) (days []AnomalyOutcomeDay, truncated bool, err error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	rows, err := s.db.Query(`SELECT a.endpoint_id, a.anomaly_type, MIN(a.timestamp), MAX(a.timestamp), COUNT(*),
			SUM(CASE WHEN a.acknowledged = 0 THEN 1 ELSE 0 END),
			SUM(CASE WHEN a.acknowledged = 1 AND r.method = ? THEN 1 ELSE 0 END),
			SUM(CASE WHEN a.acknowledged = 1 AND r.method <> ? AND r.verdict = ? THEN 1 ELSE 0 END),
			SUM(CASE WHEN r.verdict = ? THEN 1 ELSE 0 END),
			SUM(CASE WHEN a.held_reason = ? THEN 1 ELSE 0 END)
		FROM anomaly_alerts a LEFT JOIN anomaly_resolutions r ON r.anomaly_id = a.id
		WHERE a.timestamp >= ? AND a.held_reason IN ('', ?)
		GROUP BY a.endpoint_id, a.anomaly_type, substr(a.timestamp, 1, 10)
		ORDER BY MAX(a.timestamp) DESC LIMIT ?`,
		MethodTuning, MethodTuning, VerdictBenign, VerdictMalicious, HeldHunt, since.UTC(), HeldHunt, limit+1)
	if err != nil {
		return nil, false, err
	}
	defer rows.Close()
	for rows.Next() {
		var d AnomalyOutcomeDay
		var first, last any
		if err := rows.Scan(&d.EndpointID, &d.AnomalyType, &first, &last, &d.Count, &d.Open, &d.Tuning, &d.Benign, &d.Malicious, &d.Hunt); err != nil {
			return nil, false, err
		}
		d.First, d.Last = scanTime(first), scanTime(last)
		days = append(days, d)
	}
	if len(days) > limit {
		days, truncated = days[:limit], true
	}
	return days, truncated, rows.Err()
}

// ListIsolationEvents returns the isolations recorded since `since`.
func (s *Store) ListIsolationEvents(since time.Time) ([]IsolationEvent, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	rows, err := s.db.Query(`SELECT resource, timestamp FROM audit_logs WHERE timestamp >= ? AND action IN (?`+
		strings.Repeat(", ?", len(IsolationActions)-1)+`)`, append([]any{since.UTC()}, toAny(IsolationActions)...)...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []IsolationEvent
	for rows.Next() {
		var e IsolationEvent
		var at any
		if err := rows.Scan(&e.Resource, &at); err != nil {
			return nil, err
		}
		e.At = scanTime(at)
		out = append(out, e)
	}
	return out, rows.Err()
}

func toAny(v []string) []any {
	out := make([]any, len(v))
	for i, s := range v {
		out[i] = s
	}
	return out
}

// SetSettingOnce stores value under key unless one is already there, and
// returns whichever is stored. Two first callers agree on one value.
func (s *Store) SetSettingOnce(key, value string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, err := s.db.Exec(`INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO NOTHING`, key, value); err != nil {
		return "", err
	}
	var stored string
	err := s.db.QueryRow(`SELECT value FROM settings WHERE key = ?`, key).Scan(&stored)
	return stored, err
}
