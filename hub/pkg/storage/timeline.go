package storage

import "time"

// TimelineAlerts returns the findings raised in [from, to), newest first, at
// most limit, for one endpoint or for every endpoint when endpointID is empty.
// Findings held by a learning window are left out: nobody was shown them.
// More reports whether the limit cut older findings off.
func (s *Store) TimelineAlerts(endpointID string, from, to time.Time, limit int) (alerts []AnomalyAlert, more bool, err error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	where := " WHERE timestamp >= ? AND timestamp < ? AND COALESCE(held_reason, '') <> ?"
	args := []any{from.UTC(), to.UTC(), HeldLearning}
	if endpointID != "" {
		where += " AND endpoint_id = ?"
		args = append(args, endpointID)
	}
	args = append(args, limit+1)
	rows, err := s.db.Query("SELECT id, tenant_id, location_id, endpoint_id, hostname, anomaly_type, severity, title, description, details, COALESCE(evidence, ''), COALESCE(technique, ''), COALESCE(held_reason, ''), process_path, dst_ip, dst_port, timestamp, acknowledged FROM anomaly_alerts"+where+" ORDER BY timestamp DESC LIMIT ?", args...)
	if err != nil {
		return nil, false, err
	}
	defer rows.Close()
	alerts = make([]AnomalyAlert, 0)
	for rows.Next() {
		var a AnomalyAlert
		var ack int
		if err := rows.Scan(&a.ID, &a.TenantID, &a.LocationID, &a.EndpointID, &a.Hostname,
			&a.AnomalyType, &a.Severity, &a.Title, &a.Description, &a.Details, &a.Evidence,
			&a.Technique, &a.HeldReason, &a.ProcessPath, &a.DstIP, &a.DstPort, &a.Timestamp, &ack); err != nil {
			return nil, false, err
		}
		if len(alerts) == limit {
			more = true
			break
		}
		a.Acknowledged = ack != 0
		alerts = append(alerts, a)
	}
	return alerts, more, rows.Err()
}
