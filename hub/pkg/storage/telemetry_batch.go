package storage

import (
	"crypto/sha256"
	"fmt"
	"path/filepath"
	"strings"
	"time"
)

// RecordNetworkCommsBatch persists the communication projection for one
// accepted telemetry batch in one transaction. The event rows and this
// projection are deliberately separate transactions: event durability is the
// acknowledgement boundary, while a projection failure is returned to the
// caller and never hidden behind a successful request.
func (s *Store) RecordNetworkCommsBatch(events []Event, hostname, locationID string) error {
	if len(events) == 0 {
		return nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin communication batch: %w", err)
	}
	defer tx.Rollback()

	stmt, err := tx.Prepare(`
		INSERT INTO comm_profiles (id, tenant_id, location_id, endpoint_id, hostname, process_name, process_path, dst_ip, dst_port, protocol, direction, country, first_seen, last_seen, event_count, total_bytes_in, total_bytes_out, is_baseline, domain)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, 1, ?)
		ON CONFLICT(id) DO UPDATE SET
			last_seen=excluded.last_seen,
			event_count=comm_profiles.event_count + 1,
			total_bytes_in=comm_profiles.total_bytes_in + excluded.total_bytes_in,
			total_bytes_out=comm_profiles.total_bytes_out + excluded.total_bytes_out,
			domain=CASE WHEN excluded.domain != '' THEN excluded.domain ELSE comm_profiles.domain END
	`)
	if err != nil {
		return fmt.Errorf("prepare communication batch: %w", err)
	}
	defer stmt.Close()

	for _, ev := range events {
		values := communicationValues(ev, hostname, locationID)
		if _, err := stmt.Exec(values...); err != nil {
			return fmt.Errorf("insert communication profile batch: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit communication batch: %w", err)
	}
	return nil
}

func communicationValues(ev Event, hostname, locationID string) []interface{} {
	ev.Timestamp = ev.Timestamp.UTC()
	ev.SrcIP, ev.DstIP = canonicalAddress(ev.SrcIP), canonicalAddress(ev.DstIP)
	cleanPath := strings.ReplaceAll(ev.ProcessPath, "\\", "/")
	procName := filepath.Base(cleanPath)
	if procName == "." || procName == "/" || procName == "\\" || procName == "" {
		procName = "unknown"
	}

	proto := ProtocolName(int(ev.Protocol))
	direction := ev.Direction
	if direction == "" {
		direction = "OUTBOUND"
	}
	country := ev.Country
	if country == "" {
		country = CountryUnknown
	}
	if locationID == "" {
		locationID = "loc-home"
	}
	// A loopback conversation is profiled by its service port: the server
	// side of it reports the client's ephemeral port as the destination, and
	// one profile per ephemeral port was 80% of this table.
	if IsLocalFlow(ev) {
		ev.DstPort = servicePort(ev.SrcPort, ev.DstPort)
	}
	profileKey := fmt.Sprintf("%q|%q|%q|%d|%q|%d", ev.EndpointID, cleanPath, ev.DstIP, ev.DstPort, direction, ev.Protocol)
	profileID := fmt.Sprintf("v2:%x", sha256.Sum256([]byte(profileKey)))
	return []interface{}{
		profileID, ev.TenantID, locationID, ev.EndpointID, hostname,
		procName, ev.ProcessPath, ev.DstIP, ev.DstPort, proto, direction, country,
		ev.Timestamp, ev.Timestamp, ev.BytesIn, ev.BytesOut, ev.Domain,
	}
}

// InsertTelemetryBatch is the durable ingestion boundary for the hub. Event
// rows and their communication projection commit together, so a successful
// response cannot leave one accepted representation missing the other.
func (s *Store) InsertTelemetryBatch(events []Event, hostname, locationID string) error {
	return s.IngestTelemetryBatch(events, hostname, locationID)
}

func (s *Store) IngestTelemetryBatch(events []Event, hostname, locationID string) error {
	if len(events) == 0 {
		return nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	started := time.Now()
	defer recordIngest(started, len(events))

	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin telemetry batch: %w", err)
	}
	defer tx.Rollback()

	commStmt, err := tx.Prepare(`
		INSERT INTO comm_profiles (id, tenant_id, location_id, endpoint_id, hostname, process_name, process_path, dst_ip, dst_port, protocol, direction, country, first_seen, last_seen, event_count, total_bytes_in, total_bytes_out, is_baseline, domain)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, 1, ?)
		ON CONFLICT(id) DO UPDATE SET
			last_seen=excluded.last_seen,
			event_count=comm_profiles.event_count + 1,
			total_bytes_in=comm_profiles.total_bytes_in + excluded.total_bytes_in,
			total_bytes_out=comm_profiles.total_bytes_out + excluded.total_bytes_out,
			domain=CASE WHEN excluded.domain != '' THEN excluded.domain ELSE comm_profiles.domain END
	`)
	if err != nil {
		return fmt.Errorf("prepare telemetry communication profiles: %w", err)
	}
	defer commStmt.Close()

	for _, ev := range events {
		ev.SrcIP, ev.DstIP = canonicalAddress(ev.SrcIP), canonicalAddress(ev.DstIP)
		ev.Timestamp = ev.Timestamp.UTC()
		if _, err := commStmt.Exec(communicationValues(ev, hostname, locationID)...); err != nil {
			return fmt.Errorf("insert telemetry communication profile: %w", err)
		}
	}
	flows, err := s.writeFlows(tx, events, true)
	if err != nil {
		return fmt.Errorf("insert telemetry flows: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit telemetry batch: %w", err)
	}
	flows.commit()
	return nil
}
