package storage

import (
	"crypto/sha256"
	"fmt"
	"net"
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
	profileKey := fmt.Sprintf("%q|%q|%q|%d|%q|%d", ev.EndpointID, cleanPath, ev.DstIP, ev.DstPort, direction, ev.Protocol)
	profileID := fmt.Sprintf("v2:%x", sha256.Sum256([]byte(profileKey)))
	return []interface{}{
		profileID, ev.TenantID, locationID, ev.EndpointID, hostname,
		procName, ev.ProcessPath, ev.DstIP, ev.DstPort, proto, direction, country,
		ev.Timestamp, ev.Timestamp, ev.BytesIn, ev.BytesOut, ev.Domain,
	}
}

// MatchesExclusion applies a previously loaded exclusion snapshot. Loading
// the snapshot is the caller's responsibility; this function has no database
// side effect and can be used for every event in one batch.
func MatchesExclusion(ev Event, locationID string, exclusions []Exclusion) bool {
	for _, ex := range exclusions {
		if !ex.Active {
			continue
		}
		switch ex.Scope {
		case "client":
			if ex.ScopeValue != "" && ex.ScopeValue != ev.TenantID {
				continue
			}
		case "location":
			if ex.ScopeValue != "" && ex.ScopeValue != locationID {
				continue
			}
		case "endpoint":
			if ex.ScopeValue != "" && ex.ScopeValue != ev.EndpointID {
				continue
			}
		}

		if ex.Protocol != "any" && ex.Protocol != "" {
			if strings.ToUpper(ex.Protocol) == "TCP" && ev.Protocol != 6 {
				continue
			}
			if strings.ToUpper(ex.Protocol) == "UDP" && ev.Protocol != 17 {
				continue
			}
			if strings.ToUpper(ex.Protocol) == "ICMP" && ev.Protocol != 1 {
				continue
			}
		}

		if ex.DstIPRange != "*" && ex.DstIPRange != "" {
			if strings.Contains(ex.DstIPRange, "/") {
				_, ipNet, err := net.ParseCIDR(ex.DstIPRange)
				if err == nil {
					targetIP := net.ParseIP(ev.DstIP)
					if targetIP != nil && !ipNet.Contains(targetIP) {
						continue
					}
				}
			} else {
				if ex.DstIPRange != ev.DstIP {
					continue
				}
			}
		}

		if ex.Port != 0 && ex.Port != ev.DstPort {
			continue
		}

		if ex.ProcessPath != "*" && ex.ProcessPath != "" {
			pattern := strings.ToLower(strings.ReplaceAll(ex.ProcessPath, "\\", "/"))
			actual := strings.ToLower(strings.ReplaceAll(ev.ProcessPath, "\\", "/"))
			matched, err := filepath.Match(pattern, actual)
			if err != nil || !matched {
				if !strings.Contains(actual, pattern) && !strings.HasSuffix(actual, pattern) {
					continue
				}
			}
		}

		return true
	}
	return false
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

	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin telemetry batch: %w", err)
	}
	defer tx.Rollback()

	eventStmt, err := tx.Prepare(`
		INSERT INTO events (tenant_id, endpoint_id, timestamp, layer, action, direction, protocol, src_ip, dst_ip, src_port, dst_port, bytes_in, bytes_out, country, process_path, process_id, domain, sni, process_instance_id, parent_pid, parent_process_instance_id, command_line, user_identity, executable_sha256, attribution_status, observed_at, observation_json)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`)
	if err != nil {
		return fmt.Errorf("prepare telemetry events: %w", err)
	}
	defer eventStmt.Close()

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

	tenantIDs := make(map[string]struct{}, 1)
	for _, ev := range events {
		ev.SrcIP, ev.DstIP = canonicalAddress(ev.SrcIP), canonicalAddress(ev.DstIP)
		ev.Timestamp = ev.Timestamp.UTC()
		country := ev.Country
		if country == "" {
			country = CountryUnknown
		}
		var obsVal interface{}
		if ev.ObservedAt != nil && !ev.ObservedAt.IsZero() {
			obsVal = ev.ObservedAt.UTC().Format(time.RFC3339Nano)
		}
		if _, err := eventStmt.Exec(
			ev.TenantID, ev.EndpointID, ev.Timestamp, ev.Layer, ev.Action, ev.Direction, ev.Protocol,
			ev.SrcIP, ev.DstIP, ev.SrcPort, ev.DstPort, ev.BytesIn, ev.BytesOut, country,
			ev.ProcessPath, ev.ProcessID, ev.Domain, ev.SNI,
			ev.ProcessInstanceID, ev.ParentPID, ev.ParentProcessInstanceID, ev.CommandLine, ev.UserIdentity, ev.ExecutableSHA256, ev.AttributionStatus, obsVal, ev.Observation,
		); err != nil {
			return fmt.Errorf("insert telemetry event: %w", err)
		}
		if _, err := commStmt.Exec(communicationValues(ev, hostname, locationID)...); err != nil {
			return fmt.Errorf("insert telemetry communication profile: %w", err)
		}

		tenantID := ev.TenantID
		if tenantID == "" {
			tenantID = "default"
		}
		tenantIDs[tenantID] = struct{}{}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit telemetry batch: %w", err)
	}
	return nil
}
