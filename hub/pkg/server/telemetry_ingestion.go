package server

import (
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
	"time"

	"ominull/hub/pkg/detector"
	"ominull/hub/pkg/storage"
	"ominull/hub/pkg/threatintel"
)

var errRetiredEndpoint = errors.New("endpoint is retired")

// ingestTelemetry is the hub's single authenticated telemetry seam. It keeps
// request decoding in the HTTP handler and owns the ordered work after that:
// validate identity, snapshot shared state, durably write the event and
// communication projections, then run detection and build control state.
func (s *Server) ingestTelemetry(r *http.Request, tenantID string, batch TelemetryBatchMessage) (map[string]interface{}, error) {
	if strings.TrimSpace(batch.EndpointID) == "" {
		return nil, fmt.Errorf("endpoint_id is required")
	}
	if existing, err := s.store.GetEndpoint(batch.EndpointID); err != nil {
		return nil, fmt.Errorf("load endpoint before ingestion: %w", err)
	} else if existing != nil && existing.Status == "retired" {
		return nil, errRetiredEndpoint
	}

	now := time.Now().UTC()
	ip := requestRemoteIP(r)
	if strings.TrimSpace(batch.IP) != "" {
		ip = strings.TrimSpace(batch.IP)
	}
	ep := storage.Endpoint{
		ID:                       batch.EndpointID,
		TenantID:                 tenantID,
		LocationID:               batch.LocationID,
		RoleTag:                  batch.Role,
		Hostname:                 batch.Hostname,
		OS:                       batch.OS,
		IP:                       ip,
		MAC:                      batch.MAC,
		DriverVersion:            batch.DriverVersion,
		UpdateCapability:         batch.UpdateCapability,
		InstallType:              batch.InstallType,
		PackageIdentifier:        batch.PackageIdentifier,
		RegisteredPackageVersion: batch.RegisteredPackageVersion,
		ProvenanceStatus:         batch.ProvenanceStatus,
		Status:                   "online",
		LastSeenAt:               now,
		CreatedAt:                now,
	}
	// A pre-provenance or legacy agent sends no package fields. Make that
	// absence explicit on every heartbeat instead of retaining a stale native
	// receipt from an earlier binary or rollback.
	if strings.TrimSpace(ep.ProvenanceStatus) == "" {
		ep.ProvenanceStatus = "unknown"
	}
	if strings.TrimSpace(ep.InstallType) == "" {
		ep.InstallType = "unknown"
	}
	if err := s.store.UpsertEndpoint(ep); err != nil {
		return nil, fmt.Errorf("upsert endpoint: %w", err)
	}
	persisted, err := s.store.GetEndpoint(batch.EndpointID)
	if err != nil || persisted == nil {
		if err == nil {
			err = fmt.Errorf("endpoint disappeared after upsert")
		}
		return nil, fmt.Errorf("load endpoint snapshot: %w", err)
	}
	if err := s.store.SetEndpointCertCN(batch.EndpointID, r.Header.Get("X-Client-CN")); err != nil {
		return nil, fmt.Errorf("record endpoint certificate identity: %w", err)
	}
	if batch.Readiness != nil {
		if err := s.store.SetEndpointObservations(batch.EndpointID, batch.ObservedServices, *batch.Readiness); err != nil {
			return nil, fmt.Errorf("record endpoint readiness: %w", err)
		}
	}

	events := normalizeTelemetryEvents(batch.Events, tenantID, batch.EndpointID, now)
	snapshot, err := s.telemetrySnapshot(tenantID, *persisted, events)
	if err != nil {
		return nil, err
	}
	applyThreatIntel(s.ti, events, batch.EndpointID)

	if err := s.store.InsertTelemetryBatch(events, persisted.Hostname, persisted.LocationID); err != nil {
		return nil, fmt.Errorf("persist telemetry batch: %w", err)
	}
	// Detection sees only durable rows. A detector failure is not allowed to
	// erase accepted telemetry; it is surfaced by the detector's own metrics and
	// logs while the request's durability contract remains true.
	s.detector.EvaluateBatch(events, snapshot)

	return s.telemetryControlResponse(r, batch.EndpointID, batch.DriverVersion, batch.UpdateCapability)
}

func requestRemoteIP(r *http.Request) string {
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil {
		return ip
	}
	return r.RemoteAddr
}

func normalizeTelemetryEvents(input []storage.Event, tenantID, endpointID string, now time.Time) []storage.Event {
	events := make([]storage.Event, len(input))
	copy(events, input)
	for i := range events {
		events[i].TenantID = tenantID
		events[i].EndpointID = endpointID
		if events[i].Timestamp.IsZero() {
			events[i].Timestamp = now
		}
		if events[i].Action == "" {
			events[i].Action = "PERMIT"
		}
		if events[i].Direction == "" {
			events[i].Direction = "OUTBOUND"
		}
	}
	return events
}

func (s *Server) telemetrySnapshot(tenantID string, endpoint storage.Endpoint, events []storage.Event) (detector.BatchSnapshot, error) {
	exclusions, err := s.store.ListExclusions(tenantID)
	if err != nil {
		return detector.BatchSnapshot{}, fmt.Errorf("load exclusion snapshot: %w", err)
	}

	geo := make(map[string]threatintel.GeoRecord)
	firstSeen := make(map[string]bool)
	for i := range events {
		ev := &events[i]
		if _, ok := geo[ev.DstIP]; !ok {
			geo[ev.DstIP] = threatintel.ResolveGeoIP(ev.DstIP)
		}
		if ev.Country == "" || ev.Country == "US" {
			ev.Country = geo[ev.DstIP].Country
		}
		if _, ok := firstSeen[ev.DstIP]; !ok && ev.DstIP != "" {
			firstSeen[ev.DstIP] = s.store.IsFirstSeenDestination(tenantID, ev.DstIP)
		}
	}
	return detector.BatchSnapshot{
		Endpoint:   endpoint,
		Geo:        geo,
		Exclusions: exclusions,
		FirstSeen:  firstSeen,
		LocationID: endpoint.LocationID,
	}, nil
}

func applyThreatIntel(ti *threatintel.Manager, events []storage.Event, endpointID string) {
	checked := make(map[string]*storage.IOC)
	for i := range events {
		for _, address := range []string{events[i].DstIP, events[i].SrcIP} {
			if address == "" {
				continue
			}
			if _, ok := checked[address]; !ok {
				if ioc, found := ti.CheckThreat(address); found {
					checked[address] = ioc
				} else {
					checked[address] = nil
				}
			}
		}
	}
	for i := range events {
		if ioc := checked[events[i].DstIP]; ioc != nil {
			events[i].Action = "BLOCK"
			log.Printf("[!] THREAT MATCH: endpoint %s -> %s blocked (source: %s, threat: %s, confidence: %d%%)",
				endpointID, events[i].DstIP, ioc.Source, ioc.ThreatType, ioc.Confidence)
			continue
		}
		if ioc := checked[events[i].SrcIP]; ioc != nil {
			events[i].Action = "BLOCK"
			log.Printf("[!] THREAT MATCH: inbound %s blocked on endpoint %s (source: %s, threat: %s)",
				events[i].SrcIP, endpointID, ioc.Source, ioc.ThreatType)
		}
	}
}

func (s *Server) telemetryControlResponse(r *http.Request, endpointID, reportedVersion, capability string) (map[string]interface{}, error) {
	qPeers, err := s.store.GetQuarantinedPeers()
	if err != nil {
		return nil, fmt.Errorf("load quarantined peers: %w", err)
	}
	qIPs := make([]string, 0, len(qPeers))
	for _, peer := range qPeers {
		if peer.Active {
			qIPs = append(qIPs, peer.TargetIP)
		}
	}

	isolated, allowIPs, err := s.store.GetEndpointIsolation(endpointID)
	if err != nil {
		return nil, fmt.Errorf("load endpoint isolation: %w", err)
	}
	if allowIPs == nil {
		allowIPs = []string{}
	}
	baseline, err := s.store.ResolveBaseline(endpointID)
	if err != nil {
		return nil, fmt.Errorf("resolve endpoint baseline: %w", err)
	}
	wire, trimmed := storage.CapBaselineWireRules(storage.BaselineWireRules(baseline.Rules))
	if trimmed && baseline.ReadinessReported && len(baseline.Uncovered) == 0 {
		return nil, fmt.Errorf("endpoint baseline exceeds the agent wire limit")
	}

	resp := map[string]interface{}{
		"status":              "ok",
		"quarantined_peers":   qIPs,
		"is_isolated":         isolated,
		"isolation_allow_ips": allowIPs,
		"isolation_baseline":  wire,
	}
	if s.ti != nil {
		resp["threat_indicators"] = s.ti.GetActiveIndicators(128)
	}
	// A retained 1.7.x agent still arrives with the shared tenant key while
	// migration mode is open. Issue its endpoint credential in the successful
	// heartbeat response; the updated native agent writes it to its protected
	// key file and uses the device header on the next beat. The store rotates an
	// unused issuance if this response was lost, but stops rotating once the new
	// credential has actually been used.
	if r.Header.Get("X-Role") == "tenant" && strings.TrimSpace(r.Header.Get("X-Device-Endpoint-ID")) == "" {
		credential, issued, err := s.store.EnsureDeviceCredential(endpointID)
		if err != nil {
			return nil, fmt.Errorf("ensure endpoint device credential: %w", err)
		}
		if issued {
			resp["device_credential"] = credential
			s.audit(r, "DEVICE_CREDENTIAL_MIGRATED", endpointID,
				"Issued a unique device credential to replace legacy shared-key authentication")
		}
	}
	if target, outdated := s.pendingAgentUpdate(endpointID, reportedVersion); outdated {
		if pkg, ok := updatePackageFor(capability); ok {
			if desc, signed := s.agentUpdateDescriptor(r, target, pkg); signed {
				resp["agent_update"] = desc
			}
		}
	}
	return resp, nil
}

func (s *Server) ingestLegacyEvents(tenantID string, events []storage.Event) error {
	now := time.Now().UTC()
	events = normalizeTelemetryEvents(events, tenantID, "", now)
	if len(events) == 0 {
		return nil
	}
	snapshot, err := s.telemetrySnapshot(tenantID, storage.Endpoint{ID: events[0].EndpointID, TenantID: tenantID, RoleTag: "workstation"}, events)
	if err != nil {
		return err
	}
	applyThreatIntel(s.ti, events, events[0].EndpointID)
	if err := s.store.InsertTelemetryBatch(events, "", ""); err != nil {
		return fmt.Errorf("persist legacy telemetry batch: %w", err)
	}
	s.detector.EvaluateBatch(events, snapshot)
	return nil
}
