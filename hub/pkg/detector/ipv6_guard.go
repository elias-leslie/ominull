package detector

import (
	"encoding/json"
	"github.com/google/uuid"
	"ominull/hub/pkg/ipv6guard"
	"ominull/hub/pkg/storage"
	"ominull/hub/pkg/threatintel"
	"strings"
)

// Infrastructure findings retain the normal learning hold semantics and never
// request automatic isolation. A rule mismatch is not proof of compromise.
func (e *Engine) RecordIPv6Finding(f storage.IPv6Finding, c ipv6guard.Config) error {
	o := f.Observation
	ep := storage.Endpoint{TenantID: c.TenantID}
	fields := map[string]any{"ipv6_observation": o, "violations": f.Reasons, "source_ip": o.Source, "source_mac": o.MAC}
	if a, err := e.store.GetAsset(o.Source); err == nil && a != nil && (a.TenantID == "" || a.TenantID == c.TenantID) {
		fields["source_asset_id"] = a.ID
		if a.AgentEndpointID != "" {
			if found, err := e.store.GetEndpoint(a.AgentEndpointID); err == nil && found != nil && found.TenantID == c.TenantID {
				ep = *found
			}
		}
	}
	raw, _ := json.Marshal(fields)
	ev := storage.Event{TenantID: c.TenantID, EndpointID: ep.ID, SrcIP: o.Source, DstIP: o.Destination, Protocol: 58, Timestamp: o.LastSeen}
	if o.Kind == "dhcpv6_server" || o.Kind == "wpad_query" {
		ev.Protocol = 17
	}
	return e.recordAnomaly(ev, threatintel.GeoRecord{}, ep, storage.AnomalyAlert{
		ID: uuid.NewString(), TenantID: c.TenantID, EndpointID: ep.ID, Hostname: ep.Hostname,
		AnomalyType: "IPV6_INFRASTRUCTURE", Severity: "HIGH", Title: "IPv6 infrastructure differs from approved configuration",
		Description: strings.Join(f.Reasons, "; ") + ". Verify the source and configuration; this observation alone does not prove an attack.",
		Details:     o.Summary(), Evidence: string(raw), Technique: "T1557", Timestamp: o.LastSeen,
	})
}
