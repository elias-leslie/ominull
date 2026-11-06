package detector

import (
	"encoding/json"
	"strings"

	"ominull/hub/pkg/storage"
	"ominull/hub/pkg/threatintel"
)

// expectCtx describes one flow for the expected-rule matcher
// (storage.DetectionTuning.Expected). quietPath is the process path the
// detectors compare programs by: empty when the agent found that its reported
// path is not the file that runs, so such a process matches no rule that names
// a program. vouched is the workload (an interpreter and what it runs) under
// the same condition.
func expectCtx(ev storage.Event, geo threatintel.GeoRecord, endpoint storage.Endpoint, role, quietPath, vouched string) storage.ExpectCtx {
	return storage.ExpectCtx{
		Host:      strings.ToLower(ev.EndpointID),
		Role:      role,
		Path:      quietPath,
		SHA:       ev.ExecutableSHA256,
		User:      ev.UserIdentity,
		Workload:  vouched,
		Domain:    firstNonEmpty(ev.SNI, ev.Domain),
		DstIP:     ev.DstIP,
		Port:      int(ev.DstPort),
		Protocol:  ev.Protocol,
		Direction: ev.Direction,
		ASN:       geo.ASN,
		Org:       geo.Org,
		Tenancy:   geo.Tenancy,
		Source:    geo.Source,
	}
}

// expectedFor binds a flow to the tuning's rules: the returned function says
// whether a finding of that kind is expected here.
func expectedFor(cfg storage.DetectionTuning, c storage.ExpectCtx) func(kind string) bool {
	return func(kind string) bool {
		c.Kind = kind
		_, ok := cfg.Expected(c)
		return ok
	}
}

// FindingKinds are the expected-rule kinds that would have made a stored
// finding expected: its anomaly type, and for a bandwidth finding the floor's
// burst line (marked in its evidence) the burst kind. Empty when no rule can
// cover it.
func FindingKinds(a storage.AnomalyAlert) []string {
	return storage.ExpectedKindsOf(a.AnomalyType, strings.Contains(a.Evidence, `"floor_rule":"bandwidth_burst"`))
}

// FindingExpectCtx rebuilds the flow behind a stored finding from its row and
// its evidence, for replaying the rules over history and for marking a finding
// expected. Fields the finding does not carry are left empty, which only
// narrows what a rule can match.
func FindingExpectCtx(a storage.AnomalyAlert, role string) storage.ExpectCtx {
	var f struct {
		CommandLine string  `json:"command_line"`
		User        string  `json:"user_identity"`
		SHA         string  `json:"executable_sha256"`
		Attribution string  `json:"attribution_status"`
		Domain      string  `json:"domain"`
		SNI         string  `json:"sni"`
		ASN         string  `json:"destination_asn"`
		Owner       string  `json:"destination_owner"`
		Tenancy     string  `json:"destination_tenancy"`
		Source      string  `json:"attribution_source"`
		Protocol    float64 `json:"protocol"`
	}
	if strings.TrimSpace(a.Evidence) != "" {
		_ = json.Unmarshal([]byte(a.Evidence), &f)
	}
	path := a.ProcessPath
	if strings.TrimSpace(f.Attribution) == storage.AttributionPathMismatch {
		path = ""
	}
	return storage.ExpectCtx{
		Host:      strings.ToLower(a.EndpointID),
		Role:      role,
		Path:      path,
		SHA:       f.SHA,
		User:      f.User,
		Workload:  vouchedWorkload(a.ProcessPath, f.CommandLine, f.Attribution),
		Domain:    firstNonEmpty(f.SNI, f.Domain),
		DstIP:     a.DstIP,
		Port:      int(a.DstPort),
		Protocol:  uint8(f.Protocol),
		Direction: "OUTBOUND",
		ASN:       strings.TrimSpace(f.ASN),
		Org:       strings.TrimSpace(f.Owner),
		Tenancy:   strings.TrimSpace(f.Tenancy),
		Source:    strings.TrimSpace(f.Source),
	}
}
