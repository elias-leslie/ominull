package detector

import (
	"fmt"
	"net/netip"
	"sort"
	"time"

	"ominull/hub/pkg/storage"
	"ominull/hub/pkg/threatintel"
)

// The floor drill.
//
// A tuning save, an exclusion or a code change can blind a floor detector
// without anything else noticing: the detector simply stops raising. The hub
// therefore runs, inside its own process, one synthetic event or burst per
// floor rule through a throwaway engine that reads the live tuning (with the
// floor applied, as the live engine does) and the live exclusions, and checks
// that each still raises. The throwaway engine stores no finding, records no
// learning observation and isolates nothing: its isolate hook only notes that
// it was asked. The server judges the result and reports a miss, or a drill
// that has stopped running, on the Nightshift feed (server/floor_drill.go).

// DrillEndpointID is the endpoint the synthetic events come from. It is never
// enrolled; no finding from it is stored.
const DrillEndpointID = "ominull-floor-drill"

// drillTenant is the tenant whose exclusions the drill runs against.
const drillTenant = "default"

// DrillCase is one floor rule exercised.
type DrillCase struct {
	Rule     string                 `json:"rule"`
	Want     string                 `json:"want"`
	Findings []storage.AnomalyAlert `json:"-"`
	// Isolated is whether the engine asked to isolate the endpoint.
	Isolated bool `json:"isolated,omitempty"`
	// WantIsolated is set where the rule also isolates (a threat-list match).
	WantIsolated bool `json:"-"`
	// Tuning is what the case ran with, for judging how its finding reads.
	Tuning storage.DetectionTuning `json:"-"`
}

// Raised returns the case's finding of the type it wants.
func (c DrillCase) Raised() (storage.AnomalyAlert, bool) {
	for _, f := range c.Findings {
		if f.AnomalyType == c.Want {
			return f, true
		}
	}
	return storage.AnomalyAlert{}, false
}

// drillProgram is where the drill's synthetic programs claim to live: an
// absolute path no quiet list or known workload names.
const drillProgram = "/usr/local/libexec/ominull-floor-drill/"

// Drill runs every floor case against the store's live tuning and exclusions.
func Drill(store *storage.Store, now time.Time) ([]DrillCase, error) {
	exclusions, err := store.ListExclusions(drillTenant)
	if err != nil {
		return nil, fmt.Errorf("read exclusions: %w", err)
	}
	live, _ := ClampToFloor(store.GetDetectionTuning())
	lan := drillLAN(store)
	ep := storage.Endpoint{ID: DrillEndpointID, TenantID: drillTenant, Hostname: DrillEndpointID, RoleTag: "server",
		Status: "online", CreatedAt: now.Add(-30 * 24 * time.Hour), LastSeenAt: now}

	flow := func(proc string, dst string, port uint16, bytes int64, at time.Duration) storage.Event {
		return storage.Event{TenantID: drillTenant, EndpointID: DrillEndpointID, Timestamp: now.Add(at),
			Action: "PERMIT", Direction: "OUTBOUND", Protocol: 6, DstIP: dst, DstPort: port, BytesOut: bytes, ProcessPath: proc}
	}
	run := func(c DrillCase, tuning storage.DetectionTuning, events []storage.Event) DrillCase {
		// EvaluateBatch is synchronous, so the hooks need no lock.
		e := New(store, nil, func(string, string) error {
			c.Isolated = true
			return nil
		})
		e.pinned = &tuning
		e.sink = func(a storage.AnomalyAlert) { c.Findings = append(c.Findings, a) }
		snap := BatchSnapshot{Endpoint: ep, Geo: map[string]threatintel.GeoRecord{}, Exclusions: exclusions, FirstSeen: map[string]bool{}}
		e.EvaluateBatch(events, snap)
		c.Tuning = tuning
		return c
	}

	var cases []DrillCase

	ti := flow(drillProgram+"implant", "203.0.113.66", 443, 600, 0)
	ti.ThreatMatch = &storage.IOC{Value: ti.DstIP, Type: "ipv4", Source: "floor-drill", ThreatType: "c2", Confidence: 100, Active: true}
	cases = append(cases, run(DrillCase{Rule: "threat-list match isolates", Want: "THREAT_INTEL_MATCH", WantIsolated: true}, live, []storage.Event{ti}))

	cases = append(cases, run(DrillCase{Rule: "sensitive port to the internet", Want: "SENSITIVE_PORT_EGRESS"}, live,
		[]storage.Event{flow(drillProgram+"smb", "203.0.113.67", 445, 600, 0)}))

	var sweep []storage.Event
	for i := 0; i < portSweepPorts; i++ {
		sweep = append(sweep, flow(drillProgram+"scanner", "203.0.113.68", uint16(2000+i), 60, time.Duration(i)*100*time.Millisecond))
	}
	cases = append(cases, run(DrillCase{Rule: "port sweep", Want: "PORT_SCAN_RECON"}, live, sweep))

	// Twice the threshold, so a single LAN host the sweep does not count (a
	// container address, say) does not read as a blinded rule.
	var fanout []storage.Event
	for i := 0; i < 2*lateralHosts; i++ {
		fanout = append(fanout, flow(drillProgram+"fanout", lan(200+i), 8080, 60, time.Duration(i)*time.Second))
	}
	cases = append(cases, run(DrillCase{Rule: "lateral sweep", Want: "LATERAL_PORT_SWEEP"}, live, fanout))

	cases = append(cases, run(DrillCase{Rule: "bandwidth burst", Want: "BANDWIDTH_SPIKE"}, live,
		[]storage.Event{flow(drillProgram+"uploader", "203.0.113.69", 443, bandwidthBurstBytes+1<<20, 0)}))

	// A connection test that carried data out is not a connection test: the
	// resolver bypass is raised and the feed must not explain it away.
	probe := flow("/usr/bin/bash", "8.8.8.8", 53, 512, 0)
	probe.CommandLine = "bash -c '</dev/tcp/8.8.8.8/53'"
	cases = append(cases, run(DrillCase{Rule: "resolver bypass shaped as a connection test", Want: "AGENT_DNS_BYPASS"}, live, []storage.Event{probe}))

	// An agent's ssh fan-out from an admin workstation that also reaches SMB:
	// raised, and neither the actor nor the admin rule may explain it.
	admin := live
	admin.AdminFanoutSources = append(append([]string(nil), live.AdminFanoutSources...), DrillEndpointID)
	var ssh []storage.Event
	for i := 0; i < 2*lateralShellHosts; i++ {
		// SMB first, so every window the sweep is judged in holds it.
		port := uint16(22)
		if i == 0 {
			port = 445
		}
		ev := flow("/usr/bin/ssh", lan(241+i), port, 60, time.Duration(i)*time.Second)
		ev.Actor = "agent:claude:f100d411"
		ssh = append(ssh, ev)
	}
	cases = append(cases, run(DrillCase{Rule: "agent ssh fan-out reaching a floor port", Want: "LATERAL_PORT_SWEEP"}, admin, ssh))

	silent := DrillCase{Rule: "host gone quiet", Want: silenceAnomalyType, Tuning: live}
	quiet := ep
	quiet.LastSeenAt = now.Add(-(floorSilenceMinutes + 1) * time.Minute)
	if q, threshold, watched := silentFor(quiet, live, now); watched && q > threshold {
		silent.Findings = []storage.AnomalyAlert{{EndpointID: DrillEndpointID, AnomalyType: silenceAnomalyType, Severity: "HIGH"}}
	}
	cases = append(cases, silent)
	return cases, nil
}

// drillLAN returns addresses in the estate's own LAN: the private IPv4 /24
// holding the most enrolled endpoints (a lab network or a container bridge
// holds fewer), so a container network or exclusion that covers the real LAN
// covers the drill too.
func drillLAN(store *storage.Store) func(host int) string {
	base := netip.MustParseAddr("192.168.250.0")
	count := map[netip.Addr]int{}
	if eps, err := store.ListEndpoints(""); err == nil {
		for _, ep := range eps {
			a, err := netip.ParseAddr(ep.IP)
			if err == nil && a.Is4() && a.IsPrivate() && ep.Status != "retired" {
				b := a.As4()
				count[netip.AddrFrom4([4]byte{b[0], b[1], b[2], 0})]++
			}
		}
	}
	nets := make([]netip.Addr, 0, len(count))
	for n := range count {
		nets = append(nets, n)
	}
	sort.Slice(nets, func(i, j int) bool {
		if count[nets[i]] != count[nets[j]] {
			return count[nets[i]] > count[nets[j]]
		}
		return nets[i].Less(nets[j])
	})
	if len(nets) > 0 {
		base = nets[0]
	}
	return func(host int) string {
		b := base.As4()
		b[3] = byte(host)
		return netip.AddrFrom4(b).String()
	}
}
