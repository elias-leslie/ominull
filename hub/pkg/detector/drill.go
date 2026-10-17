package detector

import (
	"fmt"
	"net/netip"
	"path/filepath"
	"sort"
	"strings"
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
// that each still raises. The sweeps run again as each quiet process, and the
// floor cases again inside each exclusion scoped to one endpoint, location or
// program. The throwaway engine stores no finding, records no
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
	return DrillWith(store, now, nil, nil)
}

// DrillWith runs every floor case against a proposed policy: tuning, when not
// nil, instead of the saved tuning, and exclusions, when not nil, instead of
// the saved ones. An owner approval shows what a loosening change would blind
// before it is applied.
func DrillWith(store *storage.Store, now time.Time, tuning *storage.DetectionTuning, exclusions []storage.Exclusion) ([]DrillCase, error) {
	if exclusions == nil {
		var err error
		if exclusions, err = store.ListExclusions(drillTenant); err != nil {
			return nil, fmt.Errorf("read exclusions: %w", err)
		}
	}
	saved := store.GetDetectionTuning()
	if tuning != nil {
		saved = *tuning
	}
	live, _ := ClampToFloor(saved)
	lan := drillLAN(store)
	ep := storage.Endpoint{ID: DrillEndpointID, TenantID: drillTenant, Hostname: DrillEndpointID, RoleTag: "server",
		Status: "online", CreatedAt: now.Add(-30 * 24 * time.Hour), LastSeenAt: now}

	flow := func(proc string, dst string, port uint16, bytes int64, at time.Duration) storage.Event {
		return storage.Event{TenantID: drillTenant, EndpointID: DrillEndpointID, Timestamp: now.Add(at),
			Action: "PERMIT", Direction: "OUTBOUND", Protocol: 6, DstIP: dst, DstPort: port, BytesOut: bytes, ProcessPath: proc}
	}
	runAt := func(c DrillCase, ep storage.Endpoint, location string, tuning storage.DetectionTuning, events []storage.Event) DrillCase {
		// EvaluateBatch is synchronous, so the hooks need no lock.
		e := New(store, nil, func(string, string) error {
			c.Isolated = true
			return nil
		})
		e.pinned = &tuning
		e.sink = func(a storage.AnomalyAlert) { c.Findings = append(c.Findings, a) }
		snap := BatchSnapshot{Endpoint: ep, Geo: map[string]threatintel.GeoRecord{}, Exclusions: exclusions, FirstSeen: map[string]bool{}, LocationID: location}
		e.EvaluateBatch(events, snap)
		c.Tuning = tuning
		return c
	}
	run := func(c DrillCase, tuning storage.DetectionTuning, events []storage.Event) DrillCase {
		return runAt(c, ep, "", tuning, events)
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

	// A quiet process silences neither sweep: each entry's sweeps are run as
	// the process it matches. An installed resolver or container runtime
	// listed there is exempt from the sweeps in code, not by the entry.
	for _, entry := range live.QuietProcesses {
		path, sha, user := storage.QuietProcessSample(entry)
		if isKnownInfrastructureProcess(path, user) {
			continue
		}
		as := func(ev storage.Event) storage.Event {
			ev.ProcessPath, ev.ExecutableSHA256, ev.UserIdentity = path, sha, user
			return ev
		}
		var ports, hosts []storage.Event
		for _, ev := range sweep {
			ports = append(ports, as(ev))
		}
		for _, ev := range fanout {
			hosts = append(hosts, as(ev))
		}
		cases = append(cases,
			run(DrillCase{Rule: "port sweep as " + path + " (" + user + ")", Want: "PORT_SCAN_RECON"}, live, ports),
			run(DrillCase{Rule: "lateral sweep as " + path + " (" + user + ")", Want: "LATERAL_PORT_SWEEP"}, live, hosts))
	}

	// An exclusion scoped to one endpoint, location or program is outside the
	// cases above, which come from no listed program on an unenrolled host. Each
	// one gets the floor cases its traffic could meet - from its endpoint, at
	// its location, by its program, to its range and port - wherever the case
	// can be built to match it. The burst is left out: an exclusion may cover a
	// program's uploads (detector.go).
	for _, ex := range exclusions {
		if !ex.Active || ex.Problem(now) != "" || !(ex.Scope == "endpoint" || ex.Scope == "location" || ex.ProcessPath != "") {
			continue
		}
		cases = append(cases, drillExclusion(ex, ep, lan, live, runAt)...)
	}
	return cases, nil
}

// drillExclusion builds the floor cases one scoped exclusion's traffic could
// meet, each made only of events the exclusion matches; a case that cannot be
// built that way (a sweep across ports under an exclusion for one port, a
// lateral sweep under a public or small range) is left out.
func drillExclusion(ex storage.Exclusion, ep storage.Endpoint, lan func(int) string, tuning storage.DetectionTuning,
	run func(DrillCase, storage.Endpoint, string, storage.DetectionTuning, []storage.Event) DrillCase) []DrillCase {
	location := ""
	switch ex.Scope {
	case "endpoint":
		ep.ID, ep.Hostname = ex.ScopeValue, ex.ScopeValue
	case "location":
		location = ex.ScopeValue
	}
	proto := uint8(6)
	switch strings.ToLower(strings.TrimSpace(ex.Protocol)) {
	case "udp":
		proto = 17
	case "icmp":
		return nil // no ports: none of the cases can match it
	}
	prefix, ranged := ex.DstPrefix()
	// dests returns n destinations of the kind a case needs (private or
	// public): inside the exclusion's range when it names one, else own(i).
	dests := func(n int, private bool, own func(int) string) ([]string, bool) {
		out := make([]string, 0, n)
		if !ranged {
			for i := 0; i < n; i++ {
				out = append(out, own(i))
			}
			return out, true
		}
		a := prefix.Addr()
		if prefix.Bits() < a.BitLen() {
			a = a.Next() // past the network address
		}
		for i := 0; i < n; i++ {
			if !a.IsValid() || !prefix.Contains(a) || isPrivateIP(a.String()) != private {
				return nil, false
			}
			out = append(out, a.String())
			a = a.Next()
		}
		return out, true
	}
	public := func(addr string) func(int) string { return func(int) string { return addr } }
	path := func(own string) string {
		if ex.ProcessPath != "" {
			return ex.ProcessPath
		}
		return drillProgram + own
	}
	flow := func(proc, to string, port uint16, bytes int64, offset time.Duration) storage.Event {
		return storage.Event{TenantID: drillTenant, EndpointID: ep.ID, Timestamp: ep.LastSeenAt.Add(offset), Action: "PERMIT",
			Direction: "OUTBOUND", Protocol: proto, DstIP: to, DstPort: port, BytesOut: bytes, ProcessPath: proc, UserIdentity: "root"}
	}
	add := func(cases []DrillCase, c DrillCase, events []storage.Event) []DrillCase {
		c.Rule += " under exclusion " + ex.ID
		return append(cases, run(c, ep, location, tuning, events))
	}
	// An installed container runtime or resolver is exempt from the sweeps in
	// code, whatever the exclusion says.
	infra := ex.ProcessPath != "" && isKnownInfrastructureProcess(ex.ProcessPath, "root")
	var cases []DrillCase

	if to, ok := dests(1, false, public("203.0.113.66")); ok {
		port := ex.Port
		if port == 0 {
			port = 443
		}
		ti := flow(path("implant"), to[0], port, 600, 0)
		kind := "ipv4"
		if netip.MustParseAddr(to[0]).Is6() {
			kind = "ipv6"
		}
		ti.ThreatMatch = &storage.IOC{Value: to[0], Type: kind, Source: "floor-drill", ThreatType: "c2", Confidence: 100, Active: true}
		cases = add(cases, DrillCase{Rule: "threat-list match", Want: "THREAT_INTEL_MATCH", WantIsolated: true}, []storage.Event{ti})
	}
	if to, ok := dests(1, false, public("203.0.113.67")); ok && (ex.Port == 0 || FloorPort(int(ex.Port))) {
		port := ex.Port
		if port == 0 {
			port = 445
		}
		cases = add(cases, DrillCase{Rule: "sensitive port", Want: "SENSITIVE_PORT_EGRESS"}, []storage.Event{flow(path("smb"), to[0], port, 600, 0)})
	}
	if to, ok := dests(1, false, public("203.0.113.68")); ok && ex.Port == 0 && !infra {
		var sweep []storage.Event
		for i := 0; i < portSweepPorts; i++ {
			sweep = append(sweep, flow(path("scanner"), to[0], uint16(2000+i), 60, time.Duration(i)*100*time.Millisecond))
		}
		cases = add(cases, DrillCase{Rule: "port sweep", Want: "PORT_SCAN_RECON"}, sweep)
	}
	// Twice the threshold of hosts, on SMB unless the exclusion names a port.
	// A container network is outside the lateral rule by design; the
	// estate-wide case shows one laid over the LAN.
	if to, ok := dests(2*lateralHosts, true, func(i int) string { return lan(200 + i) }); ok && !infra && !tuning.IsContainerAddress(to[0]) {
		port := ex.Port
		if port == 0 {
			port = 445
		}
		var fanout []storage.Event
		for i, host := range to {
			fanout = append(fanout, flow(path("fanout"), host, port, 60, time.Duration(i)*time.Second))
		}
		cases = add(cases, DrillCase{Rule: "lateral sweep", Want: "LATERAL_PORT_SWEEP"}, fanout)
	}
	// The resolver bypass is judged for agent runtimes and interpreters only.
	resolver := ex.ProcessPath
	if resolver == "" {
		resolver = "/usr/bin/bash"
	}
	name := filepath.Base(strings.ReplaceAll(resolver, "\\", "/"))
	google := netip.MustParseAddr("8.8.8.8")
	if (!ranged || prefix.Contains(google)) && (ex.Port == 0 || ex.Port == 53) &&
		(tuning.AgentRuntimeOf(resolver) != "" || isInterpreterOrShell(name)) {
		cases = add(cases, DrillCase{Rule: "resolver bypass", Want: "AGENT_DNS_BYPASS"}, []storage.Event{flow(resolver, google.String(), 53, 512, 0)})
	}
	return cases
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
