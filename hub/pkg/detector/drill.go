package detector

import (
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
// A tuning save, an expected rule or a code change can blind a floor detector
// without anything else noticing: the detector simply stops raising. The hub
// therefore runs, inside its own process, one synthetic event or burst per
// floor rule through a throwaway engine that reads the live tuning (with the
// floor applied, as the live engine does, expected rules included), and checks
// that each still raises. The sweeps run again as each program an expected rule
// names, and the floor cases again inside each rule narrowed to a host, a
// destination range or a port. The throwaway engine stores no finding, writes no device
// memory and isolates nothing: its isolate hook only notes that
// it was asked. The server judges the result and reports a miss, or a drill
// that has stopped running, on the Aico push (server/floor_drill.go).

// DrillEndpointID is the endpoint the synthetic events come from. It is never
// enrolled; no finding from it is stored.
const DrillEndpointID = "ominull-floor-drill"

// drillTenant is the tenant the drill runs as.
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
	// WantClass is the class the finding must carry; "" means page. A rule
	// that is recorded, not paged, must still raise: the drill proves the
	// detector sees it, not that it pushes.
	WantClass string `json:"want_class,omitempty"`
}

// DrillAnyClass as a WantClass asks only that the finding is raised, whatever
// class the tuning's thresholds give it: a sweep on an ordinary port may be
// recorded or paged, depending on the program, the host count and
// lan_sweep_hosts.
const DrillAnyClass = "any"

// Raised returns the case's finding of the type it wants, the one of the
// class it wants where there are several (a beacon is raised when it is first
// seen and again when it is strong enough to page).
func (c DrillCase) Raised() (storage.AnomalyAlert, bool) {
	want := c.WantClass
	if want == "" {
		want = storage.ClassPage
	}
	var first *storage.AnomalyAlert
	for i, f := range c.Findings {
		if f.AnomalyType != c.Want {
			continue
		}
		if want != DrillAnyClass && storage.AlertClass(f) == want {
			return f, true
		}
		if first == nil {
			first = &c.Findings[i]
		}
	}
	if first != nil {
		return *first, true
	}
	return storage.AnomalyAlert{}, false
}

// drillProgram is where the drill's synthetic programs claim to live: an
// absolute path no quiet list or known workload names.
const drillProgram = "/usr/local/libexec/ominull-floor-drill/"

// Drill runs every floor case against the store's live tuning.
func Drill(store *storage.Store, now time.Time) ([]DrillCase, error) {
	return DrillWith(store, now, nil)
}

// DrillWith runs every floor case against a proposed policy: tuning, when not
// nil, instead of the saved tuning. An authorization shows what a loosening change would blind
// before it is applied.
func DrillWith(store *storage.Store, now time.Time, tuning *storage.DetectionTuning) ([]DrillCase, error) {
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
		snap := BatchSnapshot{Endpoint: ep, Geo: map[string]threatintel.GeoRecord{}, FirstSeen: map[string]bool{}, LocationID: location}
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
	// Run from a personal device: a match isolates only the roles in
	// auto_isolate_roles, and an agent workstation or the hypervisor is not
	// cut off automatically.
	tiEP := ep
	tiEP.RoleTag = storage.RolePersonal
	cases = append(cases, runAt(DrillCase{Rule: "threat-list match isolates", Want: "THREAT_INTEL_MATCH", WantIsolated: live.AutoIsolates(storage.RolePersonal)},
		tiEP, "", live, []storage.Event{ti}))

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

	// A connection test that carried data out is not a connection test: the
	// resolver bypass is raised and the feed must not explain it away.
	probe := flow("/usr/bin/bash", "8.8.8.8", 53, 512, 0)
	probe.CommandLine = "bash -c '</dev/tcp/8.8.8.8/53'"
	cases = append(cases, run(DrillCase{Rule: "resolver bypass shaped as a connection test", Want: "AGENT_DNS_BYPASS", WantClass: storage.ClassRecord}, live, []storage.Event{probe}))

	// A decoy address nothing uses: one touch pages. The drill lists its own
	// decoy, so it runs whether or not the operator has listed any.
	decoyed := live
	decoyed.DecoyAddrs = append(append([]string(nil), live.DecoyAddrs...), lan(199))
	cases = append(cases, run(DrillCase{Rule: "decoy touch", Want: "DECOY_TOUCH"}, decoyed,
		[]storage.Event{flow(drillProgram+"mapper", lan(199), 80, 60, 0)}))

	// A device looking up a decoy name (the host in a planted credential)
	// pages, and so does a lookup of a name on a feed sure enough to page.
	runDNS := func(c DrillCase, tuning storage.DetectionTuning, l DNSLookup, intel *storage.IOC) DrillCase {
		e := New(store, nil, func(string, string) error { c.Isolated = true; return nil })
		e.pinned = &tuning
		e.sink = func(a storage.AnomalyAlert) { c.Findings = append(c.Findings, a) }
		l.TenantID, l.At = drillTenant, now
		e.NoteDNSLookup(l, intel)
		c.Tuning = tuning
		return c
	}
	named := live
	named.DecoyNames = append(append([]string(nil), live.DecoyNames...), "floor-drill.decoy.invalid")
	cases = append(cases, runDNS(DrillCase{Rule: "decoy name lookup", Want: "DECOY_TOUCH"}, named,
		DNSLookup{ClientIP: lan(198), Domain: "floor-drill.decoy.invalid"}, nil))
	cases = append(cases, runDNS(DrillCase{Rule: "threat-listed name lookup", Want: "THREAT_INTEL_MATCH"}, live,
		DNSLookup{ClientIP: lan(198), Domain: "floor-drill.c2.invalid"},
		&storage.IOC{Value: "floor-drill.c2.invalid", Type: "domain", Source: "floor-drill", ThreatType: "malicious domain", Confidence: 100, Active: true}))

	// A parked lab guest reaching a home host outside the lab pages.
	labEP := ep
	labEP.RoleTag, labEP.Presence = "", storage.PresenceParked
	var escape []storage.Event
	for i := range min(max(live.LabEscapeHosts, 1), 40) {
		escape = append(escape, flow(drillProgram+"escape", lan(150+i), 8080, 60, time.Duration(i)*time.Second))
	}
	cases = append(cases, runAt(DrillCase{Rule: "lab escape", Want: "LAB_ESCAPE"}, labEP, "", live, escape))

	// A metronomic, uniform beacon to a destination no device reaches pages.
	var beacon []storage.Event
	for i := 0; i <= 40; i++ {
		beacon = append(beacon, flow(drillProgram+"implant", "203.0.113.70", 443, 600, time.Duration(i)*time.Minute))
	}
	cases = append(cases, run(DrillCase{Rule: "rare beacon", Want: "C2_BEACONING"}, live, beacon))

	// An agent's ssh fan-out from an admin workstation that also reaches SMB:
	// raised, and neither the actor nor the admin rule may explain it. The
	// hosts are in the infrastructure zone, so the only thing between this
	// window and the rule's suppression is the floor port.
	admin := live
	admin.InfraCIDRs = append(append([]string(nil), live.InfraCIDRs...), lan(0)+"/24")
	admin.ExpectedRules = append(append([]storage.ExpectedRule(nil), live.ExpectedRules...), storage.ExpectedRule{
		ID: "floor-drill-admin-ssh", Reason: "the drill's own admin ssh rule", Findings: []string{storage.KindLateralSweep},
		Hosts: []string{DrillEndpointID}, Programs: []storage.ExpectedProgram{{Path: "/usr/bin/ssh"}}, Port: 22, MaxHosts: storage.AdminFanoutMaxDefault})
	// Exactly the shell threshold of hosts: within the rule's bound, so the
	// first window the sweep is judged in is one the rule would explain.
	var ssh []storage.Event
	for i := 0; i < lateralShellHosts; i++ {
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

	// A lateral rule that names a floor port itself, which a save refuses but a
	// row from an older build, or a change to the matcher, could let through:
	// the hosts are inventoried, the program and host are the rule's, every
	// connection is on SMB. It must still page.
	onFloor := live
	onFloor.InfraCIDRs = admin.InfraCIDRs
	onFloor.ExpectedRules = append(append([]storage.ExpectedRule(nil), live.ExpectedRules...), storage.ExpectedRule{
		ID: "floor-drill-lateral-on-floor-port", Reason: "the drill's own rule on a floor port", Findings: []string{storage.KindLateralSweep},
		Hosts: []string{DrillEndpointID}, Programs: []storage.ExpectedProgram{{Path: "/usr/bin/ssh"}}, Port: 445, MaxHosts: storage.AdminFanoutMaxDefault})
	var smb []storage.Event
	for i := 0; i < lateralShellHosts; i++ {
		smb = append(smb, flow("/usr/bin/ssh", lan(241+i), 445, 60, time.Duration(i)*time.Second))
	}
	cases = append(cases, run(DrillCase{Rule: "lateral rule on a floor port", Want: "LATERAL_PORT_SWEEP"}, onFloor, smb))

	silent := DrillCase{Rule: "host gone quiet", Want: silenceAnomalyType, Tuning: live}
	quiet := ep
	quiet.LastSeenAt = now.Add(-(floorSilenceMinutes + 1) * time.Minute)
	if q, threshold, _, watched := silentFor(quiet, live, storage.AicoFleet{}, now); watched && q > threshold {
		silent.Findings = []storage.AnomalyAlert{{EndpointID: DrillEndpointID, AnomalyType: silenceAnomalyType, Severity: "HIGH"}}
	}
	cases = append(cases, silent)

	// A machine Aico says is up, its agent quiet past the floor: no presence
	// the host carries can hide it.
	dark := DrillCase{Rule: "machine up, sensor dark", Want: silenceAnomalyType, Tuning: live}
	up := true
	darkHost := quiet
	darkHost.Presence = storage.PresenceParked
	darkRun := New(store, nil, nil)
	darkRun.pinned = &live
	darkRun.sink = func(a storage.AnomalyAlert) { dark.Findings = append(dark.Findings, a) }
	darkRun.sweepEndpoint(darkHost, live, storage.AicoFleet{At: now, Machines: []storage.AicoMachine{
		{Machine: storage.ShortHost(darkHost.Hostname), Up: &up, UpSince: quiet.LastSeenAt}}}, now)
	cases = append(cases, dark)

	// An expected rule silences neither darkRun: each program a rule names is
	// run through both as the process it matches. An installed resolver or
	// container runtime a rule names is exempt from the sweeps in code, not by
	// the rule.
	seen := map[string]bool{}
	now2 := now
	for _, r := range live.ExpectedRules {
		if r.Expired(now2) {
			continue
		}
		for _, prog := range r.Programs {
			path, sha, user := prog.Sample()
			if seen[path+"|"+sha+"|"+user] || isKnownInfrastructureProcess(path, user) {
				continue
			}
			seen[path+"|"+sha+"|"+user] = true
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
			// A shell or interpreter trips the lateral sweep at its lower
			// host count, below the count that pages, so its first sweep
			// is recorded; the case still has to raise.
			lateral := DrillCase{Rule: "lateral sweep as " + path + " (" + user + ")", Want: "LATERAL_PORT_SWEEP"}
			if isInterpreterOrShell(filepath.Base(path)) {
				lateral.WantClass = DrillAnyClass
			}
			cases = append(cases,
				run(DrillCase{Rule: "port sweep as " + path + " (" + user + ")", Want: "PORT_SCAN_RECON"}, live, ports),
				run(lateral, live, hosts))
		}
	}

	// A rule narrowed to a host, a destination range or a port is outside the
	// cases above, which come from no listed program on an unenrolled host.
	// Each one gets the floor cases its traffic could meet - from its host,
	// by its program, to its range and port - wherever the case can be built
	// to match it. The burst is left out: a rule may cover a program's uploads.
	for _, r := range live.ExpectedRules {
		for _, ph := range pinholesOf(r, now) {
			cases = append(cases, drillPinhole(ph, ep, lan, live, runAt)...)
		}
	}
	return cases, nil
}

// pinhole is one narrowed corner of an expected rule, as the drill's traffic
// would meet it.
type pinhole struct {
	id         string
	host       string
	path       string
	sha, user  string
	prefix     netip.Prefix
	ranged     bool
	port       uint16
	proto      string
	hasProgram bool
}

// drillMaxPinholes bounds the cases one rule can add.
const drillMaxPinholes = 8

// pinholesOf lists the corners of a rule that narrow it to a host, a range, a
// port or a protocol; a rule that is only a program (or only a network)
// yields none, since the sweeps above already cover it.
func pinholesOf(r storage.ExpectedRule, now time.Time) []pinhole {
	if r.Expired(now) || !(len(r.Hosts) > 0 || len(r.Prefixes) > 0 || r.Port != 0 || (r.Protocol != "" && r.Protocol != "any")) {
		return nil
	}
	base := pinhole{id: r.ID, port: uint16(r.Port), proto: r.Protocol, user: "root"}
	if len(r.Prefixes) > 0 {
		if p, err := netip.ParsePrefix(r.Prefixes[0]); err == nil {
			base.prefix, base.ranged = p.Masked(), true
		}
	}
	hosts := []string{""}
	if len(r.Hosts) > 0 {
		hosts = r.Hosts
	}
	programs := []storage.ExpectedProgram{{}}
	if len(r.Programs) > 0 {
		programs = r.Programs
	}
	var out []pinhole
	for _, h := range hosts {
		for _, prog := range programs {
			ph := base
			ph.host = h
			if prog.Path != "" {
				ph.path, ph.sha, ph.user = prog.Sample()
				ph.hasProgram = true
			}
			out = append(out, ph)
			if len(out) >= drillMaxPinholes {
				return out
			}
		}
	}
	return out
}

// drillPinhole builds the floor cases one narrowed rule's traffic could
// meet, each made only of events the rule matches; a case that cannot be
// built that way (a sweep across ports under a rule for one port, a
// lateral sweep under a public or small range) is left out.
func drillPinhole(ph pinhole, ep storage.Endpoint, lan func(int) string, tuning storage.DetectionTuning,
	run func(DrillCase, storage.Endpoint, string, storage.DetectionTuning, []storage.Event) DrillCase) []DrillCase {
	location := ""
	if ph.host != "" {
		ep.ID, ep.Hostname = ph.host, ph.host
	}
	proto := uint8(6)
	switch ph.proto {
	case "udp":
		proto = 17
	case "icmp":
		return nil // no ports: none of the cases can match it
	}
	prefix, ranged := ph.prefix, ph.ranged
	// dests returns n destinations of the kind a case needs (private or
	// public): inside the rule's range when it names one, else own(i).
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
		if ph.path != "" {
			return ph.path
		}
		return drillProgram + own
	}
	flow := func(proc, to string, port uint16, bytes int64, offset time.Duration) storage.Event {
		return storage.Event{TenantID: drillTenant, EndpointID: ep.ID, Timestamp: ep.LastSeenAt.Add(offset), Action: "PERMIT",
			Direction: "OUTBOUND", Protocol: proto, DstIP: to, DstPort: port, BytesOut: bytes, ProcessPath: proc, UserIdentity: ph.user, ExecutableSHA256: ph.sha}
	}
	add := func(cases []DrillCase, c DrillCase, events []storage.Event) []DrillCase {
		c.Rule += " under rule " + ph.id
		return append(cases, run(c, ep, location, tuning, events))
	}
	// An installed container runtime or resolver is exempt from the sweeps in
	// code, whatever the rule says.
	infra := ph.path != "" && isKnownInfrastructureProcess(ph.path, ph.user)
	var cases []DrillCase

	if to, ok := dests(1, false, public("203.0.113.66")); ok {
		port := ph.port
		if port == 0 {
			port = 443
		}
		ti := flow(path("implant"), to[0], port, 600, 0)
		kind := "ipv4"
		if netip.MustParseAddr(to[0]).Is6() {
			kind = "ipv6"
		}
		ti.ThreatMatch = &storage.IOC{Value: to[0], Type: kind, Source: "floor-drill", ThreatType: "c2", Confidence: 100, Active: true}
		role := NewClassContext(tuning, nil, nil).RoleOf(ep)
		cases = add(cases, DrillCase{Rule: "threat-list match", Want: "THREAT_INTEL_MATCH", WantIsolated: tuning.AutoIsolates(role)}, []storage.Event{ti})
	}
	if to, ok := dests(1, false, public("203.0.113.67")); ok && (ph.port == 0 || FloorPort(int(ph.port))) {
		port := ph.port
		if port == 0 {
			port = 445
		}
		cases = add(cases, DrillCase{Rule: "sensitive port", Want: "SENSITIVE_PORT_EGRESS"}, []storage.Event{flow(path("smb"), to[0], port, 600, 0)})
	}
	if to, ok := dests(1, false, public("203.0.113.68")); ok && ph.port == 0 && !infra {
		var sweep []storage.Event
		for i := 0; i < portSweepPorts; i++ {
			sweep = append(sweep, flow(path("scanner"), to[0], uint16(2000+i), 60, time.Duration(i)*100*time.Millisecond))
		}
		cases = add(cases, DrillCase{Rule: "port sweep", Want: "PORT_SCAN_RECON"}, sweep)
	}
	// Twice the threshold of hosts, on SMB unless the rule names a port.
	// A container network is outside the lateral rule by design; the
	// estate-wide case shows one laid over the LAN.
	if to, ok := dests(2*lateralHosts, true, func(i int) string { return lan(200 + i) }); ok && !infra && !tuning.IsContainerAddress(to[0]) {
		port := ph.port
		if port == 0 {
			port = 445
		}
		var fanout []storage.Event
		for i, host := range to {
			fanout = append(fanout, flow(path("fanout"), host, port, 60, time.Duration(i)*time.Second))
		}
		lateral := DrillCase{Rule: "lateral sweep", Want: "LATERAL_PORT_SWEEP"}
		// A sweep on a port outside the floor list (a rule for ssh on 22) is
		// recorded or paged by the program, the host count and lan_sweep_hosts;
		// the case only has to raise.
		if ph.port != 0 && !FloorPort(int(ph.port)) {
			lateral.WantClass = DrillAnyClass
		}
		cases = add(cases, lateral, fanout)
	}
	// The resolver bypass is judged for agent runtimes and interpreters only.
	resolver := ph.path
	if resolver == "" {
		resolver = "/usr/bin/bash"
	}
	name := filepath.Base(strings.ReplaceAll(resolver, "\\", "/"))
	google := netip.MustParseAddr("8.8.8.8")
	if (!ranged || prefix.Contains(google)) && (ph.port == 0 || ph.port == 53) &&
		(tuning.AgentRuntimeOf(resolver) != "" || isInterpreterOrShell(name)) {
		cases = add(cases, DrillCase{Rule: "resolver bypass", Want: "AGENT_DNS_BYPASS", WantClass: storage.ClassRecord}, []storage.Event{flow(resolver, google.String(), 53, 512, 0)})
	}
	return cases
}

// drillLAN returns addresses in the estate's own LAN: the private IPv4 /24
// holding the most enrolled endpoints (a lab network or a container bridge
// holds fewer), so a container network or rule that covers the real LAN
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
