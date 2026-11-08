package storage

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"regexp"
	"sort"
	"strings"
	"time"

	"golang.org/x/net/publicsuffix"

	"ominull/hub/pkg/netaddr"
)

// Expected rules: the one place the operator says "this is normal here".
//
// A rule matches on any combination of program, destination, host and port,
// and its effect is to suppress the named finding kinds. Every detector that
// can be told something is expected asks the same function (Expected) with the
// kind it is about to raise and the facts of the flow; there are no other
// lists of exceptions. The rules are data in the tuning row, edited through the
// hub API without a release; the Go values below are only what a hub that was
// never tuned starts with.
//
// Rules never reach the floor. Only the kinds in expectableKinds consult the
// matcher: the sensitive ports, port sweeps, threat-list matches, decoys, lab
// escapes, the resolver bypass and silence cannot be made expected by any rule.
// Inside a rule, an exception always wins over a match (ExceptDomains, rented
// compute), and a rule that does not name the findings it covers never covers a
// kind that pages on its own account (explicitKinds).
//
// Every clause a rule sets must match; a list inside a clause matches on any
// entry. Past ExpiresAt a rule vouches for nothing and the next save drops it.
//
// Program. Programs is [{path, sha256, run_as, exact}]: the lower-cased installed
// path, * for one path segment such as a version number; run_as is "system" (root
// and the system accounts) or one account; exact keeps the path as written, with
// no pattern and no " (deleted)" allowance, as a migrated exclusion had it.
// Runtime names an agent runtime from agent_runtimes. Workload is an interpreter
// plus the script it runs (python3.13 /srv/app/.venv/bin/python -m app.worker) or
// an installed path. A program in a folder any account can write (/tmp, /var/tmp,
// /dev/shm) needs sha256; one under /home does not, so a self-updating program
// stays expected after it updates, bound by run_as. A workload needs an absolute
// script, -m module or -jar file; inline (-c, -e), stdin and preloaded code make
// it "<interpreter> -c", which never matches. A workload rule needs an expires_at
// at most 90 days out, and an interpreter workload must name networks or prefixes
// (* means any named network).
//
// Destination. Domains, prefixes and networks (AS numbers, exact network names,
// or * for any named network). A name is only what a client sent, so domains must
// be anchored by prefixes or networks, and a rule listing domains needs the name
// the client asked for under one of them as well as the address. A rule naming a
// vendor must list its domains; vendor prefixes are no wider than /16 or /32.
// ExceptDomains are names under the listed domains that are anyone's (Cloud
// Storage buckets) and never match. Tenancy is "vendor" (only a published maker
// range), the default (any network that is not rented compute) or "any" (rented
// compute too, which an implant can hide in). No prefix and no network matches any
// destination.
//
// Narrowing. Hosts (endpoint ids or roles), port, protocol, direction, and
// max_hosts for a lateral fan-out (at most 8; left out it means 8). A lateral rule
// names hosts, programs and one port, never a floor port, and a window that touches
// a floor port is never routine.
//
// Effect. Findings lists the kinds it makes expected; empty means every kind except
// explicitKinds, which a rule covers only when it names them.

// The finding kinds a rule can make expected. A kind is what the detector asks
// about, which is usually the anomaly type; the bandwidth detector asks twice,
// because a baselined outlier and a single transfer past the burst line yield
// to different rules.
const (
	KindNovelProcess     = "NOVEL_PROCESS_EGRESS"
	KindOffHours         = "OFF_HOURS_ACTIVITY"
	KindBandwidthSpike   = "BANDWIDTH_SPIKE"
	KindBandwidthBurst   = "BANDWIDTH_BURST"
	KindBeacon           = "C2_BEACONING"
	KindNovelDestination = "NOVEL_DESTINATION"
	KindNewPlaceUpload   = "NEW_PLACE_UPLOAD"
	KindAgentNewDest     = "AGENT_NEW_DESTINATION"
	KindAgentUpload      = "AGENT_UPLOAD_VOLUME"
	KindCloudStorage     = "CLOUD_STORAGE_EGRESS"
	KindLateralSweep     = "LATERAL_PORT_SWEEP"
)

// expectableKinds are every kind a rule may name.
var expectableKinds = []string{
	KindNovelProcess, KindOffHours, KindBandwidthSpike, KindBandwidthBurst, KindBeacon, KindNovelDestination,
	KindNewPlaceUpload, KindAgentNewDest, KindAgentUpload, KindCloudStorage, KindLateralSweep,
}

// explicitKinds page, or hide a transfer the operator is told about, on their
// own account. A rule covers them only when it names them, so "this program
// anywhere" can never silence an upload to a new place.
var explicitKinds = map[string]bool{
	KindNewPlaceUpload: true, KindAgentUpload: true, KindCloudStorage: true, KindLateralSweep: true,
}

// ExpectableKind says whether a finding kind can be made expected at all.
func ExpectableKind(kind string) bool {
	for _, k := range expectableKinds {
		if k == kind {
			return true
		}
	}
	return false
}

// ExpectedKindsOf maps a stored finding to the kinds that make it expected:
// its anomaly type, and for a bandwidth finding raised by the burst line the
// burst kind. Empty means nothing can make it expected (a floor rule).
func ExpectedKindsOf(anomalyType string, burst bool) []string {
	switch {
	case anomalyType == KindBandwidthSpike && burst:
		return []string{KindBandwidthBurst}
	case ExpectableKind(anomalyType):
		return []string{anomalyType}
	}
	return nil
}

// Tenancy values of a rule's network clause.
const (
	// ExpectedTenancyDefault covers a network wherever it is not rented
	// compute: an EC2 instance is Amazon's address and somebody else's machine.
	ExpectedTenancyDefault = ""
	// ExpectedTenancyVendor covers only what a published feed attributes to
	// the maker's own service, never its rented compute or a shared CDN.
	ExpectedTenancyVendor = "vendor"
	// ExpectedTenancyAny also covers rented compute and unnamed addresses, for
	// a program whose job is those destinations (a crawler).
	ExpectedTenancyAny = "any"
)

// FloorPortList is SMB, RDP, telnet and RPC: how a worm moves. No expected rule
// explains a flow on one (the detector's floor, detector/floor.go).
var FloorPortList = [...]int{23, 135, 445, 3389}

// IsFloorPort says whether a port is on the sensitive-port floor.
func IsFloorPort(p int) bool {
	for _, f := range FloorPortList {
		if p == f {
			return true
		}
	}
	return false
}

// AnyNetwork is the network entry for any named network.
const AnyNetwork = "*"

// ExpectedMaxWorkloadLifetime is the longest term a rule that identifies a
// program by an interpreter and what it runs can be written for: that name is
// read from a command line any process can imitate.
const ExpectedMaxWorkloadLifetime = 90 * 24 * time.Hour

// ExpectedProgram names one program by where it is installed. Path may use "*"
// for one path segment (a versioned directory). SHA256 pins one build and is
// left out for a program that updates itself. RunAs binds the entry to the
// account it runs as: "system" for root and the system accounts, or one
// service account name (which also admits the system ones).
//
// Exact matches the reported path as it is written, with no pattern, no case
// folding of a Unix path and no " (deleted)" allowance: what an exclusion
// named, carried over as it was.
type ExpectedProgram struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256,omitempty"`
	RunAs  string `json:"run_as,omitempty"`
	Exact  bool   `json:"exact,omitempty"`
}

// ExpectedRule is one expected thing. Every clause that is set must match; a
// list inside a clause matches on any of its entries.
//
//   - Programs, Runtime and Workload name the program: by installed path, by an
//     agent runtime from the tuning's agent_runtimes, or by an interpreter
//     together with the script it runs (detector.WorkloadOf).
//   - Domains, Prefixes and Networks name the destination. Networks are AS
//     numbers, exact network names, or "*" for any named network. A name is
//     only what a client sent, so Domains must be anchored by Prefixes or
//     Networks: the name counts where the address proves it. ExceptDomains are
//     names under those domains that are anyone's (Cloud Storage buckets) and
//     never match.
//   - Hosts are endpoint ids or roles; Port, Protocol and Direction narrow the
//     flow; MaxHosts bounds a lateral fan-out (LATERAL_PORT_SWEEP only).
//   - Findings are the kinds it makes expected; empty is every kind that does
//     not page on its own account.
//
// ExpiresAt is optional, except for a Workload, which is bounded.
type ExpectedRule struct {
	ID string `json:"id"`
	// Name is a short label for the console; Reason is why it is expected.
	Name     string   `json:"name,omitempty"`
	Reason   string   `json:"reason"`
	Findings []string `json:"findings,omitempty"`

	Programs []ExpectedProgram `json:"programs,omitempty"`
	Runtime  string            `json:"runtime,omitempty"`
	Workload string            `json:"workload,omitempty"`
	Hosts    []string          `json:"hosts,omitempty"`

	// Vendor is the maker's display name, for the sentence that explains a
	// finding; it matches nothing.
	Vendor        string   `json:"vendor,omitempty"`
	Domains       []string `json:"domains,omitempty"`
	ExceptDomains []string `json:"except_domains,omitempty"`
	Prefixes      []string `json:"prefixes,omitempty"`
	Networks      []string `json:"networks,omitempty"`
	Tenancy       string   `json:"tenancy,omitempty"`

	Port      int    `json:"port,omitempty"`
	Protocol  string `json:"protocol,omitempty"`
	Direction string `json:"direction,omitempty"`
	MaxHosts  int    `json:"max_hosts,omitempty"`

	ExpiresAt time.Time `json:"expires_at,omitzero"`
}

// UnmarshalJSON starts from an empty rule. Saved tuning is decoded over the
// shipped defaults and encoding/json decodes an array into the existing
// elements in place, so without this a saved rule missing a field kept
// whatever the shipped rule at its position held (the same fault as
// AgentRuntimeVendor's, which merged Claude with Google's network).
func (r *ExpectedRule) UnmarshalJSON(b []byte) error {
	type plain ExpectedRule
	var p plain
	if err := json.Unmarshal(b, &p); err != nil {
		return err
	}
	*r = ExpectedRule(p)
	return nil
}

// Expired reports a rule past its expiry; one without an expiry never is.
func (r ExpectedRule) Expired(now time.Time) bool {
	return !r.ExpiresAt.IsZero() && !now.Before(r.ExpiresAt)
}

// covers says whether the rule makes this kind expected.
func (r ExpectedRule) covers(kind string) bool {
	if !ExpectableKind(kind) {
		return false
	}
	if len(r.Findings) == 0 {
		return !explicitKinds[kind]
	}
	for _, f := range r.Findings {
		if f == kind {
			return true
		}
	}
	return false
}

// ExpectCtx is the flow a detector is about to raise a finding about.
type ExpectCtx struct {
	Kind string
	// Host is the endpoint id and Role its zone role.
	Host, Role string
	// Path, SHA and User describe the process. Path is empty when the agent
	// found that its reported path is not the file that runs.
	Path, SHA, User string
	// Workload is the interpreter-and-script form, empty when unknown or
	// path-mismatched.
	Workload string
	// Domain is the name the client asked for (SNI, else the resolved name).
	Domain string
	DstIP  string
	Port   int
	// Protocol is the IP protocol number; 0 when unknown.
	Protocol  uint8
	Direction string
	// ASN, Org, Tenancy and Source are the destination's network attribution.
	ASN, Org, Tenancy, Source string
	// Targets is the number of hosts in a lateral fan-out window.
	Targets int
}

// Expected returns the rule that makes this flow's finding expected, if one
// does. Expired rules never match.
func (t DetectionTuning) Expected(c ExpectCtx) (ExpectedRule, bool) {
	if !ExpectableKind(c.Kind) {
		return ExpectedRule{}, false
	}
	now := time.Now()
	for _, r := range t.ExpectedRules {
		if r.matches(t, c, now) {
			return r, true
		}
	}
	return ExpectedRule{}, false
}

func (r ExpectedRule) matches(t DetectionTuning, c ExpectCtx, now time.Time) bool {
	if r.Expired(now) || !r.covers(c.Kind) {
		return false
	}
	// A fan-out that touches a floor port is never routine, whatever a rule
	// says (a saved row can hold one that a save would now refuse).
	if c.Kind == KindLateralSweep && (IsFloorPort(c.Port) || IsFloorPort(r.Port)) {
		return false
	}
	if len(r.Hosts) > 0 && !listHas(r.Hosts, c.Host) && !listHas(r.Hosts, c.Role) {
		return false
	}
	if r.Direction != "" && !strings.EqualFold(r.Direction, c.Direction) {
		return false
	}
	if r.Port != 0 && r.Port != c.Port {
		return false
	}
	if r.Protocol != "" && r.Protocol != "any" && r.Protocol != protocolName(c.Protocol) {
		return false
	}
	if r.Runtime != "" && (!t.AgentEgressOn || c.Path == "" || t.AgentRuntimeOf(c.Path) != r.Runtime) {
		return false
	}
	if len(r.Programs) > 0 && !r.programMatches(c) {
		return false
	}
	if r.Workload != "" && (c.Workload == "" || isInlineWorkload(c.Workload) || !matchWorkload(r.Workload, c.Workload)) {
		return false
	}
	if !r.destinationMatches(c) {
		return false
	}
	if c.Kind == KindLateralSweep && c.Targets > RuleMaxHosts(r) {
		return false
	}
	return true
}

// RuleMaxHosts is how many hosts a lateral fan-out rule admits: its max_hosts,
// else the default (an omitted bound is not an unlimited one, nor a smaller one).
func RuleMaxHosts(r ExpectedRule) int {
	if r.MaxHosts > 0 {
		return r.MaxHosts
	}
	return AdminFanoutMaxDefault
}

func (r ExpectedRule) programMatches(c ExpectCtx) bool {
	key := ProcessPathKey(c.Path)
	if key == "" {
		return false
	}
	for _, p := range r.Programs {
		if p.Exact {
			if !sameExactPath(p.Path, c.Path) {
				continue
			}
		} else if !matchWorkload(p.Path, key) {
			continue
		}
		if p.SHA256 != "" && !strings.EqualFold(p.SHA256, strings.TrimSpace(c.SHA)) {
			continue
		}
		switch p.RunAs {
		case "":
		case runAsSystem:
			if !IsServiceAccount(c.User, "") {
				continue
			}
		default:
			if !IsServiceAccount(c.User, p.RunAs) {
				continue
			}
		}
		return true
	}
	return false
}

var windowsDriveRe = regexp.MustCompile(`^[A-Za-z]:/`)

// sameExactPath compares an exact program path with the path a process
// reported: byte for byte for a Unix path, without case for a Windows one.
func sameExactPath(want, got string) bool {
	want, got = exactPathForm(want), exactPathForm(got)
	if want == "" {
		return false
	}
	if windowsDriveRe.MatchString(want) {
		return strings.EqualFold(want, got)
	}
	return want == got
}

func exactPathForm(p string) string {
	return strings.ReplaceAll(strings.TrimSpace(p), "\\", "/")
}

// runAsSystem binds a program to root or the system's own accounts.
const runAsSystem = "system"

func (r ExpectedRule) anchored() bool { return len(r.Prefixes) > 0 || len(r.Networks) > 0 }

// destinationMatches applies the destination clauses. An excepted name never
// matches. A rule that lists Domains needs the name the client asked for under
// one of them, whichever way the address proves the maker (its published
// prefix or its network): the address alone would cover a customer's bucket on
// the maker's network, or any program's own server inside its range.
func (r ExpectedRule) destinationMatches(c ExpectCtx) bool {
	name := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(c.Domain), "."))
	for _, d := range r.ExceptDomains {
		if name != "" && underDomain(name, d) {
			return false
		}
	}
	if !r.anchored() {
		return true
	}
	if len(r.Domains) > 0 {
		named := false
		for _, d := range r.Domains {
			named = named || (name != "" && underDomain(name, d))
		}
		if !named {
			return false
		}
	}
	if addr, err := netaddr.Parse(strings.TrimSpace(c.DstIP)); err == nil {
		addr = addr.WithZone("").Unmap()
		for _, raw := range r.Prefixes {
			if p, err := netip.ParsePrefix(raw); err == nil && p.Contains(addr) {
				return true
			}
		}
	}
	for _, n := range r.Networks {
		if r.networkMatches(n, c) {
			return true
		}
	}
	return false
}

func (r ExpectedRule) networkMatches(entry string, c ExpectCtx) bool {
	switch r.Tenancy {
	case ExpectedTenancyAny:
	case ExpectedTenancyVendor:
		source := strings.TrimSpace(c.Source)
		// Only a published feed's attribution counts: the built-in table is
		// coarse and lumps a maker's rented compute in with its service.
		if strings.TrimSpace(c.Tenancy) != TenancyVendor || source == "" || source == "built-in" {
			return false
		}
	default:
		if strings.TrimSpace(c.Tenancy) == TenancyHosting {
			return false
		}
	}
	if entry == AnyNetwork {
		return r.Tenancy == ExpectedTenancyAny || strings.TrimSpace(c.Org) != ""
	}
	return OwnerMatches(entry, c.ASN, c.Org)
}

func listHas(list []string, v string) bool {
	v = strings.ToLower(strings.TrimSpace(v))
	if v == "" {
		return false
	}
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

func protocolName(p uint8) string {
	switch p {
	case 6:
		return "tcp"
	case 17:
		return "udp"
	case 1:
		return "icmp"
	}
	return ""
}

// --- validation and normalisation ---

// problem says why a rule may not be saved, or "" when it is sound. A rule
// silences detection, so the write and every read use the same checks.
func (r ExpectedRule) problem() string {
	id := r.ID
	switch {
	case id == "" || strings.ContainsAny(id, " \t\n/\\?#") || len(id) > 96:
		return fmt.Sprintf("rule id %q must be 1 to 96 characters without spaces or slashes", id)
	case strings.TrimSpace(r.Reason) == "":
		return "rule " + id + " needs a reason"
	}
	for _, f := range r.Findings {
		if !ExpectableKind(f) {
			return fmt.Sprintf("rule %s: %q is not a finding a rule can make expected (the floor rules cannot be); use one of %s", id, f, strings.Join(expectableKinds, ", "))
		}
	}
	if r.Tenancy != ExpectedTenancyDefault && r.Tenancy != ExpectedTenancyVendor && r.Tenancy != ExpectedTenancyAny {
		return fmt.Sprintf("rule %s: tenancy %q must be empty, vendor or any", id, r.Tenancy)
	}
	switch r.Protocol {
	case "", "any", "tcp", "udp", "icmp":
	default:
		return fmt.Sprintf("rule %s: protocol %q must be tcp, udp, icmp or any", id, r.Protocol)
	}
	switch strings.ToUpper(r.Direction) {
	case "", "OUTBOUND", "INBOUND":
	default:
		return fmt.Sprintf("rule %s: direction %q must be outbound or inbound", id, r.Direction)
	}
	if r.Port < 0 || r.Port > 65535 {
		return fmt.Sprintf("rule %s: port %d is out of range", id, r.Port)
	}
	if r.MaxHosts != 0 && !r.coversLateral() {
		return "rule " + id + ": max_hosts bounds a lateral fan-out, so the rule must name " + KindLateralSweep
	}
	if r.coversLateral() && (len(r.Hosts) == 0 || len(r.Programs) == 0 || r.Port == 0) {
		return "rule " + id + ": a rule that makes a lateral fan-out expected must name the hosts, the programs and the one port it is for"
	}
	if r.coversLateral() && IsFloorPort(r.Port) {
		return fmt.Sprintf("rule %s: port %d is on the detection floor (SMB, RDP, telnet, RPC); no rule makes a fan-out on it expected", id, r.Port)
	}
	if r.Vendor != "" && len(r.Domains) == 0 {
		return "rule " + id + ": a rule that names a vendor must name the vendor's domains; an address alone does not show it is the maker's own service"
	}
	if r.MaxHosts < 0 || r.MaxHosts > AdminFanoutMaxDefault {
		return fmt.Sprintf("rule %s: max_hosts %d must be between 1 and %d", id, r.MaxHosts, AdminFanoutMaxDefault)
	}
	if len(r.Programs) == 0 && r.Runtime == "" && r.Workload == "" && len(r.Domains) == 0 && len(r.Prefixes) == 0 && len(r.Networks) == 0 && r.Port == 0 {
		return "rule " + id + " names nothing to match: add a program, a runtime, a workload, a destination or a port"
	}
	for _, p := range r.Programs {
		if msg := p.problem(); msg != "" {
			return "rule " + id + ": " + msg
		}
	}
	if r.Workload != "" {
		if err := validWorkloadPattern(r.Workload); err != nil {
			return fmt.Sprintf("rule %s: %v", id, err)
		}
		if !isPathWorkload(r.Workload) && len(r.Networks) == 0 && len(r.Prefixes) == 0 {
			return "rule " + id + ": an interpreter's workload must name the network it talks to (\"*\" for any named network)"
		}
		if r.ExpiresAt.IsZero() {
			return "rule " + id + " names a workload, which needs an expires_at: an interpreter and its script are read from a command line any process can imitate"
		}
	}
	if len(r.Domains) > 0 && !r.anchored() {
		return "rule " + id + ": a domain only counts where the address proves it; add the maker's prefixes or networks"
	}
	for _, d := range r.Domains {
		if err := validVendorDomain(d, true); err != nil {
			return "rule " + id + ": " + strings.TrimPrefix(err.Error(), ErrInvalidDetectionTuning.Error()+": ")
		}
	}
	for _, d := range r.ExceptDomains {
		if d == "" || strings.ContainsAny(d, " /*:@") || !strings.Contains(d, ".") {
			return fmt.Sprintf("rule %s: excepted domain %q must be a plain domain name such as storage.googleapis.com", id, d)
		}
		if len(r.Domains) > 0 {
			under := false
			for _, m := range r.Domains {
				under = under || underDomain(d, m)
			}
			if !under {
				return fmt.Sprintf("rule %s: excepted domain %q is not under any of the rule's domains", id, d)
			}
		}
	}
	for _, n := range r.Networks {
		if n == AnyNetwork && r.Tenancy == ExpectedTenancyVendor {
			return "rule " + id + ": a vendor-tenancy rule names the maker's networks, not any network"
		}
		if r.Tenancy == ExpectedTenancyVendor && !IsASN(n) {
			return fmt.Sprintf("rule %s: network %q must be an AS number such as as15169", id, n)
		}
		if strings.TrimSpace(n) == "" || strings.ContainsAny(n, "@") {
			return fmt.Sprintf("rule %s: network %q must be an AS number, an exact network name or *", id, n)
		}
	}
	for _, raw := range r.Prefixes {
		p, err := netip.ParsePrefix(raw)
		if err != nil || p.Addr().Is4In6() {
			return fmt.Sprintf("rule %s: prefix %q is not a network such as 160.79.104.0/23", id, raw)
		}
		if len(r.Domains) == 0 {
			continue
		}
		// A prefix that vouches for a named domain is the maker's published
		// service range: public, and no wider than a /16 (/32 for IPv6).
		p = p.Masked()
		minBits := vendorPrefixMinBits4
		if p.Addr().Is6() {
			minBits = vendorPrefixMinBits6
		}
		a := p.Addr()
		switch {
		case p.Bits() < minBits:
			return fmt.Sprintf("rule %s: prefix %q is wider than a /%d; name the vendor's published service range", id, raw, minBits)
		case a.IsPrivate() || a.IsLoopback() || a.IsLinkLocalUnicast() || a.IsMulticast() || a.IsUnspecified() || privatePrefix(p):
			return fmt.Sprintf("rule %s: prefix %q is not public address space", id, raw)
		}
	}
	return ""
}

func (r ExpectedRule) coversLateral() bool {
	for _, f := range r.Findings {
		if f == KindLateralSweep {
			return true
		}
	}
	return false
}

// sharedWritablePrefixes are directories every local account can put a
// program in. A path there names whatever was copied there last, so a rule
// under one has to pin the build it means. A home folder is not on the list:
// only its owner writes there, so a rule for a program in it also names that
// account (run_as), and survives the program updating itself.
var sharedWritablePrefixes = []string{"/tmp/", "/var/tmp/", "/dev/shm/", "/run/user/", "c:/users/public/", "c:/windows/temp/"}

func sharedWritable(path string) bool {
	key := ProcessPathKey(path)
	for _, dir := range sharedWritablePrefixes {
		if strings.HasPrefix(key, dir) {
			return true
		}
	}
	return false
}

// SharedWritable reports a path in a folder every account can write to, which
// a rule may only name together with the build's hash.
func SharedWritable(path string) bool { return sharedWritable(path) }

func (p ExpectedProgram) problem() string {
	if p.SHA256 != "" && (len(p.SHA256) != 64 || strings.Trim(p.SHA256, "0123456789abcdef") != "") {
		return fmt.Sprintf("program %q: sha256 must be 64 hex digits", p.Path)
	}
	if p.RunAs != "" && p.RunAs != runAsSystem && (strings.ContainsAny(p.RunAs, "@* ") || strings.HasPrefix(p.RunAs, runAsSystem+":")) {
		return fmt.Sprintf("program %q: run_as must be system or one account name", p.Path)
	}
	if p.Exact && strings.ContainsAny(p.Path, "*?[]") {
		return fmt.Sprintf("program %q: an exact path has no pattern in it", p.Path)
	}
	if !isPathWorkload(p.Path) {
		return fmt.Sprintf("program %q is not an absolute path; a program is named by where it is installed, not by its name", p.Path)
	}
	if p.SHA256 == "" && sharedWritable(p.Path) {
		return fmt.Sprintf("program %q is in a folder any account can write to; add its sha256 to name the build you mean", p.Path)
	}
	pattern := p.Path
	if len(pattern) > 2 && pattern[1] == ':' {
		pattern = pattern[2:]
	}
	if err := literalPath(pattern); err != nil {
		return "program " + err.Error()
	}
	return ""
}

// validWorkloadPattern is the check a workload (an interpreter and what it
// runs, or an installed path) passes: an interpreter is only known together
// with the program it runs, spelled out, and inline code is never known.
func validWorkloadPattern(w string) error {
	if strings.Trim(w, "* ") == "" || strings.HasPrefix(w, "*") {
		return fmt.Errorf("workload %q names no program", w)
	}
	if !isPathWorkload(w) {
		tokens := strings.Fields(w)
		if len(tokens) < 2 {
			return fmt.Errorf("workload %q is an interpreter without the program it runs", w)
		}
		prog := tokens[len(tokens)-1]
		switch {
		case len(tokens) >= 3 && tokens[len(tokens)-2] == "-m":
			if strings.Contains(prog, "*") {
				return fmt.Errorf("workload %q: a module after -m is named exactly", w)
			}
		case len(tokens) >= 3 && tokens[len(tokens)-2] == "-jar":
			if err := literalPath(prog); err != nil {
				return fmt.Errorf("workload %q: the jar %v", w, err)
			}
		default:
			if err := literalPath(prog); err != nil {
				return fmt.Errorf("workload %q must end with the program it runs (an absolute script path, -m module or -jar file): the script %v", w, err)
			}
		}
	}
	if isInlineWorkload(w) {
		return fmt.Errorf("workload %q is inline code, which is never a known program", w)
	}
	return nil
}

// readableRules keeps the rules a save would accept, in order, and says which
// it left out. A rule silences detection, so one that fails the checks (a saved
// row can hold what an older build accepted) covers nothing, as an old
// exclusion that failed its own checks never matched; the first of two rules
// with one id stands. DetectionTuningProblem reports the row.
func readableRules(rules []ExpectedRule) (kept []ExpectedRule, skipped []string) {
	seen := map[string]bool{}
	kept = make([]ExpectedRule, 0, len(rules))
	for _, r := range rules {
		if msg := r.problem(); msg != "" {
			skipped = append(skipped, msg)
			continue
		}
		if seen[r.ID] {
			skipped = append(skipped, fmt.Sprintf("rule id %q is used twice", r.ID))
			continue
		}
		seen[r.ID] = true
		kept = append(kept, r)
	}
	return kept, skipped
}

// validExpectedRules checks every rule and that ids are unique.
func validExpectedRules(rules []ExpectedRule) error {
	seen := map[string]bool{}
	for _, r := range rules {
		if msg := r.problem(); msg != "" {
			return fmt.Errorf("%w: %s", ErrInvalidDetectionTuning, msg)
		}
		if seen[r.ID] {
			return fmt.Errorf("%w: rule id %q is used twice", ErrInvalidDetectionTuning, r.ID)
		}
		seen[r.ID] = true
	}
	return nil
}

// CheckNewRuleExpiry refuses a workload rule a save adds or changes with an
// expiry further out than ExpectedMaxWorkloadLifetime. An entry carried over
// exactly as saved keeps the expiry it has.
func CheckNewRuleExpiry(before, after []ExpectedRule, now time.Time) error {
	had := map[string]string{}
	for _, r := range before {
		had[r.ID] = ruleKey(r)
	}
	for _, r := range after {
		if r.Workload == "" || had[r.ID] == ruleKey(r) {
			continue
		}
		if !r.ExpiresAt.After(now) {
			return fmt.Errorf("%w: rule %s needs an expires_at in the future", ErrInvalidDetectionTuning, r.ID)
		}
		if r.ExpiresAt.After(now.Add(ExpectedMaxWorkloadLifetime)) {
			return fmt.Errorf("%w: rule %s expires_at is more than %d days out; renew it when it nears expiry instead", ErrInvalidDetectionTuning, r.ID, int(ExpectedMaxWorkloadLifetime.Hours()/24))
		}
	}
	return nil
}

func ruleKey(r ExpectedRule) string {
	b, _ := json.Marshal(r)
	return string(b)
}

// tidyRules normalises a list of rules: lower-cased, trimmed, deduplicated,
// sorted lists, and the rules in id order.
func tidyRules(in []ExpectedRule) []ExpectedRule {
	out := make([]ExpectedRule, 0, len(in))
	for _, r := range in {
		out = append(out, r.tidy())
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func (r ExpectedRule) tidy() ExpectedRule {
	r.ID = strings.TrimSpace(r.ID)
	r.Reason = strings.TrimSpace(r.Reason)
	r.Name = strings.TrimSpace(r.Name)
	r.Vendor = strings.TrimSpace(r.Vendor)
	r.Runtime = strings.ToLower(strings.TrimSpace(r.Runtime))
	r.Workload = strings.Join(strings.Fields(r.Workload), " ")
	if isPathWorkload(r.Workload) {
		r.Workload = strings.ToLower(r.Workload) // detector.WorkloadOf lower-cases paths
	}
	r.Tenancy = strings.ToLower(strings.TrimSpace(r.Tenancy))
	r.Protocol = strings.ToLower(strings.TrimSpace(r.Protocol))
	r.Direction = strings.ToLower(strings.TrimSpace(r.Direction))
	r.Findings = tidyList(r.Findings)
	for i, f := range r.Findings {
		r.Findings[i] = strings.ToUpper(f)
	}
	sort.Strings(r.Findings)
	r.Hosts = tidyList(r.Hosts)
	r.Domains = tidyDomains(r.Domains)
	r.ExceptDomains = tidyDomains(r.ExceptDomains)
	r.Networks = tidyList(r.Networks)
	prefixes := make([]string, 0, len(r.Prefixes))
	for _, raw := range r.Prefixes {
		raw = strings.TrimSpace(raw)
		if p, err := netip.ParsePrefix(raw); err == nil {
			raw = p.Masked().String()
		} else if a, err := netip.ParseAddr(raw); err == nil {
			a = a.Unmap()
			raw = netip.PrefixFrom(a, a.BitLen()).String()
		}
		prefixes = append(prefixes, raw)
	}
	r.Prefixes = tidyList(prefixes)
	seen := map[ExpectedProgram]bool{}
	programs := make([]ExpectedProgram, 0, len(r.Programs))
	for _, p := range r.Programs {
		if p.Exact {
			p.Path = exactPathForm(p.Path)
		} else {
			p.Path = ProcessPathKey(p.Path)
		}
		p.SHA256 = strings.ToLower(strings.TrimSpace(p.SHA256))
		p.RunAs = strings.ToLower(strings.TrimSpace(p.RunAs))
		if p.Path == "" || seen[p] {
			continue
		}
		seen[p] = true
		programs = append(programs, p)
	}
	sort.Slice(programs, func(i, j int) bool {
		if programs[i].Path != programs[j].Path {
			return programs[i].Path < programs[j].Path
		}
		if programs[i].SHA256 != programs[j].SHA256 {
			return programs[i].SHA256 < programs[j].SHA256
		}
		return programs[i].RunAs < programs[j].RunAs
	})
	r.Programs = programs
	if !r.ExpiresAt.IsZero() {
		r.ExpiresAt = r.ExpiresAt.UTC().Truncate(time.Second)
	}
	return r
}

// withoutExpired drops the rules past their expiry: a save that drops one only
// tightens.
func withoutExpired(rules []ExpectedRule, now time.Time) []ExpectedRule {
	live := make([]ExpectedRule, 0, len(rules))
	for _, r := range rules {
		if !r.Expired(now) {
			live = append(live, r)
		}
	}
	return live
}

// RuleByID returns one rule.
func (t DetectionTuning) RuleByID(id string) (ExpectedRule, bool) {
	for _, r := range t.ExpectedRules {
		if r.ID == id {
			return r, true
		}
	}
	return ExpectedRule{}, false
}

// RuleNamingMaker returns the maker's display name when a runtime reaching a
// name is a runtime reaching its own maker's service, for explaining a finding
// ("Probably claude itself: api.anthropic.com is Anthropic's own service").
func (t DetectionTuning) RuleNamingMaker(runtime, name string) string {
	runtime = strings.ToLower(strings.TrimSpace(runtime))
	name = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), "."))
	if runtime == "" || name == "" {
		return ""
	}
	for _, r := range t.ExpectedRules {
		if r.Runtime != runtime || r.Vendor == "" {
			continue
		}
		excluded := false
		for _, d := range r.ExceptDomains {
			excluded = excluded || underDomain(name, d)
		}
		if excluded {
			continue
		}
		for _, d := range r.Domains {
			if underDomain(name, d) {
				return r.Vendor
			}
		}
	}
	return ""
}

// Vendor prefixes narrower than these only: a vendor range is a statement
// about one service, and anything wider would vouch for whole providers.
const (
	vendorPrefixMinBits4 = 16
	vendorPrefixMinBits6 = 32
)

func tidyDomains(in []string) []string {
	out := make([]string, 0, len(in))
	for _, d := range in {
		out = append(out, strings.TrimSuffix(strings.ToLower(strings.TrimSpace(d)), "."))
	}
	return tidyList(out)
}

// validVendorDomain refuses what is not a plain domain name, or is a public
// suffix: every site under it shares it. A suffix in the private section of
// the list (googleapis.com, github.io) passes only for a rule anchored to the
// maker's own addresses (prefixes or networks), so the name counts only where
// the maker serves it; the hosts under it that serve anyone's content (Cloud
// Storage buckets) are then named in except_domains. An ICANN suffix (com,
// co.uk) never passes.
func validVendorDomain(d string, anchored bool) error {
	if d == "" || strings.ContainsAny(d, " /*:@") || !strings.Contains(d, ".") {
		return fmt.Errorf("%w: domain %q must be a plain domain name such as anthropic.com", ErrInvalidDetectionTuning, d)
	}
	suffix, icann := publicsuffix.PublicSuffix(d)
	if d == suffix && (icann || !anchored) {
		return fmt.Errorf("%w: domain %q is a public suffix, which every site under it shares", ErrInvalidDetectionTuning, d)
	}
	if reg, err := publicsuffix.EffectiveTLDPlusOne(d); err == nil && !(d == reg || strings.HasSuffix(d, "."+reg)) {
		return fmt.Errorf("%w: domain %q is a public suffix, which every site under it shares", ErrInvalidDetectionTuning, d)
	}
	return nil
}

func underDomain(name, domain string) bool {
	return name == domain || strings.HasSuffix(name, "."+domain)
}

// Sample is a process this entry matches: its path with each "*" filled in,
// the hash it pins and the account it names (root when it names none or the
// system). The floor drill runs its sweeps as this process.
func (p ExpectedProgram) Sample() (path, sha, user string) {
	user = "root"
	if p.RunAs != "" && p.RunAs != runAsSystem {
		user = p.RunAs
	}
	return strings.ReplaceAll(p.Path, "*", "floor-drill"), p.SHA256, user
}

// Kinds lists the finding kinds the rule makes expected.
func (r ExpectedRule) Kinds() []string {
	var out []string
	for _, k := range expectableKinds {
		if r.covers(k) {
			out = append(out, k)
		}
	}
	return out
}

// HasAdminFanoutRule reports a rule that makes a lateral fan-out from this
// endpoint expected, for the sentence that explains such a finding.
func (t DetectionTuning) HasAdminFanoutRule(host string) bool {
	host = strings.ToLower(strings.TrimSpace(host))
	for _, r := range t.ExpectedRules {
		if r.coversLateral() && listHas(r.Hosts, host) {
			return true
		}
	}
	return false
}

// ExpectableKinds lists every finding kind a rule may name.
func ExpectableKinds() []string { return append([]string(nil), expectableKinds...) }

// ExplicitKinds lists the kinds a rule covers only when it names them.
func ExplicitKinds() []string {
	var out []string
	for _, k := range expectableKinds {
		if explicitKinds[k] {
			out = append(out, k)
		}
	}
	return out
}

// ValidExpectedProgram says why a program entry may not be saved, or "".
func ValidExpectedProgram(p ExpectedProgram) string { return p.problem() }
