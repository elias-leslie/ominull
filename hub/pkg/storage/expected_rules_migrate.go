package storage

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"log"
	"net/netip"
	"strings"
	"time"
)

// AttributionPathMismatch is the attribution status an agent reports when the
// path the kernel gives for a process's executable does not name, on the host,
// the file that runs (a user namespace bind mount over a listed path, a
// container's own path). A program named by path is never matched then.
const AttributionPathMismatch = "path_mismatch"

// The seeds and the one-time conversion of what the tuning held before
// expected rules (quiet process, network, client and pair lists, known
// workloads, runtime vendors, admin fan-out sources, and the exclusions table).
// The shipped seeds are the same conversion applied to the shipped lists, so a
// hub that was never tuned and one that was migrated read the same way.

// legacyLists is the part of a saved tuning row that expected rules replace.
// A list the row does not carry at all is the shipped one; a list it carries
// empty is empty.
type legacyLists struct {
	QuietProcesses      *[]string        `json:"quiet_processes"`
	QuietOrgs           *[]string        `json:"quiet_orgs"`
	QuietClients        *[]string        `json:"quiet_clients"`
	QuietPairs          []string         `json:"quiet_pairs"`
	KnownWorkloads      []legacyWorkload `json:"known_workloads"`
	AgentRuntimeVendors *[]legacyVendor  `json:"agent_runtime_vendors"`
	AdminFanoutSources  []string         `json:"admin_fanout_sources"`
	AdminFanoutMax      int              `json:"admin_fanout_max_hosts"`
	ExpectedRules       *json.RawMessage `json:"expected_rules"`
}

type legacyWorkload struct {
	Workload      string    `json:"workload"`
	Owner         string    `json:"owner"`
	Reason        string    `json:"reason"`
	IncludeRented bool      `json:"include_rented"`
	ExpiresAt     time.Time `json:"expires_at"`
}

type legacyVendor struct {
	Runtime        string   `json:"runtime"`
	Vendor         string   `json:"vendor"`
	Domains        []string `json:"domains"`
	ExcludeDomains []string `json:"exclude_domains"`
	Prefixes       []string `json:"prefixes"`
	Networks       []string `json:"networks"`
}

type legacyExclusion struct {
	ID, Scope, ScopeValue, Name, ProcessPath, DstIPRange, Protocol, Reason string
	Port                                                                   int
	Active                                                                 bool
	ExpiresAt                                                              time.Time
}

// Shipped lists. Each is a starting point and is read back as rules the
// operator can change; none of it is consulted by a detector directly.

// defaultQuietProcesses are operating system components whose whole job is to
// talk to their vendor on a timer. Each is the path it is installed at, in a
// directory only an administrator can write, and matches only while it runs as
// the system or as its own service account: a login user can make any program
// appear at one of these paths, but not run it as that account.
func defaultQuietProcesses() []string {
	return []string{
		// Windows
		"c:/windows/system32/svchost.exe", "c:/windows/system32/lsass.exe",
		"c:/programdata/microsoft/windows defender/platform/*/msmpeng.exe",
		// Linux
		"/usr/lib/systemd/systemd-resolved user:systemd-resolve",
		"/usr/lib/systemd/systemd-timesyncd user:systemd-timesync",
		"/usr/sbin/chronyd user:_chrony", "/usr/sbin/chronyd user:chrony",
		"/usr/lib/snapd/snapd", "/snap/snapd/*/usr/lib/snapd/snapd",
		// This fleet's own agent, which heartbeats on a fixed interval.
		"/opt/ominull/bin/ominulld", "c:/program files/ominull/ominulld.exe",
	}
}

// defaultQuietClients are the programs that talk to vendor networks all day by
// design: browsers, platform updaters, this agent, chat clients with fixed
// keepalives.
func defaultQuietClients() []string {
	return []string{
		"/opt/google/chrome/chrome", "c:/program files/google/chrome/application/chrome.exe",
		"c:/program files (x86)/google/chrome/application/chrome.exe",
		"/usr/lib/chromium/chromium", "/snap/chromium/*/usr/lib/chromium-browser/chrome",
		"/usr/lib/firefox/firefox", "/snap/firefox/*/usr/lib/firefox/firefox",
		"c:/program files/mozilla firefox/firefox.exe",
		"c:/program files (x86)/microsoft/edge/application/msedge.exe",
		"/applications/safari.app/contents/macos/safari",
		"/opt/brave.com/brave/brave", "c:/program files/bravesoftware/brave-browser/application/brave.exe",
		"c:/windows/system32/svchost.exe", "c:/windows/system32/usocoreworker.exe",
		"c:/programdata/microsoft/windows defender/platform/*/msmpeng.exe",
		"/usr/lib/snapd/snapd", "/snap/snapd/*/usr/lib/snapd/snapd", "/usr/libexec/packagekitd",
		"/usr/libexec/nsurlsessiond",
		"/system/library/privateframeworks/softwareupdate.framework/resources/softwareupdated",
		"/opt/ominull/bin/ominulld", "c:/program files/ominull/ominulld.exe",
		"/usr/lib/chatgpt/chatgpt", "/usr/lib/claude-desktop/claude-desktop",
	}
}

// defaultQuietOrgs are the vendors' own AS numbers: Apple, Microsoft, Google,
// Cloudflare, Amazon, Akamai and Fastly. Rented compute inside them is never
// covered.
func defaultQuietOrgs() []string {
	return []string{"as714", "as8075", "as15169", "as13335", "as16509", "as20940", "as54113"}
}

// defaultLegacyVendors: Anthropic's prefixes are from
// platform.claude.com/docs/en/api/ip-addresses (inbound, checked 2026-10-16).
// OpenAI's API sits behind Cloudflare, an address any site can be fronted
// from, so codex has none. Antigravity (agy) talks to Google's API hosts; its
// network is AS15169 as attributed from goog.json less cloud.json. Cloud
// Storage and Firebase Storage hosts are excluded: anyone's buckets live there.
// So is www.googleapis.com, which also serves Drive and Cloud Storage uploads
// (owner decision 2026-11-06).
func defaultLegacyVendors() []legacyVendor {
	return []legacyVendor{
		{Runtime: "claude", Vendor: "Anthropic", Domains: []string{"anthropic.com", "claude.ai", "claude.com", "claudeusercontent.com"},
			Prefixes: []string{"160.79.104.0/23", "2607:6bc0::/48"}},
		{Runtime: "antigravity", Vendor: "Google", Domains: []string{"googleapis.com"},
			ExcludeDomains: []string{"storage.googleapis.com", "storage-download.googleapis.com", "storage-upload.googleapis.com",
				"content-storage-download.googleapis.com", "content-storage-upload.googleapis.com", "storage.mtls.googleapis.com",
				"firebasestorage.googleapis.com", "www.googleapis.com"},
			Networks: []string{"as15169"}},
	}
}

// seedExpectedRules are the rules a hub that was never tuned starts with.
func seedExpectedRules() []ExpectedRule {
	rules, _ := rulesFromLegacy(legacyLists{}, time.Now())
	return rules
}

// Findings sets the conversions share.
var (
	kindsVouched = []string{KindBandwidthSpike, KindBeacon, KindNovelProcess}
	kindsPair    = []string{KindBandwidthSpike, KindBeacon, KindNovelProcess, KindNewPlaceUpload}
	kindsVendor  = []string{KindBandwidthSpike, KindBandwidthBurst, KindNewPlaceUpload}
	// kindsExclusion is what an exclusion covered: every behavioural detector
	// and the cloud storage and agent rules, but not the floor-style new-place
	// upload and lateral sweep, which ran before exclusions.
	kindsExclusion = []string{KindNovelProcess, KindOffHours, KindBandwidthSpike, KindBandwidthBurst, KindBeacon,
		KindNovelDestination, KindAgentNewDest, KindAgentUpload, KindCloudStorage}
)

// ruleSlug makes a short, readable and unique id part from free text.
func ruleSlug(s string) string {
	var b strings.Builder
	dash := true
	for _, r := range strings.ToLower(s) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '.' {
			b.WriteRune(r)
			dash = false
		} else if !dash {
			b.WriteByte('-')
			dash = true
		}
	}
	out := strings.Trim(b.String(), "-")
	if len(out) > 40 {
		out = strings.Trim(out[:40], "-")
	}
	sum := sha256.Sum256([]byte(s))
	return out + "-" + hex.EncodeToString(sum[:3])
}

// plainSlug is a readable id part where the text is already unique (a runtime
// name, a host name).
func plainSlug(s string) string {
	var b strings.Builder
	dash := true
	for _, r := range strings.ToLower(s) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '.' || r == '_' {
			b.WriteRune(r)
			dash = false
		} else if !dash {
			b.WriteByte('-')
			dash = true
		}
	}
	out := strings.Trim(b.String(), "-")
	if len(out) > 60 {
		out = strings.Trim(out[:60], "-")
	}
	return out
}

// RuleSlug is ruleSlug for callers that name a rule from what it matches.
func RuleSlug(s string) string { return ruleSlug(s) }

func programFromEntry(entry string, system bool) (ExpectedProgram, bool) {
	q := splitQuietPath(entry)
	p := ExpectedProgram{Path: ProcessPathKey(q.pattern), SHA256: strings.ToLower(q.sha)}
	switch {
	case q.hasAccount:
		p.RunAs = q.account
	case system:
		p.RunAs = runAsSystem
	}
	return p, p.problem() == ""
}

func programsFromEntries(list []string, system bool, what string, dropped *[]string) []ExpectedProgram {
	var out []ExpectedProgram
	for _, e := range list {
		if system == false && splitQuietPath(e).hasAccount {
			*dropped = append(*dropped, what+" "+e)
			continue
		}
		if p, ok := programFromEntry(e, system); ok {
			out = append(out, p)
		} else {
			*dropped = append(*dropped, what+" "+e)
		}
	}
	return out
}

// rulesFromLegacy converts the old lists to rules and returns what it could not
// carry over. Expired workloads are not carried: they vouched for nothing.
func rulesFromLegacy(l legacyLists, now time.Time) ([]ExpectedRule, []string) {
	var dropped []string
	var rules []ExpectedRule
	list := func(p *[]string, def func() []string) []string {
		if p == nil {
			return def()
		}
		return *p
	}
	procs := list(l.QuietProcesses, defaultQuietProcesses)
	orgs := list(l.QuietOrgs, defaultQuietOrgs)
	clients := list(l.QuietClients, defaultQuietClients)

	var asns []string
	for _, o := range orgs {
		if IsASN(o) {
			asns = append(asns, strings.ToLower(strings.TrimSpace(o)))
		} else {
			dropped = append(dropped, "quiet network "+o)
		}
	}
	if ps := programsFromEntries(procs, true, "quiet process", &dropped); len(ps) > 0 {
		rules = append(rules, ExpectedRule{ID: "system-components", Name: "System components",
			Reason:   "Operating system and fleet components whose job is to talk to their vendor on a timer, run as the system or as their own service account.",
			Programs: ps})
	}
	if len(asns) > 0 {
		rules = append(rules, ExpectedRule{ID: "vendor-networks", Name: "Vendor networks are not new",
			Reason:   "Networks the operator has said are normal here: a first connection to one is not news. Rented compute inside them is not covered.",
			Findings: []string{KindNovelDestination}, Networks: asns})
	}
	if ps := programsFromEntries(clients, false, "expected client", &dropped); len(ps) > 0 {
		if len(asns) > 0 {
			rules = append(rules, ExpectedRule{ID: "everyday-programs-on-vendor-networks", Name: "Everyday programs on vendor networks",
				Reason:   "Browsers, updaters and this agent talking to a vendor network all day. Only these programs: python or curl to the same network is still judged.",
				Findings: kindsVouched, Programs: ps, Networks: asns})
		}
		rules = append(rules, ExpectedRule{ID: "everyday-programs-on-named-networks", Name: "Everyday programs on named networks",
			Reason:   "A browser or updater holds keepalives open to whatever the user is looking at. Not on rented compute or an unnamed address.",
			Findings: []string{KindBeacon}, Programs: ps, Networks: []string{AnyNetwork}})
	}
	for _, pair := range l.QuietPairs {
		proc, owner, ok := splitPair(pair)
		if !ok {
			dropped = append(dropped, "expected pair "+pair)
			continue
		}
		prog, valid := programFromEntry(proc, false)
		if !valid || splitQuietPath(proc).hasAccount {
			dropped = append(dropped, "expected pair "+pair)
			continue
		}
		rules = append(rules, ExpectedRule{ID: "pair-" + ruleSlug(pair), Name: prog.Path + " to " + owner,
			Reason:   "Operator-confirmed: " + prog.Path + " talking to " + owner + " is its job.",
			Findings: kindsPair, Programs: []ExpectedProgram{prog}, Networks: []string{owner}})
	}
	for _, k := range l.KnownWorkloads {
		if k.ExpiresAt.IsZero() || !k.ExpiresAt.After(now) {
			dropped = append(dropped, "expired known workload "+k.Workload)
			continue
		}
		rules = append(rules, ruleFromWorkload(k))
	}
	vendors := []legacyVendor(nil)
	if l.AgentRuntimeVendors == nil {
		vendors = defaultLegacyVendors()
	} else {
		vendors = *l.AgentRuntimeVendors
	}
	for _, v := range vendors {
		if len(v.Prefixes) == 0 && len(v.Networks) == 0 {
			dropped = append(dropped, "runtime vendor "+v.Runtime+" (a name alone proves nothing)")
			continue
		}
		rules = append(rules, ExpectedRule{ID: "vendor-" + plainSlug(v.Runtime), Name: v.Vendor + " service for " + v.Runtime,
			Reason:   v.Vendor + "'s own service: a runtime talking to its maker is the runtime working. Its volume is judged per hour (AGENT_UPLOAD_VOLUME) instead.",
			Findings: kindsVendor, Runtime: v.Runtime, Vendor: v.Vendor, Domains: v.Domains, ExceptDomains: v.ExcludeDomains,
			Prefixes: v.Prefixes, Networks: v.Networks, Tenancy: ExpectedTenancyVendor})
	}
	maxHosts := l.AdminFanoutMax
	if maxHosts <= 0 || maxHosts > AdminFanoutMaxDefault {
		maxHosts = AdminFanoutMaxDefault
	}
	for _, src := range l.AdminFanoutSources {
		src = strings.ToLower(strings.TrimSpace(src))
		if src == "" {
			continue
		}
		rules = append(rules, ExpectedRule{ID: "admin-ssh-" + plainSlug(src), Name: "Admin ssh from " + src,
			Reason:   "Routine administration: ssh from this workstation to inventoried hosts on port 22.",
			Findings: []string{KindLateralSweep}, Hosts: []string{src}, Port: 22, MaxHosts: maxHosts,
			Programs: []ExpectedProgram{{Path: "/usr/bin/ssh"}, {Path: "c:/windows/system32/openssh/ssh.exe"}}})
	}
	return keepValidRules(rules, &dropped), dropped
}

// ruleFromWorkload carries a known workload over with the reach it had: an
// installed program known for any owner reached every destination, an
// interpreter only named networks unless it said include_rented, and a named
// owner never rented compute. A workload known for any owner also silenced
// the off-hours finding (it is a service).
func ruleFromWorkload(k legacyWorkload) ExpectedRule {
	r := ExpectedRule{ID: "workload-" + ruleSlug(k.Workload+" "+k.Owner+map[bool]string{true: " rented", false: ""}[k.IncludeRented]),
		Name: k.Workload, Reason: strings.TrimSpace(k.Reason), Workload: k.Workload, ExpiresAt: k.ExpiresAt,
		Findings: []string{KindNovelDestination, KindNovelProcess}}
	if r.Reason == "" {
		r.Reason = "Known workload."
	}
	owner := strings.ToLower(strings.TrimSpace(k.Owner))
	switch {
	case owner == AnyNetwork || owner == "":
		r.Findings = append(r.Findings, KindOffHours)
		if isPathWorkload(k.Workload) {
			r.Tenancy = ExpectedTenancyAny
		} else {
			r.Networks = []string{AnyNetwork}
			if k.IncludeRented {
				r.Tenancy = ExpectedTenancyAny
			}
		}
	default:
		r.Networks = []string{owner}
	}
	return r
}

// keepValidRules drops what a save would refuse, so one bad old entry cannot
// stop the rest from being carried over.
func keepValidRules(in []ExpectedRule, dropped *[]string) []ExpectedRule {
	out := make([]ExpectedRule, 0, len(in))
	seen := map[string]bool{}
	for _, r := range tidyRules(in) {
		if msg := r.problem(); msg != "" {
			*dropped = append(*dropped, "rule "+r.ID+": "+msg)
			continue
		}
		if seen[r.ID] {
			continue
		}
		seen[r.ID] = true
		out = append(out, r)
	}
	return out
}

// ruleFromExclusion carries an exclusion over: the same program, range, port
// and protocol, on its endpoint or everywhere, for the same finding kinds.
// A client or location scope has no equivalent (the hub has one tenant) and is
// dropped; so is one switched off or expired.
func ruleFromExclusion(ex legacyExclusion, now time.Time) (ExpectedRule, string) {
	switch {
	case !ex.Active:
		return ExpectedRule{}, "switched off"
	case !ex.ExpiresAt.After(now):
		return ExpectedRule{}, "expired"
	case ex.Scope != "global" && ex.Scope != "endpoint":
		return ExpectedRule{}, "a " + ex.Scope + " scope has no equivalent"
	}
	r := ExpectedRule{ID: "exclusion-" + strings.Map(func(c rune) rune {
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-' {
			return c
		}
		return '-'
	}, ex.ID), Name: strings.TrimSpace(ex.Name), Findings: append([]string(nil), kindsExclusion...), ExpiresAt: ex.ExpiresAt, Port: ex.Port}
	r.Reason = strings.TrimSpace(strings.TrimSpace(ex.Name) + ": " + strings.TrimSpace(ex.Reason))
	r.Reason = strings.Trim(r.Reason, ": ")
	if ex.Scope == "endpoint" {
		r.Hosts = []string{strings.ToLower(strings.TrimSpace(ex.ScopeValue))}
	}
	if proto := strings.ToLower(strings.TrimSpace(ex.Protocol)); proto != "any" {
		r.Protocol = proto
	}
	if v := strings.TrimSpace(ex.ProcessPath); v != "" && v != "*" {
		r.Programs = []ExpectedProgram{{Path: ProcessPathKey(v)}}
	}
	if v := strings.TrimSpace(ex.DstIPRange); v != "" && v != "*" {
		p, ok := parsePrefixOrAddr(v)
		if !ok {
			return ExpectedRule{}, "its address range does not parse"
		}
		r.Prefixes = []string{p.String()}
	}
	return r, ""
}

func parsePrefixOrAddr(v string) (netip.Prefix, bool) {
	if strings.Contains(v, "/") {
		p, err := netip.ParsePrefix(v)
		return p.Masked(), err == nil
	}
	a, err := netip.ParseAddr(v)
	if err != nil {
		return netip.Prefix{}, false
	}
	a = a.Unmap()
	return netip.PrefixFrom(a, a.BitLen()), true
}

// migrateExpectedRules runs once when the tuning row has no expected rules yet,
// and again for any leftover exclusions: it converts the old lists and the
// exclusions table into rules, saves them, and drops the table. A row it cannot
// save is left as it is and the table kept, loudly.
func (s *Store) migrateExpectedRules(now time.Time) {
	var raw string
	err := s.db.QueryRow(`SELECT settings FROM detection_tuning WHERE id = 1`).Scan(&raw)
	hasRow := err == nil
	exclusions, haveTable := s.legacyExclusions()
	var probe legacyLists
	if hasRow {
		if err := json.Unmarshal([]byte(raw), &probe); err != nil {
			return // an unreadable row is reported by DetectionTuningProblem
		}
	}
	converted := hasRow && probe.ExpectedRules != nil
	if converted && len(exclusions) == 0 {
		if haveTable {
			s.dropExclusionsTable()
		}
		return
	}
	if !hasRow && len(exclusions) == 0 {
		if haveTable {
			s.dropExclusionsTable()
		}
		return
	}
	t := DefaultDetectionTuning()
	var dropped []string
	if hasRow {
		t = s.GetDetectionTuning()
	}
	if hasRow && !converted {
		var rules []ExpectedRule
		rules, dropped = rulesFromLegacy(probe, now)
		t.ExpectedRules = rules
	}
	have := map[string]bool{}
	for _, r := range t.ExpectedRules {
		have[r.ID] = true
	}
	for _, ex := range exclusions {
		r, why := ruleFromExclusion(ex, now)
		if why != "" {
			dropped = append(dropped, "exclusion "+ex.ID+" ("+why+")")
			continue
		}
		var bad []string
		kept := keepValidRules([]ExpectedRule{r}, &bad)
		if len(kept) == 0 {
			dropped = append(dropped, "exclusion "+ex.ID+" ("+strings.Join(bad, "; ")+")")
			continue
		}
		if !have[kept[0].ID] {
			t.ExpectedRules = append(t.ExpectedRules, kept[0])
		}
	}
	if _, err := s.SaveDetectionTuning(t, "upgrade"); err != nil {
		log.Printf("[-] Detection tuning: the saved row could not be converted to expected rules; the old quiet lists, known workloads and exclusions match nothing now: %v", err)
		return
	}
	if haveTable {
		s.dropExclusionsTable()
	}
	log.Printf("[+] Detection tuning: converted to %d expected rules (not carried over: %s)", len(t.ExpectedRules), strings.Join(dropped, ", "))
}

func (s *Store) dropExclusionsTable() {
	if _, err := s.db.Exec(`DROP TABLE IF EXISTS exclusions`); err != nil {
		log.Printf("[-] Detection tuning: the converted exclusions table could not be dropped: %v", err)
	}
}

func (s *Store) legacyExclusions() ([]legacyExclusion, bool) {
	var n int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'exclusions'`).Scan(&n); err != nil || n == 0 {
		return nil, false
	}
	rows, err := s.db.Query(`SELECT id, scope, scope_value, name, process_path, dst_ip_range, port, protocol, reason, active, expires_at FROM exclusions`)
	if err != nil {
		return nil, false // a table this code cannot read is left as it is
	}
	defer rows.Close()
	var out []legacyExclusion
	for rows.Next() {
		var ex legacyExclusion
		var active int
		var expires sql.NullTime
		if err := rows.Scan(&ex.ID, &ex.Scope, &ex.ScopeValue, &ex.Name, &ex.ProcessPath, &ex.DstIPRange, &ex.Port, &ex.Protocol, &ex.Reason, &active, &expires); err != nil {
			continue
		}
		ex.Active = active != 0
		if expires.Valid {
			ex.ExpiresAt = expires.Time.UTC()
		}
		out = append(out, ex)
	}
	return out, true
}
