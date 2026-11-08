package storage

import (
	"encoding/json"
	"errors"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func expects(t DetectionTuning, c ExpectCtx) bool {
	_, ok := t.Expected(c)
	return ok
}

// googleOwn is Google's own service address as the hub's feeds attribute it.
var googleOwn = ExpectCtx{ASN: "AS15169", Org: "Google LLC", Tenancy: TenancyVendor, Source: "google"}

func with(c ExpectCtx, edit func(*ExpectCtx)) ExpectCtx {
	edit(&c)
	return c
}

// A system component is the program installed at a path, never its name: an
// implant copied to /tmp as svchost.exe is not the operating system's svchost,
// and it matches only as the system or the daemon's own account, because a
// login user can make any program appear at a path but not run it as root.
func TestShippedSystemComponentsMatchInstalledPathsAsTheirAccount(t *testing.T) {
	cfg := DefaultDetectionTuning()
	proc := func(path, user string) ExpectCtx {
		return ExpectCtx{Kind: KindNovelProcess, Path: path, User: user}
	}
	if !expects(cfg, proc(`C:\Windows\System32\SVCHOST.EXE`, `NT AUTHORITY\NETWORK SERVICE`)) {
		t.Error("the installed svchost is not expected; Windows paths compare case-insensitively")
	}
	for _, impostor := range []string{"svchost.exe", `C:\Users\Public\svchost.exe`, "/tmp/svchost.exe", "/tmp/systemd-resolved", "", "system"} {
		if expects(cfg, proc(impostor, "root")) {
			t.Errorf("%q is expected by name alone", impostor)
		}
	}
	if !expects(cfg, proc("/snap/snapd/28254/usr/lib/snapd/snapd", "root")) {
		t.Error("a snap revision directory is not covered by its wildcard")
	}
	if expects(cfg, proc("/snap/snapd/28254/tmp/usr/lib/snapd/snapd", "root")) {
		t.Error("a wildcard reached across a directory boundary")
	}
	resolved := "/usr/lib/systemd/systemd-resolved"
	for _, user := range []string{"systemd-resolve", "root"} {
		if !expects(cfg, proc(resolved, user)) {
			t.Errorf("systemd-resolved running as %s is not expected", user)
		}
	}
	for _, user := range []string{"alice", "UID:1000", "", "systemd-timesync", "nobody"} {
		if expects(cfg, proc(resolved, user)) {
			t.Errorf("systemd-resolved running as %q is expected", user)
		}
	}
	if expects(cfg, proc("/snap/snapd/28254/usr/lib/snapd/snapd", "alice")) || expects(cfg, proc("/opt/ominull/bin/ominulld", "alice")) {
		t.Error("a root daemon's path was expected for a login user")
	}
	svchost := `C:\Windows\System32\svchost.exe`
	for _, user := range []string{`NT AUTHORITY\SYSTEM`, `NT AUTHORITY\LOCAL SERVICE`, `nt authority\network service`, "SYSTEM"} {
		if !expects(cfg, proc(svchost, user)) {
			t.Errorf("svchost running as %s is not expected", user)
		}
	}
	if expects(cfg, proc(svchost, `WORKSTATION-01\Administrator`)) || expects(cfg, proc(svchost, "")) {
		t.Error("svchost started by a login user, or by nobody known, is expected")
	}
	// A path the agent found is not the file that runs arrives with no path.
	if expects(cfg, ExpectCtx{Kind: KindNovelProcess, User: "root"}) {
		t.Error("a process with no trustworthy path matched a program rule")
	}
}

// Browsers and updaters talk to vendor networks all day by design. That covers
// those programs on those networks, never rented compute inside them, and
// never the findings that page on their own account.
func TestShippedEverydayProgramsAreExpectedOnNamedNetworksOnly(t *testing.T) {
	cfg := DefaultDetectionTuning()
	chrome := with(googleOwn, func(c *ExpectCtx) { c.Path, c.User, c.Kind = "/opt/google/chrome/chrome", "alice", KindBeacon })
	if !expects(cfg, chrome) {
		t.Fatal("chrome beaconing to Google is not expected")
	}
	for _, kind := range []string{KindNovelProcess, KindBandwidthSpike} {
		if !expects(cfg, with(chrome, func(c *ExpectCtx) { c.Kind = kind })) {
			t.Errorf("chrome to Google is not expected for %s", kind)
		}
	}
	if expects(cfg, with(chrome, func(c *ExpectCtx) { c.Path = "/home/user/.cache/chrome" })) {
		t.Error("a program at another path was expected as chrome")
	}
	rented := with(chrome, func(c *ExpectCtx) { c.ASN, c.Org, c.Tenancy = "AS16509", "Amazon.com, Inc.", TenancyHosting })
	if expects(cfg, rented) {
		t.Error("chrome to rented compute inside Amazon's AS was expected")
	}
	if expects(cfg, with(chrome, func(c *ExpectCtx) { c.ASN, c.Org = "", "" })) {
		t.Error("chrome to an unnamed address was expected")
	}
	for _, kind := range []string{KindNewPlaceUpload, KindCloudStorage, KindAgentUpload, KindLateralSweep} {
		if expects(cfg, with(chrome, func(c *ExpectCtx) { c.Kind = kind })) {
			t.Errorf("a rule that names no findings made %s expected", kind)
		}
	}
	// Python to the same network is still judged: the rule is for the browser.
	if expects(cfg, with(chrome, func(c *ExpectCtx) { c.Path = "/usr/bin/python3" })) {
		t.Error("python was expected because chrome is")
	}
}

// A first connection to a vendor's own AS is not news; to rented compute
// inside it, or to an address nothing numbered, it is.
func TestShippedVendorNetworksAreNotNewButRentedComputeIs(t *testing.T) {
	cfg := DefaultDetectionTuning()
	dest := with(googleOwn, func(c *ExpectCtx) { c.Kind, c.Path, c.User = KindNovelDestination, "/usr/bin/curl", "alice" })
	if !expects(cfg, dest) {
		t.Error("Google's own AS is not a known network")
	}
	for name, edit := range map[string]func(*ExpectCtx){
		"rented compute in Amazon": func(c *ExpectCtx) { c.ASN, c.Org, c.Tenancy = "AS16509", "Amazon", TenancyHosting },
		"Google Cloud customer": func(c *ExpectCtx) {
			c.ASN, c.Org, c.Tenancy = "AS396982", "Google Cloud (customer range)", TenancyHosting
		},
		"no AS":                     func(c *ExpectCtx) { c.ASN, c.Org = "", "" },
		"an unlisted network":       func(c *ExpectCtx) { c.ASN, c.Org = "AS64500", "Example Net" },
		"a floor-ish port finding":  func(c *ExpectCtx) { c.Kind = "SENSITIVE_PORT_EGRESS" },
		"a threat-list match":       func(c *ExpectCtx) { c.Kind = "THREAT_INTEL_MATCH" },
		"a decoy touch":             func(c *ExpectCtx) { c.Kind = "DECOY_TOUCH" },
		"a lab escape":              func(c *ExpectCtx) { c.Kind = "LAB_ESCAPE" },
		"a port sweep":              func(c *ExpectCtx) { c.Kind = "PORT_SCAN_RECON" },
		"a resolver bypass":         func(c *ExpectCtx) { c.Kind = "RESOLVER_BYPASS" },
		"a silent endpoint":         func(c *ExpectCtx) { c.Kind = "ENDPOINT_SILENT" },
		"an empty kind":             func(c *ExpectCtx) { c.Kind = "" },
		"a cloud storage upload":    func(c *ExpectCtx) { c.Kind = KindCloudStorage },
		"a new-place upload":        func(c *ExpectCtx) { c.Kind = KindNewPlaceUpload },
		"a lateral fan-out":         func(c *ExpectCtx) { c.Kind = KindLateralSweep },
		"an agent upload":           func(c *ExpectCtx) { c.Kind = KindAgentUpload },
		"an agent destination only": func(c *ExpectCtx) { c.Kind = KindAgentNewDest },
	} {
		if expects(cfg, with(dest, edit)) {
			t.Errorf("%s was made expected", name)
		}
	}
}

// Floor kinds can be named by no rule: a save that tries is refused.
func TestNoRuleCanNameAFloorFinding(t *testing.T) {
	for _, kind := range []string{"SENSITIVE_PORT_EGRESS", "THREAT_INTEL_MATCH", "DECOY_TOUCH", "LAB_ESCAPE", "PORT_SCAN_RECON", "RESOLVER_BYPASS", "ENDPOINT_SILENT"} {
		cfg := DefaultDetectionTuning()
		cfg.ExpectedRules = append(cfg.ExpectedRules, ExpectedRule{ID: "floor", Reason: "r", Findings: []string{kind}, Networks: []string{"as15169"}})
		if _, err := PrepareDetectionTuning(cfg); !errors.Is(err, ErrInvalidDetectionTuning) {
			t.Errorf("a rule naming %s was accepted: %v", kind, err)
		}
	}
}

// A rule may pin the build and the account. An event that reports no hash is
// not the pinned build.
func TestARuleCanPinTheBuildAndTheAccount(t *testing.T) {
	sha := strings.Repeat("ab", 32)
	cfg := DefaultDetectionTuning()
	cfg.ExpectedRules = []ExpectedRule{{ID: "ntpd", Reason: "time", Findings: []string{KindNovelProcess},
		Programs: []ExpectedProgram{{Path: "/usr/sbin/ntpd", SHA256: sha, RunAs: "ntp"}}}}
	cfg, err := PrepareDetectionTuning(cfg)
	if err != nil {
		t.Fatal(err)
	}
	c := ExpectCtx{Kind: KindNovelProcess, Path: "/usr/sbin/ntpd", SHA: strings.ToUpper(sha), User: "ntp"}
	if !expects(cfg, c) {
		t.Error("the pinned build as its account is not expected")
	}
	for name, edit := range map[string]func(*ExpectCtx){
		"another build": func(c *ExpectCtx) { c.SHA = strings.Repeat("cd", 32) },
		"no hash":       func(c *ExpectCtx) { c.SHA = "" },
		"another user":  func(c *ExpectCtx) { c.User = "alice" },
		"no user":       func(c *ExpectCtx) { c.User = "" },
	} {
		if expects(cfg, with(c, edit)) {
			t.Errorf("%s matched a pinned entry", name)
		}
	}
}

// A program that updates itself in a folder its user owns can be made expected
// without a hash, for that user only: the next release installs under a new
// version directory and the rule keeps matching.
func TestASelfUpdatingProgramInHomeIsExpectedForItsUser(t *testing.T) {
	cfg := DefaultDetectionTuning()
	cfg.ExpectedRules = append(cfg.ExpectedRules, ExpectedRule{ID: "marked-agy", Reason: "marked from a finding",
		Findings: []string{KindNovelDestination, KindBeacon}, Hosts: []string{"ws-1"},
		Programs: []ExpectedProgram{{Path: "/home/alice/.local/share/agy/versions/*/agy", RunAs: "alice"}}, Networks: []string{"as64500"}})
	cfg, err := PrepareDetectionTuning(cfg)
	if err != nil {
		t.Fatalf("a program in a home folder with no hash was refused: %v", err)
	}
	c := with(ExpectCtx{ASN: "AS64500", Org: "Example Net"}, func(c *ExpectCtx) {
		c.Kind, c.Host, c.User = KindNovelDestination, "ws-1", "alice"
		c.Path = "/home/alice/.local/share/agy/versions/1.4.2/agy"
	})
	if !expects(cfg, c) {
		t.Fatal("the program is not expected")
	}
	if !expects(cfg, with(c, func(c *ExpectCtx) { c.Path = "/home/alice/.local/share/agy/versions/1.5.0/agy" })) {
		t.Error("the next release is not expected")
	}
	for name, edit := range map[string]func(*ExpectCtx){
		"another user":   func(c *ExpectCtx) { c.User = "mallory" },
		"another host":   func(c *ExpectCtx) { c.Host = "ws-2" },
		"another folder": func(c *ExpectCtx) { c.Path = "/home/alice/Downloads/agy" },
		"hosting range":  func(c *ExpectCtx) { c.Tenancy = TenancyHosting },
		"another kind":   func(c *ExpectCtx) { c.Kind = KindBandwidthSpike },
	} {
		if expects(cfg, with(c, edit)) {
			t.Errorf("%s was expected", name)
		}
	}
}

// The matchers would read a name or a fragment more widely than it is written,
// or never match it, so a save that holds one is refused outright.
func TestASaveRefusesUnsoundRules(t *testing.T) {
	s := newTestStore(t)
	prog := func(path string) []ExpectedProgram { return []ExpectedProgram{{Path: path}} }
	bad := map[string]ExpectedRule{
		"no id":                       {Reason: "r", Programs: prog("/usr/bin/x")},
		"no reason":                   {ID: "a", Programs: prog("/usr/bin/x")},
		"matches nothing":             {ID: "a", Reason: "r", Findings: []string{KindBeacon}},
		"program by name":             {ID: "a", Reason: "r", Programs: prog("svchost.exe")},
		"wildcard first directory":    {ID: "a", Reason: "r", Programs: prog("/*/chrome")},
		"wildcard file name":          {ID: "a", Reason: "r", Programs: prog("/opt/google/chrome/*")},
		"short hash":                  {ID: "a", Reason: "r", Programs: []ExpectedProgram{{Path: "/usr/bin/x", SHA256: "abc"}}},
		"run as a fragment":           {ID: "a", Reason: "r", Programs: []ExpectedProgram{{Path: "/usr/bin/x", RunAs: "a b"}}},
		"unknown tenancy":             {ID: "a", Reason: "r", Networks: []string{"as15169"}, Tenancy: "all"},
		"unknown protocol":            {ID: "a", Reason: "r", Port: 80, Protocol: "sctp"},
		"unknown direction":           {ID: "a", Reason: "r", Port: 80, Direction: "sideways"},
		"port out of range":           {ID: "a", Reason: "r", Port: 70000},
		"domain with nothing to pin":  {ID: "a", Reason: "r", Domains: []string{"example.com"}},
		"public suffix domain":        {ID: "a", Reason: "r", Domains: []string{"co.uk"}, Networks: []string{"as15169"}},
		"wildcard domain":             {ID: "a", Reason: "r", Domains: []string{"*.example.com"}, Networks: []string{"as15169"}},
		"wide IPv4 maker prefix":      {ID: "a", Reason: "r", Domains: []string{"example.com"}, Prefixes: []string{"104.0.0.0/8"}},
		"wide IPv6 maker prefix":      {ID: "a", Reason: "r", Domains: []string{"example.com"}, Prefixes: []string{"2600::/16"}},
		"private maker prefix":        {ID: "a", Reason: "r", Domains: []string{"example.com"}, Prefixes: []string{"10.1.0.0/16"}},
		"malformed prefix":            {ID: "a", Reason: "r", Prefixes: []string{"198.51.100/24"}},
		"exception outside domains":   {ID: "a", Reason: "r", Domains: []string{"example.com"}, Networks: []string{"as15169"}, ExceptDomains: []string{"storage.googleapis.com"}},
		"vendor tenancy, any network": {ID: "a", Reason: "r", Networks: []string{"*"}, Tenancy: ExpectedTenancyVendor},
		"vendor tenancy, a name":      {ID: "a", Reason: "r", Networks: []string{"Google LLC"}, Tenancy: ExpectedTenancyVendor},
		"workload with no expiry":     {ID: "a", Reason: "r", Workload: "node /opt/app/server.js"},
		"inline code":                 {ID: "a", Reason: "r", Workload: "python3 -c print(1)", ExpiresAt: time.Now().Add(time.Hour)},
		"max hosts without a sweep":   {ID: "a", Reason: "r", Programs: prog("/usr/bin/x"), MaxHosts: 3},
		"sweep without hosts":         {ID: "a", Reason: "r", Findings: []string{KindLateralSweep}, Programs: prog("/usr/bin/ssh"), Port: 22},
		"sweep without a program":     {ID: "a", Reason: "r", Findings: []string{KindLateralSweep}, Hosts: []string{"ws"}, Port: 22},
		"sweep without a port":        {ID: "a", Reason: "r", Findings: []string{KindLateralSweep}, Hosts: []string{"ws"}, Programs: prog("/usr/bin/ssh")},
		"too many sweep hosts":        {ID: "a", Reason: "r", Findings: []string{KindLateralSweep}, Hosts: []string{"ws"}, Programs: prog("/usr/bin/ssh"), Port: 22, MaxHosts: 99},
	}
	for name, r := range bad {
		cfg := DefaultDetectionTuning()
		cfg.ExpectedRules = append(cfg.ExpectedRules, r)
		if _, err := s.SaveDetectionTuning(cfg, "test"); !errors.Is(err, ErrInvalidDetectionTuning) {
			t.Errorf("%s: saved: err=%v", name, err)
		}
		if _, err := PrepareDetectionTuning(cfg); !errors.Is(err, ErrInvalidDetectionTuning) {
			t.Errorf("%s: a replay draft accepted what a save refuses: %v", name, err)
		}
	}
	dup := DefaultDetectionTuning()
	dup.ExpectedRules = append(dup.ExpectedRules, dup.ExpectedRules[0])
	if _, err := PrepareDetectionTuning(dup); !errors.Is(err, ErrInvalidDetectionTuning) {
		t.Errorf("a rule id used twice was accepted: %v", err)
	}
}

// The runtimes' makers are rules. Anthropic's published ranges vouch for
// claude by address alone; Google's API hosts vouch for antigravity only on
// Google's own network and never on Cloud Storage (anyone's buckets).
func TestRuntimeMakerRulesShipAndKeepToTheirService(t *testing.T) {
	d := DefaultDetectionTuning()
	claude := ExpectCtx{Kind: KindBandwidthSpike, Path: "/home/alice/.local/share/claude/versions/2.1.5", User: "alice", Domain: "api.anthropic.com"}
	for _, ip := range []string{"160.79.104.10", "160.79.105.255", "2607:6bc0::10", "::ffff:160.79.104.10"} {
		for _, kind := range []string{KindBandwidthSpike, KindBandwidthBurst, KindNewPlaceUpload} {
			if !expects(d, with(claude, func(c *ExpectCtx) { c.DstIP, c.Kind = ip, kind })) {
				t.Errorf("claude to %s is not expected for %s", ip, kind)
			}
		}
	}
	for _, ip := range []string{"160.79.106.1", "104.18.1.1"} {
		if expects(d, with(claude, func(c *ExpectCtx) { c.DstIP = ip })) {
			t.Errorf("an address outside the published range (%s) was expected", ip)
		}
	}
	for _, kind := range []string{KindAgentUpload, KindNovelProcess, KindCloudStorage} {
		if expects(d, with(claude, func(c *ExpectCtx) { c.DstIP, c.Kind = "160.79.104.10", kind })) {
			t.Errorf("the maker rule made %s expected; the hourly volume rule keeps judging it", kind)
		}
	}
	if expects(d, with(claude, func(c *ExpectCtx) { c.Path, c.DstIP = "/tmp/tool", "160.79.104.10" })) {
		t.Error("a program at another path counted as the runtime")
	}
	off := d
	off.AgentEgressOn = false
	if expects(off, with(claude, func(c *ExpectCtx) { c.DstIP = "160.79.104.10" })) {
		t.Error("a runtime rule matched while agent egress was switched off")
	}
	for _, runtime := range []string{"codex"} {
		for _, r := range d.ExpectedRules {
			if r.Runtime == runtime {
				t.Errorf("%s ships a maker rule although its API sits behind a shared CDN", runtime)
			}
		}
	}

	agy := with(googleOwn, func(c *ExpectCtx) { c.Kind, c.Path, c.User = KindBandwidthSpike, "/home/alice/.local/bin/agy", "alice" })
	for name, want := range map[string]bool{
		"generativelanguage.googleapis.com":                  true,
		"oauth2.googleapis.com":                              true,
		"storage.googleapis.com":                             false,
		"my-bucket.storage.googleapis.com":                   false,
		"storage-upload.googleapis.com":                      false,
		"storage-download.googleapis.com":                    false,
		"firebasestorage.googleapis.com":                     false,
		"googleapis.com.example.net":                         false,
		"x.storage.googleapis.com.":                          false,
		"antigravity-cli-auto-updater-1.us-central1.run.app": false,
		"": false,
	} {
		if got := expects(d, with(agy, func(c *ExpectCtx) { c.Domain = name })); got != want {
			t.Errorf("antigravity to %q: expected=%v, want %v", name, got, want)
		}
	}
	api := with(agy, func(c *ExpectCtx) { c.Domain = "oauth2.googleapis.com" })
	for name, edit := range map[string]func(*ExpectCtx){
		"Google Cloud customer": func(c *ExpectCtx) { c.ASN, c.Tenancy, c.Source = "AS396982", TenancyHosting, "google-cloud" },
		"hosting in Google AS":  func(c *ExpectCtx) { c.Tenancy = TenancyHosting },
		"the built-in table":    func(c *ExpectCtx) { c.Source = "built-in" },
		"a CDN":                 func(c *ExpectCtx) { c.ASN, c.Source = "AS13335", "cloudflare-v4" },
		"another runtime":       func(c *ExpectCtx) { c.Path = "/home/alice/.local/share/claude/versions/2.1.5" },
	} {
		if expects(d, with(api, edit)) {
			t.Errorf("%s was expected as Google's own service", name)
		}
	}

	if got := d.RuleNamingMaker("claude", "api.anthropic.com"); got != "Anthropic" {
		t.Errorf("claude's maker = %q", got)
	}
	if d.RuleNamingMaker("claude", "anthropic.com.example.net") != "" || d.RuleNamingMaker("ollama", "anthropic.com") != "" ||
		d.RuleNamingMaker("antigravity", "storage.googleapis.com") != "" || d.RuleNamingMaker("claude", "oauth2.googleapis.com") != "" {
		t.Error("a look-alike name, another runtime or Cloud Storage was named as a maker")
	}
}

// Exceptions always win over what a rule matches.
func TestAnExceptionBeatsTheRuleThatMatches(t *testing.T) {
	cfg := DefaultDetectionTuning()
	cfg.ExpectedRules = []ExpectedRule{{ID: "everything-named", Reason: "r", Networks: []string{AnyNetwork},
		Programs: []ExpectedProgram{{Path: "/usr/bin/tool"}}, ExceptDomains: []string{"evil.example.com"}}}
	c := ExpectCtx{Kind: KindNovelDestination, Path: "/usr/bin/tool", Org: "Example Net", ASN: "AS64500", Domain: "ok.example.net"}
	if !expects(cfg, c) {
		t.Fatal("the rule does not match its own traffic")
	}
	for _, name := range []string{"evil.example.com", "a.b.evil.example.com", "EVIL.example.com."} {
		if expects(cfg, with(c, func(c *ExpectCtx) { c.Domain = name })) {
			t.Errorf("%s matched although it is excepted", name)
		}
	}
}

// A rule past its expiry stops matching and a save drops it; a workload rule
// needs an expiry, and a save may not add or change one far out or in the past.
func TestAnExpiredRuleStopsMatching(t *testing.T) {
	cfg := DefaultDetectionTuning()
	rule := ExpectedRule{ID: "temp", Reason: "r", Findings: []string{KindNovelProcess}, Programs: []ExpectedProgram{{Path: "/usr/bin/temp"}}}
	c := ExpectCtx{Kind: KindNovelProcess, Path: "/usr/bin/temp"}
	rule.ExpiresAt = time.Now().Add(time.Hour)
	cfg.ExpectedRules = []ExpectedRule{rule}
	if !expects(cfg, c) {
		t.Fatal("a live rule does not match")
	}
	cfg.ExpectedRules[0].ExpiresAt = time.Now().Add(-time.Minute)
	if expects(cfg, c) {
		t.Fatal("an expired rule still matches")
	}
	got, err := PrepareDetectionTuning(cfg)
	if err != nil || len(got.ExpectedRules) != 0 {
		t.Fatalf("a save kept an expired rule: %+v %v", got.ExpectedRules, err)
	}
}

func TestANewWorkloadRuleNeedsAFutureBoundedExpiry(t *testing.T) {
	now := time.Now()
	mk := func(id string, until time.Time) ExpectedRule {
		return ExpectedRule{ID: id, Reason: "r", Workload: "/usr/bin/gh", ExpiresAt: until}
	}
	old, live := mk("old", now.Add(-time.Hour)), mk("live", now.Add(time.Hour))
	if err := CheckNewRuleExpiry([]ExpectedRule{old}, []ExpectedRule{old, live}, now); err != nil {
		t.Fatalf("carrying a rule over: %v", err)
	}
	if err := CheckNewRuleExpiry([]ExpectedRule{old}, []ExpectedRule{mk("new", now.Add(-time.Minute))}, now); err == nil {
		t.Fatal("a new rule with a past expiry was accepted")
	}
	if err := CheckNewRuleExpiry(nil, []ExpectedRule{mk("far", now.Add(ExpectedMaxWorkloadLifetime+time.Hour))}, now); err == nil {
		t.Fatal("a rule past the longest term was accepted")
	}
	renewed := old
	renewed.ExpiresAt = now.Add(-time.Minute)
	if err := CheckNewRuleExpiry([]ExpectedRule{old}, []ExpectedRule{renewed}, now); err == nil {
		t.Fatal("a changed rule with a past expiry was accepted")
	}
}

// An admin ssh fan-out is expected only from the named host, by the named
// program, on its one port, and for no more hosts than the rule allows.
func TestALateralRuleIsBoundedByHostProgramPortAndCount(t *testing.T) {
	cfg := DefaultDetectionTuning()
	cfg.ExpectedRules = []ExpectedRule{{ID: "admin-ssh", Reason: "routine administration", Findings: []string{KindLateralSweep},
		Hosts: []string{"ws-1"}, Programs: []ExpectedProgram{{Path: "/usr/bin/ssh"}}, Port: 22, MaxHosts: 3}}
	cfg, err := PrepareDetectionTuning(cfg)
	if err != nil {
		t.Fatal(err)
	}
	c := ExpectCtx{Kind: KindLateralSweep, Host: "ws-1", Path: "/usr/bin/ssh", Port: 22, Targets: 3}
	if !expects(cfg, c) {
		t.Fatal("the routine fan-out is not expected")
	}
	for name, edit := range map[string]func(*ExpectCtx){
		"one host too many": func(c *ExpectCtx) { c.Targets = 4 },
		"another source":    func(c *ExpectCtx) { c.Host = "ws-2" },
		"another port":      func(c *ExpectCtx) { c.Port = 445 },
		"another program":   func(c *ExpectCtx) { c.Path = "/usr/bin/nc" },
	} {
		if expects(cfg, with(c, edit)) {
			t.Errorf("%s was expected", name)
		}
	}
}

// A saved rule list reads back as written. Saved tuning is decoded over the
// shipped defaults and encoding/json reuses array elements in place, so a
// saved rule that left a field out used to keep the shipped rule's value at
// its position (Claude's vendor entry read back with Google's network live).
func TestASavedRuleListDoesNotInheritShippedFields(t *testing.T) {
	s := newTestStore(t)
	if _, err := s.db.Exec(`INSERT INTO detection_tuning (id, settings, updated_at, updated_by) VALUES (1, ?, ?, 'old')`,
		`{"expected_rules":[{"id":"a","reason":"r","programs":[{"path":"/usr/bin/a"}]},`+
			`{"id":"b","reason":"r","findings":["NOVEL_DESTINATION"],"networks":["as15169"]},`+
			`{"id":"c","reason":"r","programs":[{"path":"/usr/bin/c"}]}]}`, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	got := s.GetDetectionTuning().ExpectedRules
	want := []ExpectedRule{
		{ID: "a", Reason: "r", Programs: []ExpectedProgram{{Path: "/usr/bin/a"}}},
		{ID: "b", Reason: "r", Findings: []string{KindNovelDestination}, Networks: []string{"as15169"}},
		{ID: "c", Reason: "r", Programs: []ExpectedProgram{{Path: "/usr/bin/c"}}},
	}
	gotJSON, _ := json.Marshal(got)
	wantJSON, _ := json.Marshal(tidyRules(want))
	if string(gotJSON) != string(wantJSON) {
		t.Fatalf("rules read back as\n%s\nwant\n%s", gotJSON, wantJSON)
	}
	if p := s.DetectionTuningProblem(); p != "" {
		t.Fatalf("the row is reported unsound: %s", p)
	}
}

// liveRow is the shape of the production row at 1.8.111: the quiet lists left
// at their shipped values (absent from the row), one expected pair, known
// workloads for installed programs and interpreters, an admin ssh source, and
// the agent runtime vendors in the exclude_domains and networks form.
const liveRow = `{"first_seen_cooldown_minutes":240,"warmup_hours":12,
"quiet_pairs":["/usr/local/bin/rclone@google llc"],
"known_workloads":[
 {"workload":"/opt/google/chrome/chrome","owner":"*","reason":"the owner's browser","expires_at":"2099-01-15T02:32:09Z"},
 {"workload":"/usr/bin/gh","owner":"as36459","reason":"GitHub CLI","expires_at":"2099-01-15T02:32:09Z"},
 {"workload":"node /home/owner/.local/bin/pnpm","owner":"as13335","reason":"pnpm","expires_at":"2099-01-15T02:32:09Z"},
 {"workload":"/usr/bin/old","owner":"*","reason":"expired","expires_at":"2020-01-15T02:32:09Z"}],
"admin_fanout_sources":["linux-workstation"],"admin_fanout_targets":[],"admin_fanout_max_hosts":8,
"agent_runtime_vendors":[
 {"runtime":"antigravity","vendor":"Google","domains":["googleapis.com"],"exclude_domains":["content-storage-download.googleapis.com","content-storage-upload.googleapis.com","firebasestorage.googleapis.com","storage-download.googleapis.com","storage-upload.googleapis.com","storage.googleapis.com","storage.mtls.googleapis.com","www.googleapis.com"],"prefixes":[],"networks":["as15169"]},
 {"runtime":"claude","vendor":"Anthropic","domains":["anthropic.com","claude.ai","claude.com","claudeusercontent.com"],"exclude_domains":[],"prefixes":["160.79.104.0/23","2607:6bc0::/48"],"networks":[]},
 {"runtime":"codex","vendor":"OpenAI","domains":["chatgpt.com","openai.com"],"exclude_domains":[],"prefixes":[],"networks":[]}]}`

// The four live exclusions: an endpoint-scoped backup, and three global ones.
func insertLiveExclusions(t *testing.T, s *Store) {
	t.Helper()
	if _, err := s.db.Exec(`CREATE TABLE exclusions (id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL DEFAULT "default",
		scope TEXT NOT NULL DEFAULT "global", scope_value TEXT NOT NULL DEFAULT "", name TEXT NOT NULL,
		process_path TEXT NOT NULL DEFAULT "*", dst_ip_range TEXT NOT NULL DEFAULT "*", port INTEGER NOT NULL DEFAULT 0,
		protocol TEXT NOT NULL DEFAULT "any", reason TEXT NOT NULL DEFAULT "", active INTEGER NOT NULL DEFAULT 1,
		created_at DATETIME NOT NULL, expires_at DATETIME)`); err != nil {
		t.Fatal(err)
	}
	until := time.Now().UTC().Add(60 * 24 * time.Hour)
	for _, ex := range [][]any{
		{"ex-backup", "endpoint", "linux-workstation", "Offsite backup", "/usr/local/bin/rclone", "172.217.0.0/16", 443, "tcp", "restic copy to Google Drive", 1},
		{"ex-agy", "global", "", "Antigravity developer assistant", "/home/owner/.local/bin/agy", "", 0, "", "telemetry", 1},
		{"ex-py", "global", "", "Local development service", "/home/owner/.local/share/uv/python/cpython-3.13.12-linux-x86_64-gnu/bin/python3.13", "127.0.0.1/32", 7070, "tcp", "test runner", 1},
		{"ex-docker", "global", "", "Docker proxy local bridge", "/usr/bin/docker-proxy", "172.18.0.0/16", 7070, "tcp", "bridge", 1},
		{"ex-off", "global", "", "Switched off", "/usr/bin/off", "", 0, "", "no longer", 0},
	} {
		if _, err := s.db.Exec(`INSERT INTO exclusions (id, scope, scope_value, name, process_path, dst_ip_range, port, protocol, reason, active, created_at, expires_at)
			VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`, append(ex, time.Now().UTC(), until)...); err != nil {
			t.Fatal(err)
		}
	}
}

// The storage migration turns the live quiet lists, pair, known workloads,
// admin source, vendors and exclusions into rules, keeping what each
// suppressed and nothing more, drops the exclusions table, and does not run a
// second time.
func TestTheLiveRowAndExclusionsMigrateToRulesWithoutLoosening(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy.db")
	s, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`INSERT INTO detection_tuning (id, settings, updated_at, updated_by) VALUES (1, ?, ?, 'admin')`, liveRow, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	insertLiveExclusions(t, s)
	s.Close()

	s, err = New(path)
	if err != nil {
		t.Fatal(err)
	}
	got := s.GetDetectionTuning()
	if got.UpdatedBy != "upgrade" || got.WarmupHours != 12 {
		t.Fatalf("migrated row (it still holds the retired first_seen_cooldown_minutes): by %q warmup %d", got.UpdatedBy, got.WarmupHours)
	}
	if _, err := PrepareDetectionTuning(got); err != nil {
		t.Fatalf("the migrated row is not one a save would accept: %v", err)
	}
	var n int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE name = 'exclusions'`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("the exclusions table is still there: %d %v", n, err)
	}
	ids := map[string]bool{}
	for _, r := range got.ExpectedRules {
		ids[r.ID] = true
	}
	for _, id := range []string{"system-components", "vendor-networks", "vendor-claude", "vendor-antigravity", "exclusion-ex-backup", "exclusion-ex-agy", "exclusion-ex-py", "exclusion-ex-docker"} {
		if !ids[id] {
			t.Errorf("no rule %s after the migration; have %v", id, ids)
		}
	}
	for id := range ids {
		if strings.Contains(id, "off") && strings.HasPrefix(id, "exclusion-") || strings.Contains(id, "codex") {
			t.Errorf("rule %s was carried over: a switched-off exclusion and a name-only vendor prove nothing", id)
		}
	}

	rclone := ExpectCtx{Kind: KindBandwidthSpike, Host: "linux-workstation", Path: "/usr/local/bin/rclone", User: "owner",
		DstIP: "172.217.4.1", Port: 443, Protocol: 6, Direction: "OUTBOUND"}
	agy := ExpectCtx{Kind: KindNovelDestination, Host: "any", Path: "/home/owner/.local/bin/agy", User: "owner"}
	python := ExpectCtx{Kind: KindNovelDestination, Host: "any", User: "owner", DstIP: "127.0.0.1", Port: 7070, Protocol: 6, Direction: "OUTBOUND",
		Path: "/home/owner/.local/share/uv/python/cpython-3.13.12-linux-x86_64-gnu/bin/python3.13"}
	docker := ExpectCtx{Kind: KindBeacon, Host: "any", Path: "/usr/bin/docker-proxy", User: "root", DstIP: "172.18.0.9", Port: 7070, Protocol: 6, Direction: "OUTBOUND"}
	for name, c := range map[string]ExpectCtx{"backup": rclone, "agy": agy, "python": python, "docker proxy": docker} {
		if !expects(got, c) {
			t.Errorf("the %s exclusion no longer suppresses", name)
		}
	}
	for name, c := range map[string]ExpectCtx{
		"backup on another host":     with(rclone, func(c *ExpectCtx) { c.Host = "other" }),
		"backup to another range":    with(rclone, func(c *ExpectCtx) { c.DstIP = "8.8.8.8" }),
		"backup on another port":     with(rclone, func(c *ExpectCtx) { c.Port = 80 }),
		"python to the internet":     with(python, func(c *ExpectCtx) { c.DstIP = "8.8.8.8" }),
		"python on another port":     with(python, func(c *ExpectCtx) { c.Port = 22 }),
		"docker proxy out of range":  with(docker, func(c *ExpectCtx) { c.DstIP = "10.9.9.9" }),
		"a lookalike agy":            with(agy, func(c *ExpectCtx) { c.Path = "/tmp/agy" }),
		"curl uploading to a bucket": {Kind: KindCloudStorage, Path: "/usr/bin/curl", User: "owner", Domain: "x.storage.googleapis.com", ASN: "AS15169", Org: "Google LLC", Tenancy: TenancyVendor, Source: "google"},
		"the switched-off exclusion": {Kind: KindNovelProcess, Path: "/usr/bin/off", User: "owner"},
		"a floor finding":            with(agy, func(c *ExpectCtx) { c.Kind = "LAB_ESCAPE" }),
	} {
		if expects(got, c) {
			t.Errorf("%s is suppressed", name)
		}
	}

	// The pair, as its conversion: that program to Google by name.
	pair := ExpectCtx{Kind: KindBeacon, Path: "/usr/local/bin/rclone", User: "owner", ASN: "AS15169", Org: "google llc", Tenancy: TenancyVendor, Source: "google"}
	if !expects(got, pair) || expects(got, with(pair, func(c *ExpectCtx) { c.Tenancy = TenancyHosting })) || expects(got, with(pair, func(c *ExpectCtx) { c.Path = "/tmp/rclone" })) {
		t.Error("the expected pair did not carry over exactly")
	}
	// Known workloads keep their reach: an installed program known for any
	// owner reached anywhere, a named owner never rented compute, an
	// interpreter only the owner it named, and the expired one nothing.
	chrome := ExpectCtx{Kind: KindNovelDestination, Path: "/opt/google/chrome/chrome", Workload: "/opt/google/chrome/chrome", ASN: "AS64500", Org: "Example Net", User: "owner"}
	gh := ExpectCtx{Kind: KindNovelDestination, Path: "/usr/bin/gh", Workload: "/usr/bin/gh", ASN: "AS36459", Org: "GitHub, Inc.", Tenancy: TenancyVendor, User: "owner"}
	pnpm := ExpectCtx{Kind: KindNovelProcess, Path: "/usr/bin/node", Workload: "node /home/owner/.local/bin/pnpm", ASN: "AS13335", Org: "Cloudflare, Inc.", User: "owner"}
	if !expects(got, chrome) || !expects(got, gh) || !expects(got, pnpm) {
		t.Error("a known workload no longer vouches")
	}
	if !expects(got, with(chrome, func(c *ExpectCtx) { c.Kind = KindOffHours })) || expects(got, with(gh, func(c *ExpectCtx) { c.Kind = KindOffHours })) {
		t.Error("only a workload known for any owner is also expected off-hours")
	}
	if expects(got, with(gh, func(c *ExpectCtx) { c.Tenancy = TenancyHosting })) || expects(got, with(pnpm, func(c *ExpectCtx) { c.ASN, c.Org = "AS64500", "Example Net" })) {
		t.Error("a known workload widened to rented compute or another owner")
	}
	if expects(got, ExpectCtx{Kind: KindNovelDestination, Path: "/usr/bin/old", Workload: "/usr/bin/old", ASN: "AS64500", Org: "Example Net"}) {
		t.Error("an expired known workload still vouches")
	}
	// Admin ssh.
	ssh := ExpectCtx{Kind: KindLateralSweep, Host: "linux-workstation", Path: "/usr/bin/ssh", Port: 22, Targets: 8}
	if !expects(got, ssh) || expects(got, with(ssh, func(c *ExpectCtx) { c.Targets = 9 })) || expects(got, with(ssh, func(c *ExpectCtx) { c.Host = "x" })) {
		t.Error("the admin ssh source did not carry over exactly")
	}
	// Vendors: the 1.8.111 shape with exclude_domains and networks.
	agyAPI := with(googleOwn, func(c *ExpectCtx) {
		c.Kind, c.Path, c.User, c.Domain = KindBandwidthSpike, "/home/owner/.local/bin/agy.real", "owner", "oauth2.googleapis.com"
	})
	agyAPI.Path = "/usr/bin/agy"
	if !expects(got, with(agyAPI, func(c *ExpectCtx) { c.Domain = "generativelanguage.googleapis.com" })) ||
		expects(got, with(agyAPI, func(c *ExpectCtx) { c.Domain = "www.googleapis.com" })) {
		t.Error("agy to www.googleapis.com (Drive and Cloud Storage uploads too) must page; the Gemini API host must not")
	}
	if !expects(got, agyAPI) || expects(got, with(agyAPI, func(c *ExpectCtx) { c.Domain = "storage.googleapis.com" })) {
		t.Error("the antigravity vendor did not carry over with its exclusions")
	}
	if !expects(got, ExpectCtx{Kind: KindBandwidthSpike, Path: "/usr/bin/claude", DstIP: "160.79.104.9", Domain: "api.anthropic.com"}) {
		t.Error("the claude vendor range did not carry over")
	}
	if expects(got, ExpectCtx{Kind: KindBandwidthSpike, Path: "/usr/bin/codex", DstIP: "104.18.1.1", Domain: "chatgpt.com"}) {
		t.Error("codex became expected through a name alone")
	}

	stamped := got.UpdatedAt
	s.Close()
	s, err = New(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if again := s.GetDetectionTuning(); !again.UpdatedAt.Equal(stamped) || !reflect.DeepEqual(again.ExpectedRules, got.ExpectedRules) {
		t.Errorf("a second start rewrote the row (%v, then %v)", stamped, again.UpdatedAt)
	}
}

// A row that never carried the old lists reads as the shipped rules, and an
// exclusions table with nothing in it is simply dropped.
func TestARowWithoutOldListsGetsTheShippedRules(t *testing.T) {
	path := filepath.Join(t.TempDir(), "plain.db")
	s, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`INSERT INTO detection_tuning (id, settings, updated_at, updated_by) VALUES (1, ?, ?, 'admin')`, `{"warmup_hours":12}`, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	s.Close()
	s, err = New(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	got := s.GetDetectionTuning()
	if got.WarmupHours != 12 || !reflect.DeepEqual(got.ExpectedRules, DefaultDetectionTuning().ExpectedRules) {
		t.Fatalf("an old row did not get the shipped rules: %+v", got.ExpectedRules)
	}
	if p := s.DetectionTuningProblem(); p != "" {
		t.Fatalf("old row reported unsound: %s", p)
	}
}
