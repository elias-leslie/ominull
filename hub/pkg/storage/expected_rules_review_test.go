package storage

import (
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func sshProgram() []ExpectedProgram { return []ExpectedProgram{{Path: "/usr/bin/ssh"}} }

// No lateral rule may name a floor port, and a stored one covers nothing:
// SMB, RDP, telnet and RPC fan-outs are how a worm moves.
func TestALateralRuleNeverCoversAFloorPort(t *testing.T) {
	for _, port := range []int{23, 135, 445, 3389} {
		r := ExpectedRule{ID: "lat", Reason: "r", Findings: []string{KindLateralSweep}, Hosts: []string{"ws"}, Programs: sshProgram(), Port: port}
		if r.problem() == "" {
			t.Errorf("a lateral rule on port %d was accepted", port)
		}
		cfg := DefaultDetectionTuning()
		cfg.ExpectedRules = append(cfg.ExpectedRules, r)
		if _, err := PrepareDetectionTuning(cfg); err == nil {
			t.Errorf("port %d: a save accepted it", port)
		}
		// A row from an older build: the matcher itself refuses.
		if expects(cfg, ExpectCtx{Kind: KindLateralSweep, Host: "ws", Path: "/usr/bin/ssh", Port: port, Targets: 3}) {
			t.Errorf("a stored lateral rule on port %d explained a fan-out", port)
		}
	}
	ok := ExpectedRule{ID: "lat", Reason: "r", Findings: []string{KindLateralSweep}, Hosts: []string{"ws"}, Programs: sshProgram(), Port: 22}
	if msg := ok.problem(); msg != "" {
		t.Fatalf("admin ssh on 22 refused: %s", msg)
	}
	cfg := DefaultDetectionTuning()
	cfg.ExpectedRules = append(cfg.ExpectedRules, ok)
	if !expects(cfg, ExpectCtx{Kind: KindLateralSweep, Host: "ws", Path: "/usr/bin/ssh", Port: 22, Targets: 3}) {
		t.Error("admin ssh on 22 no longer expected")
	}
}

// A rule that lists domains needs the name under one of them whichever way the
// address proves the maker, and a vendor rule must have domains.
func TestAVendorRuleNeedsTheMakersName(t *testing.T) {
	d := DefaultDetectionTuning()
	claude := ExpectCtx{Kind: KindBandwidthSpike, Path: "/usr/bin/claude", User: "alice", DstIP: "160.79.104.10"}
	if expects(d, claude) {
		t.Error("claude to the maker's range with no name was expected")
	}
	if expects(d, with(claude, func(c *ExpectCtx) { c.Domain = "evil.example.com" })) {
		t.Error("claude to the maker's range under another name was expected")
	}
	if !expects(d, with(claude, func(c *ExpectCtx) { c.Domain = "api.anthropic.com" })) {
		t.Error("claude to the maker's range under the maker's name was not expected")
	}
	agy := ExpectCtx{Kind: KindBandwidthSpike, Path: "/usr/bin/agy", User: "alice", ASN: "AS15169", Org: "Google LLC", Tenancy: TenancyVendor, Source: "google"}
	if expects(d, agy) || expects(d, with(agy, func(c *ExpectCtx) { c.Domain = "example.org" })) {
		t.Error("agy on the maker's network with no maker's name was expected")
	}
	if !expects(d, with(agy, func(c *ExpectCtx) { c.Domain = "oauth2.googleapis.com" })) {
		t.Error("agy to the maker's API was not expected")
	}
	r := ExpectedRule{ID: "v", Reason: "r", Runtime: "claude", Vendor: "Anthropic", Prefixes: []string{"160.79.104.0/23"}, Tenancy: ExpectedTenancyVendor}
	if r.problem() == "" {
		t.Error("a vendor rule without domains was accepted")
	}
}

func newLegacyStore(t *testing.T, row string) (string, *Store) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "legacy.db")
	s, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`INSERT INTO detection_tuning (id, settings, updated_at, updated_by) VALUES (1, ?, ?, 'admin')`, row, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	return path, s
}

// The conversion keeps each old entry's reach: quiet processes did not cover
// the agent first-contact finding, a workload without an owner never matched,
// a vendor without domains needed a name it did not have, and the managed-host
// list moved into the infrastructure zone.
func TestMigrationKeepsTheReachOfEachOldEntry(t *testing.T) {
	row := `{"quiet_processes":["/usr/sbin/chronyd user:chrony"],"quiet_orgs":[],"quiet_clients":[],"quiet_pairs":[],
	 "known_workloads":[{"workload":"/usr/bin/nameless","owner":"","reason":"x","expires_at":"2099-01-01T00:00:00Z"}],
	 "agent_runtime_vendors":[{"runtime":"claude","vendor":"Anthropic","domains":[],"prefixes":["160.79.104.0/23"]}],
	 "admin_fanout_sources":[],"admin_fanout_targets":["10.0.0.1","8.8.8.8"]}`
	path, s := newLegacyStore(t, row)
	s.Close()
	s, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	got := s.GetDetectionTuning()
	chronyd := ExpectCtx{Kind: KindNovelProcess, Path: "/usr/sbin/chronyd", User: "chrony"}
	if !expects(got, chronyd) {
		t.Error("a quiet process no longer covers the novelty finding")
	}
	if expects(got, with(chronyd, func(c *ExpectCtx) { c.Kind = KindAgentNewDest })) {
		t.Error("a quiet process now covers AGENT_NEW_DESTINATION, which it never did")
	}
	for _, r := range got.ExpectedRules {
		if strings.HasPrefix(r.ID, "workload-") || strings.HasPrefix(r.ID, "vendor-claude") {
			t.Errorf("rule %s carried over: an ownerless workload and a domainless vendor matched nothing", r.ID)
		}
	}
	if !got.IsInfraAddress("10.0.0.1") {
		t.Error("the admin fan-out target did not move into the infrastructure zone")
	}
	if got.IsInfraAddress("8.8.8.8") {
		t.Error("a public fan-out target became infrastructure")
	}
}

// A migrated exclusion matched its path byte for byte; the rule does too.
// Two exclusions whose ids read the same both survive, and a second boot is a
// no-op.
func TestMigratedExclusionsStayExactAndCollisionsSurvive(t *testing.T) {
	path, s := newLegacyStore(t, `{"quiet_processes":[],"quiet_orgs":[],"quiet_clients":[]}`)
	if _, err := s.db.Exec(`CREATE TABLE exclusions (id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL DEFAULT "default",
		scope TEXT NOT NULL DEFAULT "global", scope_value TEXT NOT NULL DEFAULT "", name TEXT NOT NULL,
		process_path TEXT NOT NULL DEFAULT "*", dst_ip_range TEXT NOT NULL DEFAULT "*", port INTEGER NOT NULL DEFAULT 0,
		protocol TEXT NOT NULL DEFAULT "any", reason TEXT NOT NULL DEFAULT "", active INTEGER NOT NULL DEFAULT 1,
		created_at DATETIME NOT NULL, expires_at DATETIME)`); err != nil {
		t.Fatal(err)
	}
	until := time.Now().UTC().Add(30 * 24 * time.Hour)
	for _, ex := range [][]any{
		{"a/b", "/opt/App/Tool", "first"},
		{"a-b", "/opt/other/tool", "second"},
	} {
		if _, err := s.db.Exec(`INSERT INTO exclusions (id, name, process_path, reason, created_at, expires_at) VALUES (?,?,?,?,?,?)`,
			ex[0], ex[2], ex[1], "r", time.Now().UTC(), until); err != nil {
			t.Fatal(err)
		}
	}
	s.Close()
	s, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	got := s.GetDetectionTuning()
	s.Close()
	n := 0
	for _, r := range got.ExpectedRules {
		if strings.HasPrefix(r.ID, "exclusion-a-b") {
			n++
		}
	}
	if n != 2 {
		t.Fatalf("the two colliding exclusions became %d rules: %+v", n, got.ExpectedRules)
	}
	exact := ExpectCtx{Kind: KindNovelProcess, Path: "/opt/App/Tool", User: "u"}
	if !expects(got, exact) {
		t.Error("the exclusion no longer matches its own path")
	}
	for _, p := range []string{"/opt/app/tool", "/opt/App/Tool (deleted)"} {
		if expects(got, with(exact, func(c *ExpectCtx) { c.Path = p })) {
			t.Errorf("the exclusion for /opt/App/Tool also matches %q", p)
		}
	}
	// A second boot changes nothing.
	s, err = New(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if again := s.GetDetectionTuning(); len(again.ExpectedRules) != len(got.ExpectedRules) {
		t.Errorf("a second boot changed the rules: %d then %d", len(got.ExpectedRules), len(again.ExpectedRules))
	}
}

// A saved rule the checks refuse covers nothing and the row is reported.
func TestARuleThatFailsTheChecksIsSkippedOnRead(t *testing.T) {
	path, s := newLegacyStore(t, `{"expected_rules":[
	 {"id":"good","reason":"r","programs":[{"path":"/usr/bin/good"}]},
	 {"id":"lat","reason":"r","findings":["LATERAL_PORT_SWEEP"],"hosts":["ws"],"programs":[{"path":"/usr/bin/ssh"}],"port":445},
	 {"id":"noreason","programs":[{"path":"/usr/bin/other"}]}]}`)
	defer s.Close()
	_ = path
	got := s.GetDetectionTuning()
	ids := []string{}
	for _, r := range got.ExpectedRules {
		ids = append(ids, r.ID)
	}
	if strings.Join(ids, ",") != "good" {
		t.Errorf("rules read: %v", ids)
	}
	if s.DetectionTuningProblem() == "" {
		t.Error("the refused rules were not reported")
	}
}
