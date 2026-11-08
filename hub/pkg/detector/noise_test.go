package detector

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"ominull/hub/pkg/storage"
	"ominull/hub/pkg/threatintel"
)

// The production fleet carried 2,549 open alerts, and the great majority of
// them were the detectors describing the platform rather than an intruder.
// These tests hold each of the specific causes shut.

func noiseEngine(t *testing.T) (*Engine, *storage.Store) {
	t.Helper()
	store, err := storage.New(filepath.Join(t.TempDir(), "noise.db"))
	if err != nil {
		t.Fatalf("storage.New() failed: %v", err)
	}
	t.Cleanup(func() { store.Close() })

	// Warm-up holds every behavioural finding for a day after an endpoint first
	// reports, which would mask everything these tests are checking.
	tuning := storage.DefaultDetectionTuning()
	tuning.WarmupHours = 0
	if _, err := store.SaveDetectionTuning(tuning, "test"); err != nil {
		t.Fatalf("saving tuning: %v", err)
	}
	return New(store, make(chan storage.Event, 64), func(string, string) error { return nil }), store
}

// firstBeacons is the beacon findings but the one raised again for a
// conversation that turned strong enough to page (strengthened).
func firstBeacons(t *testing.T, store *storage.Store) []storage.AnomalyAlert {
	t.Helper()
	var out []storage.AnomalyAlert
	for _, a := range anomaliesOfType(t, store, "C2_BEACONING") {
		if !strings.Contains(a.Evidence, `"strengthened":true`) {
			out = append(out, a)
		}
	}
	return out
}

func anomaliesOfType(t *testing.T, store *storage.Store, kind string) []storage.AnomalyAlert {
	t.Helper()
	all, err := store.ListAnomalyAlerts("", 500)
	if err != nil {
		t.Fatalf("ListAnomalyAlerts failed: %v", err)
	}
	var out []storage.AnomalyAlert
	for _, a := range all {
		if a.AnomalyType == kind {
			out = append(out, a)
		}
	}
	return out
}

// Chrome and the ChatGPT client holding Google's push channel open scored 1.00
// with zero payload variation. Google is in the shipped quiet-organisation
// list; the exemption applied only on port 443, and the push channel is 5228.
func TestAQuietOrganisationIsQuietOnEveryPort(t *testing.T) {
	engine, store := noiseEngine(t)
	now := time.Now().UTC()
	// 74.125.0.0/16 is Google. Thirty check-ins, thirty seconds apart, is the
	// shape that scored 1.00 on the fleet.
	for i := 0; i < 30; i++ {
		engine.Evaluate(storage.Event{
			TenantID: "default", EndpointID: "linux-03", Timestamp: now.Add(time.Duration(i) * 30 * time.Second),
			Action: "PERMIT", Direction: "OUTBOUND",
			DstIP: "74.125.26.188", DstPort: 5228, BytesOut: 64,
			ProcessPath: "/opt/google/chrome/chrome",
		})
	}
	if got := anomaliesOfType(t, store, "C2_BEACONING"); len(got) != 0 {
		t.Errorf("a keepalive to a trusted network owner raised %d beacon alert(s): %s", len(got), got[0].Title)
	}
}

// A metronomic conversation with a network nobody has vouched for is still the
// finding this detector exists for.
func TestBeaconingToAnUnvouchedNetworkStillFires(t *testing.T) {
	engine, store := noiseEngine(t)
	now := time.Now().UTC()
	for i := 0; i < 30; i++ {
		engine.Evaluate(storage.Event{
			TenantID: "default", EndpointID: "linux-04", Timestamp: now.Add(time.Duration(i) * 30 * time.Second),
			Action: "PERMIT", Direction: "OUTBOUND",
			DstIP: "198.51.100.44", DstPort: 8443, BytesOut: 128,
			ProcessPath: "/tmp/implant",
		})
	}
	if got := anomaliesOfType(t, store, "C2_BEACONING"); len(got) == 0 {
		t.Error("a metronomic conversation with an unattributed network raised nothing")
	}
}

func itoa(n int) string { return strconv.Itoa(n) }

// A quiet organisation on its own is a very wide statement: it silences every
// process on every port to a network that fronts a large part of the web. That
// is where beaconing hides, so what is vouched for is the pair - this process,
// to this owner.

func beaconEvents(engine *Engine, endpointID, dstIP, procPath string, now time.Time) {
	for i := 0; i < 40; i++ {
		engine.Evaluate(storage.Event{
			TenantID: "default", EndpointID: endpointID,
			Timestamp: now.Add(time.Duration(i) * 60 * time.Second),
			Action:    "PERMIT", Direction: "OUTBOUND",
			DstIP: dstIP, DstPort: 443, BytesOut: 1024,
			ProcessPath: procPath,
		})
	}
}

func TestAnInterpreterBeaconingThroughAVouchedNetworkIsStillAFinding(t *testing.T) {
	engine, store := noiseEngine(t)
	// 104.16.0.1 is Cloudflare, which the shipped tuning vouches for.
	beaconEvents(engine, "linux-20", "104.16.0.1", "/usr/bin/python3.13", time.Now().UTC().Add(-2*time.Hour))

	if got := anomaliesOfType(t, store, "C2_BEACONING"); len(got) == 0 {
		t.Fatal("python3.13 beaconing through a CDN raised nothing; a vouched owner is not a vouched conversation")
	}
}

func TestABrowserTalkingToTheSameVouchedNetworkIsNotAFinding(t *testing.T) {
	engine, store := noiseEngine(t)
	beaconEvents(engine, "linux-21", "104.16.0.1", "/opt/google/chrome/chrome", time.Now().UTC().Add(-2*time.Hour))

	if got := anomaliesOfType(t, store, "C2_BEACONING"); len(got) != 0 {
		t.Fatalf("an ordinary browser keepalive to a vouched network raised %d alerts: %q", len(got), got[0].Title)
	}
}

// Rented compute is never vouched for, whoever owns the range. An EC2 address
// is Amazon's allocation and somebody else's machine, and "amazon" is in the
// shipped quiet-org list.
func TestABrowserTalkingToRentedComputeIsNotVouchedFor(t *testing.T) {
	tuning := storage.DefaultDetectionTuning()
	for _, tc := range []struct {
		name    string
		tenancy string
		want    bool
	}{
		{"vendor range", storage.TenancyVendor, true},
		{"shared edge", storage.TenancySharedCDN, true},
		{"rented compute", storage.TenancyHosting, false},
	} {
		_, got := tuning.Expected(storage.ExpectCtx{Kind: storage.KindBeacon, Path: "/opt/google/chrome/chrome",
			ASN: "AS16509", Org: "Amazon Web Services", Tenancy: tc.tenancy, Direction: "OUTBOUND"})
		if got != tc.want {
			t.Fatalf("%s: the shipped rules expected a beacon = %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestAnExplicitRuleCoversThatConversationAndNoOther(t *testing.T) {
	tuning := storage.DefaultDetectionTuning()
	tuning.ExpectedRules = append(tuning.ExpectedRules, storage.ExpectedRule{ID: "backup", Reason: "fixture",
		Findings: []string{storage.KindBeacon}, Programs: []storage.ExpectedProgram{{Path: "/opt/backup/backup-agent"}}, Networks: []string{"backblaze, inc."}})
	tuning = mustSaveTuning(t, tuning)

	covered := func(path, asn, org string) bool {
		_, ok := tuning.Expected(storage.ExpectCtx{Kind: storage.KindBeacon, Path: path, ASN: asn, Org: org,
			Tenancy: storage.TenancyVendor, Source: "published-feed", Direction: "OUTBOUND"})
		return ok
	}
	if !covered("/opt/backup/backup-agent", "", "Backblaze, Inc.") {
		t.Fatal("the rule the operator named was not honoured")
	}
	if covered("/usr/bin/python3", "", "Backblaze, Inc.") || covered("/tmp/backup-agent", "", "Backblaze, Inc.") {
		t.Fatal("a rule covered every process reaching that owner")
	}
	if covered("/opt/backup/backup-agent", "AS13335", "Cloudflare, Inc.") {
		t.Fatal("a rule covered its process reaching any owner")
	}
}

func TestAMalformedRuleIsRefusedRatherThanWidened(t *testing.T) {
	store, err := storage.New(filepath.Join(t.TempDir(), "tuning.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	for name, r := range map[string]storage.ExpectedRule{
		"no reason":           {ID: "a", Programs: []storage.ExpectedProgram{{Path: "/usr/bin/curl"}}, Networks: []string{"as36459"}},
		"no match at all":     {ID: "b", Reason: "r"},
		"a bare program name": {ID: "c", Reason: "r", Programs: []storage.ExpectedProgram{{Path: "chrome"}}},
	} {
		tuning := store.GetDetectionTuning()
		tuning.ExpectedRules = append(tuning.ExpectedRules, r)
		if _, err := store.SaveDetectionTuning(tuning, "test"); err == nil {
			t.Errorf("%s: saved a rule that matches too much or says nothing", name)
		}
	}
}

func mustSaveTuning(t *testing.T, tuning storage.DetectionTuning) storage.DetectionTuning {
	t.Helper()
	store, err := storage.New(filepath.Join(t.TempDir(), "tuning.db"))
	if err != nil {
		t.Fatalf("storage.New() failed: %v", err)
	}
	t.Cleanup(func() { store.Close() })
	saved, err := store.SaveDetectionTuning(tuning, "test")
	if err != nil {
		t.Fatalf("saving tuning: %v", err)
	}
	return saved
}

// The suffix match this replaces missed the interpreter behind most of the
// fleet's beacon-shaped traffic, and treated /usr/bin/sync as netcat.
func TestInterpretersAreMatchedOnTheirNameNotTheTailOfThePath(t *testing.T) {
	for _, name := range []string{
		"python3.13", "python3", "python.exe", "pythonw.exe", "perl5.38",
		"node", "ruby3.2", "php8.3", "osascript", "powershell.exe", "pwsh",
		"bash", "zsh", "nc", "ncat", "curl", "wget",
	} {
		if !isInterpreterOrShell(name) {
			t.Fatalf("%s should be recognised as an interpreter or shell", name)
		}
	}
	for _, name := range []string{
		"sync", "vnc", "zsync", "vncviewer", "nodeguard", "pythonic-agent",
		"chrome", "ominulld", "svchost.exe", "rubygems-helper",
	} {
		if isInterpreterOrShell(name) {
			t.Fatalf("%s was mistaken for an interpreter or shell", name)
		}
	}
}

// Every flow already carries the command line, the user, the executable hash
// and the parent pid. Before this, an analyst had to leave the finding and go
// looking for all four.
func TestAFindingCarriesWhatRanAndAsWhom(t *testing.T) {
	engine, store := noiseEngine(t)
	now := time.Now().UTC()

	// A floor finding (SMB leaving the network), carrying the process context
	// the agent reports.
	engine.Evaluate(storage.Event{
		TenantID: "default", EndpointID: "linux-22", Timestamp: now,
		Action: "PERMIT", Direction: "OUTBOUND",
		DstIP: "104.16.0.2", DstPort: 445, BytesOut: 12 * 1024 * 1024,
		ProcessPath:  "/usr/bin/python3.13",
		ProcessID:    4242,
		ParentPID:    991,
		CommandLine:  "python3.13 /tmp/.cache/agent.py --quiet",
		UserIdentity: "kiosk",

		ExecutableSHA256: "9f2b1c0d4e5a6b7c8d9e0f1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e",
	})

	found := anomaliesOfType(t, store, "SENSITIVE_PORT_EGRESS")
	if len(found) == 0 {
		t.Fatal("expected a finding for this conversation")
	}

	var evidence map[string]any
	for _, a := range found {
		if a.Evidence == "" {
			continue
		}
		var fields map[string]any
		if err := json.Unmarshal([]byte(a.Evidence), &fields); err != nil {
			t.Fatalf("evidence on %s is not a JSON object: %v", a.AnomalyType, err)
		}
		if _, ok := fields["command_line"]; ok {
			evidence = fields
			break
		}
	}
	if evidence == nil {
		t.Fatalf("no finding carried the process context; evidence was %q", found[0].Evidence)
	}

	for _, key := range []string{"command_line", "user_identity", "executable_sha256", "parent_pid", "process_id"} {
		if _, ok := evidence[key]; !ok {
			t.Fatalf("evidence is missing %s: %v", key, evidence)
		}
	}
	if evidence["user_identity"] != "kiosk" {
		t.Fatalf("evidence names the wrong user: %v", evidence["user_identity"])
	}
}

// The beacon detector's own numbers are the reason its findings are arguable.
// Adding context around them must not cost any of them.
func TestAddingContextKeepsTheDetectorsOwnNumbers(t *testing.T) {
	before := `{"score":0.97,"jitter_pct":2.5,"samples":31}`
	after := withFlowContext(before, storage.Event{
		CommandLine: "curl https://example.test", UserIdentity: "root", ProcessID: 12,
	}, threatintel.GeoRecord{Org: "Example", Tenancy: storage.TenancyVendor})

	var fields map[string]any
	if err := json.Unmarshal([]byte(after), &fields); err != nil {
		t.Fatalf("merged evidence is not JSON: %v", err)
	}
	for _, key := range []string{"score", "jitter_pct", "samples", "command_line", "user_identity", "destination_owner"} {
		if _, ok := fields[key]; !ok {
			t.Fatalf("%s was lost in the merge: %v", key, fields)
		}
	}
}

// A detector that wrote something other than a JSON object keeps what it wrote.
func TestNonObjectEvidenceIsLeftAlone(t *testing.T) {
	const raw = "not json at all"
	if got := withFlowContext(raw, storage.Event{CommandLine: "sh"}, threatintel.GeoRecord{}); got != raw {
		t.Fatalf("evidence was rewritten: %q", got)
	}
}

// Staging data in the file-sharing service the estate uses every day is the
// technique, so being vouched for is not an answer here.
func TestBulkUploadToStorageIsReportedEvenForAVouchedPair(t *testing.T) {
	engine, store := noiseEngine(t)
	now := time.Now().UTC()

	engine.Evaluate(storage.Event{
		TenantID: "default", EndpointID: "linux-30", Timestamp: now,
		Action: "PERMIT", Direction: "OUTBOUND",
		DstIP: "104.16.0.3", DstPort: 443, BytesOut: 64 * 1024 * 1024,
		ProcessPath: "/usr/bin/chrome",
		SNI:         "upload.dropbox.com",
	})

	got := anomaliesOfType(t, store, "CLOUD_STORAGE_EGRESS")
	if len(got) != 1 {
		t.Fatalf("expected one storage egress finding, got %d", len(got))
	}
	if !strings.Contains(got[0].Title, "dropbox") {
		t.Fatalf("the finding does not name the service: %q", got[0].Title)
	}
}

func TestOrdinaryDocumentSizedTrafficToStorageIsNotAFinding(t *testing.T) {
	engine, store := noiseEngine(t)
	engine.Evaluate(storage.Event{
		TenantID: "default", EndpointID: "linux-31", Timestamp: time.Now().UTC(),
		Action: "PERMIT", Direction: "OUTBOUND",
		DstIP: "104.16.0.3", DstPort: 443, BytesOut: 2 * 1024 * 1024,
		ProcessPath: "/usr/bin/chrome",
		SNI:         "upload.dropbox.com",
	})
	if got := anomaliesOfType(t, store, "CLOUD_STORAGE_EGRESS"); len(got) != 0 {
		t.Fatalf("a 2 MB upload raised %d storage findings", len(got))
	}
}

// One CDN-fronted service answers from a dozen addresses. Production showed the
// same worker holding one conversation open and raising four identical beacon
// findings, one per Akamai and Cloudflare address.
func TestOneBeaconingConversationIsOneFindingPerCounterparty(t *testing.T) {
	engine, store := noiseEngine(t)
	now := time.Now().UTC().Add(-2 * time.Hour)

	// Four Cloudflare addresses, each beaconing on the same 60-second cadence.
	for _, last := range []int{1, 2, 3, 4} {
		beaconEvents(engine, "linux-50", fmt.Sprintf("104.16.0.%d", last), "/usr/bin/python3.13", now)
	}

	got := firstBeacons(t, store)
	if len(got) != 1 {
		t.Fatalf("four addresses of one counterparty raised %d beacon findings", len(got))
	}
	if !strings.Contains(got[0].Title, "python3.13") {
		t.Fatalf("the finding does not name the process: %q", got[0].Title)
	}
}

// A browser keeps sessions open to whatever the user is looking at. On a named
// network that is not rented compute that is not a beacon finding, even where
// the network is not on the quiet list.
func TestABrowserIsNotABeaconOnANetworkThatResolves(t *testing.T) {
	engine, store := noiseEngine(t)
	now := time.Now().UTC().Add(-2 * time.Hour)

	// 9.9.9.0/24 is Quad9 in the built-in table: resolved, not rented, not quiet.
	beaconEvents(engine, "linux-51", "9.9.9.20", "/opt/google/chrome/chrome", now)

	if got := anomaliesOfType(t, store, "C2_BEACONING"); len(got) != 0 {
		t.Fatalf("an ordinary browser session raised %d beacon findings: %q", len(got), got[0].Title)
	}
}

// Rented compute is where an extension or an injected page would call home,
// and "the browser" was only ever a program: a regular conversation from it to
// a rented machine is a beacon finding again.
func TestABrowserBeaconingToRentedComputeIsAFinding(t *testing.T) {
	engine, store := noiseEngine(t)
	// 159.65.0.0/16 is DigitalOcean in the built-in table: resolved, and rented.
	beaconEvents(engine, "linux-52", "159.65.0.20", "/opt/google/chrome/chrome", time.Now().UTC().Add(-2*time.Hour))

	if got := firstBeacons(t, store); len(got) != 1 {
		t.Fatalf("a browser beaconing to rented compute raised %d findings, want 1", len(got))
	}
}

// An implant named after a quiet client or a quiet process, run from a
// directory anyone can write, is judged like any other program.
func TestAnImplantNamedLikeAQuietProgramIsStillABeacon(t *testing.T) {
	for i, path := range []string{"/tmp/chrome", "/tmp/svchost.exe", `C:\Users\Public\svchost.exe`, "/home/user/.local/bin/claude", "/tmp/go-build123/b001/x.test"} {
		engine, store := noiseEngine(t)
		// 104.16.0.1 is Cloudflare, which the shipped tuning vouches for.
		beaconEvents(engine, fmt.Sprintf("linux-6%d", i), "104.16.0.1", path, time.Now().UTC().Add(-2*time.Hour))
		if got := firstBeacons(t, store); len(got) != 1 {
			t.Errorf("%s beaconing to a vouched network raised %d findings, want 1", path, len(got))
		}
	}
}

// The exemption is the browser, not the network: an interpreter on the same
// rented range is still the finding this detector exists for.
func TestAnInterpreterOnTheSameNetworkIsStillABeacon(t *testing.T) {
	engine, store := noiseEngine(t)
	beaconEvents(engine, "linux-52", "159.65.0.21", "/usr/bin/python3.13", time.Now().UTC().Add(-2*time.Hour))

	if got := anomaliesOfType(t, store, "C2_BEACONING"); len(got) == 0 {
		t.Fatal("an interpreter beaconing to rented compute raised nothing")
	}
}

// A browser reaching a network nobody can name is not covered by the exemption:
// an unnamed counterparty is the one case where the process is not the whole
// story.
func TestABrowserBeaconingToAnUnnamedNetworkIsStillReported(t *testing.T) {
	engine, store := noiseEngine(t)
	beaconEvents(engine, "linux-53", "198.51.100.77", "/opt/google/chrome/chrome", time.Now().UTC().Add(-2*time.Hour))

	if got := anomaliesOfType(t, store, "C2_BEACONING"); len(got) == 0 {
		t.Fatal("a browser beaconing to an unattributable network raised nothing")
	}
}

// Build-cache test binaries ("go-build", ".test") and programs named like
// infrastructure are judged by the sweep detector unless they run from the
// path the infrastructure is installed at: any program can be given either
// name from a directory anyone can write.
func TestASweepFromATestBinaryOrAnInfrastructureNameIsReported(t *testing.T) {
	for i, path := range []string{"/tmp/go-build123/b001/server.test", "/tmp/dnsmasq", "/home/user/dockerd"} {
		engine, store := noiseEngine(t)
		now := time.Now().UTC()
		for port := 0; port < 35; port++ {
			engine.Evaluate(storage.Event{
				TenantID: "default", EndpointID: fmt.Sprintf("linux-8%d", i), Timestamp: now.Add(time.Duration(port) * 100 * time.Millisecond),
				Action: "PERMIT", Direction: "OUTBOUND",
				DstIP: "203.0.113.9", DstPort: uint16(2000 + port), BytesOut: 60, ProcessPath: path,
			})
		}
		if got := anomaliesOfType(t, store, "PORT_SCAN_RECON"); len(got) != 1 {
			t.Errorf("%s sweeping 35 ports raised %d findings, want 1", path, len(got))
		}
	}
}

// A login user can make any program appear at a daemon's path - bind-mounted
// over it in a user namespace, or with a library preloaded into the real
// binary - and the agent then reports the daemon's path and, for the preload,
// its real hash. It cannot run it as the daemon's account. So systemd-resolved
// running as a login user, or as an account nobody read, is judged by every
// detector like any other program, and only the real daemon is left alone.
func TestADaemonPathRunAsALoginUserIsStillJudged(t *testing.T) {
	start := time.Now().UTC().Add(-2 * time.Hour)
	beacon := func(engine *Engine, ep, path, user string) {
		for i := 0; i < 40; i++ {
			engine.Evaluate(storage.Event{
				TenantID: "default", EndpointID: ep, Timestamp: start.Add(time.Duration(i) * time.Minute),
				Action: "PERMIT", Direction: "OUTBOUND",
				// 104.16.0.1 is Cloudflare, which the shipped tuning vouches for.
				DstIP: "104.16.0.1", DstPort: 443, BytesOut: 1024,
				ProcessPath: path, UserIdentity: user,
			})
		}
	}
	sweep := func(engine *Engine, ep, path, user string) {
		for port := 0; port < 35; port++ {
			engine.Evaluate(storage.Event{
				TenantID: "default", EndpointID: ep, Timestamp: start.Add(time.Duration(port) * 100 * time.Millisecond),
				Action: "PERMIT", Direction: "OUTBOUND",
				DstIP: "203.0.113.9", DstPort: uint16(2000 + port), BytesOut: 60,
				ProcessPath: path, UserIdentity: user,
			})
		}
	}
	lateral := func(engine *Engine, ep, path, user string) {
		// A compiled program sweeps at twenty distinct hosts in a minute.
		for host := 1; host <= 25; host++ {
			engine.Evaluate(storage.Event{
				TenantID: "default", EndpointID: ep, Timestamp: start.Add(time.Duration(host) * time.Second),
				Action: "PERMIT", Direction: "OUTBOUND", Protocol: 6,
				DstIP: fmt.Sprintf("10.0.0.%d", 100+host), DstPort: 8080, BytesOut: 60,
				ProcessPath: path, UserIdentity: user,
			})
		}
	}
	// systemd-resolved is a quiet process and local infrastructure; dnsmasq
	// is infrastructure only, so it is exempt from the sweep detectors alone.
	for _, c := range []struct {
		detector, path, account string
		run                     func(*Engine, string, string, string)
	}{
		{"C2_BEACONING", "/usr/lib/systemd/systemd-resolved", "systemd-resolve", beacon},
		{"PORT_SCAN_RECON", "/usr/lib/systemd/systemd-resolved", "systemd-resolve", sweep},
		{"LATERAL_PORT_SWEEP", "/usr/lib/systemd/systemd-resolved", "systemd-resolve", lateral},
		{"PORT_SCAN_RECON", "/usr/sbin/dnsmasq", "nobody", sweep},
		{"LATERAL_PORT_SWEEP", "/usr/sbin/dnsmasq", "nobody", lateral},
	} {
		for i, user := range []string{"alice", "UID:1000", ""} {
			engine, store := noiseEngine(t)
			c.run(engine, fmt.Sprintf("linux-9%d", i), c.path, user)
			if got := anomaliesOfType(t, store, c.detector); len(got) == 0 {
				t.Errorf("%s: %s running as %q raised nothing", c.detector, c.path, user)
			}
		}
		engine, store := noiseEngine(t)
		c.run(engine, "linux-99", c.path, c.account)
		if got := anomaliesOfType(t, store, c.detector); len(got) != 0 {
			t.Errorf("%s: the real %s raised %d finding(s)", c.detector, c.path, len(got))
		}
	}
}

// Expected clients and pairs name a program by path alone, and a login user can
// present any program at a listed path through a user namespace bind mount.
// The agent reports such a process as path_mismatch, and then no path-based
// entry speaks for it: an implant shown as Chrome beaconing to Cloudflare is
// judged, while the real Chrome stays quiet.
func TestAPathTheAgentCouldNotMatchToItsFileVouchesForNothing(t *testing.T) {
	start := time.Now().UTC().Add(-2 * time.Hour)
	run := func(status string) int {
		engine, store := noiseEngine(t)
		for i := 0; i < 40; i++ {
			engine.Evaluate(storage.Event{
				TenantID: "default", EndpointID: "linux-chrome", Timestamp: start.Add(time.Duration(i) * time.Minute),
				Action: "PERMIT", Direction: "OUTBOUND",
				DstIP: "104.16.0.1", DstPort: 443, BytesOut: 1024,
				ProcessPath: "/opt/google/chrome/chrome", UserIdentity: "alice", AttributionStatus: status,
			})
		}
		return len(anomaliesOfType(t, store, "C2_BEACONING"))
	}
	if n := run("authoritative"); n != 0 {
		t.Fatalf("the real Chrome to Cloudflare raised %d beacon finding(s)", n)
	}
	if n := run("path_mismatch"); n == 0 {
		t.Fatal("a program shown at Chrome's path but running another file was vouched for")
	}
}

// A rule names its program by path, so it does not apply to a process whose
// path the agent could not match to its file.
func TestAProgramRuleDoesNotSilenceAPathMismatch(t *testing.T) {
	start := time.Now().UTC().Add(-2 * time.Hour)
	run := func(status string) int {
		engine, store := noiseEngine(t)
		addExpectedRule(t, engine, store, storage.ExpectedRule{ID: "sync", Name: "sync tool", Reason: "fixture",
			Programs: []storage.ExpectedProgram{{Path: "/usr/local/bin/synctool"}}, Prefixes: []string{"104.16.0.0/16"}})
		for i := 0; i < 40; i++ {
			engine.Evaluate(storage.Event{
				TenantID: "default", EndpointID: "linux-sync", Timestamp: start.Add(time.Duration(i) * time.Minute),
				Action: "PERMIT", Direction: "OUTBOUND",
				DstIP: "104.16.0.1", DstPort: 443, BytesOut: 1024,
				ProcessPath: "/usr/local/bin/synctool", UserIdentity: "alice", AttributionStatus: status,
			})
		}
		return len(anomaliesOfType(t, store, "C2_BEACONING"))
	}
	if n := run("authoritative"); n != 0 {
		t.Fatalf("the covered tool raised %d beacon finding(s)", n)
	}
	if n := run("path_mismatch"); n == 0 {
		t.Fatal("a program shown at the covered path but running another file was covered")
	}
}
