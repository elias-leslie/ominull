package detector

import (
	"encoding/json"
	"fmt"
	"math"
	"path/filepath"
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

// The fleet's own Windows agent reported six CRITICAL "Bandwidth Exfiltration
// Spike" findings for its mTLS heartbeat to its own hub. The destination is on
// the LAN, and the process is the one this product installs.
func TestTheAgentsOwnHubTrafficIsNotExfiltration(t *testing.T) {
	engine, store := noiseEngine(t)
	now := time.Now().UTC()
	for i := 0; i < 40; i++ {
		bytes := int64(2000)
		if i == 39 {
			bytes = 40 * 1024 * 1024
		}
		engine.Evaluate(storage.Event{
			TenantID: "default", EndpointID: "win-01", Timestamp: now.Add(time.Duration(i) * time.Second),
			Action: "PERMIT", Direction: "OUTBOUND",
			DstIP: "10.0.0.58", DstPort: 9443, BytesOut: bytes,
			ProcessPath: `C:\Program Files\Ominull\ominulld.exe`,
		})
	}
	if got := anomaliesOfType(t, store, "BANDWIDTH_SPIKE"); len(got) != 0 {
		t.Errorf("the agent reporting to its own hub raised %d exfiltration alert(s): %+v", len(got), got[0])
	}
}

// svchost.exe is the first name in the shipped quiet-process list and it still
// raised spikes, because the bandwidth detector never consulted the list.
func TestAQuietProcessDoesNotRaiseABandwidthSpike(t *testing.T) {
	engine, store := noiseEngine(t)
	now := time.Now().UTC()
	for i := 0; i < 40; i++ {
		bytes := int64(1500)
		if i == 39 {
			bytes = 80 * 1024 * 1024
		}
		engine.Evaluate(storage.Event{
			TenantID: "default", EndpointID: "win-02", Timestamp: now.Add(time.Duration(i) * time.Second),
			Action: "PERMIT", Direction: "OUTBOUND",
			DstIP: "20.190.135.3", DstPort: 443, BytesOut: bytes,
			ProcessPath: `C:\Windows\System32\svchost.exe`, UserIdentity: `NT AUTHORITY\NETWORK SERVICE`,
		})
	}
	if got := anomaliesOfType(t, store, "BANDWIDTH_SPIKE"); len(got) != 0 {
		t.Errorf("a quiet process raised %d bandwidth alert(s)", len(got))
	}
}

// The detector still has to fire on a real one, against a real baseline, and
// say which it is.
func TestARealSpikeAgainstARealBaselineStillFires(t *testing.T) {
	engine, store := noiseEngine(t)
	now := time.Now().UTC()
	for i := 0; i < 30; i++ {
		engine.Evaluate(storage.Event{
			TenantID: "default", EndpointID: "linux-01", Timestamp: now.Add(time.Duration(i) * time.Second),
			Action: "PERMIT", Direction: "OUTBOUND",
			DstIP: "198.51.100.9", DstPort: 443, BytesOut: 1000 + int64(i),
			ProcessPath: "/usr/bin/suspicious",
		})
	}
	engine.Evaluate(storage.Event{
		TenantID: "default", EndpointID: "linux-01", Timestamp: now.Add(time.Minute),
		Action: "PERMIT", Direction: "OUTBOUND",
		DstIP: "198.51.100.9", DstPort: 443, BytesOut: 500 * 1024 * 1024,
		ProcessPath: "/usr/bin/suspicious",
	})
	got := anomaliesOfType(t, store, "BANDWIDTH_SPIKE")
	if len(got) != 1 {
		t.Fatalf("expected one bandwidth alert for a genuine outlier, got %d", len(got))
	}
	if got[0].Severity != "CRITICAL" {
		t.Errorf("a transfer hundreds of deviations out is CRITICAL, got %q", got[0].Severity)
	}
	if !strings.Contains(got[0].Details, "Samples:") {
		t.Errorf("the alert must carry the baseline it was judged against: %q", got[0].Details)
	}
}

// The first CRITICAL production raised after the scoring fix was chrome sending
// 255KB to Google: 51 standard deviations out, because a browser's transfer
// sizes are heavy-tailed and the 50KB floor was below a single page load. The
// destination is in the shipped quiet-organisation list, so the operator has
// already answered this.
func TestAnOrdinaryBrowserUploadToAVouchedNetworkIsNotASpike(t *testing.T) {
	engine, store := noiseEngine(t)
	now := time.Now().UTC()
	for i := 0; i < 30; i++ {
		engine.Evaluate(storage.Event{
			TenantID: "default", EndpointID: "linux-10", Timestamp: now.Add(time.Duration(i) * time.Second),
			Action: "PERMIT", Direction: "OUTBOUND",
			DstIP: "142.250.176.69", DstPort: 443, BytesOut: 6000 + int64(i*10),
			ProcessPath: "/usr/bin/chrome",
		})
	}
	engine.Evaluate(storage.Event{
		TenantID: "default", EndpointID: "linux-10", Timestamp: now.Add(time.Minute),
		Action: "PERMIT", Direction: "OUTBOUND",
		DstIP: "142.250.176.69", DstPort: 443, BytesOut: 255536,
		ProcessPath: "/usr/bin/chrome",
	})
	if got := anomaliesOfType(t, store, "BANDWIDTH_SPIKE"); len(got) != 0 {
		t.Fatalf("a quarter-megabyte upload to a vouched network raised %d alerts: %q", len(got), got[0].Title)
	}
}

// The same transfer to a network nobody has vouched for is still below the
// floor: a megabyte is the smallest transfer worth waking someone for.
func TestATransferBelowTheFloorIsNotASpikeAnywhere(t *testing.T) {
	engine, store := noiseEngine(t)
	now := time.Now().UTC()
	for i := 0; i < 30; i++ {
		engine.Evaluate(storage.Event{
			TenantID: "default", EndpointID: "linux-11", Timestamp: now.Add(time.Duration(i) * time.Second),
			Action: "PERMIT", Direction: "OUTBOUND",
			DstIP: "198.51.100.40", DstPort: 443, BytesOut: 6000 + int64(i*10),
			ProcessPath: "/usr/bin/chrome",
		})
	}
	engine.Evaluate(storage.Event{
		TenantID: "default", EndpointID: "linux-11", Timestamp: now.Add(time.Minute),
		Action: "PERMIT", Direction: "OUTBOUND",
		DstIP: "198.51.100.40", DstPort: 443, BytesOut: 255536,
		ProcessPath: "/usr/bin/chrome",
	})
	if got := anomaliesOfType(t, store, "BANDWIDTH_SPIKE"); len(got) != 0 {
		t.Fatalf("a quarter-megabyte upload raised %d bandwidth alerts", len(got))
	}
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

// 1,584 of the fleet's alerts were first-seen destinations. The suppression key
// was the destination address, and a destination is first-seen exactly once, so
// the cooldown could never match and nothing bounded the rate.
func TestOneNewCounterpartyIsOneAlertNotOnePerEdgeAddress(t *testing.T) {
	engine, store := noiseEngine(t)
	now := time.Now().UTC()
	// Twelve different addresses inside one owner's network.
	for i := 0; i < 12; i++ {
		engine.Evaluate(storage.Event{
			TenantID: "default", EndpointID: "linux-05", Timestamp: now.Add(time.Duration(i) * time.Second),
			Action: "PERMIT", Direction: "OUTBOUND",
			DstIP: "159.65.0." + itoa(i+1), DstPort: 443, BytesOut: 200,
			ProcessPath: "/usr/bin/firefox",
		})
	}
	got := anomaliesOfType(t, store, "NOVEL_DESTINATION")
	if len(got) > 1 {
		t.Errorf("twelve edges of one network raised %d alerts; the counterparty is one relationship", len(got))
	}
	if len(got) == 1 && !strings.Contains(got[0].Title, "DigitalOcean") {
		t.Errorf("the alert must name the counterparty it is about, got %q", got[0].Title)
	}
}

// With the guessing removed, an address the table cannot attribute has no
// owner. The alert has to say that rather than print an empty pair of brackets.
func TestAnUnattributableDestinationSaysSoRatherThanNamingNothing(t *testing.T) {
	engine, store := noiseEngine(t)
	engine.Evaluate(storage.Event{
		TenantID: "default", EndpointID: "linux-06", Timestamp: time.Now().UTC(),
		Action: "PERMIT", Direction: "OUTBOUND",
		DstIP: "203.0.113.77", DstPort: 443, BytesOut: 200,
		ProcessPath: "/usr/bin/firefox",
	})
	got := anomaliesOfType(t, store, "NOVEL_DESTINATION")
	if len(got) != 1 {
		t.Fatalf("expected one alert for a genuinely new destination, got %d", len(got))
	}
	if strings.Contains(got[0].Details, "()") || strings.Contains(got[0].Description, "()") {
		t.Errorf("empty attribution was printed as if it were a value: %q / %q", got[0].Description, got[0].Details)
	}
	if !strings.Contains(got[0].Details, "not resolved") {
		t.Errorf("an unattributable address must be described as such: %q", got[0].Details)
	}
}

// Production, ten minutes after the geo fabrication was fixed: seven MEDIUM
// "First connection to an unattributed network" alerts from one workstation,
// all inside four minutes. An address with no owner cannot repeat as a cooldown
// key any more than the address itself could, so every unnamed destination a
// browser reached became its own alert. They belong to one finding per host.
func TestUnnamedDestinationsAreOneRollingFindingPerHost(t *testing.T) {
	engine, store := noiseEngine(t)
	now := time.Now().UTC()
	// Twenty addresses in documentation ranges, which the attribution table
	// deliberately does not name, spread over four minutes.
	for i := 0; i < 20; i++ {
		engine.Evaluate(storage.Event{
			TenantID: "default", EndpointID: "linux-07", Timestamp: now.Add(time.Duration(i*12) * time.Second),
			Action: "PERMIT", Direction: "OUTBOUND",
			DstIP: "198.51.100." + itoa(i+1), DstPort: 443, BytesOut: 200,
			ProcessPath: "/usr/bin/firefox",
		})
	}
	got := anomaliesOfType(t, store, "NOVEL_DESTINATION")
	if len(got) != 1 {
		t.Fatalf("twenty unnamed destinations raised %d alerts; the whole point of the rollup is that they are one", len(got))
	}
	if got[0].Severity != "LOW" {
		t.Errorf("severity was %q; an address nothing can attribute is the weakest evidence this detector has", got[0].Severity)
	}
	// The alert has to carry what it swallowed, or the rollup is just silence.
	if !strings.Contains(got[0].Details, "folded") {
		t.Errorf("the alert does not say that later destinations were folded into it: %q", got[0].Details)
	}
}

// The rollup must not swallow the next window: after the cooldown, a further
// unnamed destination is reported again, and it counts the ones it folded.
func TestTheUnnamedRollupReopensAfterItsCooldown(t *testing.T) {
	engine, store := noiseEngine(t)
	now := time.Now().UTC()

	engine.Evaluate(storage.Event{
		TenantID: "default", EndpointID: "linux-08", Timestamp: now,
		Action: "PERMIT", Direction: "OUTBOUND",
		DstIP: "198.51.100.10", DstPort: 443, BytesOut: 200,
		ProcessPath: "/usr/bin/firefox",
	})
	for i := 0; i < 5; i++ {
		engine.Evaluate(storage.Event{
			TenantID: "default", EndpointID: "linux-08", Timestamp: now.Add(time.Duration(i+1) * time.Minute),
			Action: "PERMIT", Direction: "OUTBOUND",
			DstIP: "198.51.100.2" + itoa(i), DstPort: 443, BytesOut: 200,
			ProcessPath: "/usr/bin/firefox",
		})
	}
	if got := anomaliesOfType(t, store, "NOVEL_DESTINATION"); len(got) != 1 {
		t.Fatalf("inside one cooldown window the endpoint raised %d alerts; expected 1", len(got))
	}

	// Expire the cooldown the way time would, then reach somewhere new again.
	engine.mu.Lock()
	for k := range engine.alertCooldown {
		engine.alertCooldown[k] = time.Now().Add(-2 * time.Hour)
	}
	engine.mu.Unlock()

	engine.Evaluate(storage.Event{
		TenantID: "default", EndpointID: "linux-08", Timestamp: now.Add(90 * time.Minute),
		Action: "PERMIT", Direction: "OUTBOUND",
		DstIP: "198.51.100.90", DstPort: 443, BytesOut: 200,
		ProcessPath: "/usr/bin/firefox",
	})
	got := anomaliesOfType(t, store, "NOVEL_DESTINATION")
	if len(got) != 2 {
		t.Fatalf("after the cooldown expired the endpoint raised %d alerts; expected a second", len(got))
	}
	var second storage.AnomalyAlert
	for _, a := range got {
		if a.Timestamp.After(second.Timestamp) {
			second = a
		}
	}
	if !strings.Contains(second.Title, "6 first connections") {
		t.Errorf("the second alert must count what it folded, got %q", second.Title)
	}
}

// A destination the table can name is still its own finding: folding those
// together would hide the one thing this detector is for.
func TestANamedCounterpartyIsStillItsOwnFinding(t *testing.T) {
	engine, store := noiseEngine(t)
	now := time.Now().UTC()
	engine.Evaluate(storage.Event{
		TenantID: "default", EndpointID: "linux-09", Timestamp: now,
		Action: "PERMIT", Direction: "OUTBOUND",
		DstIP: "159.65.0.5", DstPort: 443, BytesOut: 200,
		ProcessPath: "/usr/bin/firefox",
	})
	engine.Evaluate(storage.Event{
		TenantID: "default", EndpointID: "linux-09", Timestamp: now.Add(time.Second),
		Action: "PERMIT", Direction: "OUTBOUND",
		DstIP: "198.51.100.5", DstPort: 443, BytesOut: 200,
		ProcessPath: "/usr/bin/firefox",
	})
	got := anomaliesOfType(t, store, "NOVEL_DESTINATION")
	if len(got) != 2 {
		t.Fatalf("a named counterparty and an unnamed address raised %d alerts; expected one each", len(got))
	}
	var named, unnamed bool
	for _, a := range got {
		if strings.Contains(a.Title, "DigitalOcean") && a.Severity == "MEDIUM" {
			named = true
		}
		if strings.Contains(a.Title, "unattributed") && a.Severity == "LOW" {
			unnamed = true
		}
	}
	if !named || !unnamed {
		t.Errorf("expected one MEDIUM naming the owner and one LOW for the unnamed address, got %+v", got)
	}
}

func itoa(n int) string {
	if n < 10 {
		return string(rune('0' + n))
	}
	return string(rune('0'+n/10)) + string(rune('0'+n%10))
}

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
		got := tuning.IsVouchedPair("/opt/google/chrome/chrome", "", "AS16509", "Amazon Web Services", tc.tenancy)
		if got != tc.want {
			t.Fatalf("%s: IsVouchedPair returned %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestAnExplicitPairVouchesForThatConversationAndNoOther(t *testing.T) {
	tuning := storage.DefaultDetectionTuning()
	tuning.QuietPairs = []string{"/opt/backup/backup-agent@backblaze, inc."}
	tuning = mustSaveTuning(t, tuning)

	if !tuning.IsVouchedPair("/opt/backup/backup-agent", "", "", "Backblaze, Inc.", storage.TenancyVendor) {
		t.Fatal("the pair the operator named was not honoured")
	}
	if tuning.IsVouchedPair("/usr/bin/python3", "", "", "Backblaze, Inc.", storage.TenancyVendor) ||
		tuning.IsVouchedPair("/tmp/backup-agent", "", "", "Backblaze, Inc.", storage.TenancyVendor) {
		t.Fatal("a pair vouched for every process reaching that owner")
	}
	if tuning.IsVouchedPair("/opt/backup/backup-agent", "", "AS13335", "Cloudflare, Inc.", storage.TenancyVendor) {
		t.Fatal("a pair vouched for its process reaching any owner")
	}
}

func TestAMalformedPairIsDiscardedRatherThanWidened(t *testing.T) {
	tuning := storage.DefaultDetectionTuning()
	tuning.QuietPairs = []string{"chrome", "@google", "curl@", "  ", "/usr/bin/curl@as36459"}
	tuning = mustSaveTuning(t, tuning)

	if len(tuning.QuietPairs) != 1 || tuning.QuietPairs[0] != "/usr/bin/curl@as36459" {
		t.Fatalf("expected only the complete pair to survive, got %q", tuning.QuietPairs)
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
	beaconEvents(engine, "linux-22", "104.16.0.2", "/usr/bin/python3.13", now.Add(-2*time.Hour))

	// One more flow of the same conversation, carrying the process context the
	// agent reports.
	engine.Evaluate(storage.Event{
		TenantID: "default", EndpointID: "linux-22", Timestamp: now,
		Action: "PERMIT", Direction: "OUTBOUND",
		DstIP: "104.16.0.2", DstPort: 443, BytesOut: 12 * 1024 * 1024,
		ProcessPath:  "/usr/bin/python3.13",
		ProcessID:    4242,
		ParentPID:    991,
		CommandLine:  "python3.13 /tmp/.cache/agent.py --quiet",
		UserIdentity: "kiosk",

		ExecutableSHA256: "9f2b1c0d4e5a6b7c8d9e0f1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e",
	})

	found := append(anomaliesOfType(t, store, "C2_BEACONING"), anomaliesOfType(t, store, "BANDWIDTH_SPIKE")...)
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

// Network transfer sizes are heavy-tailed: a browser sends a few kilobytes a
// hundred times and eight megabytes once. A mean and a standard deviation are
// not robust to that, which is how a 255 KB upload came to score 51 sigma.

func TestOneLargeOrdinaryUploadDoesNotDeafenTheBaseline(t *testing.T) {
	var stats bandwidthStats
	for i := 0; i < 40; i++ {
		stats.observe(float64(5000 + i*17))
	}
	// One genuinely large but ordinary upload.
	stats.observe(8 * 1024 * 1024)
	// A second transfer of the same size is now unremarkable for this process
	// under a mean-based score, because the first one moved the mean and blew
	// up the standard deviation. Under median/MAD it still stands out.
	_, _, z, _ := stats.observe(8 * 1024 * 1024)
	if z <= 3.5 {
		t.Fatalf("a second 8 MB upload scored %.2f; one large sample deafened the baseline", z)
	}
}

func TestPerfectlyRegularTrafficDoesNotDivideByZero(t *testing.T) {
	var stats bandwidthStats
	for i := 0; i < 30; i++ {
		stats.observe(4096)
	}
	median, mad, z, samples := stats.observe(4096)
	if math.IsNaN(z) || math.IsInf(z, 0) {
		t.Fatalf("a constant series produced z=%v (median %v, mad %v)", z, median, mad)
	}
	if z > 3.5 {
		t.Fatalf("a transfer identical to every previous one scored %.2f over %d samples", z, samples)
	}

	// The same series, then a transfer a hundred times larger, must still be a
	// finding rather than an infinity.
	_, _, big, _ := stats.observe(4096 * 100)
	if math.IsInf(big, 0) || math.IsNaN(big) {
		t.Fatalf("an outlier against constant traffic produced %v", big)
	}
	if big <= 3.5 {
		t.Fatalf("a hundredfold transfer against constant traffic scored only %.2f", big)
	}
}

func TestTheBaselineIsBoundedAndRecent(t *testing.T) {
	var stats bandwidthStats
	for i := 0; i < 500; i++ {
		stats.observe(1000)
	}
	if len(stats.samples) != bandwidthRingSize {
		t.Fatalf("the baseline retained %d samples, want %d", len(stats.samples), bandwidthRingSize)
	}
	if stats.count != 500 {
		t.Fatalf("the observed count is %d, want 500", stats.count)
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

// "An interpreter talked to the internet" describes every developer machine and
// most servers. Correcting the interpreter match turned one ordinary Python
// worker into seventy-one HIGH findings in a morning, one per CDN address for
// the same conversation.
func TestAnInterpreterReachingOneCounterpartyIsOneFinding(t *testing.T) {
	engine, store := noiseEngine(t)
	now := time.Now().UTC()

	// The same owner behind a dozen edge addresses, which is how a CDN answers.
	for i := 0; i < 12; i++ {
		engine.Evaluate(storage.Event{
			TenantID: "default", EndpointID: "linux-40", Timestamp: now.Add(time.Duration(i) * time.Second),
			Action: "PERMIT", Direction: "OUTBOUND",
			DstIP: fmt.Sprintf("23.32.3.%d", 10+i), DstPort: 443, BytesOut: 800,
			ProcessPath: "/usr/bin/python3.13",
			CommandLine: "python -m app.worker",
		})
	}

	got := anomaliesOfType(t, store, "NOVEL_PROCESS_EGRESS")
	if len(got) != 1 {
		t.Fatalf("twelve edge addresses of one counterparty raised %d findings", len(got))
	}
	if got[0].Severity != "MEDIUM" {
		t.Fatalf("a named edge network is a MEDIUM finding, got %q", got[0].Severity)
	}
}

func TestAnInterpreterReachingRentedComputeIsTheLouderFinding(t *testing.T) {
	engine, store := noiseEngine(t)
	engine.Evaluate(storage.Event{
		TenantID: "default", EndpointID: "linux-41", Timestamp: time.Now().UTC(),
		Action: "PERMIT", Direction: "OUTBOUND",
		DstIP: "159.65.0.9", DstPort: 8443, BytesOut: 800,
		ProcessPath: "/usr/bin/python3.13",
	})

	got := anomaliesOfType(t, store, "NOVEL_PROCESS_EGRESS")
	if len(got) != 1 {
		t.Fatalf("expected one finding, got %d", len(got))
	}
	if got[0].Severity != "HIGH" {
		t.Fatalf("an interpreter reaching rented compute on an odd port is HIGH, got %q", got[0].Severity)
	}
}

// The operator's own answer still applies here: a pair they have vouched for is
// not reported, and a quiet process is not reported at all.
func TestAVouchedInterpreterPairIsNotReported(t *testing.T) {
	engine, store := noiseEngine(t)

	tuning := storage.DefaultDetectionTuning()
	tuning.QuietPairs = []string{"/usr/bin/python3.13@as20940"}
	if _, err := store.SaveDetectionTuning(tuning, "test"); err != nil {
		t.Fatalf("saving tuning: %v", err)
	}
	engine.InvalidateTuning()

	engine.Evaluate(storage.Event{
		TenantID: "default", EndpointID: "linux-42", Timestamp: time.Now().UTC(),
		Action: "PERMIT", Direction: "OUTBOUND",
		DstIP: "23.32.3.11", DstPort: 443, BytesOut: 800,
		ProcessPath: "/usr/bin/python3.13",
	})

	if got := anomaliesOfType(t, store, "NOVEL_PROCESS_EGRESS"); len(got) != 0 {
		t.Fatalf("a vouched pair raised %d findings: %q", len(got), got[0].Title)
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

	got := anomaliesOfType(t, store, "C2_BEACONING")
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

	if got := anomaliesOfType(t, store, "C2_BEACONING"); len(got) != 1 {
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
		if got := anomaliesOfType(t, store, "C2_BEACONING"); len(got) != 1 {
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

// Amazon is a quiet network by its AS number, and rented compute inside that
// AS is not: "amazon" as a fragment of a name used to silence first-seen for
// every EC2 machine. Google's own range stays quiet.
func TestFirstSeenToRentedComputeInsideAQuietASIsReported(t *testing.T) {
	engine, store := noiseEngine(t)
	now := time.Now().UTC()
	// 54.0.0.0/8 is Amazon in the built-in table, rented until a feed says otherwise.
	engine.Evaluate(storage.Event{
		TenantID: "default", EndpointID: "linux-70", Timestamp: now,
		Action: "PERMIT", Direction: "OUTBOUND",
		DstIP: "54.1.2.3", DstPort: 443, BytesOut: 200, ProcessPath: "/usr/bin/curl",
	})
	if got := anomaliesOfType(t, store, "NOVEL_DESTINATION"); len(got) != 1 {
		t.Fatalf("first contact with rented compute in a quiet AS raised %d findings, want 1", len(got))
	}
	engine.Evaluate(storage.Event{
		TenantID: "default", EndpointID: "linux-70", Timestamp: now.Add(time.Second),
		Action: "PERMIT", Direction: "OUTBOUND",
		DstIP: "8.8.8.8", DstPort: 443, BytesOut: 200, ProcessPath: "/usr/bin/curl",
	})
	if got := anomaliesOfType(t, store, "NOVEL_DESTINATION"); len(got) != 1 {
		t.Fatalf("Google's own range is no longer quiet: %d findings", len(got))
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

// A process exclusion names its program by path too, so it no more applies to
// a process whose path the agent could not match to its file than a quiet
// entry does.
func TestAProcessExclusionDoesNotSilenceAPathMismatch(t *testing.T) {
	start := time.Now().UTC().Add(-2 * time.Hour)
	run := func(status string) int {
		engine, store := noiseEngine(t)
		now := time.Now().UTC()
		if err := store.CreateExclusion(storage.Exclusion{ID: "ex-sync", TenantID: "default", Scope: "global", Name: "sync tool",
			ProcessPath: "/usr/local/bin/synctool", DstIPRange: "104.16.0.0/16", Reason: "fixture", Active: true,
			CreatedAt: now, ExpiresAt: now.Add(24 * time.Hour)}); err != nil {
			t.Fatal(err)
		}
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
		t.Fatalf("the excluded tool raised %d beacon finding(s)", n)
	}
	if n := run("path_mismatch"); n == 0 {
		t.Fatal("a program shown at the excluded path but running another file was excluded")
	}
}

// A known workload for an installed program names it by path too, and an
// AnyOwner entry for a path reaches every destination, rented compute
// included. So a program bind-mounted over the listed path, which the agent
// reports as path_mismatch, is not known by it: its first connection to a
// hosting network is still a first-seen finding, while the real program's is
// not.
func TestAKnownPathWorkloadDoesNotVouchForAPathMismatch(t *testing.T) {
	run := func(status string) int {
		engine, store := noiseEngine(t)
		tuning := store.GetDetectionTuning()
		tuning.KnownWorkloads = []storage.KnownWorkload{{Workload: "/usr/local/bin/synctool", Owner: storage.AnyOwner, Reason: "sync tool", ExpiresAt: testExpiry}}
		if _, err := store.SaveDetectionTuning(tuning, "test"); err != nil {
			t.Fatalf("saving tuning: %v", err)
		}
		engine.Evaluate(storage.Event{
			TenantID: "default", EndpointID: "linux-sync", Timestamp: time.Now().UTC(),
			Action: "PERMIT", Direction: "OUTBOUND",
			// 159.65.0.5 is DigitalOcean: rented compute, never seen before.
			DstIP: "159.65.0.5", DstPort: 443, BytesOut: 200,
			ProcessPath: "/usr/local/bin/synctool", UserIdentity: "alice", AttributionStatus: status,
		})
		return len(anomaliesOfType(t, store, "NOVEL_DESTINATION"))
	}
	if n := run("authoritative"); n != 0 {
		t.Fatalf("the known tool's first connection raised %d first-seen finding(s)", n)
	}
	if n := run("path_mismatch"); n != 1 {
		t.Fatalf("a program shown at the known tool's path but running another file raised %d first-seen finding(s), want 1", n)
	}
}
