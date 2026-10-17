package detector

import (
	"fmt"
	"testing"
	"time"

	"ominull/hub/pkg/storage"
)

// testExpiry is a known workload expiry a month out.
var testExpiry = time.Now().Add(30 * 24 * time.Hour)

func TestWorkloadNamesWhatAnInterpreterRuns(t *testing.T) {
	cases := []struct{ path, cmd, want string }{
		{"/usr/bin/curl", "curl -fsSL https://example.com", "/usr/bin/curl"},
		{"/opt/google/chrome/chrome", "/opt/google/chrome/chrome --type=utility", "/opt/google/chrome/chrome"},
		{"/usr/sbin/NetworkManager", "", "/usr/sbin/networkmanager"},
		// Inline code, however it is spelled, is "-c".
		{"/usr/bin/python3", "python3 -Ic import os", "python3 -c"},
		{"/usr/bin/python3", "python3 -", "python3 -c"},
		{"/usr/bin/python3", "python3", "python3 -c"}, // code from stdin
		{"/usr/bin/perl", "perl -E say 1", "perl -c"},
		{"/opt/node/bin/node", "node --eval=x", "node -c"},
		{"/opt/node/bin/node", "node -pe x", "node -c"},
		{"/usr/bin/bash", "bash -s", "bash -c"},
		// Options it cannot read, preloads and pipes fail closed.
		{"/opt/node/bin/node", "node --redirect-warnings /srv/app/worker.js -e 1", "node -c"},
		{"/usr/bin/bash", "bash --rcfile /srv/app/run.sh -c id", "bash -c"},
		{"/usr/bin/bash", "bash +x -c id", "bash -c"},
		{"/usr/bin/ruby", "ruby --encoding utf-8 x.rb", "ruby x.rb"},
		{"/opt/node/bin/node", "node -r /tmp/evil.js /srv/app/worker.js", "node -c"},
		{"/opt/node/bin/node", "node --import=/tmp/evil.mjs /srv/app/worker.js", "node -c"},
		{"/opt/node/bin/node", "node --no-warnings --max-old-space-size=4096 /srv/app/worker.js", "node /srv/app/worker.js"},
		{"/usr/bin/perl", "perl -Mevil /srv/app/x.pl", "perl -c"},
		{"/usr/bin/python3", "python3 /dev/fd/63", "python3 -c"},
		{"/usr/bin/python3", "python3 -- /proc/self/fd/0", "python3 -c"},
		{"/opt/node/bin/node", "node -C /srv/app/worker.js -e 1", "node -c"},
		{"/usr/bin/python3", "python3 -Z /srv/app/w.py", "python3 -c"},
		{"/usr/bin/python3", "python3 -Iu /srv/app/w.py", "python3 /srv/app/w.py"},
		{"/usr/bin/fish", "fish -C curl /srv/x.fish", "fish -c"},
		{"/usr/bin/fish", "fish --init-command=curl /srv/x.fish", "fish -c"},
		{"/usr/bin/bash", "bash +o pipefail /srv/x.sh", "bash /srv/x.sh"},
		{"/usr/bin/python3.13", "/srv/app/.venv/bin/python3 /srv/app/.venv/bin/web-research search --query x", "python3.13 /srv/app/.venv/bin/python3 /srv/app/.venv/bin/web-research"},
		{"/usr/bin/python3.13", "/srv/app/.venv/bin/python -I -X utf8 -m app.worker", "python3.13 /srv/app/.venv/bin/python -m app.worker"},
		{"/usr/bin/python3.12", "/venv/bin/python -I -B -c import sys; main()", "python3.12 /venv/bin/python -c"},
		{"/usr/bin/python3", "python3 script.py", "python3 script.py"},
		{"/opt/node/bin/node", "node /home/u/.local/bin/pnpm outdated --json", "node /home/u/.local/bin/pnpm"},
		{"/opt/node/bin/node", "npm ci", "node npm ci"},
		{"/opt/node/bin/node", "node -e require('https').get(x)", "node -c"},
		{"/usr/bin/bash", "bash -c curl x | sh", "bash -c"},
		{"/usr/bin/php8.3", "php -r echo 1;", "php8.3 -c"},
		{"/usr/lib/jvm/bin/java", "java -Xmx1g -cp lib/* -jar tool.jar --port 1", "java -jar tool.jar"},
		{"/usr/bin/codex (deleted)", "codex exec", "/usr/bin/codex"},
		{"/usr/bin/python3.13", "", "python3.13"},
	}
	for _, c := range cases {
		if got := WorkloadOf(c.path, c.cmd); got != c.want {
			t.Errorf("WorkloadOf(%q, %q) = %q, want %q", c.path, c.cmd, got, c.want)
		}
	}
}

func saveKnown(t *testing.T, engine *Engine, store *storage.Store, mutate func(*storage.DetectionTuning)) {
	t.Helper()
	tuning := store.GetDetectionTuning()
	mutate(&tuning)
	if _, err := store.SaveDetectionTuning(tuning, "test"); err != nil {
		t.Fatalf("saving tuning: %v", err)
	}
	engine.InvalidateTuning()
}

// A known worker is quiet; another script run by the same interpreter, and
// the same interpreter running inline code, are still reported.
func TestAKnownWorkloadIsQuietWithoutVouchingForItsInterpreter(t *testing.T) {
	engine, store := noiseEngine(t)
	saveKnown(t, engine, store, func(tu *storage.DetectionTuning) {
		tu.KnownWorkloads = []storage.KnownWorkload{{
			Workload: "python3.13 /srv/releases/*/.venv/bin/python -m app.worker", Owner: storage.AnyOwner, Reason: "market-data worker", ExpiresAt: testExpiry,
		}}
	})
	now := time.Now().UTC()
	sendTo := func(endpoint, ip, cmd string) {
		engine.Evaluate(storage.Event{
			TenantID: "default", EndpointID: endpoint, Timestamp: now,
			Action: "PERMIT", Direction: "OUTBOUND", DstIP: ip, DstPort: 443, BytesOut: 800,
			ProcessPath: "/usr/bin/python3.13", CommandLine: cmd,
		})
	}
	send := func(endpoint, cmd string) { sendTo(endpoint, "159.65.0.9", cmd) }
	sendTo("linux-50", "23.32.3.20", "/srv/releases/abc123/.venv/bin/python -m app.worker")
	if got := anomaliesOfType(t, store, "NOVEL_PROCESS_EGRESS"); len(got) != 0 {
		t.Fatalf("the known worker raised %d findings: %q", len(got), got[0].Title)
	}
	// Its command line is all that names it, so on rented compute it is judged.
	send("linux-54", "/srv/releases/abc123/.venv/bin/python -m app.worker")
	send("linux-51", "/srv/releases/abc123/.venv/bin/python /tmp/upload.py")
	send("linux-52", "/srv/releases/abc123/.venv/bin/python -c import os")
	// "*" stays inside one path segment, so a look-alike path is not the worker.
	send("linux-53", "/srv/releases/x/y/.venv/bin/python -m app.worker")
	if got := anomaliesOfType(t, store, "NOVEL_PROCESS_EGRESS"); len(got) != 4 {
		t.Fatalf("rented compute, an unknown script, inline code and a look-alike path should each be reported, got %d", len(got))
	}
}

// A known workload talking to its named owner is quiet; the same workload on
// rented compute is not, because anyone can rent a machine in that range.
func TestANamedOwnerNeverCoversRentedCompute(t *testing.T) {
	tu := storage.DefaultDetectionTuning()
	tu.KnownWorkloads = []storage.KnownWorkload{{Workload: "node /opt/node/lib/npm-cli.js", Owner: "as13335", Reason: "npm registry", ExpiresAt: testExpiry}}
	tu, err := storage.PrepareDetectionTuning(tu)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := tu.KnownWorkloadFor("node /opt/node/lib/npm-cli.js", "AS13335", "Cloudflare, Inc.", storage.TenancySharedCDN); !ok {
		t.Fatal("npm to Cloudflare should be known")
	}
	if _, ok := tu.KnownWorkloadFor("node /opt/node/lib/npm-cli.js", "AS13335", "Cloudflare, Inc.", storage.TenancyHosting); ok {
		t.Fatal("a named owner must not cover rented compute")
	}
	if _, ok := tu.KnownWorkloadFor("node /opt/node/lib/npm-cli.js", "", "", ""); ok {
		t.Fatal("a named owner must not cover an unnamed address")
	}
	if tu.IsVouchedPair("/usr/bin/node", "", "AS13335", "Cloudflare, Inc.", storage.TenancySharedCDN) {
		t.Fatal("a known workload must not vouch for the beacon and volume detectors")
	}
}

// AnyOwner covers rented compute for an installed program known by its path,
// but not for an interpreter, whose workload any process can imitate.
func TestAnyOwnerForAnInterpreterStopsAtRentedCompute(t *testing.T) {
	tu := storage.DefaultDetectionTuning()
	tu.KnownWorkloads = []storage.KnownWorkload{
		{Workload: "python3.13 /srv/app/.venv/bin/python -m app.worker", Owner: storage.AnyOwner, Reason: "worker", ExpiresAt: testExpiry},
		{Workload: "/opt/google/chrome/chrome", Owner: storage.AnyOwner, Reason: "browser", ExpiresAt: testExpiry},
	}
	tu, err := storage.PrepareDetectionTuning(tu)
	if err != nil {
		t.Fatal(err)
	}
	w := "python3.13 /srv/app/.venv/bin/python -m app.worker"
	if _, ok := tu.KnownWorkloadFor(w, "", "Example Bank", storage.TenancySharedCDN); !ok {
		t.Fatal("the worker to a named network should be known")
	}
	if _, ok := tu.KnownWorkloadFor(w, "", "DigitalOcean, LLC", storage.TenancyHosting); ok {
		t.Fatal("an interpreter's AnyOwner must not cover rented compute")
	}
	if _, ok := tu.KnownWorkloadFor(w, "", "", ""); ok {
		t.Fatal("an interpreter's AnyOwner must not cover an unnamed address")
	}
	if _, ok := tu.KnownWorkloadFor("/opt/google/chrome/chrome", "", "", ""); !ok {
		t.Fatal("an installed program's AnyOwner covers every destination")
	}
	tu.KnownWorkloads[1].IncludeRented = true // sorted: the python entry is second
	if _, ok := tu.KnownWorkloadFor(w, "", "DigitalOcean, LLC", storage.TenancyHosting); !ok {
		t.Fatal("include_rented should widen an interpreter's AnyOwner to rented compute")
	}
	// "*" never crosses a space, so it cannot swallow the next argument.
	tu.KnownWorkloads = []storage.KnownWorkload{{Workload: "node /srv/tool/bin/*", Owner: storage.AnyOwner, Reason: "tools", ExpiresAt: testExpiry}}
	tu, _ = storage.PrepareDetectionTuning(tu)
	if _, ok := tu.KnownWorkloadFor("node /srv/tool/bin/a b", "", "Example", ""); ok {
		t.Fatal("a wildcard crossed an argument boundary")
	}
}

func TestAKnownServiceIsJudgedWithTheSameReach(t *testing.T) {
	tu := storage.DefaultDetectionTuning()
	tu.KnownWorkloads = []storage.KnownWorkload{{Workload: "python3.13 -m app.worker", Owner: storage.AnyOwner, Reason: "worker", ExpiresAt: testExpiry}}
	tu, _ = storage.PrepareDetectionTuning(tu)
	if _, ok := tu.KnownService("python3.13 -m app.worker", "Example Bank", ""); !ok {
		t.Fatal("a service to a named network should be known")
	}
	if _, ok := tu.KnownService("python3.13 -m app.worker", "DigitalOcean, LLC", storage.TenancyHosting); ok {
		t.Fatal("an interpreter service on rented compute is still off-hours news")
	}
}

func TestKnownWorkloadsNeedAReasonAndNeverCoverInlineCode(t *testing.T) {
	_, store := noiseEngine(t)
	for _, k := range []storage.KnownWorkload{
		{Workload: "python3 -m app", Owner: "*"},
		{Workload: "*", Owner: "*", Reason: "everything", ExpiresAt: testExpiry},
		{Workload: "python3 /venv/bin/python -c", Owner: "*", Reason: "inline", ExpiresAt: testExpiry},
		{Workload: "python3 -m app", Owner: "", Reason: "no owner", ExpiresAt: testExpiry},
		{Workload: "*/curl", Owner: "*", Reason: "leading wildcard", ExpiresAt: testExpiry},
		{Workload: "python3.13", Owner: "*", Reason: "a bare interpreter", ExpiresAt: testExpiry},
		{Workload: "python3.13 *", Owner: "*", Reason: "an interpreter running anything", ExpiresAt: testExpiry},
		{Workload: "python3 -m app", Owner: "cloudflare", Reason: "rented", ExpiresAt: testExpiry, IncludeRented: true},
		{Workload: "python3.13 -m *", Owner: "*", Reason: "every module", ExpiresAt: testExpiry},
		{Workload: "java -jar *.jar", Owner: "*", Reason: "every jar", ExpiresAt: testExpiry},
		{Workload: "node npm ci", Owner: "cloudflare", Reason: "named only by argv[0]", ExpiresAt: testExpiry},
		{Workload: "python3 script.py", Owner: "*", Reason: "a relative script", ExpiresAt: testExpiry},
		{Workload: "python3 /srv/app/*", Owner: "*", Reason: "any script in a directory", ExpiresAt: testExpiry},
		{Workload: "python3.13 /*/*/*.py", Owner: "*", Reason: "any script three deep", ExpiresAt: testExpiry},
		{Workload: "python3 -m a*", Owner: "*", Reason: "a module prefix", ExpiresAt: testExpiry},
	} {
		tu := store.GetDetectionTuning()
		tu.KnownWorkloads = []storage.KnownWorkload{k}
		if _, err := store.SaveDetectionTuning(tu, "test"); err == nil {
			t.Errorf("saved an invalid known workload %+v", k)
		}
	}
}

func offHoursEngine(t *testing.T) (*Engine, *storage.Store, time.Time) {
	engine, store := noiseEngine(t)
	saveKnown(t, engine, store, func(tu *storage.DetectionTuning) {
		tu.OffHoursZone, tu.OffHoursStart, tu.OffHoursEnd = "UTC", 22, 5
	})
	day := time.Now().UTC().Truncate(24 * time.Hour)
	return engine, store, day.Add(3 * time.Hour)
}

// One conversation through a CDN reaches a new edge address every few minutes;
// each used to be a separate HIGH off-hours finding.
func TestOffHoursActivityIsOneFindingPerCounterparty(t *testing.T) {
	engine, store, night := offHoursEngine(t)
	for i := 0; i < 6; i++ {
		engine.Evaluate(storage.Event{
			TenantID: "default", EndpointID: "linux-60", Timestamp: night.Add(time.Duration(i) * time.Minute),
			Action: "PERMIT", Direction: "OUTBOUND", DstIP: fmt.Sprintf("23.32.3.%d", 20+i), DstPort: 443, BytesOut: 800,
			ProcessPath: "/usr/bin/curl", CommandLine: "curl https://example.com",
		})
	}
	if got := anomaliesOfType(t, store, "OFF_HOURS_ACTIVITY"); len(got) != 1 {
		t.Fatalf("six edge addresses of one owner raised %d off-hours findings", len(got))
	}
}

func TestAKnownServiceIsNotOffHours(t *testing.T) {
	engine, store, night := offHoursEngine(t)
	saveKnown(t, engine, store, func(tu *storage.DetectionTuning) {
		tu.KnownWorkloads = []storage.KnownWorkload{
			{Workload: "node /usr/local/bin/corepack", Owner: storage.AnyOwner, Reason: "registry service", ExpiresAt: testExpiry},
			{Workload: "node /opt/node/lib/npm-cli.js", Owner: "as13335", Reason: "npm registry", ExpiresAt: testExpiry},
		}
	})
	// A tool known only for one owner is not a service: a build at night is news.
	engine.Evaluate(storage.Event{
		TenantID: "default", EndpointID: "linux-62", Timestamp: night,
		Action: "PERMIT", Direction: "OUTBOUND", DstIP: "23.32.3.41", DstPort: 443, BytesOut: 800,
		ProcessPath: "/opt/node/bin/node", CommandLine: "node /opt/node/lib/npm-cli.js ci",
	})
	if got := anomaliesOfType(t, store, "OFF_HOURS_ACTIVITY"); len(got) != 1 {
		t.Fatalf("an owner-scoped tool at night should be off-hours, got %d", len(got))
	}
	engine.Evaluate(storage.Event{
		TenantID: "default", EndpointID: "linux-61", Timestamp: night,
		Action: "PERMIT", Direction: "OUTBOUND", DstIP: "23.32.3.40", DstPort: 443, BytesOut: 800,
		ProcessPath: "/opt/node/bin/node", CommandLine: "node /usr/local/bin/corepack pnpm install",
	})
	if got := anomaliesOfType(t, store, "OFF_HOURS_ACTIVITY"); len(got) != 1 {
		t.Fatalf("a known service raised off-hours findings: %d in all", len(got))
	}
	// Its counterparty is still judged: an unnamed address is not covered for an interpreter.
	if got := anomaliesOfType(t, store, "NOVEL_PROCESS_EGRESS"); len(got) == 0 {
		t.Fatal("a known service reaching an unnamed address should be reported")
	}
}

func TestReplayJudgesRecordedFindingsAgainstATuning(t *testing.T) {
	at := time.Date(2026, 10, 7, 3, 0, 0, 0, time.UTC)
	asn := map[string]string{"Cloudflare, Inc.": "AS13335", "GitHub, Inc.": "AS36459"}
	ev := func(cmd, owner string) string {
		return fmt.Sprintf(`{"command_line":%q,"destination_owner":%q,"destination_asn":%q,"destination_tenancy":"shared-cdn"}`, cmd, owner, asn[owner])
	}
	alerts := []storage.AnomalyAlert{
		{ID: "a", AnomalyType: "NOVEL_PROCESS_EGRESS", EndpointID: "e", ProcessPath: "/usr/bin/node", Evidence: ev("node /opt/node/lib/npm-cli.js ci", "Cloudflare, Inc."), Timestamp: at},
		{ID: "b", AnomalyType: "NOVEL_PROCESS_EGRESS", EndpointID: "e", ProcessPath: "/usr/bin/curl", Evidence: ev("curl x", "GitHub, Inc."), Timestamp: at},
		{ID: "c", AnomalyType: "OFF_HOURS_ACTIVITY", EndpointID: "e", ProcessPath: "/usr/bin/curl", Evidence: ev("curl x", "GitHub, Inc."), Timestamp: at},
		{ID: "d", AnomalyType: "OFF_HOURS_ACTIVITY", EndpointID: "e", ProcessPath: "/usr/bin/curl", Evidence: ev("curl y", "GitHub, Inc."), Timestamp: at.Add(5 * time.Minute)},
		{ID: "e", AnomalyType: "ENDPOINT_SILENT", EndpointID: "s", Timestamp: at},
		// The same program reaching the same owner inside the cooldown is not novel.
		{ID: "f", AnomalyType: "NOVEL_PROCESS_EGRESS", EndpointID: "e", ProcessPath: "/usr/bin/curl", Evidence: ev("curl z", "GitHub, Inc."), Timestamp: at.Add(10 * time.Minute)},
		{ID: "g", AnomalyType: "NOVEL_PROCESS_EGRESS", EndpointID: "e", ProcessPath: "/usr/bin/curl", Evidence: ev("curl z", "GitHub, Inc."), Timestamp: at.Add(2 * time.Hour)},
	}
	tu := storage.DefaultDetectionTuning()
	tu.KnownWorkloads = []storage.KnownWorkload{{Workload: "node /opt/node/lib/npm-cli.js", Owner: "as13335", Reason: "npm registry", ExpiresAt: testExpiry}}
	tu, _ = storage.PrepareDetectionTuning(tu)
	res := Replay(alerts, tu)
	kept := map[string]bool{}
	for _, d := range res.Decisions {
		kept[d.ID] = d.Kept
	}
	want := map[string]bool{"a": false, "b": true, "c": true, "d": false, "e": true, "f": false, "g": true}
	for id, k := range want {
		if kept[id] != k {
			t.Errorf("finding %s kept=%v, want %v", id, kept[id], k)
		}
	}
	if res.Before != 7 || res.After != 4 {
		t.Fatalf("before/after = %d/%d, want 7/4", res.Before, res.After)
	}
}

// A process whose agent reported path_mismatch has no workload when it would be
// known by its path, and keeps an interpreter's, which is read from its own
// command line rather than the path. Replay judges a recorded finding the same
// way, from the attribution status in its evidence.
func TestAPathMismatchHasNoPathWorkload(t *testing.T) {
	if w := vouchedWorkload("/usr/local/bin/synctool", "synctool --push", pathMismatch); w != "" {
		t.Fatalf("a path_mismatch program was given the workload %q", w)
	}
	if w := vouchedWorkload("/usr/local/bin/synctool", "synctool --push", "authoritative"); w != "/usr/local/bin/synctool" {
		t.Fatalf("an attributed program's workload is %q", w)
	}
	if w := vouchedWorkload("/usr/bin/python3", "python3 /srv/app/worker.py", pathMismatch); w != "python3 /srv/app/worker.py" {
		t.Fatalf("an interpreter's workload under path_mismatch is %q", w)
	}

	tu := storage.DefaultDetectionTuning()
	tu.KnownWorkloads = []storage.KnownWorkload{{Workload: "/usr/local/bin/synctool", Owner: storage.AnyOwner, Reason: "sync tool", ExpiresAt: testExpiry}}
	tu, err := storage.PrepareDetectionTuning(tu)
	if err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 10, 7, 3, 0, 0, 0, time.UTC)
	ev := func(status string) string {
		return fmt.Sprintf(`{"attribution_status":%q,"destination_owner":"DigitalOcean, LLC","destination_asn":"AS14061","destination_tenancy":"hosting"}`, status)
	}
	res := Replay([]storage.AnomalyAlert{
		{ID: "real", TenantID: "default", AnomalyType: "NOVEL_DESTINATION", EndpointID: "e", ProcessPath: "/usr/local/bin/synctool", Evidence: ev("authoritative"), Timestamp: at},
		{ID: "forged", TenantID: "default", AnomalyType: "NOVEL_DESTINATION", EndpointID: "f", ProcessPath: "/usr/local/bin/synctool", Evidence: ev("path_mismatch"), Timestamp: at.Add(2 * time.Hour)},
	}, tu)
	kept := map[string]bool{}
	for _, d := range res.Decisions {
		kept[d.ID] = d.Kept
	}
	if kept["real"] || !kept["forged"] {
		t.Fatalf("replay kept real=%v forged=%v, want false/true", kept["real"], kept["forged"])
	}
}
