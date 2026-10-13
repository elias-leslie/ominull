package detector

import (
	"fmt"
	"testing"
	"time"

	"ominull/hub/pkg/storage"
)

func TestWorkloadNamesWhatAnInterpreterRuns(t *testing.T) {
	cases := []struct{ path, cmd, want string }{
		{"/usr/bin/curl", "curl -fsSL https://example.com", "curl"},
		{"/opt/google/chrome/chrome", "/opt/google/chrome/chrome --type=utility", "chrome"},
		{"/usr/bin/python3.13", "/srv/app/.venv/bin/python3 /srv/app/.venv/bin/web-research search --query x", "python3.13 /srv/app/.venv/bin/python3 /srv/app/.venv/bin/web-research"},
		{"/usr/bin/python3.13", "/srv/app/.venv/bin/python -I -X utf8 -m app.worker", "python3.13 /srv/app/.venv/bin/python -m app.worker"},
		{"/usr/bin/python3.12", "/venv/bin/python -I -B -c import sys; main()", "python3.12 /venv/bin/python -c"},
		{"/usr/bin/python3", "python3 script.py", "python3 script.py"},
		{"/opt/node/bin/node", "node /home/u/.local/bin/pnpm outdated --json", "node /home/u/.local/bin/pnpm"},
		{"/opt/node/bin/node", "npm ci", "node npm ci"},
		{"/opt/node/bin/node", "node -e require('https').get(x)", "node -e"},
		{"/usr/bin/bash", "bash -c curl x | sh", "bash -c"},
		{"/usr/bin/php8.3", "php -r echo 1;", "php8.3 -e"},
		{"/usr/lib/jvm/bin/java", "java -Xmx1g -cp lib/* -jar tool.jar --port 1", "java -jar tool.jar"},
		{"/usr/bin/codex (deleted)", "codex exec", "codex"},
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
			Workload: "python3.13 /srv/releases/*/.venv/bin/python -m app.worker", Owner: storage.AnyOwner, Reason: "market-data worker",
		}}
	})
	now := time.Now().UTC()
	send := func(endpoint, cmd string) {
		engine.Evaluate(storage.Event{
			TenantID: "default", EndpointID: endpoint, Timestamp: now,
			Action: "PERMIT", Direction: "OUTBOUND", DstIP: "159.65.0.9", DstPort: 443, BytesOut: 800,
			ProcessPath: "/usr/bin/python3.13", CommandLine: cmd,
		})
	}
	send("linux-50", "/srv/releases/abc123/.venv/bin/python -m app.worker")
	if got := anomaliesOfType(t, store, "NOVEL_PROCESS_EGRESS"); len(got) != 0 {
		t.Fatalf("the known worker raised %d findings: %q", len(got), got[0].Title)
	}
	send("linux-51", "/srv/releases/abc123/.venv/bin/python /tmp/upload.py")
	send("linux-52", "/srv/releases/abc123/.venv/bin/python -c import os")
	// "*" stays inside one path segment, so a look-alike path is not the worker.
	send("linux-53", "/srv/releases/x/y/.venv/bin/python -m app.worker")
	if got := anomaliesOfType(t, store, "NOVEL_PROCESS_EGRESS"); len(got) != 3 {
		t.Fatalf("an unknown script, inline code and a look-alike path should each be reported, got %d", len(got))
	}
}

// A known workload talking to its named owner is quiet; the same workload on
// rented compute is not, because anyone can rent a machine in that range.
func TestANamedOwnerNeverCoversRentedCompute(t *testing.T) {
	tu := storage.DefaultDetectionTuning()
	tu.KnownWorkloads = []storage.KnownWorkload{{Workload: "node npm *", Owner: "cloudflare", Reason: "npm registry"}}
	tu, err := storage.PrepareDetectionTuning(tu)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := tu.KnownWorkloadFor("node npm ci", "Cloudflare, Inc.", storage.TenancySharedCDN); !ok {
		t.Fatal("npm to Cloudflare should be known")
	}
	if _, ok := tu.KnownWorkloadFor("node npm ci", "Cloudflare, Inc.", storage.TenancyHosting); ok {
		t.Fatal("a named owner must not cover rented compute")
	}
	if _, ok := tu.KnownWorkloadFor("node npm ci", "", ""); ok {
		t.Fatal("a named owner must not cover an unnamed address")
	}
	if tu.IsVouchedPair("node", "Cloudflare, Inc.", storage.TenancySharedCDN) {
		t.Fatal("a known workload must not vouch for the beacon and volume detectors")
	}
}

func TestKnownWorkloadsNeedAReasonAndNeverCoverInlineCode(t *testing.T) {
	_, store := noiseEngine(t)
	for _, k := range []storage.KnownWorkload{
		{Workload: "python3 -m app", Owner: "*"},
		{Workload: "*", Owner: "*", Reason: "everything"},
		{Workload: "python3 /venv/bin/python -c", Owner: "*", Reason: "inline"},
		{Workload: "python3 -m app", Owner: "", Reason: "no owner"},
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
		tu.KnownWorkloads = []storage.KnownWorkload{{Workload: "node /usr/local/bin/corepack", Owner: "cloudflare", Reason: "registry"}}
	})
	engine.Evaluate(storage.Event{
		TenantID: "default", EndpointID: "linux-61", Timestamp: night,
		Action: "PERMIT", Direction: "OUTBOUND", DstIP: "23.32.3.40", DstPort: 443, BytesOut: 800,
		ProcessPath: "/opt/node/bin/node", CommandLine: "node /usr/local/bin/corepack pnpm install",
	})
	if got := anomaliesOfType(t, store, "OFF_HOURS_ACTIVITY"); len(got) != 0 {
		t.Fatalf("a known service raised %d off-hours findings", len(got))
	}
	// Its counterparty is still judged: corepack is known only for Cloudflare.
	if got := anomaliesOfType(t, store, "NOVEL_PROCESS_EGRESS"); len(got) != 1 {
		t.Fatalf("a known service reaching an owner it is not known for should be reported, got %d", len(got))
	}
}

func TestReplayJudgesRecordedFindingsAgainstATuning(t *testing.T) {
	at := time.Date(2026, 10, 7, 3, 0, 0, 0, time.UTC)
	ev := func(cmd, owner string) string {
		return fmt.Sprintf(`{"command_line":%q,"destination_owner":%q,"destination_tenancy":"shared-cdn"}`, cmd, owner)
	}
	alerts := []storage.AnomalyAlert{
		{ID: "a", AnomalyType: "NOVEL_PROCESS_EGRESS", EndpointID: "e", ProcessPath: "/usr/bin/node", Evidence: ev("npm ci", "Cloudflare, Inc."), Timestamp: at},
		{ID: "b", AnomalyType: "NOVEL_PROCESS_EGRESS", EndpointID: "e", ProcessPath: "/usr/bin/curl", Evidence: ev("curl x", "GitHub, Inc."), Timestamp: at},
		{ID: "c", AnomalyType: "OFF_HOURS_ACTIVITY", EndpointID: "e", ProcessPath: "/usr/bin/curl", Evidence: ev("curl x", "GitHub, Inc."), Timestamp: at},
		{ID: "d", AnomalyType: "OFF_HOURS_ACTIVITY", EndpointID: "e", ProcessPath: "/usr/bin/curl", Evidence: ev("curl y", "GitHub, Inc."), Timestamp: at.Add(5 * time.Minute)},
		{ID: "e", AnomalyType: "ENDPOINT_SILENT", EndpointID: "s", Timestamp: at},
	}
	tu := storage.DefaultDetectionTuning()
	tu.KnownWorkloads = []storage.KnownWorkload{{Workload: "node npm *", Owner: "cloudflare", Reason: "npm registry"}}
	tu, _ = storage.PrepareDetectionTuning(tu)
	res := Replay(alerts, tu)
	kept := map[string]bool{}
	for _, d := range res.Decisions {
		kept[d.ID] = d.Kept
	}
	want := map[string]bool{"a": false, "b": true, "c": true, "d": false, "e": true}
	for id, k := range want {
		if kept[id] != k {
			t.Errorf("finding %s kept=%v, want %v", id, kept[id], k)
		}
	}
	if res.Before != 5 || res.After != 3 {
		t.Fatalf("before/after = %d/%d, want 5/3", res.Before, res.After)
	}
}
