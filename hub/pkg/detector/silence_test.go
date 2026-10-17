package detector

import (
	"testing"
	"time"

	"ominull/hub/pkg/storage"
)

// A host that goes dark is the one condition no other detector here can see:
// they all need telemetry, and this one fires because telemetry stopped.

func silentEngine(t *testing.T) (*Engine, *storage.Store) {
	t.Helper()
	engine, store := noiseEngine(t)
	return engine, store
}

func addEndpoint(t *testing.T, store *storage.Store, id string, lastSeen time.Time) {
	t.Helper()
	if err := store.UpsertEndpoint(storage.Endpoint{
		ID: id, TenantID: "default", Hostname: id, OS: "linux",
		Status: "online", LastSeenAt: lastSeen, CreatedAt: lastSeen.Add(-24 * time.Hour),
	}); err != nil {
		t.Fatalf("creating endpoint %s: %v", id, err)
	}
}

func TestAHostThatGoesQuietRaisesExactlyOneFinding(t *testing.T) {
	engine, store := silentEngine(t)
	now := time.Now().UTC()
	addEndpoint(t, store, "linux-silent", now.Add(-40*time.Minute))

	engine.SweepSilence(now)
	engine.SweepSilence(now.Add(time.Minute))
	engine.SweepSilence(now.Add(2 * time.Minute))

	got := anomaliesOfType(t, store, "ENDPOINT_SILENT")
	if len(got) != 1 {
		t.Fatalf("expected one silence finding for a host that stayed dark, got %d", len(got))
	}
	if got[0].Severity != "HIGH" {
		t.Fatalf("a silent agent is a HIGH finding, got %q", got[0].Severity)
	}
}

func TestAHostReportingNormallyRaisesNothing(t *testing.T) {
	engine, store := silentEngine(t)
	now := time.Now().UTC()
	addEndpoint(t, store, "linux-healthy", now.Add(-2*time.Minute))

	engine.SweepSilence(now)

	if got := anomaliesOfType(t, store, "ENDPOINT_SILENT"); len(got) != 0 {
		t.Fatalf("a host that reported two minutes ago raised %d findings", len(got))
	}
}

func TestTheAlertRearmsOnlyAfterTheHostReturns(t *testing.T) {
	engine, store := silentEngine(t)
	now := time.Now().UTC()
	addEndpoint(t, store, "linux-flapping", now.Add(-40*time.Minute))
	engine.SweepSilence(now)

	// It comes back.
	addEndpoint(t, store, "linux-flapping", now.Add(time.Minute))
	engine.SweepSilence(now.Add(2 * time.Minute))
	if got := anomaliesOfType(t, store, "ENDPOINT_RETURNED"); len(got) != 1 {
		t.Fatalf("expected one recovery note, got %d", len(got))
	}

	// And goes dark again.
	engine.SweepSilence(now.Add(90 * time.Minute))
	if got := anomaliesOfType(t, store, "ENDPOINT_SILENT"); len(got) != 2 {
		t.Fatalf("expected a second finding after the host returned and went quiet again, got %d", len(got))
	}
}

// A hub restart loses the in-memory state. Re-raising a finding the operator is
// already looking at would make every restart look like an event.
func TestARestartDoesNotRepeatAFindingThatIsStillOpen(t *testing.T) {
	engine, store := silentEngine(t)
	now := time.Now().UTC()
	addEndpoint(t, store, "linux-dark", now.Add(-40*time.Minute))
	engine.SweepSilence(now)

	restarted := New(store, nil, nil)
	restarted.SweepSilence(now.Add(time.Minute))

	if got := anomaliesOfType(t, store, "ENDPOINT_SILENT"); len(got) != 1 {
		t.Fatalf("a restart re-raised the open finding: %d findings", len(got))
	}
}

func TestRetiredAndEnrollingHostsAreNotExpectedToReport(t *testing.T) {
	engine, store := silentEngine(t)
	now := time.Now().UTC()

	if err := store.UpsertEndpoint(storage.Endpoint{
		ID: "linux-retired", TenantID: "default", Hostname: "retired", Status: "retired",
		LastSeenAt: now.Add(-100 * time.Hour), CreatedAt: now.Add(-200 * time.Hour),
	}); err != nil {
		t.Fatalf("creating the retired endpoint: %v", err)
	}
	if err := store.UpsertEndpoint(storage.Endpoint{
		ID: "linux-enrolling", TenantID: "default", Hostname: "enrolling", Status: "offline",
		DriverVersion: "enrolling", LastSeenAt: now.Add(-100 * time.Hour), CreatedAt: now.Add(-100 * time.Hour),
	}); err != nil {
		t.Fatalf("creating the enrolling endpoint: %v", err)
	}

	engine.SweepSilence(now)

	if got := anomaliesOfType(t, store, "ENDPOINT_SILENT"); len(got) != 0 {
		t.Fatalf("a retired or half-enrolled host raised %d findings: %q", len(got), got[0].Title)
	}
}

// The operator may shorten the silence threshold, never lengthen it past the
// floor: a sixty-minute row still reports a host quiet for twenty minutes.
func TestTheSilenceThresholdTightensButNeverPassesTheFloor(t *testing.T) {
	for _, c := range []struct {
		minutes int
		quiet   time.Duration
		want    int
	}{{5, 8 * time.Minute, 1}, {60, 20 * time.Minute, 1}, {15, 10 * time.Minute, 0}} {
		engine, store := silentEngine(t)
		now := time.Now().UTC()
		addEndpoint(t, store, "linux-slow", now.Add(-c.quiet))
		tuning := storage.DefaultDetectionTuning()
		tuning.SilenceAfterMinutes = c.minutes
		if _, err := store.SaveDetectionTuning(tuning, "test"); err != nil {
			t.Fatalf("saving tuning: %v", err)
		}
		engine.InvalidateTuning()
		engine.SweepSilence(now)
		if got := anomaliesOfType(t, store, "ENDPOINT_SILENT"); len(got) != c.want {
			t.Errorf("%v of silence against a %d-minute setting raised %d findings, want %d", c.quiet, c.minutes, len(got), c.want)
		}
	}
}

// Silence is part of the floor: a saved row that says it is off, written by
// hand or by an older hub, still leaves the sweep running.
func TestSilenceCannotBeSwitchedOff(t *testing.T) {
	engine, store := silentEngine(t)
	now := time.Now().UTC()
	addEndpoint(t, store, "linux-off", now.Add(-40*time.Minute))

	tuning := storage.DefaultDetectionTuning()
	tuning.SilenceOn = false
	if _, err := store.SaveDetectionTuning(tuning, "test"); err != nil {
		t.Fatalf("saving tuning: %v", err)
	}
	engine.InvalidateTuning()

	engine.SweepSilence(now)
	if got := anomaliesOfType(t, store, "ENDPOINT_SILENT"); len(got) != 1 {
		t.Fatalf("silence detection was switched off: %d findings, want 1", len(got))
	}
}

// A laptop that is in use but often shut, and a test guest that is off between
// experiments, go quiet as a matter of course. Reporting each absence buried
// the server outages this finding exists for.
func TestPresenceDecidesWhenQuietIsAFinding(t *testing.T) {
	engine, store := silentEngine(t)
	now := time.Now().UTC()
	addEndpoint(t, store, "laptop-recent", now.Add(-10*24*time.Hour))
	addEndpoint(t, store, "laptop-lost", now.Add(-31*24*time.Hour))
	addEndpoint(t, store, "lab-guest", now.Add(-90*24*time.Hour))
	addEndpoint(t, store, "server-down", now.Add(-40*time.Minute))
	for id, p := range map[string]string{"laptop-recent": storage.PresenceIntermittent, "laptop-lost": storage.PresenceIntermittent, "lab-guest": storage.PresenceParked} {
		if err := store.SetEndpointPresence(id, p); err != nil {
			t.Fatal(err)
		}
	}
	// A heartbeat rewrites the endpoint row; it must not reset what the
	// operator said about the host.
	addEndpoint(t, store, "laptop-recent", now.Add(-10*24*time.Hour))

	engine.SweepSilence(now)

	got := map[string]bool{}
	for _, a := range anomaliesOfType(t, store, "ENDPOINT_SILENT") {
		got[a.EndpointID] = true
	}
	if len(got) != 2 || !got["server-down"] || !got["laptop-lost"] {
		t.Fatalf("silence findings = %v, want the always-on server and the laptop quiet past 30 days", got)
	}
}
