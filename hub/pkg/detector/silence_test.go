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

func TestTheThresholdIsTheOperatorsToSet(t *testing.T) {
	engine, store := silentEngine(t)
	now := time.Now().UTC()
	addEndpoint(t, store, "linux-slow", now.Add(-20*time.Minute))

	tuning := storage.DefaultDetectionTuning()
	tuning.SilenceAfterMinutes = 60
	if _, err := store.SaveDetectionTuning(tuning, "test"); err != nil {
		t.Fatalf("saving tuning: %v", err)
	}
	engine.InvalidateTuning()

	engine.SweepSilence(now)
	if got := anomaliesOfType(t, store, "ENDPOINT_SILENT"); len(got) != 0 {
		t.Fatalf("twenty minutes of silence fired against a sixty-minute threshold: %d findings", len(got))
	}
}

func TestSilenceCanBeSwitchedOff(t *testing.T) {
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
	if got := anomaliesOfType(t, store, "ENDPOINT_SILENT"); len(got) != 0 {
		t.Fatalf("the detector fired while switched off: %d findings", len(got))
	}
}
