package detector

import (
	"strings"
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

// silentEngineOn is a second engine on the same store, as after a hub restart.
func silentEngineOn(t *testing.T, store *storage.Store) (*Engine, *storage.Store) {
	t.Helper()
	engine := New(store, nil, nil)
	return engine, store
}

// aicoSays is Aico answering every few minutes from one time to another: a gap
// in its word starts a machine's UpSince again.
func aicoSays(t *testing.T, store *storage.Store, machines []storage.AicoMachine, from, to time.Time) {
	t.Helper()
	for at := from; ; at = at.Add(5 * time.Minute) {
		if at.After(to) {
			at = to
		}
		if err := store.SaveAicoFleet(machines, at); err != nil {
			t.Fatal(err)
		}
		if !at.Before(to) {
			return
		}
	}
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

// Aico owns whether a machine should be running: off, its agent's silence
// means nothing, whatever presence says; up, a silent agent is a dark sensor
// and pages, whatever presence says. Changing a guest in Aico needs nothing here.
func TestAicoDecidesWhetherSilenceMatters(t *testing.T) {
	yes, no := true, false
	engine, store := silentEngine(t)
	now := time.Now().UTC()
	addEndpoint(t, store, "off-guest", now.Add(-48*time.Hour))
	addEndpoint(t, store, "dark-guest", now.Add(-48*time.Hour))
	addEndpoint(t, store, "parked-dark", now.Add(-48*time.Hour))
	addEndpoint(t, store, "cant-tell", now.Add(-48*time.Hour))
	addEndpoint(t, store, "laptop", now.Add(-48*time.Hour))
	if err := store.SetEndpointPresence("parked-dark", storage.PresenceParked); err != nil {
		t.Fatal(err)
	}
	if err := store.SetEndpointPresence("laptop", storage.PresenceIntermittent); err != nil {
		t.Fatal(err)
	}
	aicoSays(t, store, []storage.AicoMachine{
		{Machine: "off-guest", Intent: "on-demand", Up: &no},
		{Machine: "dark-guest", Intent: "on-demand", Up: &yes},
		{Machine: "parked-dark", Up: &yes},
		{Machine: "cant-tell", Intent: "always"},
	}, now.Add(-2*time.Hour), now)

	engine.SweepSilence(now)

	got := map[string]storage.AnomalyAlert{}
	for _, a := range anomaliesOfType(t, store, "ENDPOINT_SILENT") {
		got[a.EndpointID] = a
	}
	if _, raised := got["off-guest"]; raised {
		t.Error("a machine Aico says is off raised a finding")
	}
	if _, raised := got["laptop"]; raised {
		t.Error("a laptop Aico does not know lost its intermittent allowance")
	}
	for _, id := range []string{"dark-guest", "parked-dark"} {
		a, raised := got[id]
		if !raised {
			t.Errorf("%s is up with a silent agent and raised nothing", id)
			continue
		}
		if !strings.Contains(a.Evidence, `"sensor_dark":true`) || !strings.HasPrefix(a.Title, "Sensor dark on") {
			t.Errorf("%s: not reported as a dark sensor: %s %s", id, a.Title, a.Evidence)
		}
	}
	// Aico cannot tell: the stored presence decides, as if it did not know the host.
	if a, raised := got["cant-tell"]; !raised || strings.Contains(a.Evidence, `"sensor_dark":true`) {
		t.Errorf("a host Aico cannot read should fall back to presence: raised=%v %s", raised, a.Evidence)
	}
}

// A guest that was off for days and has just started has an agent that has not
// had time to report: the wait counts from when the machine came up. Nothing
// is reported as back while the agent is still quiet.
func TestAMachineJustUpGetsItsGrace(t *testing.T) {
	yes := true
	engine, store := silentEngine(t)
	now := time.Now().UTC()
	addEndpoint(t, store, "guest", now.Add(-72*time.Hour))
	fleet := []storage.AicoMachine{{Machine: "guest", Up: &yes}}
	if err := store.SaveAicoFleet(fleet, now); err != nil {
		t.Fatal(err)
	}
	engine.SweepSilence(now)
	if got := anomaliesOfType(t, store, "ENDPOINT_SILENT"); len(got) != 0 {
		t.Fatalf("a machine just up was called dark: %+v", got[0])
	}
	if got := anomaliesOfType(t, store, "ENDPOINT_RETURNED"); len(got) != 0 {
		t.Fatal("a still-quiet agent was reported as returned")
	}
	later := now.Add(16 * time.Minute)
	aicoSays(t, store, fleet, now, later)
	engine.SweepSilence(later)
	if got := anomaliesOfType(t, store, "ENDPOINT_SILENT"); len(got) != 1 {
		t.Fatalf("still quiet past the wait: %d findings", len(got))
	}
}

// A stale view is not acted on: Aico stopped answering, so a machine it last
// called off may be running. The hub goes back to what it knows.
func TestAStaleAicoViewFallsBackToPresence(t *testing.T) {
	no := false // an always-on machine; anything else is remembered as off for a while
	engine, store := silentEngine(t)
	now := time.Now().UTC()
	addEndpoint(t, store, "server", now.Add(-40*time.Minute))
	if err := store.SaveAicoFleet([]storage.AicoMachine{{Machine: "server", Intent: "always", Up: &no}}, now.Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	engine.SweepSilence(now)
	if got := anomaliesOfType(t, store, "ENDPOINT_SILENT"); len(got) != 1 {
		t.Fatalf("a stale off view hid a silent always-on host: %d findings", len(got))
	}
}

// A machine just stopped on demand stays off while Aico's word lapses (a restart,
// a failed Proxmox read), then falls back to presence once the memory runs out.
// An always-on machine is not remembered as off.
func TestALapseInAicosWordKeepsAnOnDemandMachineOff(t *testing.T) {
	no := false
	engine, store := silentEngine(t)
	now := time.Now().UTC()
	addEndpoint(t, store, "guest", now.Add(-40*time.Hour))
	addEndpoint(t, store, "core", now.Add(-40*time.Hour))
	if err := store.SaveAicoFleet([]storage.AicoMachine{
		{Machine: "guest", Intent: "on-demand", Up: &no},
		{Machine: "core", Intent: "always", Up: &no},
	}, now.Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	// Later replies leave guest out, as when the hypervisor read fails.
	if err := store.SaveAicoFleet([]storage.AicoMachine{}, now); err != nil {
		t.Fatal(err)
	}
	engine.SweepSilence(now)
	got := anomaliesOfType(t, store, "ENDPOINT_SILENT")
	if len(got) != 1 || got[0].EndpointID != "core" {
		t.Fatalf("want only the always-on machine reported, got %+v", got)
	}
	engine.SweepSilence(now.Add(25 * time.Hour))
	if got := anomaliesOfType(t, store, "ENDPOINT_SILENT"); len(got) != 2 {
		t.Fatalf("the memory of off never ran out: %d findings", len(got))
	}
}

// A finding raised while Aico's word lapsed is only recorded; when Aico then says
// the machine is up, the dark sensor still gets its page.
func TestAFindingFromALapseDoesNotBlockTheDarkSensorPage(t *testing.T) {
	yes := true
	engine, store := silentEngine(t)
	now := time.Now().UTC()
	addEndpoint(t, store, "guest", now.Add(-40*time.Minute))
	engine.SweepSilence(now)
	if got := anomaliesOfType(t, store, "ENDPOINT_SILENT"); len(got) != 1 {
		t.Fatalf("lapse: %d findings", len(got))
	}
	fleet := []storage.AicoMachine{{Machine: "guest", Up: &yes}}
	later := now.Add(16 * time.Minute)
	aicoSays(t, store, fleet, now, later)
	for _, at := range []time.Time{later, later.Add(time.Minute)} {
		engine.SweepSilence(at)
	}
	dark := 0
	for _, a := range anomaliesOfType(t, store, "ENDPOINT_SILENT") {
		if strings.Contains(a.Evidence, `"sensor_dark":true`) {
			dark++
			if storage.AlertClass(a) != storage.ClassPage {
				t.Errorf("a dark sensor is a page, got %s", storage.AlertClass(a))
			}
		}
	}
	if dark != 1 {
		t.Fatalf("want one dark finding after the lapse, got %d", dark)
	}
	// A hub restart must not raise it again.
	fresh, _ := silentEngineOn(t, store)
	fresh.SweepSilence(later.Add(2 * time.Minute))
	if got := anomaliesOfType(t, store, "ENDPOINT_SILENT"); len(got) != 2 {
		t.Fatalf("a restart repeated the page: %d findings", len(got))
	}
}

// When the machine goes off the old finding is closed out, and coming up dark
// again later is a new event.
func TestAMachineGoingOffClosesTheSilenceOut(t *testing.T) {
	yes, no := true, false
	engine, store := silentEngine(t)
	now := time.Now().UTC()
	addEndpoint(t, store, "guest", now.Add(-40*time.Minute))
	on := []storage.AicoMachine{{Machine: "guest", Up: &yes}}
	aicoSays(t, store, on, now.Add(-20*time.Minute), now)
	engine.SweepSilence(now)
	if got := anomaliesOfType(t, store, "ENDPOINT_SILENT"); len(got) != 1 {
		t.Fatalf("dark: %d findings", len(got))
	}
	t1 := now.Add(time.Minute)
	if err := store.SaveAicoFleet([]storage.AicoMachine{{Machine: "guest", Up: &no}}, t1); err != nil {
		t.Fatal(err)
	}
	engine.SweepSilence(t1)
	if got := anomaliesOfType(t, store, "ENDPOINT_RETURNED"); len(got) != 1 || !strings.Contains(got[0].Title, "no longer expected") {
		t.Fatalf("no note that the machine went off: %+v", got)
	}
	t2 := t1.Add(time.Minute)
	if err := store.SaveAicoFleet(on, t2); err != nil {
		t.Fatal(err)
	}
	t3 := t2.Add(5 * time.Minute)
	if err := store.SaveAicoFleet(on, t3); err != nil {
		t.Fatal(err)
	}
	engine.SweepSilence(t3)
	if got := anomaliesOfType(t, store, "ENDPOINT_SILENT"); len(got) != 1 {
		t.Fatalf("back up, still inside its grace: %d findings", len(got))
	}
	t4 := t2.Add(16 * time.Minute)
	aicoSays(t, store, on, t3, t4)
	engine.SweepSilence(t4)
	if got := anomaliesOfType(t, store, "ENDPOINT_SILENT"); len(got) != 2 {
		t.Fatalf("coming up dark again is a new event: %d findings", len(got))
	}
}

// UpSince survives a reply that cannot read the machine; a gap resets it, since
// the machine may have restarted inside the gap, and so does an explicit off.
func TestUpSinceFollowsWhatAicoActuallySaid(t *testing.T) {
	yes, no := true, false
	_, store := silentEngine(t)
	now := time.Now().UTC().Truncate(time.Second)
	cfg := store.GetDetectionTuning()
	save := func(at time.Time, up *bool) storage.AicoMachine {
		t.Helper()
		if err := store.SaveAicoFleet([]storage.AicoMachine{{Machine: "g", Up: up}}, at); err != nil {
			t.Fatal(err)
		}
		fleet, err := store.AicoFleet()
		if err != nil {
			t.Fatal(err)
		}
		m, _ := fleet.Word("g", at, cfg)
		return m
	}
	save(now, &yes)
	save(now.Add(time.Minute), nil)
	if m := save(now.Add(2*time.Minute), &yes); !m.UpSince.Equal(now) {
		t.Errorf("a null reply reset UpSince: %v", m.UpSince)
	}
	if m := save(now.Add(time.Hour), &yes); !m.UpSince.Equal(now.Add(time.Hour)) {
		t.Errorf("a gap in Aico's word kept UpSince: %v", m.UpSince)
	}
	at := now.Add(time.Hour + time.Minute)
	save(at, &no)
	if m := save(at.Add(time.Minute), &yes); !m.UpSince.Equal(at.Add(time.Minute)) {
		t.Errorf("an explicit off did not reset UpSince: %v", m.UpSince)
	}
}

// After a re-enrolment the machine's old row is not called dark: Aico's word goes
// to the agent heard from last.
func TestAicosWordGoesToTheNewestEnrolment(t *testing.T) {
	yes := true
	engine, store := silentEngine(t)
	now := time.Now().UTC()
	for id, seen := range map[string]time.Time{"old": now.Add(-48 * time.Hour), "new": now.Add(-time.Minute)} {
		if err := store.UpsertEndpoint(storage.Endpoint{ID: id, TenantID: "default", Hostname: "box.lan", OS: "linux",
			Status: "online", LastSeenAt: seen, CreatedAt: seen.Add(-time.Hour)}); err != nil {
			t.Fatal(err)
		}
	}
	if err := store.SaveAicoFleet([]storage.AicoMachine{{Machine: "box", Up: &yes}}, now.Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	engine.SweepSilence(now)
	for _, a := range anomaliesOfType(t, store, "ENDPOINT_SILENT") {
		if strings.Contains(a.Evidence, `"sensor_dark":true`) {
			t.Fatalf("an old row was called dark: %+v", a)
		}
	}
}

// A lab machine's dark sensor is only recorded, so once the machine leaves the lab
// that open row doesn't stand in for the page, even across a hub restart.
func TestARecordedLabDarkSensorDoesNotSwallowALaterPage(t *testing.T) {
	yes := true
	engine, store := silentEngine(t)
	store.SetAlertClassifier(engine.stampClass)
	now := time.Now().UTC()
	put := func(tag string) {
		t.Helper()
		if err := store.UpsertEndpoint(storage.Endpoint{ID: "guest", TenantID: "default", Hostname: "guest", OS: "linux", RoleTag: tag,
			Status: "online", LastSeenAt: now.Add(-40 * time.Minute), CreatedAt: now.Add(-48 * time.Hour)}); err != nil {
			t.Fatal(err)
		}
	}
	put(storage.RoleLab)
	later := now.Add(16 * time.Minute)
	aicoSays(t, store, []storage.AicoMachine{{Machine: "guest", Up: &yes}}, now, later)
	for _, at := range []time.Time{later, later.Add(time.Minute)} {
		engine.SweepSilence(at)
	}
	got := anomaliesOfType(t, store, "ENDPOINT_SILENT")
	if len(got) != 1 || storage.AlertClass(got[0]) != storage.ClassRecord {
		t.Fatalf("a lab machine's dark sensor should be recorded: %+v", got)
	}
	put(storage.RolePersonal)
	fresh, _ := silentEngineOn(t, store)
	store.SetAlertClassifier(fresh.stampClass)
	fresh.SweepSilence(later.Add(2 * time.Minute))
	got = anomaliesOfType(t, store, "ENDPOINT_SILENT")
	if len(got) != 2 {
		t.Fatalf("want a second finding once it left the lab, got %d", len(got))
	}
	pages := 0
	for _, a := range got {
		if storage.AlertClass(a) == storage.ClassPage {
			pages++
		}
	}
	if pages != 1 {
		t.Fatalf("want one page, got %d", pages)
	}
}
