package detector

import (
	"reflect"
	"strings"
	"testing"
	"time"

	"ominull/hub/pkg/storage"
)

// The floor holds the numbers the detectors ran on before it existed, and the
// shipped tuning sits on or above it, so the floor changes nothing by default.
func TestTheFloorKeepsTodaysNumbersAndTheDefaults(t *testing.T) {
	if floorPorts != [...]int{23, 135, 445, 3389} {
		t.Errorf("floor ports %v", floorPorts)
	}
	for _, c := range []struct {
		name      string
		got, want float64
	}{
		{"bandwidth outlier z", bandwidthOutlierZ, 3.5},
		{"bandwidth outlier bytes", bandwidthOutlierBytes, 1 << 20},
		{"bandwidth critical z", bandwidthCriticalZ, 8},
		{"bandwidth burst bytes", bandwidthBurstBytes, 10 << 20},
		{"port sweep window", portSweepWindow.Seconds(), 10},
		{"port sweep ports", portSweepPorts, 30},
		{"port sweep shell ports", portSweepShellPorts, 15},
		{"lateral window", lateralWindow.Seconds(), 60},
		{"lateral hosts", lateralHosts, 20},
		{"lateral hosts off-hours", lateralHostsOffHours, 10},
		{"lateral shell hosts", lateralShellHosts, 6},
		{"lateral shell hosts off-hours", lateralShellHostsOffHours, 3},
		{"sweep cooldown", sweepCooldown.Minutes(), 10},
		{"silence minutes", floorSilenceMinutes, 15},
	} {
		if c.got != c.want {
			t.Errorf("%s = %v, want %v", c.name, c.got, c.want)
		}
	}
	shipped := storage.DefaultDetectionTuning()
	got, notes := ClampToFloor(shipped)
	if len(notes) != 0 || !reflect.DeepEqual(got, shipped) {
		t.Fatalf("the shipped tuning is clamped: %v", notes)
	}
}

// A tuning weaker than the floor runs at the floor and says so; one stricter
// than the floor runs as it is.
func TestTheFloorClampsAWeakerTuningAndKeepsAStricterOne(t *testing.T) {
	weak := storage.DefaultDetectionTuning()
	weak.SilenceOn = false
	weak.SilenceAfterMinutes = 600
	weak.BandwidthMinSamples = 500
	weak.WarmupHours = 720
	weak.AdminFanoutMax = 20
	weak.BandwidthOn = false
	got, notes := ClampToFloor(weak)
	if !got.SilenceOn || got.SilenceAfterMinutes != 15 || got.BandwidthMinSamples != 20 || got.WarmupHours != 24 || got.AdminFanoutMax != 8 {
		t.Fatalf("weaker tuning not clamped: %+v", got)
	}
	joined := strings.Join(notes, "\n")
	for _, field := range []string{"silence_enabled", "silence_after_minutes 600", "bandwidth_min_samples 500", "warmup_hours 720", "admin_fanout_max_hosts 20", "bandwidth_enabled"} {
		if !strings.Contains(joined, field) {
			t.Errorf("no note for %s: %v", field, notes)
		}
	}

	strict := storage.DefaultDetectionTuning()
	strict.SilenceAfterMinutes = 5
	strict.BandwidthMinSamples = 8
	strict.WarmupHours = 0
	strict.AdminFanoutMax = 3
	got, notes = ClampToFloor(strict)
	if len(notes) != 0 || !reflect.DeepEqual(got, strict) {
		t.Fatalf("a stricter tuning was changed: %v", notes)
	}
}

// The engine runs the clamped tuning: a saved row with a thirty-day warmup
// and bandwidth switched off still raises a ten-megabyte burst from a host a
// day old.
func TestTheEngineRunsTheFloorAndTheBurstSurvivesBandwidthOff(t *testing.T) {
	engine, store := noiseEngine(t)
	tuning := storage.DefaultDetectionTuning()
	tuning.BandwidthOn = false
	tuning.WarmupHours = 720
	if _, err := store.SaveDetectionTuning(tuning, "test"); err != nil {
		t.Fatal(err)
	}
	engine.InvalidateTuning()
	now := time.Now().UTC()
	if err := store.UpsertEndpoint(storage.Endpoint{ID: "lin-01", TenantID: "default", Hostname: "lin-01", RoleTag: "server", CreatedAt: now.Add(-25 * time.Hour), LastSeenAt: now}); err != nil {
		t.Fatal(err)
	}
	engine.Evaluate(storage.Event{
		TenantID: "default", EndpointID: "lin-01", Timestamp: now, Action: "PERMIT", Direction: "OUTBOUND",
		DstIP: "203.0.113.9", DstPort: 443, BytesOut: 11 << 20, ProcessPath: "/usr/local/bin/uploader",
	})
	if got := anomaliesOfType(t, store, "BANDWIDTH_SPIKE"); len(got) != 1 {
		t.Fatalf("a ten-megabyte burst with bandwidth off and a long warmup raised %d findings", len(got))
	}
}
