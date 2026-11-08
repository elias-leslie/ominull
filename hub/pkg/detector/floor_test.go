package detector

import (
	"reflect"
	"strings"
	"testing"

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
	weak.WarmupHours = 720
	weak.ExpectedRules = append(weak.ExpectedRules, storage.ExpectedRule{ID: "admin-ssh", Reason: "fixture", Findings: []string{storage.KindLateralSweep},
		Hosts: []string{"ws"}, Programs: []storage.ExpectedProgram{{Path: "/usr/bin/ssh"}}, Port: 22, MaxHosts: 20})
	weak.BandwidthCooldown = 1440
	got, notes := ClampToFloor(weak)
	if !got.SilenceOn || got.SilenceAfterMinutes != 15 || got.WarmupHours != 24 || adminSSH(got).MaxHosts != 8 || got.BandwidthCooldown != 5 {
		t.Fatalf("weaker tuning not clamped: %+v", got)
	}
	joined := strings.Join(notes, "\n")
	for _, field := range []string{"silence_enabled", "silence_after_minutes 600", "warmup_hours 720", "admin-ssh max_hosts 20", "bandwidth_cooldown_minutes 1440"} {
		if !strings.Contains(joined, field) {
			t.Errorf("no note for %s: %v", field, notes)
		}
	}

	strict := storage.DefaultDetectionTuning()
	strict.SilenceAfterMinutes = 5
	strict.WarmupHours = 0
	strict.ExpectedRules = append(strict.ExpectedRules, storage.ExpectedRule{ID: "admin-ssh", Reason: "fixture", Findings: []string{storage.KindLateralSweep},
		Hosts: []string{"ws"}, Programs: []storage.ExpectedProgram{{Path: "/usr/bin/ssh"}}, Port: 22, MaxHosts: 3})
	got, notes = ClampToFloor(strict)
	if len(notes) != 0 || !reflect.DeepEqual(got, strict) {
		t.Fatalf("a stricter tuning was changed: %v", notes)
	}
}

// adminSSH is the fixture's admin fan-out rule.
func adminSSH(t storage.DetectionTuning) storage.ExpectedRule {
	r, _ := t.RuleByID("admin-ssh")
	return r
}
