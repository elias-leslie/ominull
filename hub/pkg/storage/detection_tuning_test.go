package storage

import (
	"testing"
	"time"
)

// The console decides whether to say "these settings differ from the shipped
// values" by comparing the two the hub sends. An unsorted default made every
// hub report differences it did not have.
func TestTheShippedValuesCompareEqualToThemselves(t *testing.T) {
	a := DefaultDetectionTuning()
	b := DefaultDetectionTuning().normalised()
	if len(a.QuietProcesses) != len(b.QuietProcesses) {
		t.Fatalf("list lengths differ: %d vs %d", len(a.QuietProcesses), len(b.QuietProcesses))
	}
	for i := range a.QuietProcesses {
		if a.QuietProcesses[i] != b.QuietProcesses[i] {
			t.Fatalf("defaults are not normalised: %q vs %q", a.QuietProcesses[i], b.QuietProcesses[i])
		}
	}
}

// The window that matters wraps midnight, and it is read in a named zone. Set
// in UTC with no zone anywhere near it, hours 2 to 5 are late evening here,
// which is why ordinary evening use of a workstation was reported as off-hours.
func TestTheOffHoursWindowWrapsMidnightInItsOwnZone(t *testing.T) {
	cfg := DefaultDetectionTuning()
	cfg.OffHoursStart, cfg.OffHoursEnd, cfg.OffHoursZone = 22, 5, "UTC"
	cfg = cfg.normalised()

	at := func(h int) time.Time { return time.Date(2026, 3, 1, h, 30, 0, 0, time.UTC) }
	for _, h := range []int{22, 23, 0, 3, 4} {
		if !cfg.IsOffHours(at(h)) {
			t.Errorf("%02d:30 UTC should be inside 22:00-05:00", h)
		}
	}
	for _, h := range []int{5, 9, 14, 21} {
		if cfg.IsOffHours(at(h)) {
			t.Errorf("%02d:30 UTC should be outside 22:00-05:00", h)
		}
	}
}

// A window someone switched off stays off, whatever the hour.
func TestADisabledWindowIsNeverOffHours(t *testing.T) {
	cfg := DefaultDetectionTuning()
	cfg.OffHoursOn = false
	if cfg.IsOffHours(time.Date(2026, 3, 1, 3, 0, 0, 0, time.UTC)) {
		t.Fatal("a disabled off-hours detector still reported off-hours")
	}
}

// The quiet lists are the operator's answer to "this is normal here", and the
// network one has to match how a resolver actually writes an owner.
func TestQuietMatchingIsForgivingInTheRightPlaces(t *testing.T) {
	cfg := DefaultDetectionTuning()
	if !cfg.IsQuietProcess("SVCHOST.EXE") {
		t.Error("process matching is case sensitive")
	}
	if cfg.IsQuietProcess("svchost") {
		t.Error("a partial process name matched; that is a way to be talked past")
	}
	if !cfg.IsQuietOrg("APPLE-ENGINEERING, Apple Inc.") {
		t.Error("network matching does not tolerate a real registry string")
	}
	if cfg.IsQuietOrg("") {
		t.Error("an unresolved owner counted as quiet")
	}
}

// A store that has never been tuned answers with the shipped values rather
// than a zero struct, which would read as every detector switched off.
func TestAnUntunedStoreIsNotAnEmptyStruct(t *testing.T) {
	s := newTestStore(t)
	got := s.GetDetectionTuning()
	if !got.BeaconOn || got.BeaconMinSamples == 0 {
		t.Fatalf("untuned store returned a zero configuration: %+v", got)
	}
}

// The learning period is what stops a host installed this morning reporting
// every ordinary thing it does.
func TestASavedTuningSurvivesTheRoundTrip(t *testing.T) {
	s := newTestStore(t)
	in := DefaultDetectionTuning()
	in.WarmupHours = 72
	in.BeaconScore = 0.95
	in.QuietProcesses = append(in.QuietProcesses, "Backup Helper")

	if _, err := s.SaveDetectionTuning(in, "someone@example.invalid"); err != nil {
		t.Fatalf("save: %v", err)
	}
	got := s.GetDetectionTuning()
	if got.WarmupHours != 72 || got.BeaconScore != 0.95 {
		t.Fatalf("round trip lost values: %+v", got)
	}
	if !got.IsQuietProcess("backup helper") {
		t.Error("an added name was not lower-cased on the way in")
	}
	if got.UpdatedBy != "someone@example.invalid" {
		t.Errorf("authorship not recorded: %q", got.UpdatedBy)
	}
}
