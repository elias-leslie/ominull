package storage

import (
	"reflect"
	"testing"
	"time"
)

// The console decides whether to say "these settings differ from the shipped
// values" by comparing the two the hub sends. An unsorted default made every
// hub report differences it did not have.
func TestTheShippedValuesCompareEqualToThemselves(t *testing.T) {
	a := DefaultDetectionTuning()
	b := DefaultDetectionTuning().normalised()
	if len(a.ExpectedRules) == 0 {
		t.Fatal("the shipped tuning has no expected rules")
	}
	if !reflect.DeepEqual(a.ExpectedRules, b.ExpectedRules) {
		t.Fatalf("defaults are not normalised:\n%+v\n%+v", a.ExpectedRules, b.ExpectedRules)
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

// Owners are the AS number or the exact name. A fragment such as "google" used
// to name Google Cloud's customers too.
func TestOwnersMatchExactlyOrByASNumber(t *testing.T) {
	cases := []struct {
		owner, asn, org string
		want            bool
	}{
		{"as36459", "AS36459", "GitHub, Inc.", true},
		{"github, inc.", "AS36459", "GitHub, Inc.", true},
		{"github", "AS36459", "GitHub, Inc.", false},
		{"google", "AS396982", "Google Cloud (customer range)", false},
		{"as15169", "", "Google LLC", false},
		{"", "AS15169", "Google LLC", false},
	}
	for _, c := range cases {
		if got := OwnerMatches(c.owner, c.asn, c.org); got != c.want {
			t.Errorf("OwnerMatches(%q, %q, %q) = %v, want %v", c.owner, c.asn, c.org, got, c.want)
		}
	}
}

// A store that has never been tuned answers with the shipped values rather
// than a zero struct, which would read as every detector switched off.
func TestAnUntunedStoreIsNotAnEmptyStruct(t *testing.T) {
	s := newTestStore(t)
	got := s.GetDetectionTuning()
	if !got.BeaconOn || got.BeaconMinSamples == 0 || len(got.ExpectedRules) == 0 {
		t.Fatalf("untuned store returned a zero configuration: %+v", got)
	}
}

// A hub that was never tuned has no row, and the upgrade does not write one:
// the shipped values stay the shipped values.
func TestAnUntunedHubGetsNoRowFromTheUpgrade(t *testing.T) {
	s := newTestStore(t)
	var n int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM detection_tuning`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("rows=%d err=%v", n, err)
	}
}

// The learning period is what stops a host installed this morning reporting
// every ordinary thing it does.
func TestASavedTuningSurvivesTheRoundTrip(t *testing.T) {
	s := newTestStore(t)
	in := DefaultDetectionTuning()
	in.WarmupHours = 72
	in.BeaconScore = 0.95
	in.ExpectedRules = append(in.ExpectedRules, ExpectedRule{ID: "backup-helper", Reason: "backup",
		Programs: []ExpectedProgram{{Path: "C:/Program Files/Backup Helper/helper.exe", RunAs: "system"}}})

	if _, err := s.SaveDetectionTuning(in, "someone@example.invalid"); err != nil {
		t.Fatalf("save: %v", err)
	}
	got := s.GetDetectionTuning()
	if got.WarmupHours != 72 || got.BeaconScore != 0.95 {
		t.Fatalf("round trip lost values: %+v", got)
	}
	r, ok := got.RuleByID("backup-helper")
	if !ok || r.Programs[0].Path != "c:/program files/backup helper/helper.exe" {
		t.Errorf("an added path was not lower-cased on the way in: %+v", r)
	}
	if got.UpdatedBy != "someone@example.invalid" {
		t.Errorf("authorship not recorded: %q", got.UpdatedBy)
	}
}

func TestDecoyNamesAndDomainFeedsAreChecked(t *testing.T) {
	base := DefaultDetectionTuning()
	ok := base
	ok.DecoyNames = []string{"S3.Vault-Archive.LAN.", "s3.vault-archive.lan"}
	ok.DomainIntelFeeds = []DomainIntelFeed{{Name: "ThreatFox", URL: "https://threatfox-api.abuse.ch/v2/files/exports/{auth_key}/hostfile.txt", Confidence: 90}}
	got, err := PrepareDetectionTuning(ok)
	if err != nil {
		t.Fatalf("valid tuning refused: %v", err)
	}
	if len(got.DecoyNames) != 1 || got.DecoyNames[0] != "s3.vault-archive.lan" || got.DomainIntelFeeds[0].Name != "threatfox" {
		t.Fatalf("not tidied: %v %+v", got.DecoyNames, got.DomainIntelFeeds)
	}
	if d, hit := got.DecoyName("x.s3.vault-archive.lan."); !hit || d != "s3.vault-archive.lan" {
		t.Fatalf("subdomain did not match: %q %v", d, hit)
	}
	if _, hit := got.DecoyName("xs3.vault-archive.lan"); hit {
		t.Fatal("a name that only ends with the decoy's text matched")
	}
	for name, edit := range map[string]func(*DetectionTuning){
		"one-label name":  func(t *DetectionTuning) { t.DecoyNames = []string{"archive"} },
		"name with space": func(t *DetectionTuning) { t.DecoyNames = []string{"a b.lan"} },
		"http feed": func(t *DetectionTuning) {
			t.DomainIntelFeeds = []DomainIntelFeed{{Name: "x", URL: "http://lists.example/h", Confidence: 50}}
		},
		"no confidence": func(t *DetectionTuning) {
			t.DomainIntelFeeds = []DomainIntelFeed{{Name: "x", URL: "https://lists.example/h"}}
		},
		"unnamed feed": func(t *DetectionTuning) {
			t.DomainIntelFeeds = []DomainIntelFeed{{URL: "https://lists.example/h", Confidence: 50}}
		},
		"repeated feed": func(t *DetectionTuning) {
			t.DomainIntelFeeds = []DomainIntelFeed{{Name: "x", URL: "https://a.example/h", Confidence: 50}, {Name: "X", URL: "https://b.example/h", Confidence: 50}}
		},
		"feed with a user": func(t *DetectionTuning) {
			t.DomainIntelFeeds = []DomainIntelFeed{{Name: "x", URL: "https://u:p@lists.example/h", Confidence: 50}}
		},
	} {
		bad := base
		edit(&bad)
		if _, err := PrepareDetectionTuning(bad); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
}
