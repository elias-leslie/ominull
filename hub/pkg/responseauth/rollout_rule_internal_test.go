package responseauth

import (
	"testing"
	"time"
)

func TestRolloutRuleIdleExpiry(t *testing.T) {
	now := time.Now()
	made := now.Add(-100 * 24 * time.Hour).Unix()
	if ruleLive(&RolloutRule{Created: made}, now) {
		t.Fatal("a rule unused for 100 days should have ended")
	}
	if !ruleLive(&RolloutRule{Created: made, LastUsed: now.Add(-89 * 24 * time.Hour).Unix()}, now) {
		t.Fatal("a rule used 89 days ago should still live (90 days from last use)")
	}
	b := newRolloutRules(t.TempDir())
	if err := b.create(&RolloutRule{TenantID: "default", Created: made}); err != nil {
		t.Fatal(err)
	}
	if _, ok := b.use("default", "1.8.72", now); ok {
		t.Fatal("an idle-expired rule approved a rollout")
	}
}

func TestRolloutRuleSpikeFlag(t *testing.T) {
	now := time.Now()
	day := func(n int) string { return now.Add(-time.Duration(n) * 24 * time.Hour).UTC().Format("2006-01-02") }
	r := &RolloutRule{Created: now.Add(-60 * 24 * time.Hour).Unix(), Days: map[string]int{day(0): 3, day(1): 2, day(10): 1}}
	if week, spike := ruleWeek(r, now); week != 5 || !spike {
		t.Fatalf("5 rollouts this week against about one a month should be flagged: %d %v", week, spike)
	}
	r.Days = map[string]int{day(0): 1, day(9): 1}
	if _, spike := ruleWeek(r, now); spike {
		t.Fatal("one rollout this week is not a busy week")
	}
}

func TestRolloutRuleCountsOnlyNewerReleases(t *testing.T) {
	now := time.Now()
	b := newRolloutRules(t.TempDir())
	made := now.Add(-10 * 24 * time.Hour).Unix()
	if err := b.create(&RolloutRule{TenantID: "default", Created: made, Version: "1.8.72"}); err != nil {
		t.Fatal(err)
	}
	if _, ok := b.use("default", "1.8.71", now); ok {
		t.Fatal("an older release than the rule approved was covered")
	}
	if r, ok := b.use("default", "1.8.72", now); !ok || r.LastUsed != 0 {
		t.Fatalf("the same release again should be approved without extending the rule: %v %+v", ok, r)
	}
	if r, ok := b.use("default", "1.8.73", now); !ok || r.LastUsed != now.Unix() || r.Version != "1.8.73" {
		t.Fatalf("a newer release should count as use: %v %+v", ok, r)
	}
	if compareRelease("1.10.0", "1.9.9") != 1 || compareRelease("", "1.0.0") != -1 {
		t.Fatal("release ordering is wrong")
	}
}
