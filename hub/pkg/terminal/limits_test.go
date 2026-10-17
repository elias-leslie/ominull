package terminal

import (
	"strings"
	"testing"
	"time"
)

// A session asks for its own length, never past the hub's maximum; zero asks
// for the maximum. Applied limits reach the caps of new sessions.
func TestSessionLengthAndCapsFollowTheLimits(t *testing.T) {
	mgr := NewManager(nil, nil, 0, 0)
	defer mgr.Close()
	if got := mgr.Limits(); got != DefaultLimits() || got.MaxDuration != 4*time.Hour {
		t.Fatalf("defaults = %+v", got)
	}
	for _, tc := range []struct{ ask, want time.Duration }{
		{0, 4 * time.Hour}, {90 * time.Minute, 90 * time.Minute}, {9 * time.Hour, 4 * time.Hour}, {-time.Minute, 4 * time.Hour},
	} {
		ep := "ep-" + tc.ask.String()
		s, err := mgr.CreateSessionFor("t", ep, "op", "/bin/sh", newTestGrant("t", ep, "op"), tc.ask)
		if err != nil {
			t.Fatal(err)
		}
		if got := s.ExpiresAt.Sub(s.CreatedAt); got != tc.want {
			t.Errorf("asked %s, runs %s, want %s", tc.ask, got, tc.want)
		}
	}
	mgr.SetLimits(Limits{PerEndpoint: 1, IdleTimeout: 2 * time.Minute})
	if got := mgr.Limits(); got.PerEndpoint != 1 || got.IdleTimeout != 2*time.Minute || got.MaxDuration != 4*time.Hour {
		t.Fatalf("a partial SetLimits = %+v", got)
	}
	s, err := mgr.CreateSession("t", "ep-one", "op", "/bin/sh", newTestGrant("t", "ep-one", "op"))
	if err != nil {
		t.Fatal(err)
	}
	if s.IdleExpiresAt.Sub(s.CreatedAt) != 2*time.Minute {
		t.Fatal("a new session kept the old idle timeout")
	}
	if _, err := mgr.CreateSession("t", "ep-one", "op", "/bin/sh", nil); err == nil || !strings.Contains(err.Error(), "max 1 ") {
		t.Fatalf("per-endpoint cap of 1: %v", err)
	}
}

func TestLimitsValidateAgainstTheSafetyBounds(t *testing.T) {
	ok := DefaultLimits()
	if err := ok.Validate(); err != nil {
		t.Fatal(err)
	}
	for name, l := range map[string]Limits{
		"too long":          {25 * time.Hour, 15 * time.Minute, 3, 8},
		"too short":         {time.Minute, time.Minute, 3, 8},
		"idle past the max": {10 * time.Minute, 20 * time.Minute, 3, 8},
		"no idle":           {time.Hour, 0, 3, 8},
		"per endpoint 0":    {time.Hour, time.Minute, 0, 8},
		"tenant < endpoint": {time.Hour, time.Minute, 5, 4},
		"tenant too many":   {time.Hour, time.Minute, 3, 51},
		"seconds":           {time.Hour + time.Second, time.Minute, 3, 8},
	} {
		if l.Validate() == nil {
			t.Errorf("%s accepted", name)
		}
	}
}
