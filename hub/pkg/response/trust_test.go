package response

import "testing"

func TestProfileNarrows(t *testing.T) {
	for _, c := range []struct {
		from, to string
		want     bool
	}{
		{"engagement", "respond", true},
		{"engagement", "monitor-scripts", true},
		{"monitor-scripts", "monitor", true},
		{"respond", "monitor", true},
		{"respond", "monitor-scripts", false},
		{"monitor-scripts", "respond", false},
		{"monitor", "monitor-scripts", false},
		{"respond", "respond", false},
		{"respond", "bogus", false},
	} {
		if got := ProfileNarrows(c.from, c.to); got != c.want {
			t.Errorf("ProfileNarrows(%s, %s) = %v", c.from, c.to, got)
		}
	}
	if !MonitorOnlyProfile("monitor-scripts") || !MonitorOnlyProfile("monitor") || MonitorOnlyProfile("respond") || MonitorOnlyProfile("bogus") {
		t.Fatal("MonitorOnlyProfile")
	}
}
