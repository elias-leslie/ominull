package scripts

import (
	"testing"
	"time"
)

func TestWindow(t *testing.T) {
	for _, bad := range []string{"", "1:00-5:00", "01:00-01:00", "01:00-02:00,", "01:00-02:00,03:00-04:00,05:00-06:00,07:00-08:00,09:00-10:00", "25:00-01:00", "01:00-02:00ZZ"} {
		if CheckWindow(bad) == nil {
			t.Errorf("accepted %q", bad)
		}
	}
	w, err := ParseWindow("01:00-02:00,22:00-00:30Z")
	if err != nil || !w.UTC || len(w.Ranges) != 2 || w.Param() != "01:00-02:00,22:00-00:30Z" {
		t.Fatalf("%+v %v", w, err)
	}
	at := func(s string) time.Time { v, _ := time.Parse(time.RFC3339, s); return v }
	if in, known := w.Contains(at("2026-10-17T23:59:00Z"), nil); !in || !known {
		t.Fatal("UTC window across midnight")
	}
	if in, _ := w.Contains(at("2026-10-17T12:00:00Z"), nil); in {
		t.Fatal("noon is outside")
	}
	if ns, _ := w.NextStart(at("2026-10-17T12:00:00Z"), nil); !ns.Equal(at("2026-10-17T22:00:00Z")) {
		t.Fatalf("next start %v", ns)
	}
	m := Window{Ranges: []string{"01:00-05:00"}}
	if _, known := m.Contains(time.Now(), nil); known {
		t.Fatal("machine time without an offset is unknown")
	}
	off := -300 // UTC-5: 01:00 machine is 06:00 UTC
	if in, _ := m.Contains(at("2026-10-17T06:30:00Z"), &off); !in {
		t.Fatal("machine time with offset")
	}
	if ns, _ := m.NextStart(at("2026-10-17T12:00:00Z"), &off); !ns.Equal(at("2026-10-18T06:00:00Z")) {
		t.Fatalf("next machine start %v", ns)
	}
}
