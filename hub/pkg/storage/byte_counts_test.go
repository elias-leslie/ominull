package storage

import (
	"testing"
	"time"
)

func TestByteCountValid(t *testing.T) {
	for n, want := range map[int64]bool{0: true, 1200: true, MaxByteCount: true, MaxByteCount + 1: false, -1: false, 1 << 40: true} {
		if got := ByteCountValid(n); got != want {
			t.Errorf("ByteCountValid(%d) = %v, want %v", n, got, want)
		}
	}
}

// Windows counter faults below MaxByteCount: a pointer-shaped read (1.4e14
// bytes in 193 s, live 2026-10-18) and an exact 2^32 wrap in a 2.7 s sample
// claim rates no link carries; a real 12 MB in 10 s does not. Ingest makes the
// first two unmeasured and keeps the flows.
func TestImplausibleRatesAreDroppedAtIngest(t *testing.T) {
	at := time.Date(2026, 10, 18, 1, 43, 0, 0, time.UTC)
	span := func(d time.Duration) FlowObservation {
		first, last := at, at.Add(d)
		return FlowObservation{FirstAt: &first, LastAt: &last}
	}
	events := []Event{
		{BytesIn: 148512329163520, BytesOut: 8589934787, Observation: span(193 * time.Second)},
		{BytesOut: 1 << 32, Observation: span(2700 * time.Millisecond)},
		{BytesOut: 12 << 20, Observation: span(10 * time.Second)},
		{BytesOut: 5 << 30}, // no span: a batch total, not a rate
	}
	limit := float64(DefaultDetectionTuning().MaxPlausibleRateMbps) * 125000
	first, rate, n := DropImplausibleRates(events, limit)
	if n != 2 || first.BytesIn != 148512329163520 || rate < 7e11 {
		t.Fatalf("dropped %d, first %+v at %.0f B/s", n, first, rate)
	}
	if events[0].BytesIn != 0 || events[0].BytesOut != 0 || events[1].BytesOut != 0 {
		t.Fatalf("faults kept their bytes: %+v %+v", events[0], events[1])
	}
	if events[2].BytesOut != 12<<20 || events[3].BytesOut != 5<<30 {
		t.Fatalf("real samples lost their bytes: %+v %+v", events[2], events[3])
	}
}
