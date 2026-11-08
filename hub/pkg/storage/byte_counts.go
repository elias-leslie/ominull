package storage

import (
	"net"
)

// MaxByteCount is the largest byte count a telemetry sample may carry: 2^53-1,
// the last integer a JSON number holds exactly in the console. Anything above
// it is not a measurement. Windows ESTATS reads have returned pointer- and
// string-shaped values (up to 8.4e18), and a pair of those overflows every
// SUM over the flows: the traffic overview answered 500 and the cold segment
// export stopped at the first such day.
const MaxByteCount = 1<<53 - 1

// ByteCountValid reports whether a sample's byte count is a measurement.
func ByteCountValid(n int64) bool { return n >= 0 && n <= MaxByteCount }

// SampleRate is the transfer rate a timed sample claims: its larger byte
// count over its observation span (at least a second), in bytes per second.
// ok is false for a sample without a span, whose bytes are a batch total.
func SampleRate(ev Event) (rate float64, ok bool) {
	if ev.Observation.FirstAt == nil || ev.Observation.LastAt == nil {
		return 0, false
	}
	seconds := max(1, ev.Observation.LastAt.Sub(*ev.Observation.FirstAt).Seconds())
	return float64(max(ev.BytesIn, ev.BytesOut)) / seconds, true
}

// DropImplausibleRates makes unmeasured every timed sample that claims more
// than limit bytes per second: no link here carries it, so it is a counter
// fault (a Windows counter wrapping at 2^32, a negative delta read as
// unsigned, a pointer-shaped read), and stored it would poison the profiles,
// the hourly buckets and the detectors' baselines. The flow is kept. It
// returns the first such sample (with its bytes as reported) and how many.
func DropImplausibleRates(events []Event, limit float64) (first Event, rate float64, n int) {
	if limit <= 0 {
		return Event{}, 0, 0
	}
	for i := range events {
		if ip := net.ParseIP(events[i].DstIP); ip != nil && ip.IsLoopback() {
			// Loopback runs past any link's rate; it is not a counter glitch.
			continue
		}
		r, ok := SampleRate(events[i])
		if !ok || r <= limit {
			continue
		}
		if n == 0 {
			first, rate = events[i], r
		}
		n++
		events[i].BytesIn, events[i].BytesOut = 0, 0
	}
	return first, rate, n
}
