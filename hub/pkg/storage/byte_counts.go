package storage

import (
	"fmt"
	"log"
	"time"
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

const byteCountRepairSetting = "byte_count_repair_v1"

// badBytes matches a stored count that is not a measurement: out of range, or
// a REAL left by an integer overflow in SQLite's addition.
const badBytes = `(typeof(%[1]s) != 'integer' OR %[1]s < 0 OR %[1]s > %[2]d)`

// repairByteCounts clears, once, the byte counts stored before ingest refused
// them: the flow sample becomes unmeasured, and the profile, bandwidth,
// loopback and agent egress rows the garbage was added into lose their byte
// totals (the real share of them cannot be told apart).
func (s *Store) repairByteCounts() error {
	if done, err := s.GetSetting(byteCountRepairSetting); err != nil || done != "" {
		return err
	}
	bad := func(a, b string) string {
		return fmt.Sprintf(badBytes, a, MaxByteCount) + " OR " + fmt.Sprintf(badBytes, b, MaxByteCount)
	}
	var total int64
	for _, stmt := range []string{
		`UPDATE flows SET bytes_in = 0, bytes_out = 0, measured = 0 WHERE ` + bad("bytes_in", "bytes_out"),
		`UPDATE comm_profiles SET total_bytes_in = 0, total_bytes_out = 0 WHERE ` + bad("total_bytes_in", "total_bytes_out"),
		`UPDATE bandwidth_buckets SET bytes_in = 0, bytes_out = 0, measured_count = 0 WHERE ` + bad("bytes_in", "bytes_out"),
		`UPDATE flow_local_hourly SET bytes_in = 0, bytes_out = 0 WHERE ` + bad("bytes_in", "bytes_out"),
		`UPDATE agent_egress_hourly SET bytes_out = 0 WHERE ` + fmt.Sprintf(badBytes, "bytes_out", MaxByteCount),
		`UPDATE agent_egress_destinations SET bytes_out = 0 WHERE ` + fmt.Sprintf(badBytes, "bytes_out", MaxByteCount),
	} {
		n, err := s.execBatch(stmt, nil)
		if err != nil {
			return fmt.Errorf("repair byte counts: %w", err)
		}
		total += n
	}
	if total > 0 {
		log.Printf("[*] Cleared %d stored byte counts that were not measurements", total)
	}
	return s.SetSetting(byteCountRepairSetting, time.Now().UTC().Format(time.RFC3339))
}

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

const rateRepairSetting = "byte_rate_repair_v1"

// implausibleTotal is a stored total no device here sends: 2^46 bytes (70
// TB). The Windows counter faults stored before ingest refused them are
// pointer-shaped, about 1.4e14 bytes each, below MaxByteCount but far above
// this.
const implausibleTotal = 1 << 46

// repairImplausibleRates clears, once, what the counter faults stored before
// ingest refused them by rate (DropImplausibleRates): flow samples whose
// rate is past the shipped max_plausible_rate_mbps become unmeasured, and the
// hourly buckets past that rate for a whole hour, and the profile and agent
// totals past implausibleTotal, lose their byte counts.
func (s *Store) repairImplausibleRates() error {
	if done, err := s.GetSetting(rateRepairSetting); err != nil || done != "" {
		return err
	}
	limit := float64(DefaultDetectionTuning().MaxPlausibleRateMbps) * 125000
	hour := limit * 3600
	var total int64
	for _, q := range []struct {
		stmt string
		args []any
	}{
		{`UPDATE flows SET bytes_in = 0, bytes_out = 0, measured = 0 WHERE first_at IS NOT NULL AND last_at IS NOT NULL
			AND MAX(bytes_in, bytes_out) * 1.0 / MAX(1.0, (last_at - first_at) / 1e9) > ?`, []any{limit}},
		{`UPDATE bandwidth_buckets SET bytes_in = 0, bytes_out = 0, measured_count = 0 WHERE MAX(bytes_in, bytes_out) > ?`, []any{hour}},
		{`UPDATE flow_local_hourly SET bytes_in = 0, bytes_out = 0 WHERE MAX(bytes_in, bytes_out) > ?`, []any{hour}},
		{`UPDATE comm_profiles SET total_bytes_in = 0, total_bytes_out = 0 WHERE MAX(total_bytes_in, total_bytes_out) > ?`, []any{implausibleTotal}},
		{`UPDATE agent_egress_hourly SET bytes_out = 0 WHERE bytes_out > ?`, []any{hour}},
		{`UPDATE agent_egress_destinations SET bytes_out = 0 WHERE bytes_out > ?`, []any{implausibleTotal}},
	} {
		n, err := s.execBatch(q.stmt, q.args)
		if err != nil {
			return fmt.Errorf("repair implausible rates: %w", err)
		}
		total += n
	}
	if total > 0 {
		log.Printf("[*] Cleared %d stored byte counts from sensor counter faults (rates no link carries)", total)
	}
	return s.SetSetting(rateRepairSetting, time.Now().UTC().Format(time.RFC3339))
}
