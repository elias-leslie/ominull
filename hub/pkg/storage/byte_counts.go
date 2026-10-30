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
