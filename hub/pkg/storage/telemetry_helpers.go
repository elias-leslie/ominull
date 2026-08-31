package storage

import (
	"strconv"
	"strings"
	"time"
)

// scanTime handles the values returned by SQLite aggregate functions over a
// DATETIME column. Aggregates return stored text rather than the driver's
// time.Time representation.
func scanTime(value interface{}) time.Time {
	switch typed := value.(type) {
	case time.Time:
		return typed.UTC()
	case string:
		return parseStoredTime(typed)
	case []byte:
		return parseStoredTime(string(typed))
	case int64:
		return time.Unix(typed, 0).UTC()
	default:
		return time.Time{}
	}
}

func parseStoredTime(value string) time.Time {
	for _, layout := range []string{
		"2006-01-02 15:04:05.999999999 -0700 MST",
		time.RFC3339Nano,
		"2006-01-02 15:04:05.999999999-07:00",
		"2006-01-02 15:04:05",
	} {
		if parsed, err := time.Parse(layout, value); err == nil {
			return parsed.UTC()
		}
	}
	return time.Time{}
}

func protoName(proto int) string {
	switch proto {
	case 17:
		return "UDP"
	case 1:
		return "ICMP"
	default:
		return "TCP"
	}
}

// IsPrivateIPv4 reports RFC1918 address space for topology grouping. It does
// not identify or infer an endpoint; unmanaged addresses remain flow-only
// nodes until an independent scanner or agent supplies identity.
func IsPrivateIPv4(ip string) bool {
	parts := strings.Split(ip, ".")
	if len(parts) != 4 {
		return false
	}
	values := make([]int, 4)
	for i, part := range parts {
		value, err := strconv.Atoi(part)
		if err != nil || value < 0 || value > 255 {
			return false
		}
		values[i] = value
	}
	return values[0] == 10 ||
		(values[0] == 172 && values[1] >= 16 && values[1] <= 31) ||
		(values[0] == 192 && values[1] == 168)
}
