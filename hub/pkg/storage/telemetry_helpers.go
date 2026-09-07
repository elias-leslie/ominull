package storage

import (
	"fmt"
	"time"

	"ominull/hub/pkg/netaddr"
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
	case 6:
		return "TCP"
	case 17:
		return "UDP"
	case 1:
		return "ICMP"
	case 58:
		return "ICMPv6"
	default:
		return fmt.Sprintf("IP/%d", proto)
	}
}

// IsPrivateIPv4 is the compatibility name for non-public address classification.
// It supports both families and does not prove asset identity or membership.
func IsPrivateIPv4(ip string) bool {
	return netaddr.IsLocal(ip)
}

// canonicalAddress normalizes valid address fields without inventing a value
// for absent or legacy non-address fields. Ingress validation remains separate.
func canonicalAddress(raw string) string {
	if a, err := netaddr.Parse(raw); err == nil {
		return a.String()
	}
	return raw
}
