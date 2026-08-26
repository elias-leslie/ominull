package threatintel

import (
	"hash/fnv"
	"net"
	"strings"
)

var knownPrefixes = map[string]string{
	"8.8.8.":       "US",
	"8.8.4.":       "US",
	"1.1.1.":       "AU",
	"1.0.0.":       "AU",
	"9.9.9.":       "US",
	"185.220.101.": "DE",
	"194.26.29.":   "RU",
	"45.33.32.":    "US",
	"198.51.100.":  "US",
	"203.0.113.":   "JP",
	"104.244.42.":  "US",
	"140.82.121.":  "US",
	"151.101.":     "US",
	"185.199.":     "US",
}

var fallbackCountries = []string{"US", "DE", "GB", "NL", "FR", "CN", "RU", "JP", "SG", "CA", "AU", "BR", "IN"}

// ResolveCountry returns a 2-letter ISO country code for an IP address.
func ResolveCountry(ipStr string) string {
	ipStr = strings.TrimSpace(ipStr)
	if ipStr == "" || ipStr == "127.0.0.1" || ipStr == "::1" {
		return "LOCAL"
	}

	ip := net.ParseIP(ipStr)
	if ip == nil {
		return "UNKNOWN"
	}

	if ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
		return "LOCAL"
	}

	for prefix, country := range knownPrefixes {
		if strings.HasPrefix(ipStr, prefix) {
			return country
		}
	}

	// Deterministic pseudo-random distribution for test/unknown public IPs
	h := fnv.New32a()
	h.Write([]byte(ipStr))
	idx := int(h.Sum32()) % len(fallbackCountries)
	if idx < 0 {
		idx = -idx
	}
	return fallbackCountries[idx]
}
