package scanner

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
)

// A deliberately manual check against the real network. It is skipped unless
// OMINULL_LIVE_TARGETS names hosts, so it never runs in the ordinary suite.
func TestLiveFingerprint(t *testing.T) {
	targets := os.Getenv("OMINULL_LIVE_TARGETS")
	if targets == "" {
		t.Skip("set OMINULL_LIVE_TARGETS=ip,ip,... to probe the real network")
	}
	for _, ip := range strings.Split(targets, ",") {
		ip = strings.TrimSpace(ip)
		if ip == "" {
			continue
		}
		ttl := measureTTL(ip)
		extras := probeExtras(ip, "")
		banners := []string{}
		for _, port := range []int{22, 80, 443, 445, 3389, 5000, 8006, 9100, 9999, 5985} {
			if b := grabBanner(ip, port); b != "" {
				banners = append(banners, b)
			}
		}
		var ports []int
		for _, port := range []int{22, 80, 443, 445, 3389, 5000, 8006, 9100, 9999, 5985, 631, 5900} {
			if portOpen(ip, port) {
				ports = append(ports, port)
			}
		}
		id := IdentifyHost(macFor(ip), ttl, ports, banners, extras, 2.0, nil)
		fmt.Printf("\n=== %s\n  ttl        : %d\n  ports      : %v\n  identity   : %s\n  category   : %s\n  confidence : %.2f via %s\n",
			ip, ttl, ports, id.Name, id.Category, id.Confidence, id.Method)
		for _, e := range id.Evidence {
			fmt.Printf("  why        : %s\n", e)
		}
		for _, b := range banners {
			fmt.Printf("  banner     : %s\n", strings.TrimSpace(trimTo(b, 110)))
		}
		for _, e := range extras {
			fmt.Printf("  extra      : %s\n", trimTo(e, 160))
		}
	}
}

func portOpen(ip string, port int) bool {
	c, err := net.DialTimeout("tcp", net.JoinHostPort(ip, strconv.Itoa(port)), 500*time.Millisecond)
	if err != nil {
		return false
	}
	c.Close()
	return true
}

func grabBanner(ip string, port int) string {
	c, err := net.DialTimeout("tcp", net.JoinHostPort(ip, strconv.Itoa(port)), 500*time.Millisecond)
	if err != nil {
		return ""
	}
	defer c.Close()
	b, _ := probeBanner(c, port)
	return b
}

func macFor(ip string) string {
	if m := parseLocalARPTable()[ip]; m != "" {
		return m
	}
	return resolveMAC(ip)
}
