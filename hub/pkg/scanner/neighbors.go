package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"os/exec"
	"sort"
	"strings"
	"time"
)

// Neighbor identities come from the kernel, never from a fabricated MAC. A
// link-local address retains its interface zone so two links cannot collide.
func parseIPv6Neighbors(raw []byte) (map[string]string, error) {
	var rows []struct {
		Dst   string   `json:"dst"`
		Dev   string   `json:"dev"`
		MAC   string   `json:"lladdr"`
		State []string `json:"state"`
	}
	if err := json.Unmarshal(raw, &rows); err != nil {
		return nil, err
	}
	out := map[string]string{}
	for _, r := range rows {
		ip, err := netip.ParseAddr(r.Dst)
		if err != nil || !ip.Is6() || ip.Is4In6() || ip.IsMulticast() || ip.IsUnspecified() || ip.IsLoopback() {
			continue
		}
		valid := true
		for _, state := range r.State {
			if state == "FAILED" || state == "INCOMPLETE" {
				valid = false
			}
		}
		mac, err := net.ParseMAC(r.MAC)
		if !valid || err != nil || len(mac) != 6 || mac[0]&1 != 0 || r.MAC == "00:00:00:00:00:00" {
			continue
		}
		if ip.IsLinkLocalUnicast() {
			if r.Dev == "" {
				continue
			}
			ip = ip.WithZone(r.Dev)
		}
		out[ip.String()] = strings.ToUpper(mac.String())
	}
	return out, nil
}

func readIPv6Neighbors() (map[string]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	raw, err := exec.CommandContext(ctx, "ip", "-j", "-6", "neigh", "show").Output()
	if err != nil {
		return nil, fmt.Errorf("read IPv6 neighbor cache: %w", err)
	}
	return parseIPv6Neighbors(raw)
}

func discoverIPv6Targets(raw string, active bool) ([]string, error) {
	prefix, err := netip.ParsePrefix(raw)
	if err != nil || !prefix.Addr().Is6() || prefix.Addr().Is4In6() {
		return nil, fmt.Errorf("invalid discovery target %q", raw)
	}
	if prefix.Addr().IsMulticast() || prefix.Addr().IsUnspecified() {
		return nil, fmt.Errorf("select a directly connected unicast IPv6 prefix")
	}
	if active {
		interfaces, err := net.Interfaces()
		if err != nil {
			return nil, err
		}
		for _, iface := range interfaces {
			if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
				continue
			}
			addrs, err := iface.Addrs()
			if err != nil {
				continue
			}
			connected := false
			for _, a := range addrs {
				p, e := netip.ParsePrefix(a.String())
				if e == nil && prefix.Contains(p.Addr()) {
					connected = true
				}
			}
			if !connected {
				continue
			}
			// Exactly one scoped echo; a /64 is never expanded into addresses.
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			_ = exec.CommandContext(ctx, "ping", "-6", "-c", "1", "-w", "1", "ff02::1%"+iface.Name).Run()
			cancel()
		}
	}
	neighbors, err := readIPv6Neighbors()
	if err != nil {
		return nil, err
	}
	var targets []string
	for raw := range neighbors {
		ip, _ := netip.ParseAddr(raw)
		if prefix.Contains(ip.WithZone("")) {
			targets = append(targets, raw)
		}
	}
	sort.Strings(targets)
	if len(targets) > 65536 {
		return nil, fmt.Errorf("neighbor set exceeds 65536 targets; select a narrower observed scope")
	}
	return targets, nil
}
