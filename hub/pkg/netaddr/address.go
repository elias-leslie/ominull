// Package netaddr defines address semantics shared by ingestion and analysis.
package netaddr

import (
	"net/netip"
	"strings"
)

var sharedSpace = netip.MustParsePrefix("100.64.0.0/10")

// Parse canonicalizes mapped IPv4 while retaining an IPv6 interface zone.
func Parse(raw string) (netip.Addr, error) {
	a, err := netip.ParseAddr(strings.TrimSpace(raw))
	if err != nil {
		return netip.Addr{}, err
	}
	return a.Unmap(), nil
}

// IsLocal reports non-public address space, not proof of estate membership.
func IsLocal(raw string) bool {
	a, err := Parse(raw)
	return err == nil && (a.IsPrivate() || a.IsLoopback() || a.IsLinkLocalUnicast() || a.IsMulticast() || a.IsUnspecified() || sharedSpace.Contains(a))
}

func IsLoopback(raw string) bool {
	a, err := Parse(raw)
	return err == nil && a.IsLoopback()
}

func Scope(raw string) string {
	a, err := Parse(raw)
	if err != nil {
		return "invalid"
	}
	switch {
	case a.IsUnspecified():
		return "unspecified"
	case a.IsLoopback():
		return "loopback"
	case a.IsMulticast():
		return "multicast"
	case a.IsLinkLocalUnicast():
		return "link-local"
	case a.IsPrivate():
		return "private"
	case sharedSpace.Contains(a):
		return "shared"
	default:
		return "public"
	}
}
