//go:build linux

package scanner

import (
	"os"
	"testing"
)

func TestIsolatedKernelNeighborDiscovery(t *testing.T) {
	if os.Getenv("OMINULL_IPV6_CAPTURE_TEST") != "1" {
		t.Skip("isolated namespace fixture only")
	}
	current, _ := os.Readlink("/proc/self/ns/net")
	host, _ := os.Readlink("/proc/1/ns/net")
	if current == "" || current == host {
		t.Fatal("isolated namespace required")
	}
	rows, err := readIPv6Neighbors()
	if err != nil {
		t.Fatal(err)
	}
	if rows["2001:db8:1::2"] != "02:00:00:00:00:02" {
		t.Fatalf("kernel NDP not ingested: %+v", rows)
	}
	targets, err := discoverIPv6Targets("2001:db8:1::/64", true)
	if err != nil {
		t.Fatal(err)
	}
	if len(targets) != 1 || targets[0] != "2001:db8:1::2" {
		t.Fatalf("wide discovery invented addresses: %+v", targets)
	}
	if len(targetsFor("2001:db8:1::/64")) != 0 {
		t.Fatal("wide prefix enumerated")
	}
}
