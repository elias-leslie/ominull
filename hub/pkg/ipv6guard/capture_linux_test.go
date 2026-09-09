//go:build linux

package ipv6guard

import (
	"golang.org/x/sys/unix"
	"net"
	"os"
	"testing"
	"time"
)

func TestIsolatedPacketCapture(t *testing.T) {
	if os.Getenv("OMINULL_IPV6_CAPTURE_TEST") != "1" {
		t.Skip("run scripts/test-ipv6-monitor.sh for isolated packet capture")
	}
	current, _ := os.Readlink("/proc/self/ns/net")
	host, _ := os.Readlink("/proc/1/ns/net")
	if current == "" || current == host {
		t.Fatal("refusing packet injection outside an isolated network namespace")
	}
	observed := make(chan []Observation, 1)
	m := New(func(batch []Observation, _ Config) {
		select {
		case observed <- batch:
		default:
		}
	})
	defer m.Stop()
	if err := m.Configure(Config{Enabled: true, Interface: "om6-in", TenantID: "fixture"}); err != nil {
		t.Fatal(err)
	}
	peer, err := net.InterfaceByName("om6-out")
	if err != nil {
		t.Fatal(err)
	}
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, 0xdd86)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	if err := unix.Sendto(fd, routerAdvertisement(), 0, &unix.SockaddrLinklayer{Ifindex: peer.Index, Protocol: 0xdd86}); err != nil {
		t.Fatal(err)
	}
	select {
	case batch := <-observed:
		found := false
		for _, o := range batch {
			if o.Kind == "router_advertisement" && o.Source == "fe80::a%om6-in" {
				found = true
			}
		}
		if !found {
			t.Fatalf("capture lost injected RA: %+v", batch)
		}
	case <-time.After(8 * time.Second):
		t.Fatalf("no packet batch: %+v", m.Status())
	}
}
