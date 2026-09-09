package ipv6guard

import (
	"testing"
	"time"
)

func TestObservationDoesNotApproveItsOwnInfrastructure(t *testing.T) {
	o, _ := ParseFrame(routerAdvertisement(), "eth0", time.Now())
	if got := Violations(o, Config{}); len(got) != 0 {
		t.Fatal("an unset policy asserted an attacker", got)
	}
	cfg := Config{Routers: []Peer{{IP: "fe80::b", MAC: "02:00:00:00:00:02"}}, Prefixes: []string{"2001:db8:2::/64"}, DNS: []string{"2001:db8::54"}}
	if got := Violations(o, cfg); len(got) != 3 {
		t.Fatalf("missing source/prefix/DNS violations: %v", got)
	}
	cfg = Config{Routers: []Peer{{IP: "fe80::a", MAC: o.MAC}}, Prefixes: o.Prefixes, DNS: o.DNS}
	if got := Violations(o, cfg); len(got) != 0 {
		t.Fatalf("approved infrastructure flagged: %v", got)
	}
}
func TestPacketAggregationIsBoundedAndReportsLoss(t *testing.T) {
	m := New(nil)
	now := time.Now()
	for i := 0; i < 1025; i++ {
		frame := routerAdvertisement()
		frame[10] = byte(i >> 8)
		frame[11] = byte(i)
		m.Observe(frame, "eth0", now)
	}
	if status := m.Status(); status.Observations != 1025 || status.Dropped != 1 || len(m.pending) != 1024 {
		t.Fatalf("unbounded or unreported loss: %+v", status)
	}
}
