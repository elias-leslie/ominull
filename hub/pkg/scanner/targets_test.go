package scanner

import "testing"

// A /30 is four addresses and two usable hosts. The console reports the host
// count while a sweep runs, and it used to say 254 for every subnet.
func TestTheHostCountIsTheSubnetsOwn(t *testing.T) {
	for _, c := range []struct {
		subnet string
		want   int
	}{
		{"10.0.4.0/24", 254},
		{"10.0.4.0/29", 6},
		{"10.0.4.0/30", 2},
	} {
		if got := len(targetsFor(c.subnet)); got != c.want {
			t.Errorf("%s: probing %d addresses, expected %d", c.subnet, got, c.want)
		}
	}
}

// A subnet the operator typed wrong must not leave the sweep with nothing to
// divide progress by.
func TestAnUnparseableSubnetStillYieldsTargets(t *testing.T) {
	if n := len(targetsFor("192.168.7.")); n == 0 {
		t.Fatal("no targets for a bare prefix; progress would divide by zero")
	}
}

func TestIPv6TargetsKeepBoundaryAddresses(t *testing.T) {
	for _, tc := range []struct {
		target string
		count  int
	}{
		{"2001:db8::/126", 4}, {"2001:db8::/127", 2}, {"2001:db8::/128", 1}, {"2001:db8::9", 1},
	} {
		if got := len(targetsFor(tc.target)); got != tc.count {
			t.Errorf("%s: got %d want %d", tc.target, got, tc.count)
		}
	}
}
func TestInvalidTargetDoesNotInventIPv4Sweep(t *testing.T) {
	if got := targetsFor("invalid-target"); len(got) != 0 {
		t.Fatalf("invented %d targets", len(got))
	}
}
func TestIPv6ReverseName(t *testing.T) {
	want := "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa"
	if got := reverseARPAName("2001:db8::1"); got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestNeighborIdentityIsScopedAndValidated(t *testing.T) {
	neighbors, err := parseIPv6Neighbors([]byte(`[
 {"dst":"fe80::1","dev":"eth0","lladdr":"00:11:22:33:44:55","state":["STALE"]},
 {"dst":"fe80::1","dev":"eth1","lladdr":"00:11:22:33:44:66","state":["REACHABLE"]},
 {"dst":"2001:0db8::1","dev":"eth0","lladdr":"00:11:22:33:44:55","state":["REACHABLE"]},
 {"dst":"2001:db8::2","dev":"eth0","lladdr":"00:11:22:33:44:55","state":["FAILED"]},
 {"dst":"ff02::1","dev":"eth0","lladdr":"33:33:00:00:00:01","state":["PERMANENT"]}]`))
	if err != nil || len(neighbors) != 3 {
		t.Fatalf("neighbors: %+v %v", neighbors, err)
	}
	if neighbors["fe80::1%eth0"] == neighbors["fe80::1%eth1"] || neighbors["2001:db8::1"] == "" {
		t.Fatalf("scope/canonicalization lost: %v", neighbors)
	}
}
