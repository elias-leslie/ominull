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
