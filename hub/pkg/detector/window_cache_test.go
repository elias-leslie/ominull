package detector

import "testing"

func TestWindowCapacityEvictsLeastRecentlyUsedHistory(t *testing.T) {
	type history struct{ n int }
	c := newWindowCache[*history](2)
	create := func() *history { return &history{} }
	original := c.get("a", create)
	original.n = 42
	c.get("b", create)
	c.get("a", create)
	c.get("c", create)
	if len(c.entries) != 2 || c.evictions != 1 {
		t.Fatalf("unbounded histories: %+v", c)
	}
	if _, ok := c.entries["b"]; ok {
		t.Fatal("evicted active history instead of least recently used")
	}
	if c.get("a", create) != original {
		t.Fatal("active baseline replaced")
	}
	replacement := c.get("b", create)
	if replacement.n != 0 {
		t.Fatal("eviction invented replacement samples")
	}
	c.removeMatching(func(key string) bool { return key == "b" })
	if _, ok := c.entries["b"]; ok {
		t.Fatal("invalidated history retained")
	}
}
