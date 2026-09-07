package detector

import "testing"

func TestWindowCapacityEvictsLeastRecentlyUsedHistory(t *testing.T) {
	c := newWindowCache[*bandwidthStats](2)
	create := func() *bandwidthStats { return &bandwidthStats{} }
	original := c.get("a", create)
	original.observe(42)
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
	if replacement.count != 0 {
		t.Fatal("eviction invented replacement samples")
	}
	c.removeMatching(func(key string) bool { return key == "b" })
	if _, ok := c.entries["b"]; ok {
		t.Fatal("invalidated history retained")
	}
}
