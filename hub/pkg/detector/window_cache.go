package detector

import "container/list"

// windowCache bounds histories across distinct peers/processes as well as
// within each history. Callers hold Engine.mu. Eviction discards a baseline;
// it never fabricates replacement samples or emits a finding.
type windowCache[T any] struct {
	entries   map[string]*list.Element
	order     *list.List
	capacity  int
	evictions uint64
}
type windowEntry[T any] struct {
	key   string
	value T
}

func newWindowCache[T any](capacity int) *windowCache[T] {
	return &windowCache[T]{entries: make(map[string]*list.Element), order: list.New(), capacity: capacity}
}
func (c *windowCache[T]) get(key string, create func() T) T {
	if entry, ok := c.entries[key]; ok {
		c.order.MoveToBack(entry)
		return entry.Value.(windowEntry[T]).value
	}
	if len(c.entries) >= c.capacity {
		c.remove(c.order.Front().Value.(windowEntry[T]).key)
		c.evictions++
	}
	value := create()
	c.entries[key] = c.order.PushBack(windowEntry[T]{key, value})
	return value
}
func (c *windowCache[T]) remove(key string) {
	if entry, ok := c.entries[key]; ok {
		c.order.Remove(entry)
		delete(c.entries, key)
	}
}
func (c *windowCache[T]) removeMatching(match func(string) bool) {
	for key := range c.entries {
		if match(key) {
			c.remove(key)
		}
	}
}
