package server

import (
	"sync"
	"time"
)

// Some reads are expensive and are polled.
//
// The topology graph groups every flow in the window by five columns - about
// 760ms for the default 24 hours on a 375k-row database, a second for seven
// days - and it holds the store's read lock for all of it. The console polls
// it. Repeating that per watcher, while agent writes arrive continuously, is
// how a reader queue forms behind a waiting writer, which is the failure this
// codebase has already had in production.
//
// The response is cached as the bytes that were sent rather than as the value
// they were built from: bytes cannot be mutated by one caller and read by
// another, so there is no copy to make and no race to reason about, and the
// re-encode is saved too. Nothing here is read to make a decision - it is a
// picture of the last day - so a few seconds of staleness is not a correctness
// question.
const responseCacheTTL = 15 * time.Second

type responseCache struct {
	mu      sync.Mutex
	entries map[string]responseEntry
}

type responseEntry struct {
	body     []byte
	computed time.Time
}

func (c *responseCache) get(key string, now time.Time) []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	entry, ok := c.entries[key]
	if !ok || now.Sub(entry.computed) > responseCacheTTL {
		return nil
	}
	return entry.body
}

func (c *responseCache) put(key string, body []byte, now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.entries == nil {
		c.entries = make(map[string]responseEntry)
	}
	c.entries[key] = responseEntry{body: body, computed: now}
}
