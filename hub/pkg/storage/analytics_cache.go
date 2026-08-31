package storage

import (
	"sync"
	"time"
)

// The analytics summary is the console's dashboard, and computing it means two
// unavoidable full passes over the events table - about 850ms on a 340k-row
// database through the pure-Go sqlite driver, all of it under the store's read
// lock. The console polls it. That is the shape of the outage this package
// already had: readers arriving faster than one finishes, a writer queued
// behind them, and everything after that waiting on a lock nobody is holding
// for a good reason.
//
// A dashboard total that is a few seconds old is still the answer to the
// question being asked, so the result is cached briefly and the scan happens at
// most once per interval however many operators are watching. It is not a
// correctness cache: nothing reads it to decide anything, and the freshest
// numbers on the page - isolation state, endpoint status - come from other
// routes that are not cached at all.
const analyticsCacheTTL = 15 * time.Second

type analyticsCache struct {
	mu      sync.Mutex
	entries map[string]analyticsEntry
}

type analyticsEntry struct {
	summary  *AnalyticsSummary
	computed time.Time
}

// get returns a private copy of a cached summary, or nil if there is none fresh.
// A copy, because the caller marshals it and callers are not obliged to treat a
// returned map as read-only; handing the same maps to two goroutines would be a
// data race the race detector would only find on a busy console.
func (c *analyticsCache) get(key string, now time.Time) *AnalyticsSummary {
	c.mu.Lock()
	defer c.mu.Unlock()
	entry, ok := c.entries[key]
	if !ok || now.Sub(entry.computed) > analyticsCacheTTL {
		return nil
	}
	return entry.summary.clone()
}

func (c *analyticsCache) put(key string, summary *AnalyticsSummary, now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.entries == nil {
		c.entries = make(map[string]analyticsEntry)
	}
	c.entries[key] = analyticsEntry{summary: summary.clone(), computed: now}
}

func (c *analyticsCache) invalidate(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.entries, key)
}

func (s *AnalyticsSummary) clone() *AnalyticsSummary {
	if s == nil {
		return nil
	}
	out := *s
	out.Countries = cloneStringCounts(s.Countries)
	out.TopProcesses = cloneStringCounts(s.TopProcesses)
	out.SeverityCounts = cloneStringCounts(s.SeverityCounts)
	out.EnforcementCounts = cloneStringCounts(s.EnforcementCounts)
	out.DiurnalBaseline = cloneHourCounts(s.DiurnalBaseline)
	out.DiurnalLive = cloneHourCounts(s.DiurnalLive)
	out.BandwidthTimeline = append([]BandwidthDataPoint(nil), s.BandwidthTimeline...)
	out.TopTalkers = append([]TopTalker(nil), s.TopTalkers...)
	out.GeoStats = append([]GeoCountryStat(nil), s.GeoStats...)
	return &out
}

func cloneStringCounts(in map[string]int64) map[string]int64 {
	if in == nil {
		return nil
	}
	out := make(map[string]int64, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func cloneHourCounts(in map[int]int64) map[int]int64 {
	if in == nil {
		return nil
	}
	out := make(map[int]int64, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}
