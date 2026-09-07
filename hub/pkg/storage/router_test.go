package storage

import (
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// A lease is the strongest identity an unagented device emits. It has to arrive
// in the asset store, because that is where the rest of the product looks.
func TestRouterLeasesBecomeAssets(t *testing.T) {
	store := openStore(t, filepath.Join(t.TempDir(), "router.db"))
	now := time.Now().UTC()

	accepted, rejected, err := store.RecordRouterLeases("gw", []RouterLease{
		{MAC: "64:16:66:3b:b5:81", IP: "10.0.0.36", Hostname: "thermostat"},
		{MAC: "b8:d6:1a:2d:e6:0c", IP: "10.0.0.118", Hostname: "Emporia"},
	}, nil, now)
	if err != nil {
		t.Fatalf("recording leases: %v", err)
	}
	if accepted != 2 || rejected != 0 {
		t.Fatalf("expected both leases kept, got %d accepted %d rejected", accepted, rejected)
	}

	assets, err := store.ListAssets("")
	if err != nil {
		t.Fatalf("listing assets: %v", err)
	}
	found := map[string]string{}
	for _, a := range assets {
		found[a.IP] = a.Hostname
	}
	if found["10.0.0.36"] != "thermostat" {
		t.Fatalf("the thermostat's lease did not become an asset: %v", found)
	}
	if found["10.0.0.118"] != "Emporia" {
		t.Fatalf("the energy monitor's lease did not become an asset: %v", found)
	}
}

// The gateway is untrusted. Rubbish in one row must be dropped and counted, not
// stored under a guess and not allowed to abort the rows around it.
func TestRouterGarbageIsRejectedNotStored(t *testing.T) {
	store := openStore(t, filepath.Join(t.TempDir(), "router.db"))
	now := time.Now().UTC()

	accepted, rejected, err := store.RecordRouterLeases("gw", []RouterLease{
		{MAC: "not-a-mac", IP: "10.0.0.5", Hostname: "liar"},
		{MAC: "64:16:66:3b:b5:81", IP: "999.999.999.999", Hostname: "also-liar"},
		{MAC: "aa:bb:cc:dd:ee:ff", IP: "10.0.0.7", Hostname: "honest"},
	}, nil, now)
	if err != nil {
		t.Fatalf("recording: %v", err)
	}
	if accepted != 1 {
		t.Fatalf("only the valid lease should have been kept, got %d", accepted)
	}
	if rejected != 2 {
		t.Fatalf("both malformed leases should have been counted, got %d", rejected)
	}

	assets, _ := store.ListAssets("")
	for _, a := range assets {
		if a.Hostname == "liar" || a.Hostname == "also-liar" {
			t.Fatalf("a malformed lease was stored anyway: %+v", a)
		}
	}
}

// dnsmasq writes "*" when the client offered no name. That is an absence and
// must not be recorded as though the device called itself "*".
func TestRouterUnnamedLeaseGetsNoHostname(t *testing.T) {
	store := openStore(t, filepath.Join(t.TempDir(), "router.db"))
	if _, _, err := store.RecordRouterLeases("gw", []RouterLease{
		{MAC: "aa:bb:cc:dd:ee:01", IP: "10.0.0.9", Hostname: "*"},
	}, nil, time.Now().UTC()); err != nil {
		t.Fatalf("recording: %v", err)
	}
	assets, _ := store.ListAssets("")
	for _, a := range assets {
		if a.Hostname == "*" {
			t.Fatalf("the absence of a name was stored as a name: %+v", a)
		}
	}
}

// A hostname is chosen by whoever owns the device, so it is attacker-controlled.
// Control characters and unbounded length must not reach the database.
func TestRouterHostnameIsBounded(t *testing.T) {
	store := openStore(t, filepath.Join(t.TempDir(), "router.db"))
	evil := "bad\x00\x1bname" + strings.Repeat("A", 4000)
	if _, _, err := store.RecordRouterLeases("gw", []RouterLease{
		{MAC: "aa:bb:cc:dd:ee:02", IP: "10.0.0.10", Hostname: evil},
	}, nil, time.Now().UTC()); err != nil {
		t.Fatalf("recording: %v", err)
	}
	assets, _ := store.ListAssets("")
	for _, a := range assets {
		if a.IP != "10.0.0.10" {
			continue
		}
		if len(a.Hostname) > maxRouterFieldLen {
			t.Fatalf("hostname was not clamped: %d chars", len(a.Hostname))
		}
		if strings.ContainsAny(a.Hostname, "\x00\x1b") {
			t.Fatalf("control characters survived into the store: %q", a.Hostname)
		}
	}
}

// A poll larger than the cap is truncated rather than trusted, and the surplus
// is reported so an operator can see a gateway that has started shouting.
func TestRouterPollIsCapped(t *testing.T) {
	store := openStore(t, filepath.Join(t.TempDir(), "router.db"))
	flows := make([]RouterFlow, MaxRouterFlowsPerPoll+50)
	for i := range flows {
		flows[i] = RouterFlow{
			SrcIP: "10.0.0.2", DstIP: fmt.Sprintf("10.1.%d.%d", i/256, i%256),
			DstPort: 443, Protocol: "tcp", OrigBytes: 1, ReplyBytes: 1,
		}
	}
	accepted, rejected, err := store.RecordRouterFlows("gw", flows, time.Now().UTC())
	if err != nil {
		t.Fatalf("recording flows: %v", err)
	}
	if accepted > MaxRouterFlowsPerPoll {
		t.Fatalf("the cap did not hold: %d accepted", accepted)
	}
	if rejected < 50 {
		t.Fatalf("the surplus was not reported: %d rejected", rejected)
	}
}

// Conntrack counters are cumulative for a live flow. Re-reporting the same flow
// must not double count it - the bucket holds what that conversation moved, not
// the sum of every time we looked at it.
func TestRepeatedPollsDoNotDoubleCount(t *testing.T) {
	store := openStore(t, filepath.Join(t.TempDir(), "router.db"))
	now := time.Now().UTC()
	flow := RouterFlow{SrcIP: "10.0.0.36", DstIP: "10.9.9.9", DstPort: 443, Protocol: "tcp"}

	for _, bytes := range []int64{1000, 2500, 4000} {
		f := flow
		f.OrigBytes, f.ReplyBytes = bytes, bytes/2
		if _, _, err := store.RecordRouterFlows("gw", []RouterFlow{f}, now); err != nil {
			t.Fatalf("recording: %v", err)
		}
	}

	rows, err := store.ListRouterFlows(RouterFlowFilter{SrcIP: "10.0.0.36"})
	if err != nil {
		t.Fatalf("listing: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("one conversation should be one row, got %d", len(rows))
	}
	if rows[0].OrigBytes != 4000 {
		t.Fatalf("counters were summed instead of carried: got %d, want 4000", rows[0].OrigBytes)
	}
}

// When conntrack evicts an entry and a new flow reuses the tuple, the counter
// restarts. That earlier traffic was real and must be kept, not overwritten.
func TestRecycledTupleKeepsEarlierTraffic(t *testing.T) {
	store := openStore(t, filepath.Join(t.TempDir(), "router.db"))
	now := time.Now().UTC()
	flow := RouterFlow{SrcIP: "10.0.0.36", DstIP: "10.9.9.9", DstPort: 443, Protocol: "tcp"}

	f := flow
	f.OrigBytes = 5000
	if _, _, err := store.RecordRouterFlows("gw", []RouterFlow{f}, now); err != nil {
		t.Fatalf("first: %v", err)
	}
	// counter goes backwards: a new flow on the same tuple
	f.OrigBytes = 300
	if _, _, err := store.RecordRouterFlows("gw", []RouterFlow{f}, now); err != nil {
		t.Fatalf("second: %v", err)
	}

	rows, _ := store.ListRouterFlows(RouterFlowFilter{SrcIP: "10.0.0.36"})
	if len(rows) != 1 {
		t.Fatalf("expected one row, got %d", len(rows))
	}
	if rows[0].OrigBytes != 5300 {
		t.Fatalf("the earlier flow's traffic was lost: got %d, want 5300", rows[0].OrigBytes)
	}
}

// The whole point of the ingest: say which silent devices are talking, and to
// whom, ranked by how much they moved.
func TestTalkersRankUnagentedDevices(t *testing.T) {
	store := openStore(t, filepath.Join(t.TempDir(), "router.db"))
	now := time.Now().UTC()

	if _, _, err := store.RecordRouterFlows("gw", []RouterFlow{
		{SrcIP: "10.0.0.36", DstIP: "198.51.100.1", DstPort: 443, Protocol: "tcp", OrigBytes: 100},
		{SrcIP: "10.0.0.36", DstIP: "198.51.100.2", DstPort: 443, Protocol: "tcp", OrigBytes: 100},
		{SrcIP: "10.0.0.99", DstIP: "198.51.100.3", DstPort: 443, Protocol: "tcp", OrigBytes: 900000},
	}, now); err != nil {
		t.Fatalf("recording: %v", err)
	}

	talkers, err := store.SummariseRouterTalkers(now.Add(-time.Hour), 0)
	if err != nil {
		t.Fatalf("summarising: %v", err)
	}
	if len(talkers) != 2 {
		t.Fatalf("expected two talkers, got %d", len(talkers))
	}
	if talkers[0].IP != "10.0.0.99" {
		t.Fatalf("ranked by bytes should put the loud one first, got %s", talkers[0].IP)
	}
	for _, tk := range talkers {
		if tk.IP == "10.0.0.36" && tk.Conversations != 2 {
			t.Fatalf("expected two conversations for the quiet device, got %d", tk.Conversations)
		}
	}
}

// Retention applies here like every other telemetry table; a flow table nobody
// prunes is a disk-full incident waiting for a busy week.
func TestRouterFlowsArePruned(t *testing.T) {
	store := openStore(t, filepath.Join(t.TempDir(), "router.db"))
	old := time.Now().UTC().Add(-72 * time.Hour)
	if _, _, err := store.RecordRouterFlows("gw", []RouterFlow{
		{SrcIP: "10.0.0.5", DstIP: "10.9.9.9", DstPort: 443, Protocol: "tcp", OrigBytes: 1},
	}, old); err != nil {
		t.Fatalf("recording: %v", err)
	}
	n, err := store.PruneOldRouterFlows(24 * time.Hour)
	if err != nil {
		t.Fatalf("pruning: %v", err)
	}
	if n != 1 {
		t.Fatalf("expected the stale bucket to be pruned, removed %d", n)
	}
}
