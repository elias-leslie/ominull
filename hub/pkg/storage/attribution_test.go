package storage

import (
	"fmt"
	"testing"
)

// The snapshot is what a hub with no internet resolves from. Losing it, or
// leaving it half-written, turns every named destination in the console back
// into a bare address - which reads to an operator as a fleet-wide change in
// behaviour rather than as a failed download.

func sampleAttribution(n int) []NetworkPrefixRow {
	rows := make([]NetworkPrefixRow, 0, n)
	for i := 0; i < n; i++ {
		rows = append(rows, NetworkPrefixRow{
			Prefix: fmt.Sprintf("198.51.%d.0/24", i%256),
			ASN:    "AS64496", Org: "Example", Tenancy: "vendor", Source: "test",
		})
	}
	return rows
}

func TestAnUndersizedSnapshotIsRefusedAndTheStoredOneSurvives(t *testing.T) {
	store := newTestStore(t)

	good := sampleAttribution(100)
	if err := store.ReplaceNetworkAttribution(good, "published feeds", 64); err != nil {
		t.Fatalf("storing the first snapshot: %v", err)
	}

	// A truncated fetch that yielded three prefixes must not become the table.
	if err := store.ReplaceNetworkAttribution(sampleAttribution(3), "published feeds", 64); err == nil {
		t.Fatal("expected an undersized snapshot to be refused")
	}

	kept, err := store.ListNetworkAttribution()
	if err != nil {
		t.Fatalf("reading the snapshot back: %v", err)
	}
	if len(kept) == 0 {
		t.Fatal("the refused write emptied the stored snapshot")
	}
	_, source, count, err := store.NetworkAttributionState()
	if err != nil {
		t.Fatalf("reading the snapshot state: %v", err)
	}
	if source != "published feeds" || count != len(good) {
		t.Fatalf("the state describes the refused write: source=%q count=%d", source, count)
	}
}

func TestAReplacementSnapshotDoesNotLeaveTheOldRangesBehind(t *testing.T) {
	store := newTestStore(t)

	first := sampleAttribution(80)
	if err := store.ReplaceNetworkAttribution(first, "published feeds", 64); err != nil {
		t.Fatalf("storing the first snapshot: %v", err)
	}

	second := make([]NetworkPrefixRow, 0, 70)
	for i := 0; i < 70; i++ {
		second = append(second, NetworkPrefixRow{
			Prefix: fmt.Sprintf("203.0.%d.0/24", i),
			ASN:    "AS64497", Org: "Replacement", Tenancy: "hosting", Source: "test",
		})
	}
	if err := store.ReplaceNetworkAttribution(second, "published feeds", 64); err != nil {
		t.Fatalf("storing the second snapshot: %v", err)
	}

	rows, err := store.ListNetworkAttribution()
	if err != nil {
		t.Fatalf("reading the snapshot back: %v", err)
	}
	if len(rows) != len(second) {
		t.Fatalf("expected exactly the new snapshot, got %d rows", len(rows))
	}
	for _, r := range rows {
		if r.Org != "Replacement" {
			t.Fatalf("a range from the previous snapshot survived: %+v", r)
		}
	}
}

func TestAHubThatHasNeverSyncedReadsAnEmptySnapshotNotAnError(t *testing.T) {
	store := newTestStore(t)

	rows, err := store.ListNetworkAttribution()
	if err != nil {
		t.Fatalf("reading an empty snapshot: %v", err)
	}
	if len(rows) != 0 {
		t.Fatalf("expected no stored ranges, got %d", len(rows))
	}
	refreshed, source, count, err := store.NetworkAttributionState()
	if err != nil {
		t.Fatalf("reading the state of an empty snapshot: %v", err)
	}
	if !refreshed.IsZero() || source != "" || count != 0 {
		t.Fatalf("expected a blank state, got %v %q %d", refreshed, source, count)
	}
}
