package scanner

import (
	"testing"
	"time"

	"ominull/hub/pkg/storage"
)

func TestScanDoesNotInventHardwareAddress(t *testing.T) {
	store, err := storage.New(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.UpsertEndpoint(storage.Endpoint{ID: "local-test", IP: "127.0.0.2", Hostname: "local-test", Status: "online"}); err != nil {
		t.Fatal(err)
	}
	s := New(store)
	id, err := s.StartScan("127.0.0.2/32", ProfileStandard)
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(10 * time.Second)
	for {
		status, err := s.GetScanStatus(id)
		if err != nil {
			t.Fatal(err)
		}
		if status.Status == "completed" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("scan did not complete: %+v", status)
		}
		time.Sleep(10 * time.Millisecond)
	}
	assets := s.GetDiscoveredAssets()
	if len(assets) != 1 {
		t.Fatalf("expected one known test endpoint, got %d", len(assets))
	}
	if assets[0].MAC != "" {
		t.Errorf("invented hardware address %q", assets[0].MAC)
	}
}
