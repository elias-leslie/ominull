package storage

import (
	"path/filepath"
	"testing"
	"time"
)

// A new host that is not a server starts intermittent: a laptop's closed lid is
// not a finding. A server stays always-on, and a choice already made stands.
func TestDefaultPresenceAtEnrolment(t *testing.T) {
	store, err := New(filepath.Join(t.TempDir(), "presence.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	now := time.Now().UTC()
	for _, id := range []string{"laptop", "server", "parked"} {
		if err := store.UpsertEndpoint(Endpoint{ID: id, TenantID: "default", Hostname: id, LastSeenAt: now, CreatedAt: now}); err != nil {
			t.Fatal(err)
		}
	}
	if err := store.SetEndpointPresence("parked", PresenceParked); err != nil {
		t.Fatal(err)
	}
	for id, role := range map[string]string{"laptop": "workstation", "server": "server", "parked": "workstation"} {
		if err := store.DefaultPresenceAtEnrolment(id, role); err != nil {
			t.Fatal(err)
		}
	}
	list, err := store.ListEndpoints("")
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"laptop": PresenceIntermittent, "server": PresenceAlwaysOn, "parked": PresenceParked}
	for _, ep := range list {
		if ep.Presence != want[ep.ID] {
			t.Errorf("%s: presence %q, want %q", ep.ID, ep.Presence, want[ep.ID])
		}
	}
}
