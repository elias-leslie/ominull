package storage

import (
	"errors"
	"path/filepath"
	"testing"
)

func operatorStore(t *testing.T) *Store {
	t.Helper()
	s, err := New(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("opening the store: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

// TestTheLastAdminIsProtectedFromEveryDirection. Demote or delete, it is the
// same hole: a console nobody can open, repairable only with a shell on the hub.
func TestTheLastAdminIsProtectedFromEveryDirection(t *testing.T) {
	s := operatorStore(t)

	if err := s.EnsureBootstrapAdmin("boss@example.com"); err != nil {
		t.Fatalf("seeding: %v", err)
	}
	if err := s.UpsertOperator("boss@example.com", "auditor", "boss@example.com"); !errors.Is(err, ErrLastAdmin) {
		t.Errorf("demoting the only administrator gave %v, want ErrLastAdmin", err)
	}
	if err := s.DeleteOperator("boss@example.com"); !errors.Is(err, ErrLastAdmin) {
		t.Errorf("deleting the only administrator gave %v, want ErrLastAdmin", err)
	}
	if role, ok := s.GetOperatorRole("boss@example.com"); !ok || role != "admin" {
		t.Errorf("the administrator is now %q/%v after two refused changes", role, ok)
	}
}

// TestTheBootstrapAdminNeverDemotesAnyone. The flag exists so a hub that nobody
// can sign in to can be repaired by restarting it. If it also overwrote roles,
// leaving it in a unit file would silently undo every change made in the console
// on the next restart.
func TestTheBootstrapAdminNeverDemotesAnyone(t *testing.T) {
	s := operatorStore(t)

	if err := s.EnsureBootstrapAdmin("boss@example.com"); err != nil {
		t.Fatalf("seeding: %v", err)
	}
	if err := s.UpsertOperator("boss@example.com", "admin", "boss@example.com"); err != nil {
		t.Fatalf("re-granting admin: %v", err)
	}
	if err := s.UpsertOperator("deputy@example.com", "analyst", "boss@example.com"); err != nil {
		t.Fatalf("granting the deputy: %v", err)
	}
	// A second run with a different address adds, and changes nothing else.
	if err := s.EnsureBootstrapAdmin("deputy@example.com"); err != nil {
		t.Fatalf("second bootstrap: %v", err)
	}
	if role, _ := s.GetOperatorRole("deputy@example.com"); role != "admin" {
		t.Errorf("the bootstrap address is %q, want admin", role)
	}
	// And running it again against someone who is already an admin is a no-op
	// rather than an error, because it runs on every start.
	if err := s.EnsureBootstrapAdmin("deputy@example.com"); err != nil {
		t.Errorf("a repeat bootstrap failed: %v", err)
	}
	if err := s.EnsureBootstrapAdmin(""); err != nil {
		t.Errorf("an unset bootstrap address should do nothing, got %v", err)
	}
}

func TestAnOperatorRoleMustBeOneTheHubImplements(t *testing.T) {
	s := operatorStore(t)

	if err := s.UpsertOperator("someone@example.com", "superuser", "test"); err == nil {
		t.Errorf("a role the hub does not implement was stored")
	}
	if err := s.UpsertOperator("not-an-address", "admin", "test"); err == nil {
		t.Errorf("an operator was stored without an email address")
	}
	// Addresses are matched case-insensitively: the identity provider decides
	// the capitalisation, and it is not the same decision every time.
	if err := s.UpsertOperator("Mixed.Case@Example.COM", "analyst", "test"); err != nil {
		t.Fatalf("granting: %v", err)
	}
	if role, ok := s.GetOperatorRole("mixed.case@example.com"); !ok || role != "analyst" {
		t.Errorf("a differently-capitalised address did not match: %q/%v", role, ok)
	}
}
