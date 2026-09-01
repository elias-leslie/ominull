package storage

import (
	"path/filepath"
	"testing"
	"time"
)

func windowStore(t *testing.T) *Store {
	t.Helper()
	s, err := New(filepath.Join(t.TempDir(), "w.db"))
	if err != nil {
		t.Fatalf("opening a store: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func openWindow(t *testing.T, s *Store, w EnrolmentWindow, passcode string) EnrolmentWindow {
	t.Helper()
	if w.ExpiresAt.IsZero() {
		w.ExpiresAt = time.Now().UTC().Add(time.Hour)
	}
	got, err := s.CreateEnrolmentWindow(w, passcode)
	if err != nil {
		t.Fatalf("opening a window: %v", err)
	}
	return got
}

// A window authorises the networks it names and nothing else. This is the whole
// control: the portal is unauthenticated, so an address outside every open
// window must get nothing at all.
func TestAWindowOnlyCoversTheNetworksItNames(t *testing.T) {
	s := windowStore(t)
	openWindow(t, s, EnrolmentWindow{Label: "office", CIDRs: []string{"10.0.0.0/24"}}, "")

	if _, err := s.ClaimEnrolment("10.0.0.57", ""); err != nil {
		t.Fatalf("an address inside the window was refused: %v", err)
	}
	if _, err := s.ClaimEnrolment("10.0.9.57", ""); err == nil {
		t.Fatal("an address outside every window was allowed to enrol itself")
	}
	if _, err := s.ClaimEnrolment("not-an-address", ""); err == nil {
		t.Fatal("a request with an unparseable source address was allowed to enrol")
	}
}

// A bare address is read as one host, because that is what an operator
// authorising a single machine will type.
func TestABareAddressCoversThatHostAlone(t *testing.T) {
	s := windowStore(t)
	openWindow(t, s, EnrolmentWindow{CIDRs: []string{"10.0.0.57"}}, "")

	if _, err := s.ClaimEnrolment("10.0.0.57", ""); err != nil {
		t.Fatalf("the named host was refused: %v", err)
	}
	if _, err := s.ClaimEnrolment("10.0.0.58", ""); err == nil {
		t.Fatal("a bare address in a window covered its neighbour too")
	}
}

// The passcode is a second factor for a flat network, so a wrong one must not
// be distinguishable from no window at all in what it grants - and a right one
// must still be required after a wrong one.
func TestAPasscodeWindowRefusesTheWrongWordAndAcceptsTheRight(t *testing.T) {
	s := windowStore(t)
	openWindow(t, s, EnrolmentWindow{CIDRs: []string{"10.0.0.0/24"}}, "open-sesame")

	_, err := s.ClaimEnrolment("10.0.0.57", "")
	if err == nil {
		t.Fatal("a window with a passcode enrolled a machine that gave none")
	}
	var unavailable *EnrolmentWindowUnavailable
	if u, ok := err.(*EnrolmentWindowUnavailable); ok {
		unavailable = u
	}
	if unavailable == nil || !unavailable.NeedsPasscode {
		t.Fatalf("a covered machine with no passcode should be told to give one, got %v", err)
	}

	if _, err := s.ClaimEnrolment("10.0.0.57", "wrong"); err == nil {
		t.Fatal("the wrong passcode enrolled a machine")
	}
	if _, err := s.ClaimEnrolment("10.0.0.57", "open-sesame"); err != nil {
		t.Fatalf("the right passcode was refused: %v", err)
	}
}

// The budget is the bound on blast radius if a window is left open. It has to
// hold exactly, including against the request that would be one too many.
func TestAWindowStopsAtItsBudget(t *testing.T) {
	s := windowStore(t)
	openWindow(t, s, EnrolmentWindow{CIDRs: []string{"10.0.0.0/24"}, MaxUses: 2}, "")

	for i := 1; i <= 2; i++ {
		if _, err := s.ClaimEnrolment("10.0.0.57", ""); err != nil {
			t.Fatalf("enrolment %d of a 2-use window was refused: %v", i, err)
		}
	}
	if _, err := s.ClaimEnrolment("10.0.0.57", ""); err == nil {
		t.Fatal("a spent window kept enrolling")
	}

	windows, err := s.ListEnrolmentWindows()
	if err != nil || len(windows) != 1 {
		t.Fatalf("listing windows: %v (%d rows)", err, len(windows))
	}
	if windows[0].Used != 2 {
		t.Fatalf("a spent window should report 2 uses, reported %d", windows[0].Used)
	}
	if windows[0].State() != "spent" {
		t.Fatalf("a window at its budget should read as spent, read %q", windows[0].State())
	}
}

// Two machines asking at once must not both be served by a window with one use
// left. The claim is one statement for exactly this reason.
func TestTwoMachinesCannotBothSpendTheLastUse(t *testing.T) {
	s := windowStore(t)
	openWindow(t, s, EnrolmentWindow{CIDRs: []string{"10.0.0.0/24"}, MaxUses: 1}, "")

	results := make(chan error, 8)
	start := make(chan struct{})
	for i := 0; i < 8; i++ {
		go func() {
			<-start
			_, err := s.ClaimEnrolment("10.0.0.57", "")
			results <- err
		}()
	}
	close(start)

	granted := 0
	for i := 0; i < 8; i++ {
		if err := <-results; err == nil {
			granted++
		}
	}
	if granted != 1 {
		t.Fatalf("a 1-use window granted %d simultaneous enrolments; it must grant exactly 1", granted)
	}
}

// Expiry and revocation are the two ways a window closes, and both must take
// effect on the next request rather than at some sweep later.
func TestAWindowClosesWhenItExpiresOrIsRevoked(t *testing.T) {
	s := windowStore(t)

	past := openWindow(t, s, EnrolmentWindow{CIDRs: []string{"10.0.0.0/24"},
		ExpiresAt: time.Now().UTC().Add(-time.Minute)}, "")
	if _, err := s.ClaimEnrolment("10.0.0.57", ""); err == nil {
		t.Fatal("an expired window still enrolled a machine")
	}
	if past.State() != "expired" {
		t.Fatalf("an elapsed window should read as expired, read %q", past.State())
	}

	live := openWindow(t, s, EnrolmentWindow{CIDRs: []string{"10.0.0.0/24"}}, "")
	if err := s.RevokeEnrolmentWindow(live.ID); err != nil {
		t.Fatalf("revoking: %v", err)
	}
	if _, err := s.ClaimEnrolment("10.0.0.57", ""); err == nil {
		t.Fatal("a revoked window still enrolled a machine")
	}
	if err := s.RevokeEnrolmentWindow(live.ID); err == nil {
		t.Fatal("revoking an already-closed window reported success")
	}
}

// A window carries the tenant, location and role the enrolled host lands in, so
// a claim has to hand those back or the portal enrols into the wrong tenant.
func TestAClaimCarriesTheEnrolmentParameters(t *testing.T) {
	s := windowStore(t)
	openWindow(t, s, EnrolmentWindow{
		CIDRs: []string{"10.0.0.0/24"}, TenantID: "acme",
		LocationID: "loc-hq", Role: "laptop",
	}, "")

	got, err := s.ClaimEnrolment("10.0.0.57", "")
	if err != nil {
		t.Fatalf("claiming: %v", err)
	}
	if got.TenantID != "acme" || got.LocationID != "loc-hq" || got.Role != "laptop" {
		t.Fatalf("a claim lost the enrolment parameters: %+v", got)
	}
}

// A window with no networks authorises nothing, and must be refused at creation
// rather than stored as one that quietly matches nothing.
func TestAWindowMustNameANetworkAndAnExpiry(t *testing.T) {
	s := windowStore(t)
	if _, err := s.CreateEnrolmentWindow(EnrolmentWindow{
		CIDRs: []string{}, ExpiresAt: time.Now().Add(time.Hour)}, ""); err == nil {
		t.Fatal("a window covering no network was accepted")
	}
	if _, err := s.CreateEnrolmentWindow(EnrolmentWindow{
		CIDRs: []string{"10.0.0.0/24"}}, ""); err == nil {
		t.Fatal("a window with no expiry was accepted")
	}
	if _, err := s.CreateEnrolmentWindow(EnrolmentWindow{
		CIDRs: []string{"not a network"}, ExpiresAt: time.Now().Add(time.Hour)}, ""); err == nil {
		t.Fatal("a window with an unparseable network was accepted")
	}
}

// The passcode is never readable back out of the hub, only its presence.
func TestAPasscodeIsNotReadableBack(t *testing.T) {
	s := windowStore(t)
	openWindow(t, s, EnrolmentWindow{CIDRs: []string{"10.0.0.0/24"}}, "hunter2")

	windows, err := s.ListEnrolmentWindows()
	if err != nil || len(windows) != 1 {
		t.Fatalf("listing: %v", err)
	}
	if !windows[0].HasPasscode {
		t.Fatal("a window with a passcode did not report having one")
	}
	for _, cidr := range windows[0].CIDRs {
		if cidr == "hunter2" {
			t.Fatal("the passcode leaked into the listed window")
		}
	}
}

// Someone walking a building hits a spent budget mid-rollout. Telling them they
// are "not authorised" sends them looking for the wrong problem, so a window
// that named their network and has closed must say so.
func TestAClosedWindowSaysItClosedRatherThanUnauthorised(t *testing.T) {
	s := windowStore(t)
	openWindow(t, s, EnrolmentWindow{CIDRs: []string{"10.0.0.0/24"}, MaxUses: 1}, "")

	if _, err := s.ClaimEnrolment("10.0.0.57", ""); err != nil {
		t.Fatalf("the first enrolment was refused: %v", err)
	}

	_, err := s.ClaimEnrolment("10.0.0.57", "")
	u, ok := err.(*EnrolmentWindowUnavailable)
	if !ok {
		t.Fatalf("expected an unavailable answer, got %v", err)
	}
	if u.Closed != "spent" {
		t.Fatalf("a spent window should report itself spent, reported %q", u.Closed)
	}

	// An address no window ever named still learns nothing about what exists.
	_, err = s.ClaimEnrolment("10.0.9.57", "")
	u, ok = err.(*EnrolmentWindowUnavailable)
	if !ok || u.Closed != "" {
		t.Fatalf("an uncovered address was told about a window: %+v", u)
	}
}
