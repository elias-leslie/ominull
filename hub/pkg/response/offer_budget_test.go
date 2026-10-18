package response

import (
	"database/sql"
	"strings"
	"testing"
	"time"
)

func offerStore(t *testing.T) *Store {
	t.Helper()
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	store, err := NewStore(db)
	if err != nil {
		t.Fatal(err)
	}
	return store
}

func offerJob(t *testing.T, store *Store, payload string) *JobRecord {
	t.Helper()
	now := time.Now()
	grant := &EndpointGrant{Version: GrantVersion, GrantID: "g-" + time.Now().Format("150405.000000000"), TenantID: "t", EndpointID: "ep",
		ActionKind: ActionKindScriptExec, OperatorID: "op", IssuedAt: now.Unix(), ExpiresAt: now.Add(time.Hour).Unix()}
	job, err := store.CreateJob("t", "ep", ActionKindScriptExec, "op", grant, payload, "")
	if err != nil {
		t.Fatal(err)
	}
	return job
}

// Offers are packed by size so a heartbeat reply never carries more than the
// agent reads; the oldest job always goes, even alone over the budget.
func TestOfferBytesBudget(t *testing.T) {
	store := offerStore(t)
	big := `{"source":"` + strings.Repeat("x", 100<<10) + `"}`
	for i := 0; i < 4; i++ {
		offerJob(t, store, big)
	}
	offers, err := store.OfferPendingJobs("t", "ep", 4, time.Minute)
	if err != nil || len(offers) != 2 {
		t.Fatalf("two 100 KiB jobs fit a reply, not more: %v %d", err, len(offers))
	}
	huge := offerStore(t)
	offerJob(t, huge, `{"source":"`+strings.Repeat("x", 300<<10)+`"}`)
	offerJob(t, huge, `{}`)
	if offers, err := huge.OfferPendingJobs("t", "ep", 4, time.Minute); err != nil || len(offers) != 1 {
		t.Fatalf("the oldest job goes alone even over the budget: %v %d", err, len(offers))
	}
}

// A job the agent never takes fails with a reason after offerAttemptsMax
// offers instead of being offered forever.
func TestOfferNeverTaken(t *testing.T) {
	store := offerStore(t)
	job := offerJob(t, store, `{}`)
	for i := 0; i < offerAttemptsMax; i++ {
		if offers, err := store.OfferPendingJobs("t", "ep", 4, time.Nanosecond); err != nil || len(offers) != 1 {
			t.Fatalf("offer %d: %v %d", i+1, err, len(offers))
		}
		time.Sleep(time.Millisecond)
	}
	if offers, err := store.OfferPendingJobs("t", "ep", 4, time.Nanosecond); err != nil || len(offers) != 0 {
		t.Fatalf("offered past the cap: %v %d", err, len(offers))
	}
	got, err := store.GetJob("t", job.ID)
	if err != nil || got.State != StateFailed || got.ErrorCode != ErrNeverTaken {
		t.Fatalf("never-taken job: %v %+v", err, got)
	}
}
