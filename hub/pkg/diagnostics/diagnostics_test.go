package diagnostics

import (
	"context"
	"testing"
	"time"
)

func TestRunnerReturnsStableBoundedResults(t *testing.T) {
	runner := Runner{Timeout: time.Second, Limit: 2, Checks: []Check{
		func(context.Context) Result { return Result{ID: "z", State: Pass} },
		func(context.Context) Result { return Result{ID: "a", State: Warn} },
	}}
	got := runner.Run(context.Background())
	if len(got) != 2 || got[0].ID != "a" || got[1].ID != "z" {
		t.Fatalf("results not stable: %+v", got)
	}
	if got[0].CheckedAt.IsZero() || HasFailure(got) {
		t.Fatalf("unexpected result metadata: %+v", got)
	}
}
