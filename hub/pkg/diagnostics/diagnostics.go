// Package diagnostics supplies bounded, reusable health checks for first-run
// setup and the operator status page.
package diagnostics

import (
	"context"
	"sort"
	"sync"
	"time"
)

type State string

const (
	Pass          State = "pass"
	Fail          State = "fail"
	Warn          State = "warn"
	NotConfigured State = "not_configured"
)

type Result struct {
	ID          string    `json:"id"`
	Title       string    `json:"title"`
	State       State     `json:"state"`
	Summary     string    `json:"summary"`
	Evidence    string    `json:"evidence,omitempty"`
	Remediation string    `json:"remediation,omitempty"`
	CheckedAt   time.Time `json:"checked_at"`
}

type Check func(context.Context) Result

type Runner struct {
	Timeout time.Duration
	Limit   int
	Checks  []Check
}

func (r Runner) Run(ctx context.Context) []Result {
	timeout := r.Timeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	limit := r.Limit
	if limit <= 0 {
		limit = 4
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	out := make([]Result, len(r.Checks))
	sem := make(chan struct{}, limit)
	var wg sync.WaitGroup
	for i, check := range r.Checks {
		if check == nil {
			continue
		}
		wg.Add(1)
		go func(i int, check Check) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				out[i] = Result{State: Fail, Summary: "diagnostic did not start before the time limit", CheckedAt: time.Now().UTC()}
				return
			}
			defer func() { <-sem }()
			result := check(ctx)
			if result.CheckedAt.IsZero() {
				result.CheckedAt = time.Now().UTC()
			}
			out[i] = result
		}(i, check)
	}
	wg.Wait()
	sort.SliceStable(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func HasFailure(results []Result) bool {
	for _, result := range results {
		if result.State == Fail {
			return true
		}
	}
	return false
}
