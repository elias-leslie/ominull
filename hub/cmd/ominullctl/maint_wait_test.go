package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// The hub holds a wait request open longer than the ordinary client timeout;
// the wait must outlast it on the first request rather than cutting every
// quiet poll short and giving up after a few minutes of no news.
func TestMaintWaitOutlastsClientTimeout(t *testing.T) {
	old := waitPollSeconds
	waitPollSeconds = 1
	defer func() { waitPollSeconds = old }()
	var calls atomic.Int32
	hub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.URL.Query().Get("wait") != "1" {
			t.Errorf("wait param: %s", r.URL.RawQuery)
		}
		time.Sleep(1200 * time.Millisecond) // the hub's hold, past the client's base timeout
		_, _ = w.Write([]byte(`{"entries":[{"id":"job-1","job_id":"job-1","endpoint_id":"ep-1","package":"windows-audit","state":"succeeded","final":true}],"any_final":true,"all_final":true}`))
	}))
	defer hub.Close()
	c := newAPIClient(CLIConfig{HubURL: hub.URL, APIKey: "test"})
	c.httpClient.Timeout = 500 * time.Millisecond
	out := captureOut(t, func() error { return c.waitRuns([]string{"job-1"}, true, time.Minute) })
	if calls.Load() != 1 || !strings.Contains(out, "succeeded") {
		t.Fatalf("calls %d, out %q", calls.Load(), out)
	}
	if c.httpClient.Timeout != 500*time.Millisecond {
		t.Fatal("the shared client's timeout must not change")
	}
}
