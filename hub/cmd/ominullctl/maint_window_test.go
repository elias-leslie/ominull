package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func TestWindowChangeArguments(t *testing.T) {
	cases := []struct {
		args []string
		want string
		err  string
	}{
		{[]string{"set", "ep-1", "22:00-02:00,12:00-13:00", "--clock", "utc"}, `{"clock":"utc","endpoint_id":"ep-1","ranges":["22:00-02:00","12:00-13:00"]}`, ""},
		{[]string{"set", "--default", "01:00-05:00"}, `{"ranges":["01:00-05:00"]}`, ""},
		{[]string{"reset", "ep-1"}, `{"endpoint_id":"ep-1","reset":true}`, ""},
		{[]string{"reset", "--default"}, `{"reset":true}`, ""},
		{[]string{"set", "ep-1"}, "", "at least one range"},
		{[]string{"set", "01:00-02:00"}, "", "one machine or --default"},
		{[]string{"set", "ep-1", "--default", "01:00-02:00"}, "", "one machine or --default"},
		{[]string{"set", "ep-1", "01:00-02:00", "--clock", "local"}, "", "machine or utc"},
		{[]string{"reset", "ep-1", "01:00-02:00"}, "", "no ranges"},
	}
	for _, tc := range cases {
		body, _, err := windowChange(tc.args)
		if tc.err != "" {
			if err == nil || !strings.Contains(err.Error(), tc.err) {
				t.Errorf("%v: want error %q, got %v", tc.args, tc.err, err)
			}
			continue
		}
		got, _ := json.Marshal(body)
		if err != nil || string(got) != tc.want {
			t.Errorf("%v: got %s (%v), want %s", tc.args, got, err, tc.want)
		}
	}
}

func TestMaintWindowShowAndSet(t *testing.T) {
	var gotPut string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/maintenance/windows" {
			http.NotFound(w, r)
			return
		}
		if r.Method == http.MethodPut {
			b, _ := io.ReadAll(r.Body)
			gotPut = string(b)
			_, _ = w.Write([]byte(`{"endpoint_id":"ep-1","ranges":["22:00-02:00"],"clock":"utc","source":"endpoint","open_now":true,"changed":true}`))
			return
		}
		_, _ = w.Write([]byte(`{"default":{"ranges":["01:00-05:00"],"clock":"machine","source":"default"},"endpoints":{"ep-1":{"endpoint_id":"ep-1","ranges":["22:00-02:00"],"clock":"utc","source":"endpoint","open_now":false,"next_start":"2026-10-18T22:00:00Z"}}}`))
	}))
	defer ts.Close()
	c := newAPIClient(CLIConfig{HubURL: ts.URL})
	out := captureOut(t, func() error { return c.cmdMaint([]string{"window", "show"}) })
	if !strings.Contains(out, "fleet default: 01:00-05:00 machine time (shipped default)") || !strings.Contains(out, "ep-1: 22:00-02:00 UTC (its own), next opens") {
		t.Fatalf("show output:\n%s", out)
	}
	out = captureOut(t, func() error { return c.cmdMaint([]string{"window", "set", "ep-1", "22:00-02:00", "--clock=utc"}) })
	if !strings.Contains(gotPut, `"endpoint_id":"ep-1"`) || !strings.Contains(out, "ep-1: 22:00-02:00 UTC (its own), open now") {
		t.Fatalf("set sent %s, printed %s", gotPut, out)
	}
}

func captureOut(t *testing.T, fn func() error) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	old := os.Stdout
	os.Stdout = w
	runErr := fn()
	os.Stdout = old
	_ = w.Close()
	b, _ := io.ReadAll(r)
	if runErr != nil {
		t.Fatalf("command failed: %v\n%s", runErr, b)
	}
	return string(b)
}
