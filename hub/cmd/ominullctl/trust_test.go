package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"ominull/hub/pkg/trustfabric"
)

func TestTrustRuleFromArgs(t *testing.T) {
	now := time.Date(2026, 11, 8, 12, 0, 0, 0, time.UTC)
	rule, err := trustRuleFromArgs(strings.Fields("allow 10.0.0.5 --scope endpoint:ep-1 --port 443 --proto tcp --direction out --locked --expires 2h --reason backup"), now)
	if err != nil {
		t.Fatal(err)
	}
	if rule.Kind != trustfabric.KindIP || rule.ScopeType != "endpoint" || rule.ScopeID != "ep-1" || rule.Port != 443 || rule.Proto != "tcp" ||
		rule.Direction != "out" || !rule.Locked || rule.Justification != "backup" || !rule.ExpiresAt.Equal(now.Add(2*time.Hour)) {
		t.Fatalf("rule: %+v", rule)
	}
	// What the command builds is what the hub would store.
	for _, args := range []string{
		"allow 10.0.0.5 --scope endpoint:ep-1",
		"deny 10.0.0.0/24 --scope client:t-01",
		"allow updates.example.com --scope group:pos",
		"allow 10.0.0.5 --scope provider",
		"deny 2001:db8::/32 --scope site:s-1 --proto udp",
	} {
		rule, err := trustRuleFromArgs(strings.Fields(args), now)
		if err != nil {
			t.Errorf("%s: %v", args, err)
			continue
		}
		if _, err := trustfabric.Normalize(rule); err != nil {
			t.Errorf("%s: the hub would refuse %+v: %v", args, rule, err)
		}
	}
	for args, want := range map[string]string{
		"allow 10.0.0.5":                               "--scope is required",
		"allow":                                        "usage",
		"--scope provider allow 10.0.0.5":              "usage",
		"allow 10.0.0.5 --scope provider extra":        "unexpected",
		"allow 10.0.0.5 --scope provider --expires 2x": "--expires takes",
		"allow 10.0.0.5 --scope provider --port x":     "--port",
		"allow 10.0.0.5 --scope provider --nope":       "nope",
		"allow 10.0.0.5 --scope provider:t-01":         "takes no id",
		"allow 10.0.0.5 --scope PROVIDER:t-01":         "takes no id",
	} {
		if _, err := trustRuleFromArgs(strings.Fields(args), now); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: want error with %q, got %v", args, want, err)
		}
	}
}

func captureStdout(t *testing.T, run func() error) string {
	t.Helper()
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	defer func() { os.Stdout = old }()
	done := make(chan string)
	go func() {
		var b bytes.Buffer
		_, _ = io.Copy(&b, r)
		done <- b.String()
	}()
	runErr := run()
	_ = w.Close()
	out := <-done
	if runErr != nil {
		t.Fatalf("%v (output %q)", runErr, out)
	}
	return out
}

func TestTrustCommandsTalkToTheHub(t *testing.T) {
	var posted trustfabric.Rule
	var deleted, effective string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/api/v1/trust/rules" && r.Method == http.MethodGet:
			_, _ = w.Write([]byte(`{"rules":[{"id":"r-1","scope_type":"client","scope_id":"t-01","kind":"cidr","value":"10.0.0.0/24","action":"deny","direction":"both","proto":"any","justification":"quarantine"}]}`))
		case r.URL.Path == "/api/v1/trust/rules" && r.Method == http.MethodPost:
			dec := json.NewDecoder(r.Body)
			dec.DisallowUnknownFields() // as the hub does
			if err := dec.Decode(&posted); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			if _, err := trustfabric.Normalize(posted); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(posted)
		case r.URL.Path == "/api/v1/trust/rules" && r.Method == http.MethodDelete:
			deleted = r.URL.Query().Get("id")
			_, _ = w.Write([]byte(`{"status":"deleted","rule":{"id":"r-1","scope_type":"provider","value":"10.0.0.5","action":"allow"}}`))
		case r.URL.Path == "/api/v1/trust/effective":
			effective = r.URL.RawQuery
			_, _ = w.Write([]byte(`{"endpoint_id":"ep-1","agent_report":"dropped 1 range","decision":{"action":"allow","basis":"most_specific","rule_id":"r-1","scope":"client"},"policy":{"allow":["10.0.0.0/30"],"enforced":["10.0.0.0/30"],"not_enforced":["10.0.1.0/24","names a port"],"withheld":[{"rule_id":"r-2","reason":"names a port"}]}}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer ts.Close()
	c := newAPIClient(CLIConfig{HubURL: ts.URL})

	out := captureStdout(t, func() error { return c.cmdTrust([]string{"rules"}) })
	for _, want := range []string{"r-1", "deny", "10.0.0.0/24", "client:t-01", "everything", "quarantine"} {
		if !strings.Contains(out, want) {
			t.Errorf("rules output lacks %q: %s", want, out)
		}
	}
	out = captureStdout(t, func() error {
		return c.cmdTrust(strings.Fields("add allow updates.example.com --scope group:pos --port 443 --proto tcp"))
	})
	if posted.Kind != trustfabric.KindFQDN || posted.ScopeID != "pos" || posted.Port != 443 || !strings.Contains(out, "updates.example.com") {
		t.Errorf("add sent %+v, printed %s", posted, out)
	}
	out = captureStdout(t, func() error { return c.cmdTrust([]string{"remove", "r-1"}) })
	if deleted != "r-1" || !strings.Contains(out, "Removed r-1 allow 10.0.0.5 provider") {
		t.Errorf("remove sent %q, printed %s", deleted, out)
	}
	out = captureStdout(t, func() error {
		return c.cmdTrust(strings.Fields("show ep-1 --addr 10.0.0.2 --port 443 --proto TCP"))
	})
	if effective != "addr=10.0.0.2&direction=out&endpoint_id=ep-1&port=443&proto=tcp" {
		t.Errorf("show asked %q", effective)
	}
	for _, want := range []string{"10.0.0.2, tcp 443 out: the rules say allow (most_specific, rule r-1 at client); on the isolated allow list: yes", "Agent would enforce: 10.0.0.0/30", "Doesn't fit, stays closed: 10.0.1.0/24\n", "rule r-2: names a port", "Agent's last report: dropped 1 range"} {
		if !strings.Contains(out, want) {
			t.Errorf("show output lacks %q: %s", want, out)
		}
	}
	if out = captureStdout(t, func() error { return c.cmdTrust(strings.Fields("show ep-1 --addr 192.0.2.1")) }); !strings.Contains(out, "allow list: no") {
		t.Errorf("an address off the list: %s", out)
	}
	if !strings.Contains(out, "192.0.2.1, the address as a whole:") {
		t.Errorf("the answer should say what it answers: %s", out)
	}
	if out = captureStdout(t, func() error { return c.cmdTrust(strings.Fields("show ep-1 --addr ::ffff:10.0.0.2")) }); !strings.Contains(out, "allow list: yes") {
		t.Errorf("a mapped address read as off the list: %s", out)
	}
	if err := c.cmdTrust(strings.Fields("show ep-1 --addr 192.0.2.1")); err != nil {
		t.Fatal(err)
	}
	if effective != "addr=192.0.2.1&endpoint_id=ep-1" {
		t.Errorf("a question about the whole address asked %q", effective)
	}
	for _, args := range []string{"show ep-1 --port 443 --proto tcp", "show ep-1 --addr 10.0.0.5 --port 443", "show ep-1 --addr 10.0.0.5 --port 443 --proto any", "show ep-1 --addr 10.0.0.5 --direction both"} {
		if err := c.cmdTrust(strings.Fields(args)); err == nil {
			t.Errorf("%s was accepted", args)
		}
	}
}
