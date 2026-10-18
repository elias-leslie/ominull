package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeSigner writes a stand-in for `nightshift sign host-grant FILE` that
// records its arguments and the reservation it was given, then answers with
// body on stdout and exit code.
func fakeSigner(t *testing.T, body string, code int) (string, string) {
	t.Helper()
	dir := t.TempDir()
	seen := filepath.Join(dir, "seen")
	script := filepath.Join(dir, "nightshift")
	src := "#!/bin/sh\necho \"$@\" > " + seen + "\ncat \"$3\" >> " + seen + "\nprintf '%s\\n' '" + body + "'\nexit " + string(rune('0'+code)) + "\n"
	if err := os.WriteFile(script, []byte(src), 0o755); err != nil {
		t.Fatal(err)
	}
	return script, seen
}

type hostHub struct {
	mu          sync.Mutex
	reserveCode int
	reserveBody string
	submitCode  int
	submitted   map[string]json.RawMessage
}

func (h *hostHub) server(t *testing.T) *httptest.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/endpoints/ep-ws/jobs/signed/reserve", func(w http.ResponseWriter, r *http.Request) {
		h.mu.Lock()
		defer h.mu.Unlock()
		raw, _ := io.ReadAll(r.Body)
		if !strings.Contains(string(raw), `"package":"zfs-scrub"`) {
			t.Errorf("reserve body %s", raw)
		}
		w.WriteHeader(h.reserveCode)
		_, _ = w.Write([]byte(h.reserveBody))
	})
	mux.HandleFunc("/api/v1/endpoints/ep-ws/jobs/signed", func(w http.ResponseWriter, r *http.Request) {
		h.mu.Lock()
		defer h.mu.Unlock()
		_ = json.NewDecoder(r.Body).Decode(&h.submitted)
		if h.submitCode != http.StatusOK {
			w.WriteHeader(h.submitCode)
			_, _ = w.Write([]byte(`{"error":"reservation lapsed"}`))
			return
		}
		_, _ = w.Write([]byte(`{"job_id":"job-7","state":"queued"}`))
	})
	mux.HandleFunc("/api/v1/maintenance/wait", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"entries":[{"id":"job-7","job_id":"job-7","endpoint_id":"ep-ws","package":"zfs-scrub","state":"ok","final":true}],"any_final":true,"all_final":true}`))
	})
	return httptest.NewServer(mux)
}

func reserveAnswerJSON(expires int64) string {
	b, _ := json.Marshal(map[string]interface{}{"job_id": "job-7", "payload_json": `{"script_id":"s","source":"echo \u003cx\u003e"}`,
		"action_digest": strings.Repeat("ab", 32), "tenant_id": "default", "endpoint_id": "ep-ws", "expires_at": expires})
	return string(b)
}

func TestHostScriptRun(t *testing.T) {
	signer, seen := fakeSigner(t, `{"version":3,"job_id":"job-7","signature":"aa"}`, 0)
	t.Setenv("OMINULL_HOST_SIGNER", signer)
	h := &hostHub{reserveCode: 200, reserveBody: reserveAnswerJSON(time.Now().Add(15 * time.Minute).Unix()), submitCode: 200}
	hub := h.server(t)
	defer hub.Close()
	c := newAPIClient(CLIConfig{HubURL: hub.URL, APIKey: "test"})
	if err := c.cmdHostScript([]string{"run", "ep-ws", "--package", "zfs-scrub", "--mode", "audit", "--auto"}); err != nil {
		t.Fatalf("run: %v", err)
	}
	got, _ := os.ReadFile(seen)
	if !strings.HasPrefix(string(got), "sign host-grant ") || !strings.Contains(string(got), "--auto") ||
		!strings.Contains(string(got), `"job_id":"job-7"`) {
		t.Fatalf("signer saw %s", got)
	}
	// The payload goes back exactly as the hub encoded it.
	if string(h.submitted["payload"]) != `{"script_id":"s","source":"echo \u003cx\u003e"}` || !strings.Contains(string(h.submitted["grant"]), `"signature":"aa"`) {
		t.Fatalf("submitted %s / %s", h.submitted["payload"], h.submitted["grant"])
	}
}

func TestHostScriptErrors(t *testing.T) {
	future := time.Now().Add(15 * time.Minute).Unix()
	cases := []struct {
		name        string
		reserveCode int
		reserveBody string
		signerOut   string
		signerCode  int
		submitCode  int
		wantCode    int
		want        string
	}{
		{"lock level", 403, `{"error":"the endpoint's lock level \"isolate\" does not allow scripts"}`, "", 0, 200, exitHostLocked, "lock level"},
		{"signer refused", 200, reserveAnswerJSON(future), "not submitted: not signed (denied): the owner did not approve", 2, 200, exitHostRefused, "owner did not approve"},
		{"lapsed before signing", 200, reserveAnswerJSON(time.Now().Add(-time.Minute).Unix()), "not submitted: timed out", 2, 200, exitHostLapsed, "lapsed"},
		{"lapsed at submit", 200, reserveAnswerJSON(future), `{"version":3,"signature":"aa"}`, 0, 409, exitHostLapsed, "no longer holds"},
		{"grant rejected", 200, reserveAnswerJSON(future), `{"version":3,"signature":"aa"}`, 0, 400, exitHostRejected, "refused the signed grant"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			signer, _ := fakeSigner(t, tc.signerOut, tc.signerCode)
			t.Setenv("OMINULL_HOST_SIGNER", signer)
			h := &hostHub{reserveCode: tc.reserveCode, reserveBody: tc.reserveBody, submitCode: tc.submitCode}
			hub := h.server(t)
			defer hub.Close()
			c := newAPIClient(CLIConfig{HubURL: hub.URL, APIKey: "test"})
			err := c.cmdHostScript([]string{"run", "ep-ws", "--package", "zfs-scrub"})
			code, msg := exitCodeOf(err)
			if code != tc.wantCode || !strings.Contains(msg, tc.want) {
				t.Fatalf("code %d msg %q", code, msg)
			}
		})
	}
	if code, _ := exitCodeOf(newAPIClient(CLIConfig{}).cmdHostScript([]string{"run", "ep-ws"})); code != 2 {
		t.Fatalf("usage code %d", code)
	}
}
