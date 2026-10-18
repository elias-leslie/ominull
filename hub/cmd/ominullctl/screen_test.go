package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// writeTestCA writes a throwaway self-signed CA certificate (no key kept).
func writeTestCA(t *testing.T, dir string) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test ca"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(p, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// hubEnded makes the fake hub answer /attach as for a session that ended.
var (
	screenHubMu sync.Mutex
	hubEnded    bool
)

func fakeScreenHub(t *testing.T) (*httptest.Server, func() []string) {
	t.Helper()
	var seen []string
	screenHubMu.Lock()
	hubEnded = false
	screenHubMu.Unlock()
	note := func(s string) { screenHubMu.Lock(); seen = append(seen, s); screenHubMu.Unlock() }
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/screen/sessions", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete {
			note("deleted " + r.URL.Query().Get("id"))
			_, _ = w.Write([]byte(`{"closed":true}`))
			return
		}
		var req map[string]interface{}
		_ = json.NewDecoder(r.Body).Decode(&req)
		if req["endpoint_id"] != "win-01" {
			t.Errorf("sent %v", req)
		}
		mode, _ := req["mode"].(string)
		if r.Header.Get("X-Approval-ID") == "" {
			note("asked")
			w.WriteHeader(http.StatusAccepted)
			_, _ = w.Write([]byte(`{"approval_id":"ap-1","state":"pending","action":"Watch screen","summary":"Watch the screen on win-01"}`))
			return
		}
		note("opened")
		w.WriteHeader(http.StatusCreated)
		_, _ = fmt.Fprintf(w, `{"session_id":"ss-1","mode":%q,"connect_token":"op-secret"}`, mode)
	})
	attaches := 0
	mux.HandleFunc("/api/v1/screen/sessions/attach", func(w http.ResponseWriter, r *http.Request) {
		screenHubMu.Lock()
		attaches++
		n, gone := attaches, hubEnded
		screenHubMu.Unlock()
		if gone {
			w.WriteHeader(http.StatusConflict)
			_, _ = w.Write([]byte(`{"error":"session is no longer live and cannot be attached"}`))
			return
		}
		note("attach")
		_, _ = fmt.Fprintf(w, `{"session_id":"ss-1","connect_token":"op-rot-%d"}`, n)
	})
	mux.HandleFunc("/api/v1/screen/settings", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			note("settings get " + r.URL.RawQuery)
			_, _ = w.Write([]byte(`{"endpoint_id":"win-01","ask_first":true,"source":"endpoint","fleet_ask_first":false}`))
			return
		}
		body, _ := io.ReadAll(r.Body)
		if strings.Contains(string(body), `"ask_first":false`) && r.Header.Get("X-Approval-ID") == "" {
			note("settings asked")
			w.WriteHeader(http.StatusAccepted)
			_, _ = w.Write([]byte(`{"approval_id":"ap-1","state":"pending","action":"Stop asking before screen sessions","summary":"Screen sessions on endpoint win-01 open without asking"}`))
			return
		}
		note("settings put " + string(body))
		_, _ = w.Write([]byte(`{"endpoint_id":"win-01","ask_first":false,"source":"endpoint","fleet_ask_first":false,"changed":true}`))
	})
	mux.HandleFunc("/api/v1/screen/sessions/watch", func(w http.ResponseWriter, r *http.Request) {
		note("watch")
		_, _ = w.Write([]byte(`{"session_id":"ss-1","token":"watch-secret","mode":"view","host":"Office PC","expires_at":"2030-01-01T00:00:00Z"}`))
	})
	mux.HandleFunc("/api/v1/approvals", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"id":"ap-1","state":"approved"}`))
	})
	mux.HandleFunc("/api/v1/endpoints", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`[{"id":"win-01","hostname":"Office PC"}]`))
	})
	hub := httptest.NewServer(mux)
	t.Cleanup(hub.Close)
	return hub, func() []string { screenHubMu.Lock(); defer screenHubMu.Unlock(); return append([]string(nil), seen...) }
}

// screen open waits for the tap, hands the viewer the session as one JSON
// line on stdin (token included, never argv or env), waits for it, and ends
// the session when it exits.
func TestScreenOpenStartsViewer(t *testing.T) {
	hub, seen := fakeScreenHub(t)
	dir := t.TempDir()
	ca := writeTestCA(t, dir)
	viewer := filepath.Join(dir, "viewer.sh")
	got := filepath.Join(dir, "got")
	script := "#!/bin/sh\ncat > '" + got + "'\nprintf '%s\\n' \"$*\" > '" + got + ".args'\nenv > '" + got + ".env'\n"
	if err := os.WriteFile(viewer, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	c := newAPIClient(CLIConfig{HubURL: hub.URL, APIKey: "test", CAFile: ca})
	var out bytes.Buffer
	if err := c.screenOpen([]string{"--view", "--ttl", "90m", "--viewer", viewer, "win-01"}, &out); err != nil {
		t.Fatal(err)
	}
	line, _ := os.ReadFile(got)
	if bytes.Count(line, []byte("\n")) != 1 {
		t.Fatalf("viewer stdin is not one line: %q", line)
	}
	var hs screenHandshake
	if err := json.Unmarshal(line, &hs); err != nil {
		t.Fatal(err)
	}
	if hs.HubURL != hub.URL || !strings.Contains(hs.CAPEM, "BEGIN CERTIFICATE") || hs.SessionID != "ss-1" || hs.Token != "op-secret" || hs.Mode != "view" || hs.Host != "Office PC" {
		t.Fatalf("handshake %+v", hs)
	}
	for _, f := range []string{got + ".args", got + ".env"} {
		if b, _ := os.ReadFile(f); bytes.Contains(b, []byte("op-secret")) {
			t.Fatalf("token leaked into %s", filepath.Ext(f))
		}
	}
	if strings.Contains(out.String(), "op-secret") || !strings.Contains(out.String(), "Watch-only screen session on win-01 ended") {
		t.Fatalf("printed %q", out.String())
	}
	if s := strings.Join(seen(), ","); s != "asked,opened,deleted ss-1" {
		t.Fatalf("hub saw %s", s)
	}
}

// With no viewer to be found nothing is asked of the owner; a viewer that
// cannot start leaves no session holding the endpoint's slot.
func TestScreenOpenWithoutViewer(t *testing.T) {
	hub, seen := fakeScreenHub(t)
	c := newAPIClient(CLIConfig{HubURL: hub.URL, APIKey: "test"})
	var out bytes.Buffer
	err := c.screenOpen([]string{"--view", "--ttl", "90m", "--viewer", filepath.Join(t.TempDir(), "missing"), "win-01"}, &out)
	if err == nil || !strings.Contains(err.Error(), "no screen viewer") || len(seen()) != 0 {
		t.Fatalf("err %v, hub saw %v", err, seen())
	}
	notExec := filepath.Join(t.TempDir(), "viewer")
	if err := os.WriteFile(notExec, []byte("not a program"), 0o600); err != nil {
		t.Fatal(err)
	}
	err = c.screenOpen([]string{"--view", "--ttl", "90m", "--viewer", notExec, "win-01"}, &out)
	if err == nil || !strings.Contains(err.Error(), "session was ended") {
		t.Fatalf("err %v", err)
	}
	if s := strings.Join(seen(), ","); s != "asked,opened,deleted ss-1" {
		t.Fatalf("hub saw %s", s)
	}
	if err := c.screenOpen(nil, &out); err == nil {
		t.Fatal("no endpoint accepted")
	}
}

// fakeCtl writes an ominull-screen stand-in: each run appends its argv to
// ARGS, its stdin to STDIN and its environment to ENV, then prints a result
// like ctl does (an error JSON and exit 1 when FAIL holds a message).
func fakeCtl(t *testing.T, dir string) (tool string, read func(string) string) {
	t.Helper()
	tool = filepath.Join(dir, "ominull-screen")
	script := `#!/bin/sh
d='` + dir + `'
printf '%s\n' "$*" >> "$d/ARGS"
cat >> "$d/STDIN"
env >> "$d/ENV"
if [ -s "$d/FAIL" ]; then printf '{"error":"%s"}\n' "$(cat "$d/FAIL")"; exit 1; fi
case "$2" in
info) echo '{"monitors":[{"id":0,"w":1920,"h":1080,"primary":true}],"desktop":"user"}' ;;
shot) echo '{"path":"x.png","width":1280,"height":720,"scale":0.6667,"monitor":0,"monitor_width":1920,"monitor_height":1080}' ;;
*) echo '{"ok":true}' ;;
esac
`
	if err := os.WriteFile(tool, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	return tool, func(name string) string { b, _ := os.ReadFile(filepath.Join(dir, name)); return string(b) }
}

// The held session: one tap at hold (which attaches at once with ctl info),
// then each command rotates a token through /attach and runs ctl with the
// handshake on stdin; an ended session leaves the marker and every later
// command says to open a new one.
func TestScreenHeldSession(t *testing.T) {
	t.Setenv("XDG_RUNTIME_DIR", t.TempDir())
	t.Setenv("OMINULL_SCREEN_MAX_EDGE", "")
	hub, seen := fakeScreenHub(t)
	dir := t.TempDir()
	tool, read := fakeCtl(t, dir)
	c := newAPIClient(CLIConfig{HubURL: hub.URL, APIKey: "test", CAFile: writeTestCA(t, dir)})

	var out bytes.Buffer
	if err := c.screenAction("info", []string{"--viewer", tool, "win-01"}, &out); err == nil || !strings.Contains(err.Error(), "screen hold win-01") {
		t.Fatalf("command before hold: %v", err)
	}
	if err := c.screenHold([]string{"--viewer", tool, "win-01"}, &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), `"monitors"`) {
		t.Fatalf("hold printed %q", out.String())
	}
	if raw, _ := os.ReadFile(heldScreenFile("win-01")); bytes.Contains(raw, []byte("op-")) || !bytes.Contains(raw, []byte(`"ss-1"`)) {
		t.Fatalf("held state %s", raw)
	}

	cases := []struct {
		action string
		args   []string
		ctl    string
	}{
		{"shot", []string{"win-01", "-o", filepath.Join(dir, "s.png"), "--monitor", "1"}, "ctl shot --max-edge 1280 --monitor 1 -o " + filepath.Join(dir, "s.png") + " --"},
		{"click", []string{"win-01", "640", "360", "--button", "right", "--double"}, "ctl click --max-edge 1280 --button right --double -- 640 360"},
		{"move", []string{"--max-edge", "800", "win-01", "10", "20"}, "ctl move --max-edge 800 -- 10 20"},
		{"drag", []string{"win-01", "1", "2", "3", "4", "--monitor", "0"}, "ctl drag --max-edge 1280 --monitor 0 -- 1 2 3 4"},
		{"scroll", []string{"win-01", "5", "6", "-3"}, "ctl scroll --max-edge 1280 -- 5 6 -3"},
		{"type", []string{"win-01", "--", "--hello world"}, "ctl type --max-edge 1280 -- --hello world"},
		{"key", []string{"win-01", "ctrl+alt+del"}, "ctl key --max-edge 1280 -- ctrl+alt+del"},
		{"info", []string{"win-01"}, "ctl info --max-edge 1280 --"},
	}
	for _, tc := range cases {
		out.Reset()
		if err := c.screenAction(tc.action, append([]string{"--viewer", tool}, tc.args...), &out); err != nil {
			t.Fatalf("%s: %v", tc.action, err)
		}
		lines := strings.Split(strings.TrimSpace(read("ARGS")), "\n")
		if last := lines[len(lines)-1]; last != tc.ctl {
			t.Fatalf("%s ran %q, want %q", tc.action, last, tc.ctl)
		}
		if tc.action == "shot" && !strings.Contains(out.String(), `"monitor_width":1920`) {
			t.Fatalf("shot printed %q", out.String())
		}
	}
	// Every run got a fresh token on stdin, one JSON line each; none in argv
	// or env.
	stdin := strings.Split(strings.TrimSpace(read("STDIN")), "\n")
	if len(stdin) != 1+len(cases) {
		t.Fatalf("%d handshakes", len(stdin))
	}
	var first, second screenHandshake
	_ = json.Unmarshal([]byte(stdin[0]), &first)
	_ = json.Unmarshal([]byte(stdin[1]), &second)
	if first.Token != "op-secret" || second.Token != "op-rot-1" || second.SessionID != "ss-1" || second.Mode != "control" || second.Host != "Office PC" || !strings.Contains(second.CAPEM, "BEGIN CERTIFICATE") {
		t.Fatalf("handshakes %+v %+v", first, second)
	}
	if strings.Contains(read("ARGS")+read("ENV")+out.String(), "op-") {
		t.Fatal("a token reached argv, env or output")
	}
	// Bad arguments never reach the hub.
	for _, args := range [][]string{{"win-01", "x", "1"}, {"win-01", "1"}} {
		if err := c.screenAction("click", args, &out); err == nil {
			t.Fatalf("click %v accepted", args)
		}
	}
	if err := c.screenAction("shot", []string{"win-01"}, &out); err == nil || !strings.Contains(err.Error(), "-o") {
		t.Fatalf("shot without -o: %v", err)
	}

	// The owner watches along: a watch token, the viewer in view mode.
	if err := c.screenWatch([]string{"--viewer", tool, "win-01"}, &out); err != nil {
		t.Fatal(err)
	}
	if last := strings.Split(strings.TrimSpace(read("STDIN")), "\n"); !strings.Contains(last[len(last)-1], `"token":"watch-secret"`) || !strings.Contains(last[len(last)-1], `"mode":"view"`) {
		t.Fatalf("watch handshake %s", last[len(last)-1])
	}

	// ctl reports the session ended: marker, and the next command says so.
	if err := os.WriteFile(filepath.Join(dir, "FAIL"), []byte("the session ended: agent_bye. Open a new one."), 0o600); err != nil {
		t.Fatal(err)
	}
	err := c.screenAction("info", []string{"--viewer", tool, "win-01"}, &out)
	if err == nil || !strings.Contains(err.Error(), "ended (agent_bye); open a new one with ominullctl screen hold win-01") {
		t.Fatalf("ended: %v", err)
	}
	_ = os.Remove(filepath.Join(dir, "FAIL"))
	before := len(seen())
	err = c.screenAction("click", []string{"--viewer", tool, "win-01", "1", "2"}, &out)
	if err == nil || !strings.Contains(err.Error(), "open a new one") || len(seen()) != before {
		t.Fatalf("after end: %v (hub saw %v)", err, seen()[before:])
	}

	// A new hold is the answer: one more tap. The hub then ends it.
	out.Reset()
	if err := c.screenHold([]string{"--viewer", tool, "win-01"}, &out); err != nil {
		t.Fatal(err)
	}
	screenHubMu.Lock()
	hubEnded = true
	screenHubMu.Unlock()
	if err := c.screenAction("info", []string{"--viewer", tool, "win-01"}, &out); err == nil || !strings.Contains(err.Error(), "no longer live") {
		t.Fatalf("hub-ended: %v", err)
	}
	if err := c.screenEnd([]string{"win-01"}, &out); err != nil || !strings.Contains(out.String(), "already ended") {
		t.Fatalf("end after ended: %v %q", err, out.String())
	}

	// screen end of a live held session deletes it on the hub.
	screenHubMu.Lock()
	hubEnded = false
	screenHubMu.Unlock()
	if err := c.screenHold([]string{"--viewer", tool, "win-01"}, &out); err != nil {
		t.Fatal(err)
	}
	if err := c.screenEnd([]string{"win-01"}, &out); err != nil {
		t.Fatal(err)
	}
	if s := seen(); s[len(s)-1] != "deleted ss-1" {
		t.Fatalf("hub saw %v", s)
	}
	if _, err := os.Stat(heldScreenFile("win-01")); !os.IsNotExist(err) {
		t.Fatal("held state left after end")
	}
	asks := 0
	for _, s := range seen() {
		if s == "asked" {
			asks++
		}
	}
	if asks != 3 {
		t.Fatalf("%d owner asks, want one per hold (3)", asks)
	}
}

// A hold whose first attach fails ends the session and holds nothing.
func TestScreenHoldFirstAttachFails(t *testing.T) {
	t.Setenv("XDG_RUNTIME_DIR", t.TempDir())
	hub, seen := fakeScreenHub(t)
	dir := t.TempDir()
	tool, _ := fakeCtl(t, dir)
	_ = os.WriteFile(filepath.Join(dir, "FAIL"), []byte("timed out waiting for the screen's monitor list"), 0o600)
	c := newAPIClient(CLIConfig{HubURL: hub.URL, APIKey: "test"})
	var out bytes.Buffer
	err := c.screenHold([]string{"--viewer", tool, "win-01"}, &out)
	if err == nil || !strings.Contains(err.Error(), "session was ended") {
		t.Fatalf("err %v", err)
	}
	if s := seen(); s[len(s)-1] != "deleted ss-1" {
		t.Fatalf("hub saw %v", s)
	}
	if _, err := os.Stat(heldScreenFile("win-01")); !os.IsNotExist(err) {
		t.Fatal("held state written for a failed hold")
	}
}

// screen settings shows the setting; turning ask-first off goes through the
// owner's tap.
func TestScreenSettings(t *testing.T) {
	hub, seen := fakeScreenHub(t)
	c := newAPIClient(CLIConfig{HubURL: hub.URL, APIKey: "test"})
	var out bytes.Buffer
	if err := c.screenSettings([]string{"win-01"}, &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "on win-01: on (its own setting; fleet default off)") {
		t.Fatalf("printed %q", out.String())
	}
	out.Reset()
	if err := c.screenSettings([]string{"win-01", "--ask-first", "off"}, &out); err != nil {
		t.Fatal(err)
	}
	if s := strings.Join(seen(), ","); s != `settings get endpoint_id=win-01,settings asked,settings put {"ask_first":false}` {
		t.Fatalf("hub saw %s", s)
	}
	if err := c.screenSettings([]string{"--ask-first", "maybe"}, &out); err == nil {
		t.Fatal("bad value accepted")
	}
}
