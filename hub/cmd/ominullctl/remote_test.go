package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

// runInSh feeds what ominullctl would type to a plain sh and returns its
// output with terminal noise around it, the way a pty would deliver it.
func runInSh(t *testing.T, typed string) []byte {
	t.Helper()
	cmd := exec.Command("sh")
	cmd.Stdin = strings.NewReader(typed)
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Run(); err != nil {
		t.Fatalf("sh: %v\n%s", err, out.String())
	}
	noisy := "\x1b]0;title\x07\x1b[?2004h$ " + strings.ReplaceAll(out.String(), "\n", "\r\n\x1b[K")
	return []byte(noisy)
}

// The command, its stdout, stderr and exit code survive the trip intact,
// whatever bytes they hold.
func TestExecJobReturnsCleanOutputAndExitCode(t *testing.T) {
	command := "printf 'it'\"'\"'s \\033[31mred\\033[0m\\n'\necho to-stderr >&2\nseq 1 3000\nexit 3"
	nonce := newNonce()
	script, err := jobScript(shellPOSIX, remoteJob{Op: "exec", Command: command}, nonce)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(script, "OMNX"+nonce) {
		t.Fatal("the typed text contains a marker, so echo could fake a result")
	}
	res, done, err := parseResult(runInSh(t, script), nonce)
	if err != nil || !done {
		t.Fatalf("done=%v err=%v", done, err)
	}
	want := "it's \x1b[31mred\x1b[0m\n"
	if !strings.HasPrefix(string(res.Stdout), want) || !strings.HasSuffix(string(res.Stdout), "\n2999\n3000\n") {
		t.Fatalf("stdout %q...", string(res.Stdout[:40]))
	}
	if string(res.Stderr) != "to-stderr\n" || res.Exit != 3 {
		t.Fatalf("stderr %q exit %d", res.Stderr, res.Exit)
	}
	// An unfinished result is not done, and a stale nonce matches nothing.
	if _, done, _ := parseResult(runInSh(t, script)[:200], nonce); done {
		t.Fatal("a partial result counted as done")
	}
	if _, done, _ := parseResult(runInSh(t, script), newNonce()); done {
		t.Fatal("another job's markers were accepted")
	}
}

func TestPutAndGetJobsCopyFiles(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "it's here.bin")
	data := make([]byte, 5000)
	for i := range data {
		data[i] = byte(i * 7)
	}
	nonce := newNonce()
	script, _ := jobScript(shellPOSIX, remoteJob{Op: "put", Path: target, Data: data}, nonce)
	if res, done, err := parseResult(runInSh(t, script), nonce); err != nil || !done || res.Exit != 0 {
		t.Fatalf("put: %+v %v %v", res, done, err)
	}
	if got, _ := os.ReadFile(target); !bytes.Equal(got, data) {
		t.Fatal("put wrote different bytes")
	}
	nonce = newNonce()
	script, _ = jobScript(shellPOSIX, remoteJob{Op: "get", Path: target}, nonce)
	res, done, err := parseResult(runInSh(t, script), nonce)
	if err != nil || !done || res.Exit != 0 || !bytes.Equal(res.Stdout, data) {
		t.Fatalf("get: exit %d err %v %d bytes", res.Exit, err, len(res.Stdout))
	}
	nonce = newNonce()
	script, _ = jobScript(shellPOSIX, remoteJob{Op: "get", Path: filepath.Join(dir, "missing")}, nonce)
	if res, _, _ := parseResult(runInSh(t, script), nonce); res.Exit == 0 || len(res.Stderr) == 0 {
		t.Fatalf("missing file: %+v", res)
	}
}

func TestPowerShellJobQuotesAndChunks(t *testing.T) {
	nonce := newNonce()
	script, err := jobScript(shellPowerShell, remoteJob{Op: "exec", Command: strings.Repeat("Write-Output 'x'\n", 200)}, nonce)
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(script, "\r") {
		if len(line) > 1000 {
			t.Fatalf("typed line of %d bytes", len(line))
		}
	}
	if strings.Contains(script, "OMNX"+nonce) || !strings.Contains(script, "Start-Process -FilePath powershell.exe") {
		t.Fatal("unexpected PowerShell job text")
	}
	// The child gets PATHEXT and friends (the terminal starts with a minimal
	// environment), and the ready text is one line, typed once.
	if !strings.Contains(script, base64.StdEncoding.EncodeToString([]byte("\xef\xbb\xbf" + psEnvPrefix))[:40]) {
		t.Fatal("PowerShell exec payload lacks the environment prefix")
	}
	if r := readyScript(shellPowerShell, nonce); strings.Count(r, "\r") != 1 || !strings.HasSuffix(r, "\r") {
		t.Fatalf("PowerShell ready text is not one line: %q", r)
	}
	script, _ = jobScript(shellPowerShell, remoteJob{Op: "get", Path: `C:\it's.txt`}, nonce)
	if !strings.Contains(script, `'C:\it''s.txt'`) {
		t.Fatal("path not quoted for PowerShell")
	}
}

func TestRemoteRefusesPlainHTTPOffHost(t *testing.T) {
	if hubSafe("http://192.0.2.10:9999") == nil {
		t.Fatal("plain http to another host accepted")
	}
	for _, ok := range []string{"https://192.0.2.10:9443", "http://127.0.0.1:9999"} {
		if err := hubSafe(ok); err != nil {
			t.Fatalf("%s: %v", ok, err)
		}
	}
}

// fakeHub answers like the hub: the session waits for the owner, then the
// operator socket is a shell (here a local sh standing in for the agent).
func fakeHub(t *testing.T) (*httptest.Server, func() string) {
	t.Helper()
	var mu sync.Mutex
	var seen []string
	note := func(s string) { mu.Lock(); seen = append(seen, s); mu.Unlock() }
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/endpoints", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`[{"id":"ep-1","os":"Linux","status":"online","response_capabilities":"{\"terminal\":{\"programs\":[\"/bin/bash\",\"/bin/sh\"]}}"}]`))
	})
	mux.HandleFunc("/api/v1/terminal/sessions", func(w http.ResponseWriter, r *http.Request) {
		var req map[string]string
		_ = json.NewDecoder(r.Body).Decode(&req)
		if req["program"] != "/bin/sh" {
			t.Errorf("program %q", req["program"])
		}
		if r.Header.Get("X-Approval-ID") == "" {
			note("asked")
			w.WriteHeader(http.StatusAccepted)
			_, _ = w.Write([]byte(`{"approval_id":"ap-1","state":"pending","action":"Open a shell","summary":"ep-1"}`))
			return
		}
		note("opened")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"session_id":"ts-1","endpoint_id":"ep-1","program":"/bin/sh","connect_token":"tok"}`))
	})
	mux.HandleFunc("/api/v1/approvals", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"id":"ap-1","state":"approved"}`))
	})
	up := websocket.Upgrader{}
	mux.HandleFunc("/api/v1/terminal/ws/operator", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Terminal-Token") != "tok" || r.URL.Query().Get("session_id") != "ts-1" {
			http.Error(w, "bad token", http.StatusForbidden)
			return
		}
		conn, err := up.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		sh := exec.Command("sh")
		stdin, _ := sh.StdinPipe()
		stdout, _ := sh.StdoutPipe()
		sh.Stderr = sh.Stdout
		if err := sh.Start(); err != nil {
			return
		}
		defer func() { _ = sh.Process.Kill(); _ = sh.Wait() }()
		var wmu sync.Mutex
		go func() {
			buf := make([]byte, 4096)
			for {
				n, err := stdout.Read(buf)
				if n > 0 {
					b, _ := json.Marshal(wsFrame{Type: "stdout", Data: append([]byte(nil), buf[:n]...)})
					wmu.Lock()
					_ = conn.WriteMessage(websocket.TextMessage, b)
					wmu.Unlock()
				}
				if err != nil {
					return
				}
			}
		}()
		for {
			_, msg, err := conn.ReadMessage()
			if err != nil {
				return
			}
			var f wsFrame
			_ = json.Unmarshal(msg, &f)
			switch f.Type {
			case "stdin":
				_, _ = stdin.Write(f.Data)
			case "close":
				note("closed")
				_ = stdin.Close()
				_, _ = io.Copy(io.Discard, stdout)
				return
			}
		}
	})
	return httptest.NewServer(mux), func() string { mu.Lock(); defer mu.Unlock(); return strings.Join(seen, ",") }
}

// exec opens a session under the owner's approval, runs the command over
// the terminal socket and ends the session.
func TestExecRunsThroughAnApprovedTerminalSession(t *testing.T) {
	t.Setenv("XDG_RUNTIME_DIR", t.TempDir())
	hub, seen := fakeHub(t)
	defer hub.Close()
	c := newAPIClient(CLIConfig{HubURL: hub.URL, APIKey: "test"})
	res, err := c.runJob("ep-1", remoteJob{Op: "exec", Command: "uname -s; echo oops >&2; exit 7", Timeout: 30})
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(res.Stdout)) != "Linux" || string(res.Stderr) != "oops\n" || res.Exit != 7 {
		t.Fatalf("result %+v", res)
	}
	// The close frame reaches the hub just after the result.
	for i := 0; i < 100 && seen() != "asked,opened,closed"; i++ {
		time.Sleep(20 * time.Millisecond)
	}
	if got := seen(); got != "asked,opened,closed" {
		t.Fatalf("hub saw %v", got)
	}
	if _, err := c.runJob("nope", remoteJob{Op: "exec", Command: "true"}); err == nil || !strings.Contains(err.Error(), "no endpoint") {
		t.Fatalf("unknown endpoint: %v", err)
	}
}

// A client interrupted while waiting for the owner withdraws its approval
// rather than leaving the owner an ask nobody will use.
func TestInterruptedWaitWithdrawsTheApproval(t *testing.T) {
	var mu sync.Mutex
	withdrawn := false
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/agents/update", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(`{"approval_id":"ap-9","state":"pending","action":"Update agents","summary":"1 host"}`))
	})
	mux.HandleFunc("/api/v1/approvals", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete && r.URL.Query().Get("id") == "ap-9" {
			mu.Lock()
			withdrawn = true
			mu.Unlock()
			_, _ = w.Write([]byte(`{"id":"ap-9","state":"denied"}`))
			return
		}
		time.Sleep(200 * time.Millisecond)
		_, _ = w.Write([]byte(`{"id":"ap-9","state":"pending"}`))
	})
	hub := httptest.NewServer(mux)
	defer hub.Close()
	c := newAPIClient(CLIConfig{HubURL: hub.URL, APIKey: "test"})
	go func() {
		time.Sleep(300 * time.Millisecond)
		_ = syscall.Kill(os.Getpid(), syscall.SIGINT)
	}()
	_, err := c.ownerApproved(http.MethodPost, "/api/v1/agents/update", map[string]string{})
	mu.Lock()
	defer mu.Unlock()
	if err == nil || !strings.Contains(err.Error(), "withdrawn") || !withdrawn {
		t.Fatalf("err %v withdrawn %v", err, withdrawn)
	}
}
