//go:build linux

package server

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"ominull/hub/pkg/pki"
	"ominull/hub/pkg/response"
	"ominull/hub/pkg/storage"
	"ominull/hub/pkg/terminal"
)

// agentTerminalRig drives the real Linux terminal worker (agent/include/terminal_linux.h)
// through the hub's relay over loopback, the way an endpoint and a console would.
type agentTerminalRig struct {
	t      *testing.T
	op     *websocket.Conn
	worker *exec.Cmd
	done   chan error
	mu     sync.Mutex
	out    bytes.Buffer
	closed bool
	notify chan struct{}
}

func startAgentTerminalRig(t *testing.T, program string) *agentTerminalRig {
	t.Helper()
	root, err := filepath.Abs("../../..")
	if err != nil {
		t.Fatalf("resolve root: %v", err)
	}
	tmp := t.TempDir()
	src := filepath.Join(tmp, "worker.c")
	bin := filepath.Join(tmp, "worker")
	helper := fmt.Sprintf(`#include "terminal_linux.h"
int main(int argc, char** argv) {
    if (argc < 5) return 1;
    return Terminal_RunLinuxWorker(argv[1], false, NULL, false, NULL, NULL, argv[2], argv[3], argv[4], %q);
}
`, program)
	if err := os.WriteFile(src, []byte(helper), 0o644); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("gcc", "-Wall", "-O2", "-I"+filepath.Join(root, "agent/include"), src, "-lcurl", "-lutil", "-o", bin).CombinedOutput(); err != nil {
		t.Fatalf("gcc: %v\n%s", err, out)
	}

	store, err := storage.New(filepath.Join(tmp, "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	srv := &Server{
		store:           store,
		terminalMgr:     terminal.NewManager(store.DB(), nil, 30*time.Minute, 10*time.Minute),
		pki:             &pki.Manager{},
		adminKey:        "test-admin-key",
		responseEnabled: true,
	}
	t.Cleanup(func() { _ = srv.terminalMgr.Close() })
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasPrefix(r.URL.Path, "/api/v1/terminal/ws/operator"):
			srv.handleTerminalWSOperator(w, r)
		case strings.HasPrefix(r.URL.Path, "/api/v1/terminal/ws/agent"):
			srv.handleTerminalWSAgent(w, r)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(ts.Close)

	grant := &response.EndpointGrant{
		Version: response.GrantVersion, GrantID: "grant-bench", TenantID: "tenant-bench", EndpointID: "linux-bench",
		ActionKind: response.ActionKindTerminalSession, ActionDigest: strings.Repeat("0", 64), OperatorID: "op-bench",
		ResponseSessionID: "resp-bench", IssuedAt: time.Now().Unix(), ExpiresAt: time.Now().Add(10 * time.Minute).Unix(),
	}
	sess, err := srv.terminalMgr.CreateSession("tenant-bench", "linux-bench", "op-bench", program, grant)
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(ts.URL)
	op, _, err := websocket.DefaultDialer.Dial(fmt.Sprintf("ws://%s/api/v1/terminal/ws/operator?session_id=%s&token=%s", u.Host, sess.SessionID, sess.OperatorToken), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { op.Close() })
	rig := &agentTerminalRig{t: t, op: op, done: make(chan error, 1), notify: make(chan struct{}, 1)}
	rig.worker = exec.Command(bin, ts.URL, "linux-bench", sess.SessionID, sess.ConnectToken)
	if err := rig.worker.Start(); err != nil {
		t.Fatal(err)
	}
	go func() { rig.done <- rig.worker.Wait() }()
	// Read continuously, as a console does, so the relay never backs up on us.
	go func() {
		for {
			var f terminal.TerminalFrame
			if err := op.ReadJSON(&f); err != nil {
				rig.mu.Lock()
				rig.closed = true
				rig.mu.Unlock()
				rig.wake()
				return
			}
			if f.Type == terminal.FrameStdout {
				rig.mu.Lock()
				rig.out.Write(f.Data)
				rig.mu.Unlock()
				rig.wake()
			}
		}
	}()
	t.Cleanup(func() {
		select {
		case <-rig.done:
		default:
			_ = rig.worker.Process.Kill()
			<-rig.done
		}
	})
	return rig
}

func (r *agentTerminalRig) send(data string) {
	r.t.Helper()
	if err := r.op.WriteJSON(map[string]interface{}{"type": "stdin", "data": []byte(data)}); err != nil {
		r.t.Fatalf("write stdin: %v", err)
	}
}

// waitFor waits until marker appears in everything read so far.
func (r *agentTerminalRig) waitFor(marker string, timeout time.Duration) bool {
	r.t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		r.mu.Lock()
		ok := bytes.Contains(r.out.Bytes(), []byte(marker))
		closed := r.closed
		r.mu.Unlock()
		if ok {
			return true
		}
		if closed {
			return false
		}
		select {
		case <-r.notify:
		case <-time.After(time.Until(deadline)):
			return false
		}
	}
}

func (r *agentTerminalRig) wake() {
	select {
	case r.notify <- struct{}{}:
	default:
	}
}

func (r *agentTerminalRig) output() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.out.String()
}

func (r *agentTerminalRig) outLen() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.out.Len()
}

func (r *agentTerminalRig) reset() {
	r.mu.Lock()
	r.out.Reset()
	r.mu.Unlock()
}

// TestAgentTerminalLargePasteArrivesIntact pastes 256 KiB into `wc -c` in a
// single stdin frame. Before the frame reader was rewritten, any frame over
// 8 KiB ended the session. The hub relay caps one message at 64 KiB today, so
// the paste goes as consecutive 32 KiB frames (a 48 KiB frame encodes past the relay's 64 KiB message cap), as a console would send it.
func TestAgentTerminalLargePasteArrivesIntact(t *testing.T) {
	t.Parallel()
	rig := startAgentTerminalRig(t, "/bin/sh")
	rig.send("stty -echo; PS1=; echo RE\"\"ADY\n")
	if !rig.waitFor("READY", 5*time.Second) {
		t.Fatalf("shell never became ready: %q", rig.output())
	}
	const size = 256 * 1024
	line := strings.Repeat("x", 1023) + "\n"
	paste := strings.Repeat(line, size/len(line))
	rig.reset()
	rig.send("head -c " + fmt.Sprint(len(paste)) + " | wc -c; echo PASTE-\"\"END\n")
	time.Sleep(100 * time.Millisecond)
	for off := 0; off < len(paste); off += 32 * 1024 {
		end := off + 32*1024
		if end > len(paste) {
			end = len(paste)
		}
		rig.send(paste[off:end])
	}
	if !rig.waitFor("PASTE-END", 10*time.Second) {
		t.Fatalf("paste never completed; output so far %q", tail(rig.output(), 300))
	}
	if !strings.Contains(rig.output(), fmt.Sprint(len(paste))) {
		t.Fatalf("pty received a different byte count than %d: %q", len(paste), tail(rig.output(), 300))
	}
}

func tail(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[len(s)-n:]
}

// TestAgentTerminalBenchmark reports echo latency, 4 MiB cat throughput and
// Ctrl-C responsiveness during a flood. It is a measurement, not a gate:
// run with OMINULL_TERMINAL_BENCH=1 go test -run TestAgentTerminalBenchmark -v ./pkg/server/
func TestAgentTerminalBenchmark(t *testing.T) {
	if os.Getenv("OMINULL_TERMINAL_BENCH") == "" {
		t.Skip("set OMINULL_TERMINAL_BENCH=1 to measure")
	}
	big := filepath.Join(t.TempDir(), "big.txt")
	line := strings.Repeat("0123456789abcdef", 4) + "\n"
	if err := os.WriteFile(big, []byte(strings.Repeat(line, 4*1024*1024/len(line))), 0o644); err != nil {
		t.Fatal(err)
	}
	rig := startAgentTerminalRig(t, "/bin/sh")
	rig.send("PS1='$ '; echo RE\"\"ADY\n")
	if !rig.waitFor("READY\r\n", 5*time.Second) {
		t.Fatalf("shell never became ready")
	}
	time.Sleep(200 * time.Millisecond)

	// Echo latency: one keystroke to its echo, 40 samples.
	var lat []time.Duration
	for i := 0; i < 40; i++ {
		rig.reset()
		ch := string(rune('a' + i%26))
		start := time.Now()
		rig.send(ch)
		if !rig.waitFor(ch, 2*time.Second) {
			t.Fatalf("no echo for %q", ch)
		}
		lat = append(lat, time.Since(start))
	}
	rig.send("\x15") // kill the typed line
	sort.Slice(lat, func(i, j int) bool { return lat[i] < lat[j] })
	t.Logf("echo latency p50=%v p95=%v max=%v", lat[len(lat)/2], lat[len(lat)*95/100], lat[len(lat)-1])

	// Throughput: cat 4 MiB.
	rig.reset()
	start := time.Now()
	rig.send("cat " + big + "; echo CAT-\"\"DONE\n")
	if !rig.waitFor("CAT-DONE\r\n", 60*time.Second) {
		t.Fatalf("cat never finished (%d bytes read)", rig.outLen())
	}
	el := time.Since(start)
	t.Logf("cat 4 MiB: %v, %.1f MiB/s, %d bytes relayed", el, float64(rig.outLen())/el.Seconds()/(1<<20), rig.outLen())

	// Ctrl-C during an endless flood.
	rig.reset()
	rig.send("while :; do cat " + big + "; done\n")
	time.Sleep(500 * time.Millisecond)
	start = time.Now()
	rig.send("\x03")
	rig.send("echo AFTER-\"\"INTR\n")
	if !rig.waitFor("AFTER-INTR\r\n", 30*time.Second) {
		t.Fatalf("Ctrl-C did not stop the flood")
	}
	t.Logf("Ctrl-C to prompt during flood: %v", time.Since(start))
}
