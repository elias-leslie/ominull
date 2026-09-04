//go:build linux

package server

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"ominull/hub/pkg/pki"
	"ominull/hub/pkg/response"
	"ominull/hub/pkg/storage"
	"ominull/hub/pkg/terminal"
)

func TestLinuxTerminalWorker_LoopbackWithPty(t *testing.T) {
	// 1. Compile C worker helper
	root, err := filepath.Abs("../../..")
	if err != nil {
		t.Fatalf("resolve root: %v", err)
	}

	cHelperSrc := fmt.Sprintf(`
#include <stdio.h>
#include <stdlib.h>
#include "terminal_linux.h"

int main(int argc, char** argv) {
    if (argc < 5) {
        fprintf(stderr, "usage: %%s <hub_url> <endpoint_id> <session_id> <token>\n", argv[0]);
        return 1;
    }
    const char* hub_url = argv[1];
    const char* endpoint_id = argv[2];
    const char* session_id = argv[3];
    const char* token = argv[4];

    return Terminal_RunLinuxWorker(
        hub_url,
        false, // use_tls = false (plain http for test server)
        NULL, false, NULL, NULL,
        endpoint_id,
        session_id,
        token,
        "/bin/sh"
    );
}
`)
	tmpDir := t.TempDir()
	cHelperPath := filepath.Join(tmpDir, "terminal_worker_helper.c")
	binHelperPath := filepath.Join(tmpDir, "terminal_worker_helper")

	if err := os.WriteFile(cHelperPath, []byte(cHelperSrc), 0644); err != nil {
		t.Fatalf("write C helper: %v", err)
	}

	cmdBuild := exec.Command("gcc", "-Wall", "-O2", "-I"+filepath.Join(root, "agent/include"), cHelperPath, "-lcurl", "-o", binHelperPath)
	if out, err := cmdBuild.CombinedOutput(); err != nil {
		t.Fatalf("gcc build failed: %v\nOutput: %s", err, string(out))
	}

	// 2. Spin up in-memory Hub test server
	dbPath := filepath.Join(tmpDir, "test.db")
	store, err := storage.New(dbPath)
	if err != nil {
		t.Fatalf("storage.New: %v", err)
	}
	defer store.Close()

	tenantID := "tenant-linux-pty"
	opID := "op-pty-admin"
	endpointID := "linux-box-pty"

	srv := &Server{
		store:           store,
		terminalMgr:     terminal.NewManager(store.DB(), nil, 30*time.Minute, 10*time.Minute),
		pki:             &pki.Manager{},
		adminKey:        "test-admin-key",
		responseEnabled: true,
	}
	defer srv.terminalMgr.Close()

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/v1/terminal/ws/operator") {
			srv.handleTerminalWSOperator(w, r)
			return
		}
		if strings.HasPrefix(r.URL.Path, "/api/v1/terminal/ws/agent") {
			srv.handleTerminalWSAgent(w, r)
			return
		}
		http.NotFound(w, r)
	}))
	defer ts.Close()

	// 3. Create Session on Hub
	grant := &response.EndpointGrant{
		Version:           response.GrantVersion,
		GrantID:           "grant-pty-1",
		TenantID:          tenantID,
		EndpointID:        endpointID,
		ActionKind:        response.ActionKindTerminalSession,
		ActionDigest:      "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		OperatorID:        opID,
		ResponseSessionID: "resp-pty-1",
		IssuedAt:          time.Now().Unix(),
		ExpiresAt:         time.Now().Add(10 * time.Minute).Unix(),
	}

	session, err := srv.terminalMgr.CreateSession(tenantID, endpointID, opID, "/bin/sh", grant)
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}

	// 4. Operator attaches via WebSocket
	u, _ := url.Parse(ts.URL)
	opWSURL := fmt.Sprintf("ws://%s/api/v1/terminal/ws/operator?session_id=%s&token=%s", u.Host, session.SessionID, session.ConnectToken)

	opWS, _, err := websocket.DefaultDialer.Dial(opWSURL, nil)
	if err != nil {
		t.Fatalf("operator ws dial failed: %v", err)
	}
	defer opWS.Close()

	// 5. Run Linux C Worker in Background
	workerCmd := exec.Command(binHelperPath, ts.URL, endpointID, session.SessionID, session.ConnectToken)
	if err := workerCmd.Start(); err != nil {
		t.Fatalf("start worker cmd: %v", err)
	}

	workerDone := make(chan error, 1)
	go func() {
		workerDone <- workerCmd.Wait()
	}()

	// 6. Operator writes command to stdin: echo "ominull-pty-loopback-ok"
	time.Sleep(200 * time.Millisecond) // brief pause for agent to attach
	stdinPayload := map[string]interface{}{
		"type": "stdin",
		"data": []byte("echo ominull-pty-loopback-ok\n"),
	}
	if err := opWS.WriteJSON(stdinPayload); err != nil {
		t.Fatalf("write stdin to opWS: %v", err)
	}

	// 7. Operator reads stdout frames until finding target string
	found := false
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		_ = opWS.SetReadDeadline(time.Now().Add(1 * time.Second))
		var frame terminal.TerminalFrame
		if err := opWS.ReadJSON(&frame); err != nil {
			break
		}
		if frame.Type == terminal.FrameStdout && strings.Contains(string(frame.Data), "ominull-pty-loopback-ok") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected stdout from shell containing 'ominull-pty-loopback-ok'")
	}

	// 8. Test resize frame
	resizePayload := map[string]interface{}{
		"type": "resize",
		"rows": 40,
		"cols": 120,
	}
	if err := opWS.WriteJSON(resizePayload); err != nil {
		t.Fatalf("write resize: %v", err)
	}

	// 9. Send exit to shell
	exitPayload := map[string]interface{}{
		"type": "stdin",
		"data": []byte("exit 0\n"),
	}
	_ = opWS.WriteJSON(exitPayload)

	select {
	case wErr := <-workerDone:
		if wErr != nil {
			t.Logf("worker exited with: %v", wErr)
		}
	case <-time.After(3 * time.Second):
		_ = workerCmd.Process.Kill()
		t.Fatalf("timeout waiting for worker exit")
	}
}
