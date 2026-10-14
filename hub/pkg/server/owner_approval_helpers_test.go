package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"ominull/hub/pkg/responseauth"
	"ominull/hub/pkg/responseauth/approvaltest"
	"ominull/hub/pkg/storage"
)

const testApproveRP = "approve.example.invalid"
const testApproveOrigin = "https://approve.example.invalid"

type testOwner struct {
	auth     *responseauth.Authority
	approver *approvaltest.Approver
}

var testOwners sync.Map // *Server -> *testOwner

// installTestOwner gives a test hub an in-process response authority with a
// software approver pinned, standing in for the owner's phone passkey.
func installTestOwner(t testing.TB, srv *Server, dir string) *testOwner {
	t.Helper()
	authDir := filepath.Join(dir, "owner-auth")
	if err := os.MkdirAll(filepath.Join(authDir, "keys"), 0o700); err != nil {
		t.Fatal(err)
	}
	auth, err := responseauth.NewAuthorityWithStore(responseauth.Config{StateDir: authDir}, responseauth.NewMemoryStore())
	if err != nil {
		t.Fatal(err)
	}
	ap := approvaltest.New("test-owner", testApproveRP, testApproveOrigin)
	path := filepath.Join(authDir, "approvers.json")
	if err := approvaltest.WriteFile(path, ap); err != nil {
		t.Fatal(err)
	}
	auth.SetApproversPath(path)
	srv.SetResponseAuth(responseauth.NewInProcessClient(auth))
	o := &testOwner{auth: auth, approver: ap}
	testOwners.Store(srv, o)
	return o
}

// pinTestOwner pins a software approver on an authority a test built itself.
func pinTestOwner(t testing.TB, srv *Server, auth *responseauth.Authority, dir string) *testOwner {
	t.Helper()
	ap := approvaltest.New("test-owner", testApproveRP, testApproveOrigin)
	path := filepath.Join(dir, "approvers.json")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := approvaltest.WriteFile(path, ap); err != nil {
		t.Fatal(err)
	}
	auth.SetApproversPath(path)
	o := &testOwner{auth: auth, approver: ap}
	testOwners.Store(srv, o)
	return o
}

// doApproved is serveApproved over a real HTTP client (for tests that need
// cookies and WebSockets).
func doApproved(t testing.TB, srv *Server, client *http.Client, method, url, body string, auth func(*http.Request)) *http.Response {
	t.Helper()
	send := func(approval string) *http.Response {
		req, _ := http.NewRequest(method, url, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		auth(req)
		if approval != "" {
			req.Header.Set(approvalHeader, approval)
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("%s %s: %v", method, url, err)
		}
		return resp
	}
	resp := send("")
	if resp.StatusCode != http.StatusAccepted {
		return resp
	}
	var pending struct {
		ApprovalID string `json:"approval_id"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&pending)
	resp.Body.Close()
	ownerOf(t, srv).approve(t, pending.ApprovalID)
	return send(pending.ApprovalID)
}

// seedTerminalEndpoint registers an endpoint that reports a terminal.
func seedTerminalEndpoint(t testing.TB, srv *Server, tenantID, id string, programs ...string) {
	t.Helper()
	if len(programs) == 0 {
		programs = []string{"/bin/bash", "/bin/sh"}
	}
	caps, _ := json.Marshal(map[string]interface{}{"isolate": true, "terminal": map[string]interface{}{"programs": programs}})
	if err := srv.store.UpsertEndpoint(storage.Endpoint{ID: id, TenantID: tenantID, Hostname: id, OS: "test", Status: "online", ResponseCapabilities: string(caps)}); err != nil {
		t.Fatal(err)
	}
}

func ownerOf(t testing.TB, srv *Server) *testOwner {
	t.Helper()
	if o, ok := testOwners.Load(srv); ok {
		return o.(*testOwner)
	}
	t.Fatal("test hub has no test owner installed")
	return nil
}

// approve answers a pending approval with the test owner's passkey.
func (o *testOwner) approve(t testing.TB, id string) {
	t.Helper()
	v, err := o.auth.GetApproval(id, "")
	if err != nil {
		t.Fatalf("approval %s: %v", id, err)
	}
	if _, err := o.auth.AnswerApproval(&responseauth.ApprovalAnswer{ID: id, Decision: "approve", Assertion: o.approver.Assert(v.Challenge, "approve")}); err != nil {
		t.Fatalf("approve %s: %v", id, err)
	}
}

// serveApproved sends a request through the hub; when the hub asks for an
// owner approval, the test owner approves and the identical request is sent
// again with the approval id, as a real caller would after the phone tap.
func serveApproved(t testing.TB, srv *Server, h http.Handler, req *http.Request, body string) *httptest.ResponseRecorder {
	t.Helper()
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusAccepted {
		return w
	}
	var pending struct {
		ApprovalID string `json:"approval_id"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &pending); err != nil || pending.ApprovalID == "" {
		t.Fatalf("202 without an approval id: %s", w.Body.String())
	}
	ownerOf(t, srv).approve(t, pending.ApprovalID)
	again := httptest.NewRequest(req.Method, req.URL.String(), strings.NewReader(body))
	for k, v := range req.Header {
		again.Header[k] = v
	}
	again.RemoteAddr = req.RemoteAddr
	again.Header.Set(approvalHeader, pending.ApprovalID)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, again)
	return w
}
