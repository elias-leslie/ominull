package server

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"software.sslmate.com/src/go-pkcs12"

	"ominull/hub/pkg/pki"
	"ominull/hub/pkg/storage"
)

func setupTestServer(t *testing.T) (*Server, *storage.Store) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "test.db")
	store, err := storage.New(dbPath)
	if err != nil {
		t.Fatalf("Storage init failed: %v", err)
	}

	// Create test tenant
	store.CreateTenant(storage.Tenant{
		ID:        "t-01",
		Name:      "Test Tenant",
		APIKey:    "mock_tenant_token",
		CreatedAt: time.Now().UTC(),
	})

	srv := New(store, "mock_admin_token", tempDir, "http://10.0.0.57:9999", "1.1.0")
	return srv, store
}

func TestBootstrapGenerators(t *testing.T) {
	srv, store := setupTestServer(t)
	defer store.Close()

	// 0. Bootstrap must never be minted without the admin key (no defaults, no tenant keys).
	for _, path := range []string{"/bootstrap.ps1", "/bootstrap.sh", "/bootstrap_mac.sh"} {
		for _, name := range []string{"no-key", "wrong-key"} {
			url := path
			if name == "wrong-key" {
				url = path + "?key=mock_tenant_token"
			}
			req := httptest.NewRequest("GET", url, nil)
			w := httptest.NewRecorder()
			switch path {
			case "/bootstrap.ps1":
				srv.handleBootstrapPS1(w, req)
			case "/bootstrap.sh":
				srv.handleBootstrapSH(w, req)
			default:
				srv.handleBootstrapMac(w, req)
			}
			if w.Code != http.StatusUnauthorized {
				t.Errorf("%s (%s): expected 401 Unauthorized, got %d", path, name, w.Code)
			}
		}
	}

	// Enrolment is the only step that plants the trust anchor, so every
	// generated script has to fetch the CA and hand the agent both that file
	// and the TLS address to use it against. A script that installs an agent
	// pointed at plain HTTP is the defect this checks for.
	srv.SetAgentHubURL("https://10.0.0.57:9443")

	// The credential a generated installer leaves behind on the endpoint is the
	// tenant key, never the admin key that authorised generating it. Written
	// into the agent's config, the admin key would give every host in the fleet
	// full operator control of the hub for the life of the install.
	defaultTenant, err := store.GetTenant("default")
	if err != nil || defaultTenant == nil {
		t.Fatalf("default tenant should exist: %v", err)
	}

	for _, tc := range []struct {
		name    string
		path    string
		handler func(http.ResponseWriter, *http.Request)
		want    []string
	}{
		{
			name:    "powershell",
			path:    "/bootstrap.ps1",
			handler: srv.handleBootstrapPS1,
			want: []string{
				"/api/v1/pki/ca.crt",
				`Cert:\LocalMachine\Root`,
				`--hub $AgentHubURL`,
				`--ca "$InstallDir\ca.crt"`,
				`$AgentHubURL = "https://10.0.0.57:9443"`,
				"/api/v1/pki/enroll",
				`$PfxPath = "$InstallDir\client.pfx"`,
				`--client-pfx "$PfxPath"`,
				"--id $EndpointID",
				`icacls.exe $PfxPath /inheritance:r`,
			},
		},
		{
			name:    "bash",
			path:    "/bootstrap.sh",
			handler: srv.handleBootstrapSH,
			want: []string{
				"ominulld.service",
				"/api/v1/pki/ca.crt",
				`CA_PATH="/etc/ominull/ca.crt"`,
				"--hub $AGENT_HUB_URL",
				"--ca $CA_PATH",
				`AGENT_HUB_URL="https://10.0.0.57:9443"`,
				"/api/v1/pki/enroll",
				`CLIENT_KEY="/etc/ominull/client.key"`,
				"--client-cert $CLIENT_CERT --client-key $CLIENT_KEY",
				"--id $ENDPOINT_ID",
				`chmod 600 "$CLIENT_KEY"`,
			},
		},
		{
			name:    "macos",
			path:    "/bootstrap.mac.sh",
			handler: srv.handleBootstrapMac,
			want: []string{
				"/api/v1/pki/ca.crt",
				`CA_PATH="$INSTALL_DIR/ca.crt"`,
				"<string>$ENDPOINT_ID</string>",
				"<string>$CA_PATH</string>",
				`AGENT_HUB_URL="https://10.0.0.57:9443"`,
				"/api/v1/pki/enroll",
				"<string>$CLIENT_CERT</string>",
				"<string>$CLIENT_KEY</string>",
				`chmod 600 "$CLIENT_KEY"`,
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", tc.path+"?key=mock_admin_token", nil)
			w := httptest.NewRecorder()
			tc.handler(w, req)

			if w.Code != http.StatusOK {
				t.Fatalf("expected 200, got %d", w.Code)
			}
			body := w.Body.String()
			if strings.Contains(body, "mock_admin_token") {
				t.Errorf("bootstrap script carries the hub admin key onto the endpoint:\n%s", body)
			}
			if !strings.Contains(body, defaultTenant.APIKey) {
				t.Errorf("bootstrap script does not carry the tenant key the agent reports with:\n%s", body)
			}
			// The certificate credential is separate, single-use, and has to
			// reach the enrolment call.
			if !strings.Contains(body, "X-Enrollment-Token") {
				t.Errorf("bootstrap script enrols without a single-use enrolment token:\n%s", body)
			}
			for _, want := range tc.want {
				if !strings.Contains(body, want) {
					t.Errorf("bootstrap script is missing %q:\n%s", want, body)
				}
			}
			// The private key the enrolment writes is the endpoint's identity.
			// Every generator has to close the file it lands in: on the two
			// unix platforms with chmod, on Windows by dropping inheritance.
			// A world-readable key would make the certificate decorative.
			if strings.Contains(body, "CLIENT_KEY") && !strings.Contains(body, `chmod 600 "$CLIENT_KEY"`) {
				t.Errorf("bootstrap script writes a client key it does not restrict:\n%s", body)
			}
			// The generators used to hand-build the Windows binPath, which
			// dropped the --service flag the SCM entry point needs. Registration
			// goes through the agent's own installer now.
			if strings.Contains(body, "sc.exe create") {
				t.Errorf("bootstrap script hand-builds the service binPath instead of using --install:\n%s", body)
			}
			// A generated script may hand the key to --install, which stores it
			// in a SYSTEM-only file. What it must never do is write a --service
			// command line itself: that is the registration `sc qc` shows to any
			// logged-on user, and the key would ride along in it.
			for _, line := range strings.Split(body, "\n") {
				if strings.HasPrefix(strings.TrimSpace(line), "#") {
					continue
				}
				if strings.Contains(line, "--service") && strings.Contains(line, "--key") {
					t.Errorf("bootstrap script registers a --service command line carrying the key: %q", line)
				}
			}
		})
	}
}

// TestHubTLSListenerPinsToItsOwnCA is the transport half of the same guarantee:
// the hub serves a certificate its own CA signed, so an agent that pins that CA
// connects and an agent holding any other CA is refused rather than quietly
// talking to whoever answered.
func TestHubTLSListenerPinsToItsOwnCA(t *testing.T) {
	srv, store := setupTestServer(t)
	defer store.Close()
	defer srv.Close()

	srv.SetTLS(TLSOptions{Listen: "127.0.0.1:0"})
	tlsCfg, err := srv.tlsConfig()
	if err != nil {
		t.Fatalf("tlsConfig failed: %v", err)
	}

	ln, err := tls.Listen("tcp", "127.0.0.1:0", tlsCfg)
	if err != nil {
		t.Fatalf("listen failed: %v", err)
	}
	defer ln.Close()

	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/pki/ca.crt", srv.handlePKICACert)
	go func() { _ = http.Serve(ln, mux) }()

	url := "https://" + ln.Addr().String() + "/api/v1/pki/ca.crt"

	// 1. The hub's own CA verifies the hub. This is what every agent does.
	hubCA := x509.NewCertPool()
	if !hubCA.AppendCertsFromPEM(srv.pki.GetCAPEM()) {
		t.Fatalf("hub CA PEM did not parse")
	}
	resp, err := tlsClient(hubCA).Get(url)
	if err != nil {
		t.Fatalf("an agent pinning the hub CA should reach the hub, got: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !bytes.Equal(bytes.TrimSpace(body), bytes.TrimSpace(srv.pki.GetCAPEM())) {
		t.Errorf("the hub served a CA that is not the one signing its own certificate")
	}

	// 2. A different CA does not. An agent given the wrong anchor has to fail
	// here and not fall through to an unverified connection.
	otherPKI, err := pki.New(t.TempDir())
	if err != nil {
		t.Fatalf("second PKI failed: %v", err)
	}
	otherCA := x509.NewCertPool()
	otherCA.AppendCertsFromPEM(otherPKI.GetCAPEM())
	if _, err := tlsClient(otherCA).Get(url); err == nil {
		t.Fatalf("an agent holding the wrong CA reached the hub anyway")
	}

	// 3. And neither does trusting nothing at all.
	if _, err := tlsClient(x509.NewCertPool()).Get(url); err == nil {
		t.Fatalf("an agent trusting no CA reached the hub anyway")
	}
}

func tlsClient(roots *x509.CertPool) *http.Client {
	return &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12},
		},
	}
}

func TestMultiTenantAPIAuth(t *testing.T) {
	srv, store := setupTestServer(t)
	defer store.Close()

	// 1. Unauthorized request (No API Key)
	req := httptest.NewRequest("GET", "/api/v1/endpoints", nil)
	w := httptest.NewRecorder()
	srv.authMiddleware(srv.handleEndpoints)(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected 401 Unauthorized for missing API key, got %d", w.Code)
	}

	// 2. Admin Request
	req = httptest.NewRequest("GET", "/api/v1/endpoints", nil)
	req.Header.Set("X-API-Key", "mock_admin_token")
	w = httptest.NewRecorder()
	srv.authMiddleware(srv.handleEndpoints)(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected 200 OK for admin API key, got %d", w.Code)
	}

	// 3. Ingesting Telemetry Events via Tenant Key
	eventPayload := []storage.Event{
		{
			Layer:       "CONNECT_V4",
			Action:      "BLOCK",
			Direction:   "OUTBOUND",
			Protocol:    6,
			SrcIP:       "10.0.0.5",
			DstIP:       "203.0.113.55",
			SrcPort:     12345,
			DstPort:     443,
			ProcessPath: "C:\\Windows\\System32\\cmd.exe",
			ProcessID:   999,
		},
	}
	data, _ := json.Marshal(eventPayload)

	req = httptest.NewRequest("POST", "/api/v1/events", bytes.NewReader(data))
	req.Header.Set("X-API-Key", "mock_tenant_token")
	w = httptest.NewRecorder()
	srv.authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		tenantID := r.Header.Get("X-Tenant-ID")
		var evs []storage.Event
		json.NewDecoder(r.Body).Decode(&evs)
		for i := range evs {
			evs[i].TenantID = tenantID
			evs[i].EndpointID = "ep-test"
			evs[i].Timestamp = time.Now().UTC()
		}
		store.InsertEventsBatch(evs)
		w.WriteHeader(http.StatusOK)
	})(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected 200 for event insertion, got %d", w.Code)
	}

	// 4. Query Events
	req = httptest.NewRequest("GET", "/api/v1/events", nil)
	req.Header.Set("X-API-Key", "mock_tenant_token")
	w = httptest.NewRecorder()
	srv.authMiddleware(srv.handleEvents)(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected 200 for querying events, got %d", w.Code)
	}

	var results []storage.Event
	json.NewDecoder(w.Body).Decode(&results)
	if len(results) != 1 || results[0].Action != "BLOCK" {
		t.Errorf("Expected 1 blocked event, got %v", results)
	}
}

func TestCompareVersions(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"1.1.0", "1.1.0", 0},
		{"1.1.0", "1.2.0", -1},
		{"1.2.0", "1.1.0", 1},
		{"1.1.0", "1.1.1", -1},
		{"2.0.0", "1.9.9", 1},
		{"v1.1.0", "1.1.0", 0},
		// Endpoints decorate the version with their enforcement engine.
		{"1.1.0 (WFP Callout)", "1.1.0", 0},
		{"1.1.0 (eBPF/TC)", "1.2.0", -1},
		{"1.2.0 (PF)", "1.1.0 (eBPF/TC)", 1},
		// Short and empty forms fall back to zeroes rather than erroring.
		{"1.1", "1.1.0", 0},
		{"", "1.1.0", -1},
		{"1.1.0", "", 1},
	}
	for _, c := range cases {
		if got := compareVersions(c.a, c.b); got != c.want {
			t.Errorf("compareVersions(%q, %q) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
}

func TestAgentPackageKind(t *testing.T) {
	cases := map[string]string{
		"Windows 11 Enterprise (x86_64)": "windows",
		"macOS Sonoma 14.8 (x86_64)":     "macos",
		"Darwin 23.6.0 (arm64)":          "macos",
		"Linux 6.8.0-40-generic":         "deb",
		"":                               "deb",
	}
	for osName, want := range cases {
		if got := agentPackageKind(osName); got != want {
			t.Errorf("agentPackageKind(%q) = %q, want %q", osName, got, want)
		}
	}
}

// seedEndpoint registers an endpoint reporting a specific agent version.
func seedEndpoint(t *testing.T, store *storage.Store, id, osName, version string) {
	t.Helper()
	if err := store.UpsertEndpoint(storage.Endpoint{
		ID:            id,
		TenantID:      "default",
		Hostname:      id,
		OS:            osName,
		IP:            "10.0.4.20",
		DriverVersion: version,
		Status:        "online",
		LastSeenAt:    time.Now().UTC(),
		CreatedAt:     time.Now().UTC(),
	}); err != nil {
		t.Fatalf("seeding endpoint %s failed: %v", id, err)
	}
}

// seedSignedRelease puts a package and its digest and signature sidecars in the
// hub's binary directory. The hub only checks that they are present - agents do
// the cryptography - so the contents here stand in for a real release.
func seedSignedRelease(t *testing.T, dir, name string) {
	t.Helper()
	body := []byte("package-bytes-for-" + name)
	sum := sha256.Sum256(body)
	for suffix, content := range map[string][]byte{
		"":        body,
		".sha256": []byte(hex.EncodeToString(sum[:]) + "  " + name + "\n"),
		".sig":    []byte("detached-signature"),
	} {
		if err := os.WriteFile(filepath.Join(dir, name+suffix), content, 0o644); err != nil {
			t.Fatalf("seeding %s%s: %v", name, suffix, err)
		}
	}
}

// seedEndpointWithCapability registers an endpoint that reports what package
// format it can install for itself.
func seedEndpointWithCapability(t *testing.T, store *storage.Store, id, osName, version, capability string) {
	t.Helper()
	if err := store.UpsertEndpoint(storage.Endpoint{
		ID:               id,
		TenantID:         "default",
		Hostname:         id,
		OS:               osName,
		IP:               "10.0.4.21",
		DriverVersion:    version,
		UpdateCapability: capability,
		Status:           "online",
		LastSeenAt:       time.Now().UTC(),
		CreatedAt:        time.Now().UTC(),
	}); err != nil {
		t.Fatalf("seeding endpoint %s failed: %v", id, err)
	}
}

// An endpoint is offered a package because it said it can install one, not
// because its OS string looked a certain way. That string is a display label -
// v1.2.0 changed the Windows one - so matching on it was one release away from
// misrouting a fleet-wide update.
func TestUpdatePackageFollowsReportedCapability(t *testing.T) {
	cases := []struct {
		name       string
		capability string
		osName     string
		wantPkg    string
		wantOK     bool
	}{
		{"reported deb", "deb", "Linux 6.8.0-40-generic", "deb", true},
		{"reported exe", "exe", "Windows 11 Enterprise LTSC 2024 24H2 (x86_64)", "windows", true},
		{"reported pkg", "pkg", "macOS 14.8 (x86_64)", "macos", true},
		{"capability outranks a misleading OS string", "exe", "Linux 6.8.0-40-generic", "windows", true},
		{"explicit none is offered nothing", "none", "Linux 6.8.0-40-generic", "", false},
		{"unknown capability is offered nothing", "msi", "Windows 11", "", false},
		// The only agent that shipped before the field existed and can still
		// install something is the Linux one, so that is the whole of the
		// legacy fallback.
		{"legacy linux agent still self-updates", "", "Linux 6.8.0-40-generic", "deb", true},
		{"legacy windows agent needs the push-deployer", "", "Windows 11 Enterprise (x86_64)", "", false},
		{"legacy macos agent needs the push-deployer", "", "macOS Sonoma 14.8.9 (x86_64)", "", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			pkg, ok := updatePackageFor(c.capability, c.osName)
			if ok != c.wantOK || pkg != c.wantPkg {
				t.Errorf("updatePackageFor(%q, %q) = (%q, %v), want (%q, %v)",
					c.capability, c.osName, pkg, ok, c.wantPkg, c.wantOK)
			}
		})
	}
}

// The hub must never advertise a release it cannot prove is genuine. Agents
// verify against a key compiled into them and would refuse it anyway, so an
// unsigned release has to surface as one clear answer here rather than as a
// failed install on every endpoint.
func TestUnsignedReleaseIsNeverOffered(t *testing.T) {
	srv, store := setupTestServer(t)
	defer store.Close()

	seedEndpointWithCapability(t, store, "linux-web-01", "Linux 6.8.0-40-generic", "1.0.0", "deb")
	req := httptest.NewRequest("POST", "/api/v1/events", nil)

	// 1. Nothing on disk at all.
	if _, ok := srv.agentUpdateDescriptor(req, "1.1.0", "deb"); ok {
		t.Error("Expected no descriptor when the package is not on the hub")
	}

	// 2. The package alone is not enough.
	name := "ominull-agent_1.1.0_amd64.deb"
	if err := os.WriteFile(filepath.Join(srv.binaryDir, name), []byte("package"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, ok := srv.agentUpdateDescriptor(req, "1.1.0", "deb"); ok {
		t.Error("Expected no descriptor for a package with no digest or signature")
	}

	// 3. A digest without a signature is still refused: a digest served by the
	//    same host that serves the package proves nothing about who built it.
	if err := os.WriteFile(filepath.Join(srv.binaryDir, name+".sha256"),
		[]byte(strings.Repeat("a", 64)+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, ok := srv.agentUpdateDescriptor(req, "1.1.0", "deb"); ok {
		t.Error("Expected no descriptor for a package with a digest but no signature")
	}

	// 4. An operator push reports the missing signature instead of queueing a
	//    job that could never complete.
	body, _ := json.Marshal(map[string]interface{}{"all": true})
	pushReq := httptest.NewRequest("POST", "/api/v1/agents/update", bytes.NewReader(body))
	pushReq.Header.Set("X-API-Key", "mock_admin_token")
	w := httptest.NewRecorder()
	srv.authMiddleware(srv.handleAgentsUpdate)(w, pushReq)
	var push struct {
		Scheduled   []map[string]string `json:"scheduled"`
		Unsupported []map[string]string `json:"unsupported"`
	}
	json.NewDecoder(w.Body).Decode(&push)
	if len(push.Scheduled) != 0 {
		t.Errorf("Expected nothing scheduled for an unsigned release, got %v", push.Scheduled)
	}
	if len(push.Unsupported) != 1 || !strings.Contains(push.Unsupported[0]["reason"], "no signed") {
		t.Errorf("Expected the unsigned release named as the reason, got %v", push.Unsupported)
	}

	// 5. With the signature in place the release is offered, and it carries
	//    everything an agent needs to verify it.
	if err := os.WriteFile(filepath.Join(srv.binaryDir, name+".sig"), []byte("sig"), 0o644); err != nil {
		t.Fatal(err)
	}
	desc, ok := srv.agentUpdateDescriptor(req, "1.1.0", "deb")
	if !ok {
		t.Fatal("Expected a descriptor once the package is signed")
	}
	for _, key := range []string{"version", "package", "url", "signature", "sha256"} {
		if desc[key] == "" {
			t.Errorf("Descriptor is missing %q: %v", key, desc)
		}
	}
	if !strings.HasSuffix(desc["signature"], ".deb.sig") {
		t.Errorf("Expected the signature URL to point at the .sig sidecar, got %q", desc["signature"])
	}
}

func TestAgentConfigReportsUpdateAvailability(t *testing.T) {
	srv, store := setupTestServer(t)
	defer store.Close()

	seedEndpoint(t, store, "linux-web-01", "Linux 6.8.0-40-generic", "1.0.0")

	// 1. Unknown endpoints are rejected rather than handed a package URL.
	req := httptest.NewRequest("GET", "/api/v1/agent/config?endpoint_id=ghost", nil)
	req.Header.Set("X-API-Key", "mock_admin_token")
	w := httptest.NewRecorder()
	srv.authMiddleware(srv.handleAgentConfig)(w, req)
	if w.Code != http.StatusNotFound {
		t.Errorf("Expected 404 for unregistered endpoint, got %d", w.Code)
	}

	// 2. A missing endpoint_id is a client error.
	req = httptest.NewRequest("GET", "/api/v1/agent/config", nil)
	req.Header.Set("X-API-Key", "mock_admin_token")
	w = httptest.NewRecorder()
	srv.authMiddleware(srv.handleAgentConfig)(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected 400 without endpoint_id, got %d", w.Code)
	}

	// 3. An endpoint below the bundled version is offered the .deb package.
	req = httptest.NewRequest("GET", "/api/v1/agent/config?endpoint_id=linux-web-01", nil)
	req.Header.Set("X-API-Key", "mock_admin_token")
	w = httptest.NewRecorder()
	srv.authMiddleware(srv.handleAgentConfig)(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("Expected 200 for agent config, got %d (%s)", w.Code, w.Body.String())
	}
	var cfg map[string]interface{}
	json.NewDecoder(w.Body).Decode(&cfg)
	if cfg["update_available"] != true {
		t.Errorf("Expected update_available=true for a 1.0.0 agent, got %v", cfg)
	}
	if cfg["latest_version"] != "1.1.0" {
		t.Errorf("Expected latest_version=1.1.0, got %v", cfg["latest_version"])
	}
	wantURL := "http://10.0.0.57:9999/download/ominull-agent_1.1.0_amd64.deb"
	if cfg["update_url"] != wantURL {
		t.Errorf("Expected update_url %q, got %v", wantURL, cfg["update_url"])
	}

	// 4. An up-to-date endpoint is offered nothing.
	seedEndpoint(t, store, "linux-web-02", "Linux 6.8.0-40-generic", "1.1.0 (eBPF/TC)")
	req = httptest.NewRequest("GET", "/api/v1/agent/config?endpoint_id=linux-web-02", nil)
	req.Header.Set("X-API-Key", "mock_admin_token")
	w = httptest.NewRecorder()
	srv.authMiddleware(srv.handleAgentConfig)(w, req)
	cfg = map[string]interface{}{}
	json.NewDecoder(w.Body).Decode(&cfg)
	if cfg["update_available"] != false {
		t.Errorf("Expected update_available=false for a current agent, got %v", cfg)
	}
	if _, present := cfg["update_url"]; present {
		t.Errorf("Expected no update_url for a current agent, got %v", cfg["update_url"])
	}
}

func TestAgentsUpdateSchedulingAndStatus(t *testing.T) {
	srv, store := setupTestServer(t)
	defer store.Close()

	seedSignedRelease(t, srv.binaryDir, "ominull-agent_1.1.0_amd64.deb")
	seedEndpoint(t, store, "linux-web-01", "Linux 6.8.0-40-generic", "1.0.0")
	seedEndpoint(t, store, "win-exec-01", "Windows 11 Enterprise (x86_64)", "1.0.0")
	seedEndpoint(t, store, "linux-web-02", "Linux 6.8.0-40-generic", "1.1.0 (eBPF/TC)")

	// 1. Tenant keys must not be able to push fleet-wide agent updates.
	body, _ := json.Marshal(map[string]interface{}{"all": true})
	req := httptest.NewRequest("POST", "/api/v1/agents/update", bytes.NewReader(body))
	req.Header.Set("X-API-Key", "mock_tenant_token")
	w := httptest.NewRecorder()
	srv.authMiddleware(srv.handleAgentsUpdate)(w, req)
	if w.Code != http.StatusForbidden {
		t.Errorf("Expected 403 for a tenant-scoped update push, got %d", w.Code)
	}

	// 2. Downgrades below the hub's own bundle are refused.
	body, _ = json.Marshal(map[string]interface{}{"all": true, "version": "1.0.0"})
	req = httptest.NewRequest("POST", "/api/v1/agents/update", bytes.NewReader(body))
	req.Header.Set("X-API-Key", "mock_admin_token")
	w = httptest.NewRecorder()
	srv.authMiddleware(srv.handleAgentsUpdate)(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected 400 for a downgrade request, got %d", w.Code)
	}

	// 3. An admin push schedules endpoints that can install the package and
	//    flags the rest for the push-deployer. The Windows endpoint here
	//    reports no capability, so it is correctly left out: its agent could
	//    not act on a descriptor even if one were sent.
	body, _ = json.Marshal(map[string]interface{}{"all": true})
	req = httptest.NewRequest("POST", "/api/v1/agents/update", bytes.NewReader(body))
	req.Header.Set("X-API-Key", "mock_admin_token")
	w = httptest.NewRecorder()
	srv.authMiddleware(srv.handleAgentsUpdate)(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("Expected 200 for agent update push, got %d (%s)", w.Code, w.Body.String())
	}
	var push struct {
		DesiredVersion string              `json:"desired_version"`
		Scheduled      []map[string]string `json:"scheduled"`
		Unsupported    []map[string]string `json:"unsupported"`
	}
	json.NewDecoder(w.Body).Decode(&push)
	if push.DesiredVersion != "1.1.0" {
		t.Errorf("Expected desired_version 1.1.0, got %q", push.DesiredVersion)
	}
	if len(push.Scheduled) != 1 || push.Scheduled[0]["endpoint_id"] != "linux-web-01" {
		t.Errorf("Expected only the outdated Linux endpoint scheduled, got %v", push.Scheduled)
	}
	if len(push.Unsupported) != 1 || push.Unsupported[0]["endpoint_id"] != "win-exec-01" {
		t.Errorf("Expected the Windows endpoint reported as unsupported, got %v", push.Unsupported)
	}

	// 4. Status reports both outdated endpoints and the queued job.
	req = httptest.NewRequest("GET", "/api/v1/agents/update-status", nil)
	req.Header.Set("X-API-Key", "mock_admin_token")
	w = httptest.NewRecorder()
	srv.authMiddleware(srv.handleAgentsUpdateStatus)(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("Expected 200 for update status, got %d", w.Code)
	}
	var status struct {
		LatestVersion string                   `json:"latest_version"`
		Outdated      []map[string]string      `json:"outdated"`
		Pending       []storage.AgentUpdateJob `json:"pending"`
	}
	json.NewDecoder(w.Body).Decode(&status)
	if status.LatestVersion != "1.1.0" {
		t.Errorf("Expected latest_version 1.1.0, got %q", status.LatestVersion)
	}
	if len(status.Outdated) != 2 {
		t.Errorf("Expected 2 outdated endpoints, got %v", status.Outdated)
	}
	if len(status.Pending) != 1 || status.Pending[0].EndpointID != "linux-web-01" {
		t.Errorf("Expected 1 pending job for linux-web-01, got %v", status.Pending)
	}
}

func TestTelemetryCarriesAndRetiresAgentUpdate(t *testing.T) {
	srv, store := setupTestServer(t)
	defer store.Close()

	seedSignedRelease(t, srv.binaryDir, "ominull-agent_1.1.0_amd64.deb")
	seedEndpoint(t, store, "linux-web-01", "Linux 6.8.0-40-generic", "1.0.0")
	if err := store.RequestAgentUpdate("linux-web-01", "1.1.0"); err != nil {
		t.Fatalf("queueing update failed: %v", err)
	}

	postTelemetry := func(version string) map[string]interface{} {
		t.Helper()
		batch, _ := json.Marshal(map[string]interface{}{
			"type":              "telemetry",
			"endpoint_id":       "linux-web-01",
			"hostname":          "linux-web-01",
			"os":                "Linux 6.8.0-40-generic",
			"ip":                "10.0.4.20",
			"driver_version":    version,
			"update_capability": "deb",
			"events":            []storage.Event{},
		})
		req := httptest.NewRequest("POST", "/api/v1/events", bytes.NewReader(batch))
		req.Header.Set("X-API-Key", "mock_admin_token")
		w := httptest.NewRecorder()
		srv.authMiddleware(srv.handleEvents)(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("Expected 200 for telemetry post, got %d (%s)", w.Code, w.Body.String())
		}
		var resp map[string]interface{}
		json.NewDecoder(w.Body).Decode(&resp)
		return resp
	}

	// 1. An outdated agent is handed the package URL on its own telemetry heartbeat.
	resp := postTelemetry("1.0.0")
	update, ok := resp["agent_update"].(map[string]interface{})
	if !ok {
		t.Fatalf("Expected agent_update in the telemetry response, got %v", resp)
	}
	if update["version"] != "1.1.0" || update["package"] != "deb" {
		t.Errorf("Unexpected agent_update payload: %v", update)
	}
	// The descriptor has to carry proof, not just a URL. An agent that is only
	// told where to fetch from has no way to tell a genuine release from
	// whatever an attacker on the path substituted for it.
	if update["sha256"] == nil || update["signature"] == nil {
		t.Errorf("Expected the descriptor to carry a digest and signature URL, got %v", update)
	}

	// 2. The job stays pending until the agent reports the new version.
	if pending, _ := store.ListPendingAgentUpdates(); len(pending) != 1 {
		t.Errorf("Expected the update job to stay pending, got %v", pending)
	}

	// 3. Reporting the target version closes the job and stops the offer.
	resp = postTelemetry("1.1.0 (eBPF/TC)")
	if _, present := resp["agent_update"]; present {
		t.Errorf("Expected no agent_update once current, got %v", resp["agent_update"])
	}
	pending, _ := store.ListPendingAgentUpdates()
	if len(pending) != 0 {
		t.Errorf("Expected the update job to be retired, got %v", pending)
	}
	job, _ := store.GetAgentUpdateJob("linux-web-01")
	if job == nil || job.CompletedAt == nil {
		t.Errorf("Expected a completed_at timestamp on the retired job, got %v", job)
	}
}

func TestEndpointOrderIsStableAcrossHeartbeats(t *testing.T) {
	srv, store := setupTestServer(t)
	defer store.Close()

	// Enrol out of alphabetical order so a correct sort is observable.
	for _, name := range []string{"zulu-host", "alpha-host", "mike-host"} {
		seedEndpoint(t, store, "ep-"+name, "Linux 6.8.0-40-generic", "1.1.0")
		if err := store.UpsertEndpoint(storage.Endpoint{
			ID: "ep-" + name, TenantID: "default", Hostname: name,
			OS: "Linux 6.8.0-40-generic", IP: "10.0.4.20", DriverVersion: "1.1.0",
			Status: "online", LastSeenAt: time.Now().UTC(), CreatedAt: time.Now().UTC(),
		}); err != nil {
			t.Fatalf("seeding %s failed: %v", name, err)
		}
	}

	order := func() []string {
		t.Helper()
		req := httptest.NewRequest("GET", "/api/v1/endpoints", nil)
		req.Header.Set("X-API-Key", "mock_admin_token")
		w := httptest.NewRecorder()
		srv.authMiddleware(srv.handleEndpoints)(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("Expected 200 listing endpoints, got %d", w.Code)
		}
		var eps []storage.Endpoint
		json.NewDecoder(w.Body).Decode(&eps)
		names := make([]string, 0, len(eps))
		for _, ep := range eps {
			names = append(names, ep.Hostname)
		}
		return names
	}

	want := []string{"alpha-host", "mike-host", "zulu-host"}
	if got := order(); !reflect.DeepEqual(got, want) {
		t.Fatalf("Expected hostname order %v, got %v", want, got)
	}

	// A heartbeat from the alphabetically-first host must not move it to the top or
	// bottom of the list: rows that reshuffle under the operator make an isolate click
	// land on whichever machine slid into that row.
	if err := store.UpsertEndpoint(storage.Endpoint{
		ID: "ep-zulu-host", TenantID: "default", Hostname: "zulu-host",
		OS: "Linux 6.8.0-40-generic", IP: "10.0.4.20", DriverVersion: "1.1.0",
		Status: "online", LastSeenAt: time.Now().UTC().Add(time.Minute), CreatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("heartbeat upsert failed: %v", err)
	}
	if got := order(); !reflect.DeepEqual(got, want) {
		t.Errorf("Order changed after a heartbeat: expected %v, got %v", want, got)
	}
}

// The Linux and macOS agents have always reported a hardware address, but the
// telemetry struct had no field for it, so encoding/json dropped it on the
// floor and every agented asset fell back to address-plus-subnet identity.
// That defeats the point of keying on the MAC: the whole reason to do so is
// that a host keeps its identity when its lease changes.
func TestTelemetryMACReachesAssetIdentity(t *testing.T) {
	srv, store := setupTestServer(t)
	defer store.Close()

	post := func(ip string) {
		t.Helper()
		batch, _ := json.Marshal(map[string]interface{}{
			"type":           "telemetry",
			"endpoint_id":    "linux-web-01",
			"hostname":       "linux-web-01",
			"os":             "Debian 12",
			"ip":             ip,
			"mac":            "00:1A:2B:3C:4D:5E",
			"driver_version": "1.2.0",
			"events":         []storage.Event{},
		})
		req := httptest.NewRequest("POST", "/api/v1/events", bytes.NewReader(batch))
		req.Header.Set("X-API-Key", "mock_admin_token")
		w := httptest.NewRecorder()
		srv.authMiddleware(srv.handleEvents)(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("telemetry post returned %d (%s)", w.Code, w.Body.String())
		}
	}

	post("10.0.4.20")

	assets, err := store.ListAssets("")
	if err != nil {
		t.Fatalf("ListAssets: %v", err)
	}
	if len(assets) != 1 {
		t.Fatalf("expected one asset, got %d", len(assets))
	}
	if assets[0].MAC != "00:1a:2b:3c:4d:5e" {
		t.Errorf("the reported MAC never reached the asset: %q", assets[0].MAC)
	}
	if assets[0].IdentityKind != "mac" {
		t.Errorf("identity did not key on the hardware address: kind=%q value=%q",
			assets[0].IdentityKind, assets[0].IdentityValue)
	}

	// The point of hardware identity: a new lease is the same machine.
	post("10.0.4.77")

	assets, err = store.ListAssets("")
	if err != nil {
		t.Fatalf("ListAssets: %v", err)
	}
	if len(assets) != 1 {
		t.Fatalf("a DHCP lease change forked the host into %d assets", len(assets))
	}
	if assets[0].IP != "10.0.4.77" {
		t.Errorf("asset did not follow the endpoint to its new address: %q", assets[0].IP)
	}
}

// mtlsListener serves the routes an agent uses over a TLS listener configured
// exactly as Start would configure it, so the handshake being tested is the
// real one and not a synthesized r.TLS.
func mtlsListener(t *testing.T, srv *Server) string {
	t.Helper()
	tlsCfg, err := srv.tlsConfig()
	if err != nil {
		t.Fatalf("tlsConfig failed: %v", err)
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", tlsCfg)
	if err != nil {
		t.Fatalf("listen failed: %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/events", srv.authMiddleware(srv.handleEvents))
	mux.HandleFunc("/api/v1/agent/config", srv.authMiddleware(srv.handleAgentConfig))
	go func() { _ = http.Serve(ln, mux) }()
	return "https://" + ln.Addr().String()
}

// agentClient dials the hub the way an enrolled agent does: pinned to the hub's
// CA, presenting the certificate it was issued. A nil cert is the endpoint that
// has not enrolled an identity yet.
func agentClient(t *testing.T, srv *Server, cert *tls.Certificate) *http.Client {
	t.Helper()
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(srv.pki.GetCAPEM()) {
		t.Fatalf("hub CA PEM did not parse")
	}
	cfg := &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}
	if cert != nil {
		cfg.Certificates = []tls.Certificate{*cert}
	}
	return &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{TLSClientConfig: cfg}}
}

func issueAgentCert(t *testing.T, m *pki.Manager, endpointID string) *tls.Certificate {
	t.Helper()
	bundle, err := m.IssueClientCert(endpointID, "10.0.0.9")
	if err != nil {
		t.Fatalf("IssueClientCert(%q) failed: %v", endpointID, err)
	}
	cert, err := tls.X509KeyPair(bundle.CertPEM, bundle.KeyPEM)
	if err != nil {
		t.Fatalf("the bundle issued for %q is not a usable key pair: %v", endpointID, err)
	}
	return &cert
}

func postTelemetryAs(t *testing.T, c *http.Client, base, endpointID string, extra map[string]string) (int, error) {
	t.Helper()
	body := []byte(`{"type":"telemetry","endpoint_id":"` + endpointID + `","hostname":"h","os":"Linux","events":[]}`)
	req, err := http.NewRequest("POST", base+"/api/v1/events", bytes.NewReader(body))
	if err != nil {
		return 0, err
	}
	req.Header.Set("X-API-Key", "mock_tenant_token")
	req.Header.Set("Content-Type", "application/json")
	for k, v := range extra {
		req.Header.Set(k, v)
	}
	resp, err := c.Do(req)
	if err != nil {
		return 0, err
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	return resp.StatusCode, nil
}

// The API key is shared by every agent on a tenant, so on its own it says which
// tenant is calling and nothing about which host. This is the test that the
// certificate closes that gap: holding the key is no longer enough to report as
// - or read the update descriptor of - a host you are not.
func TestClientCertificateBindsARequestToOneEndpoint(t *testing.T) {
	srv, store := setupTestServer(t)
	defer store.Close()
	defer srv.Close()

	srv.SetTLS(TLSOptions{Listen: "127.0.0.1:0"})
	base := mtlsListener(t, srv)

	own := issueAgentCert(t, srv.pki, "linux-alpha")
	client := agentClient(t, srv, own)

	// 1. Reporting as itself is what the certificate is for.
	if code, err := postTelemetryAs(t, client, base, "linux-alpha", nil); err != nil || code != http.StatusOK {
		t.Fatalf("an endpoint reporting under its own certificate got %d (err %v); want 200", code, err)
	}

	// 2. Reporting as a different host is refused, even holding a valid key and
	// a valid certificate. This is the impersonation the binding exists to stop.
	code, err := postTelemetryAs(t, client, base, "linux-beta", nil)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	if code != http.StatusForbidden {
		t.Errorf("an endpoint reported as another host and got %d; want 403", code)
	}

	// 3. The same binding covers the update descriptor, which would otherwise
	// tell any key holder which release a named host is about to install.
	req, _ := http.NewRequest("GET", base+"/api/v1/agent/config?endpoint_id=linux-beta", nil)
	req.Header.Set("X-API-Key", "mock_tenant_token")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("agent/config request failed: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("agent/config for another endpoint returned %d; want 403", resp.StatusCode)
	}

	// 4. The identity comes from the handshake and not from a header. A caller
	// that sets X-Client-CN by hand must not be able to name itself: the
	// middleware strips it, so this is a request with no certificate at all and
	// the endpoint it claims is simply believed - the pre-certificate behaviour
	// the fleet is being migrated off, not an impersonation route.
	plain := agentClient(t, srv, nil)
	if code, err := postTelemetryAs(t, plain, base, "linux-beta", map[string]string{"X-Client-CN": "linux-alpha"}); err != nil || code != http.StatusOK {
		t.Fatalf("an endpoint without a certificate got %d (err %v); want 200 while the fleet migrates", code, err)
	}
	if code, err := postTelemetryAs(t, plain, base, "linux-alpha", map[string]string{"X-Client-CN": "linux-alpha"}); err != nil || code != http.StatusOK {
		t.Fatalf("a forged X-Client-CN changed the outcome: got %d (err %v)", code, err)
	}
}

// A certificate is only an identity if the hub decides who may mint one. These
// are the two ways that could fail: trusting an anchor that is not the hub's,
// and letting an endpoint with no certificate through after certificates were
// made mandatory.
func TestClientCertificateFromAnotherCAIsRefused(t *testing.T) {
	srv, store := setupTestServer(t)
	defer store.Close()
	defer srv.Close()

	srv.SetTLS(TLSOptions{Listen: "127.0.0.1:0"})
	base := mtlsListener(t, srv)

	// A second PKI stands in for any other authority - a public one, or an
	// attacker's own. It can mint a certificate naming any endpoint it likes;
	// what it cannot do is get that certificate accepted here.
	otherPKI, err := pki.New(t.TempDir())
	if err != nil {
		t.Fatalf("second PKI failed: %v", err)
	}
	forged := issueAgentCert(t, otherPKI, "linux-alpha")
	if _, err := postTelemetryAs(t, agentClient(t, srv, forged), base, "linux-alpha", nil); err == nil {
		t.Fatalf("a certificate from a foreign CA was accepted")
	}

	// With certificates required, an endpoint that has none is refused at the
	// handshake rather than reaching a handler.
	srv.SetTLS(TLSOptions{Listen: "127.0.0.1:0", ClientCerts: ClientCertsRequired})
	strict := mtlsListener(t, srv)
	if _, err := postTelemetryAs(t, agentClient(t, srv, nil), strict, "linux-alpha", nil); err == nil {
		t.Fatalf("--client-certs required let an endpoint with no certificate through")
	}
	own := issueAgentCert(t, srv.pki, "linux-alpha")
	if code, err := postTelemetryAs(t, agentClient(t, srv, own), strict, "linux-alpha", nil); err != nil || code != http.StatusOK {
		t.Fatalf("an enrolled endpoint got %d (err %v) from a hub requiring certificates; want 200", code, err)
	}
}

// The Windows agent cannot use the PEM pair: WinHTTP wants a certificate
// context that already has its key attached, and PFXImportCertStore is the only
// way to build one from a file. So the bundle has to carry a PKCS#12 archive,
// and it has to hold the same identity as the PEM beside it.
func TestClientBundleCarriesAPKCS12ArchiveForWindows(t *testing.T) {
	srv, store := setupTestServer(t)
	defer store.Close()
	defer srv.Close()

	bundle, err := srv.pki.IssueClientCert("win11-alpha", "10.0.0.9")
	if err != nil {
		t.Fatalf("IssueClientCert failed: %v", err)
	}
	if bundle.PFXBase64 == "" {
		t.Fatalf("no PKCS#12 archive in the bundle; the Windows agent has nothing to present")
	}
	der, err := base64.StdEncoding.DecodeString(bundle.PFXBase64)
	if err != nil {
		t.Fatalf("pfx_base64 does not decode: %v", err)
	}
	// DecodeChain, not Decode: the archive carries the issuing CA alongside the
	// leaf and its key, which is what lets PFXImportCertStore build a chain on a
	// host that has not been given the CA any other way.
	key, cert, ca, err := pkcs12.DecodeChain(der, "")
	if err != nil {
		t.Fatalf("the archive does not open with an empty password, which is what the agent uses: %v", err)
	}
	if len(ca) == 0 {
		t.Errorf("the archive carries no issuing CA, so the imported certificate would not chain")
	}
	if key == nil {
		t.Errorf("the archive has no private key, so WinHTTP could not sign a handshake with it")
	}
	if cert.Subject.CommonName != "win11-alpha" {
		t.Errorf("the archive names %q; the hub binds requests to %q", cert.Subject.CommonName, "win11-alpha")
	}
}

// Whether the listener *asks* for a certificate is a separate decision from
// what it does with one, and it is not a free one: a TLS CertificateRequest has
// to be answered, and WinHTTP fails the handshake outright rather than
// answering it with an empty certificate. Turning "optional" on therefore took
// every Windows endpoint on the fleet offline at once - and off a hub they then
// could not reach to be given a certificate by. This pins the three modes to
// the handshake behaviour each one implies, because the difference between them
// is invisible until an agent that cannot answer meets one.
func TestClientCertModeDecidesWhetherTheHandshakeAsksAtAll(t *testing.T) {
	srv, store := setupTestServer(t)
	defer store.Close()
	defer srv.Close()

	for _, tc := range []struct {
		mode     ClientCertMode
		want     tls.ClientAuthType
		wantPool bool
	}{
		{ClientCertsOff, tls.NoClientCert, false},
		{"", tls.VerifyClientCertIfGiven, true},
		{ClientCertsOptional, tls.VerifyClientCertIfGiven, true},
		{ClientCertsRequired, tls.RequireAndVerifyClientCert, true},
	} {
		srv.SetTLS(TLSOptions{Listen: "127.0.0.1:0", ClientCerts: tc.mode})
		cfg, err := srv.tlsConfig()
		if err != nil {
			t.Fatalf("%q: tlsConfig failed: %v", tc.mode, err)
		}
		if cfg.ClientAuth != tc.want {
			t.Errorf("%q: ClientAuth is %v, want %v", tc.mode, cfg.ClientAuth, tc.want)
		}
		if (cfg.ClientCAs != nil) != tc.wantPool {
			t.Errorf("%q: ClientCAs pool present = %v, want %v", tc.mode, cfg.ClientCAs != nil, tc.wantPool)
		}
	}

	// Off is a recovery setting, not a spelling mistake: an unrecognized value
	// has to stop the hub rather than quietly pick one of the three.
	for _, bad := range []string{"yes", "true", "require", "optionall"} {
		if _, err := ParseClientCertMode(bad); err == nil {
			t.Errorf("ParseClientCertMode(%q) was accepted", bad)
		}
	}
	for in, want := range map[string]ClientCertMode{
		"":          ClientCertsOptional,
		"OFF":       ClientCertsOff,
		" required": ClientCertsRequired,
	} {
		got, err := ParseClientCertMode(in)
		if err != nil || got != want {
			t.Errorf("ParseClientCertMode(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
}

// TestTheConsoleCanSeeWhichEndpointsAreCertificateBound covers the reading an
// operator has to take before turning --client-certs required on. Without it
// the only way to find out who would fall off the fleet is to turn it on and
// watch.
func TestTheConsoleCanSeeWhichEndpointsAreCertificateBound(t *testing.T) {
	srv, store := setupTestServer(t)
	defer store.Close()
	defer srv.Close()

	srv.SetTLS(TLSOptions{Listen: "127.0.0.1:0"})
	base := mtlsListener(t, srv)

	// One endpoint reports under a certificate, one under the key alone.
	bound := agentClient(t, srv, issueAgentCert(t, srv.pki, "linux-alpha"))
	if code, err := postTelemetryAs(t, bound, base, "linux-alpha", nil); err != nil || code != http.StatusOK {
		t.Fatalf("certificate holder got %d (err %v); want 200", code, err)
	}
	plain := agentClient(t, srv, nil)
	if code, err := postTelemetryAs(t, plain, base, "linux-beta", nil); err != nil || code != http.StatusOK {
		t.Fatalf("key-only endpoint got %d (err %v); want 200", code, err)
	}

	byID := func() map[string]string {
		eps, err := store.ListEndpoints("")
		if err != nil {
			t.Fatalf("listing endpoints: %v", err)
		}
		out := map[string]string{}
		for _, e := range eps {
			out[e.ID] = e.CertCN
		}
		return out
	}

	seen := byID()
	if seen["linux-alpha"] != "linux-alpha" {
		t.Errorf("an endpoint that reported under its certificate shows cert_cn %q; want %q", seen["linux-alpha"], "linux-alpha")
	}
	if seen["linux-beta"] != "" {
		t.Errorf("an endpoint that never presented a certificate shows cert_cn %q; want empty", seen["linux-beta"])
	}

	// An endpoint that stops presenting one has to stop showing one, or the
	// console keeps reporting a binding that is no longer being enforced.
	if code, err := postTelemetryAs(t, plain, base, "linux-alpha", nil); err != nil || code != http.StatusOK {
		t.Fatalf("the same endpoint reporting without a certificate got %d (err %v); want 200", code, err)
	}
	if cn := byID()["linux-alpha"]; cn != "" {
		t.Errorf("an endpoint that stopped presenting a certificate still shows cert_cn %q; want empty", cn)
	}
}
