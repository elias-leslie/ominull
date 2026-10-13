package server

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"ominull/hub/pkg/pki"
	"ominull/hub/pkg/scanner"
	"ominull/hub/pkg/storage"
)

// Generating the hub's RSA-4096 root CA takes about a second, and almost every
// test here builds a fresh hub. The package generates one real CA with the
// production code path and seeds each test's certificate directory with it;
// pki.New then loads it exactly as a restarted hub loads its preserved CA.
// Tests that need a CA of their own call pki.New on an empty directory.
var sharedTestCA struct {
	once sync.Once
	dir  string
	err  error
}

func TestMain(m *testing.M) {
	code := m.Run()
	if sharedTestCA.dir != "" {
		_ = os.RemoveAll(sharedTestCA.dir)
	}
	os.Exit(code)
}

// seedTestCA places the package's shared CA in binaryDir/certs, where New
// looks for it, unless that directory already holds a CA.
func seedTestCA(t testing.TB, binaryDir string) {
	t.Helper()
	sharedTestCA.once.Do(func() {
		dir, err := os.MkdirTemp("", "ominull-server-test-ca-")
		if err != nil {
			sharedTestCA.err = err
			return
		}
		sharedTestCA.dir = dir
		_, sharedTestCA.err = pki.New(dir)
	})
	if sharedTestCA.err != nil {
		t.Fatalf("generate shared test CA: %v", sharedTestCA.err)
	}
	certDir := filepath.Join(binaryDir, "certs")
	if _, err := os.Stat(filepath.Join(certDir, "ca.key")); err == nil {
		return
	}
	if err := os.MkdirAll(certDir, 0700); err != nil {
		t.Fatalf("create test cert dir: %v", err)
	}
	for name, mode := range map[string]os.FileMode{"ca.crt": 0644, "ca.key": 0600} {
		data, err := os.ReadFile(filepath.Join(sharedTestCA.dir, name))
		if err != nil {
			t.Fatalf("read shared test CA %s: %v", name, err)
		}
		if err := os.WriteFile(filepath.Join(certDir, name), data, mode); err != nil {
			t.Fatalf("seed test CA %s: %v", name, err)
		}
	}
}

// newTestServer is New with the package's shared CA already in place.
//
// It also records that the configured public URL does not answer as this hub.
// Test hubs are configured with LAN addresses such as 10.0.0.57 that nothing
// in the test serves, and rendering a one-line installer would otherwise spend
// the probe's four-second timeout dialling whatever that address is on the
// host's network. The probe itself is covered against local servers in
// TestProbeRejectsAnOriginThatIsNotThisHub, which calls probeServesHub directly.
func newTestServer(t testing.TB, store *storage.Store, adminKey, binaryDir, hubURL, agentVersion string) *Server {
	t.Helper()
	seedTestCA(t, binaryDir)
	srv := New(store, adminKey, binaryDir, hubURL, agentVersion)
	// A test proves the hub accepts or refuses a sweep; it never runs one.
	srv.startScan = func(subnet string, _ scanner.ScanProfile) (string, error) { return "test-scan-" + subnet, nil }
	srv.startSweeps = func() {}
	srv.publicURLMu.Lock()
	srv.publicURLOK = false
	srv.publicURLAt = time.Now()
	srv.publicURLMu.Unlock()
	return srv
}
