package deployer

import (
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"ominull/hub/pkg/storage"
)

func newHostKey(t *testing.T) ssh.PublicKey {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	_ = priv
	signerPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatalf("NewPublicKey: %v", err)
	}
	return signerPub
}

// TestHostKeyIsVerified. The push deployer sends the target's credentials, the
// installer and the endpoint's whole enrolment down this connection, and it
// used to accept whatever key answered - so anything that could reply on that
// address collected all of it and could return an installer of its own.
func TestHostKeyIsVerified(t *testing.T) {
	store, err := storage.New(":memory:")
	if err != nil {
		t.Fatalf("storage.New: %v", err)
	}
	defer store.Close()

	d := New(store, "http://10.0.0.57:9999", "admin-key")
	req := DeployRequest{TargetIP: "10.0.0.9", Port: 22}
	key, other := newHostKey(t), newHostKey(t)

	// First contact records the key and accepts it.
	cb, recorded, err := d.hostKeyCallback(req)
	if err != nil {
		t.Fatalf("hostKeyCallback: %v", err)
	}
	if err := cb("10.0.0.9:22", &net.TCPAddr{}, key); err != nil {
		t.Fatalf("first contact was refused: %v", err)
	}
	if recorded() != keyFingerprint(key) {
		t.Errorf("first contact did not report the key it recorded: %q", recorded())
	}

	// The same key on a later deploy is accepted without being re-recorded.
	cb, recorded, _ = d.hostKeyCallback(req)
	if err := cb("10.0.0.9:22", &net.TCPAddr{}, key); err != nil {
		t.Errorf("the recorded key was refused on a later deploy: %v", err)
	}
	if recorded() != "" {
		t.Errorf("a known host was reported as first contact")
	}

	// A different key is refused, and the refusal names what answered.
	cb, _, _ = d.hostKeyCallback(req)
	err = cb("10.0.0.9:22", &net.TCPAddr{}, other)
	if err == nil {
		t.Fatal("a changed host key was accepted")
	}
	if !strings.Contains(err.Error(), keyFingerprint(other)) {
		t.Errorf("the refusal does not name the key that answered: %v", err)
	}

	// An explicit pin is checked even on a host never seen before.
	pinned := DeployRequest{TargetIP: "10.0.0.10", Port: 22, HostKeyFingerprint: keyFingerprint(key)}
	cb, _, _ = d.hostKeyCallback(pinned)
	if err := cb("10.0.0.10:22", &net.TCPAddr{}, other); err == nil {
		t.Error("a pinned fingerprint accepted a different key")
	}
	cb, _, _ = d.hostKeyCallback(pinned)
	if err := cb("10.0.0.10:22", &net.TCPAddr{}, key); err != nil {
		t.Errorf("a pinned fingerprint refused the key it names: %v", err)
	}
}

// TestGeneratedInstallerCarriesTheTenantKey. The deploy is authorised with the
// admin key; what it leaves installed must not be. It also replaces the old
// `curl "<hub>/bootstrap.sh?..." | sudo bash`, which had no key at all - the hub
// answered 401 and the target piped that error page into a root shell.
func TestGeneratedInstallerCarriesTheTenantKey(t *testing.T) {
	store, err := storage.New(":memory:")
	if err != nil {
		t.Fatalf("storage.New: %v", err)
	}
	defer store.Close()

	d := New(store, "http://10.0.0.57:9999", "admin-key-do-not-ship")
	d.SetAgentHubURL("https://10.0.0.57:9443")

	tenant, err := store.GetTenant("default")
	if err != nil || tenant == nil {
		t.Fatalf("default tenant: %v", err)
	}

	for _, targetOS := range []string{"linux", "macos", "windows"} {
		script, err := d.renderInstaller(targetOS, DeployRequest{TargetIP: "10.0.0.9", EndpointID: "linux-a", Role: "server"})
		if err != nil {
			t.Fatalf("renderInstaller(%s): %v", targetOS, err)
		}
		if strings.Contains(script, "admin-key-do-not-ship") {
			t.Errorf("%s installer carries the hub admin key", targetOS)
		}
		if !strings.Contains(script, tenant.APIKey) {
			t.Errorf("%s installer does not carry the tenant key", targetOS)
		}
		if !strings.Contains(script, "X-Enrollment-Token") {
			t.Errorf("%s installer enrols without a single-use token", targetOS)
		}
		if !strings.Contains(script, "https://10.0.0.57:9443") {
			t.Errorf("%s installer does not point the agent at the TLS transport", targetOS)
		}
	}
}
