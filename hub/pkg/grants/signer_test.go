package grants_test

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"ominull/hub/pkg/grants"
)

// writeKeyFile writes a key the way the signer has always stored it: the
// private key in hex, named after the tenant or tenant#slot.
func writeKeyFile(t *testing.T, dir, name string, seed byte) ed25519.PublicKey {
	t.Helper()
	priv := ed25519.NewKeyFromSeed([]byte(strings.Repeat(string(rune(seed)), ed25519.SeedSize)))
	if err := os.MkdirAll(filepath.Join(dir, "keys"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "keys", name+".key"), []byte(hex.EncodeToString(priv)), 0o600); err != nil {
		t.Fatal(err)
	}
	return priv.Public().(ed25519.PublicKey)
}

// State carried over from an earlier signer signs with the same keys: every
// agent pinned them, so a new key would be refused fleet-wide.
func TestOpenKeepsExistingKeys(t *testing.T) {
	dir := t.TempDir()
	response := writeKeyFile(t, dir, "default", 1)
	autoIso := writeKeyFile(t, dir, "default#auto-isolate", 2)
	policy := writeKeyFile(t, dir, "default#policy", 3)
	writeBooks(t, dir)
	s, err := grants.Open(grants.Config{StateDir: dir, RequireKeys: true})
	if err != nil {
		t.Fatal(err)
	}
	k, err := s.TrustKeys("default")
	if err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string][2]string{
		"response":     {k.ResponseKey, hex.EncodeToString(response)},
		"auto-isolate": {k.AutoIsolateKey, hex.EncodeToString(autoIso)},
		"policy":       {k.PolicyKey, hex.EncodeToString(policy)},
	} {
		if want[0] != want[1] {
			t.Errorf("%s key changed: %s, want %s", name, want[0], want[1])
		}
	}
	pub, id, err := s.GetOrCreateTenantKey("default")
	if err != nil {
		t.Fatal(err)
	}
	fp := sha256.Sum256(response)
	if !pub.Equal(response) || id != hex.EncodeToString(fp[:]) {
		t.Errorf("key id is not the sha256 of the public key: %s", id)
	}
}

// With a signed bundle, an empty or partial key directory stops the signer, and
// nothing is written over it.
func TestOpenRefusesMissingKeysOnceABundleIsSigned(t *testing.T) {
	dir := t.TempDir()
	if _, err := grants.Open(grants.Config{StateDir: dir, RequireKeys: true}); err == nil || !strings.Contains(err.Error(), "default") {
		t.Fatalf("an empty key directory should be refused: %v", err)
	}
	writeKeyFile(t, dir, "default", 1)
	if _, err := grants.Open(grants.Config{StateDir: dir, RequireKeys: true}); err == nil || !strings.Contains(err.Error(), "default#auto-isolate") {
		t.Fatalf("a missing slot key should be refused: %v", err)
	}
	entries, _ := os.ReadDir(filepath.Join(dir, "keys"))
	if len(entries) != 1 {
		t.Fatalf("a refused open wrote keys: %d files", len(entries))
	}
	if _, err := grants.Open(grants.Config{StateDir: t.TempDir()}); err != nil {
		t.Fatalf("a first run should open: %v", err)
	}
}

func writeBooks(t *testing.T, dir string) {
	t.Helper()
	for name, body := range map[string]string{"manifests.json": "[]", "trust_epochs.json": "{}"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

// Lost manifest or epoch numbers start over at one, and every agent that pinned
// the keys refuses what the hub signs. A first run writes them, so losing one
// later never looks like a first run.
func TestOpenRefusesLostBooksOnceABundleIsSigned(t *testing.T) {
	first := t.TempDir()
	if _, err := grants.Open(grants.Config{StateDir: first}); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"manifests.json", "trust_epochs.json"} {
		if _, err := os.Stat(filepath.Join(first, name)); err != nil {
			t.Fatalf("a first run should write %s: %v", name, err)
		}
	}
	for _, name := range []string{"manifests.json", "trust_epochs.json"} {
		dir := t.TempDir()
		writeKeyFile(t, dir, "default", 1)
		writeKeyFile(t, dir, "default#auto-isolate", 2)
		writeKeyFile(t, dir, "default#policy", 3)
		writeBooks(t, dir)
		if err := os.Remove(filepath.Join(dir, name)); err != nil {
			t.Fatal(err)
		}
		if _, err := grants.Open(grants.Config{StateDir: dir, RequireKeys: true}); err == nil || !strings.Contains(err.Error(), name) {
			t.Fatalf("a lost %s should be refused: %v", name, err)
		}
	}
}

func TestOpenRefusesBadState(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "keys"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "manifests.json"), []byte("{torn"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := grants.Open(grants.Config{StateDir: dir}); err == nil {
		t.Fatal("corrupt manifests should be refused, not started over at seq 1")
	}
	dir = t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "keys"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "keys", "default.key"), []byte("not hex"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := grants.Open(grants.Config{StateDir: dir}); err == nil {
		t.Fatal("an unreadable key should be refused, not replaced")
	}
}
