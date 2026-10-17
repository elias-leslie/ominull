package bootstrap

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
)

// TestPublishedPackagesVerifyForFreshInstall is the release gate for new
// installs: both bootstrap scripts verify the downloaded package's .sig with
// releasePublicKeyPEM, the key this hub embeds, so every published endpoint
// package must verify under it. release.sh runs it on the signed dist
// directory (OMINULL_FRESH_INSTALL_DIST); it is skipped otherwise.
func TestPublishedPackagesVerifyForFreshInstall(t *testing.T) {
	dist := os.Getenv("OMINULL_FRESH_INSTALL_DIST")
	version := os.Getenv("OMINULL_RELEASE_VERSION")
	if dist == "" || version == "" {
		t.Skip("release gate: set OMINULL_FRESH_INSTALL_DIST and OMINULL_RELEASE_VERSION")
	}
	pub := embeddedReleaseKey(t)
	for _, name := range []string{
		"ominull-agent_" + version + "_amd64.deb",
		"ominull-agent-windows-" + version + ".msi",
	} {
		if err := verifyPackage(pub, filepath.Join(dist, name)); err != nil {
			t.Errorf("a fresh install would refuse %s: %v", name, err)
		}
	}
}

func embeddedReleaseKey(t *testing.T) *ecdsa.PublicKey {
	t.Helper()
	block, _ := pem.Decode([]byte(releasePublicKeyPEM))
	if block == nil {
		t.Fatal("the embedded release key is not PEM")
	}
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	pub, ok := key.(*ecdsa.PublicKey)
	if !ok {
		t.Fatal("the embedded release key is not ECDSA")
	}
	return pub
}

type verifyError string

func (e verifyError) Error() string { return string(e) }

// verifyPackage checks PATH.sig (DER ECDSA over SHA-256), as both bootstrap
// scripts do.
func verifyPackage(pub *ecdsa.PublicKey, path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	sig, err := os.ReadFile(path + ".sig")
	if err != nil {
		return err
	}
	sum := sha256.Sum256(data)
	if !ecdsa.VerifyASN1(pub, sum[:], sig) {
		return verifyError("signature does not verify under the key the bootstrap embeds")
	}
	return nil
}

// TestFreshInstallGateRefusesAnotherKey keeps the gate honest: a package
// signed with any other key fails it.
func TestFreshInstallGateRefusesAnotherKey(t *testing.T) {
	dir := t.TempDir()
	pkg := filepath.Join(dir, "a.deb")
	if err := os.WriteFile(pkg, []byte("package"), 0o600); err != nil {
		t.Fatal(err)
	}
	other, err := ecdsa.GenerateKey(embeddedReleaseKey(t).Curve, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte("package"))
	sig, err := ecdsa.SignASN1(rand.Reader, other, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pkg+".sig", sig, 0o600); err != nil {
		t.Fatal(err)
	}
	if verifyPackage(embeddedReleaseKey(t), pkg) == nil {
		t.Fatal("a package signed with another key passed the fresh-install gate")
	}
	if verifyPackage(&other.PublicKey, pkg) != nil {
		t.Fatal("the gate refused a correctly signed package")
	}
}
