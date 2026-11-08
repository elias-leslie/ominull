package bootstrap

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// verifyBlock cuts the package check out of a rendered script.
func verifyBlock(t *testing.T, script string) string {
	t.Helper()
	i := strings.Index(script, VerifyBlockStart)
	j := strings.Index(script, VerifyBlockEnd)
	if i < 0 || j < i {
		t.Fatal("the rendered script has no package check block")
	}
	return script[i : j+len(VerifyBlockEnd)]
}

// runBashVerify runs the Linux script's check on dir (release.pub there is
// the release key) and says whether it accepted the package.
func runBashVerify(t *testing.T, block, dir, pkg string) (bool, string) {
	t.Helper()
	out, err := exec.Command("bash", "-c", block+"\nominull_verify_package \"$@\"", "bash", dir, pkg).CombinedOutput()
	return err == nil, string(out)
}

func pwshPath() string {
	if p := os.Getenv("OMINULL_PWSH"); p != "" {
		return p
	}
	p, _ := exec.LookPath("pwsh")
	return p
}

// runPwshVerify runs the Windows script's check the same way under
// PowerShell 7 (ECParameters where CNG is missing; Windows uses CNG).
func runPwshVerify(t *testing.T, pwsh, block, dir, pkg string) (bool, string) {
	t.Helper()
	q := func(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }
	runner := filepath.Join(dir, "run.ps1")
	body := block + "\n$ErrorActionPreference = 'Stop'\n" +
		"$pem = [IO.File]::ReadAllText(" + q(filepath.Join(dir, "release.pub")) + ")\n" +
		"if (Confirm-OminullPackage -Dir " + q(dir) + " -Package " + q(pkg) + " -ReleaseKeyPem $pem) { exit 0 } else { exit 1 }\n"
	if err := os.WriteFile(runner, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command(pwsh, "-NoProfile", "-NonInteractive", "-File", runner).CombinedOutput()
	return err == nil, string(out)
}

// TestPublishedPackagesVerifyForFreshInstall is the release gate for new
// installs: it runs the package check of both bootstrap scripts, with the
// release key this hub embeds, on the signed dist directory
// (OMINULL_FRESH_INSTALL_DIST, set by release.sh; skipped otherwise). The
// Windows script's check runs when PowerShell 7 is found (OMINULL_PWSH or pwsh).
func TestPublishedPackagesVerifyForFreshInstall(t *testing.T) {
	dist := os.Getenv("OMINULL_FRESH_INSTALL_DIST")
	version := os.Getenv("OMINULL_RELEASE_VERSION")
	if dist == "" || version == "" {
		t.Skip("release gate: set OMINULL_FRESH_INSTALL_DIST and OMINULL_RELEASE_VERSION")
	}
	bash := verifyBlock(t, GenerateBash(Options{HubURL: "https://hub.example.invalid"}))
	ps := verifyBlock(t, GeneratePowerShell(Options{HubURL: "https://hub.example.invalid"}))
	pwsh := pwshPath()
	if pwsh == "" {
		t.Log("PowerShell 7 not found: only the Linux script's check ran")
	}
	for _, name := range []string{
		"ominull-agent_" + version + "_amd64.deb",
		"ominull-agent-windows-" + version + ".msi",
	} {
		// A copy as the script downloads it: the package, .sig and the
		// embedded key as release.pub.
		dir := t.TempDir()
		for _, f := range []string{name, name + ".sig"} {
			if err := os.Symlink(filepath.Join(dist, f), filepath.Join(dir, f)); err != nil {
				t.Fatal(err)
			}
		}
		if err := os.WriteFile(filepath.Join(dir, "release.pub"), []byte(releasePublicKeyPEM), 0o600); err != nil {
			t.Fatal(err)
		}
		if ok, out := runBashVerify(t, bash, dir, name); !ok {
			t.Errorf("a fresh Linux-script install would refuse %s:\n%s", name, out)
		}
		if pwsh != "" {
			if ok, out := runPwshVerify(t, pwsh, ps, dir, name); !ok {
				t.Errorf("a fresh Windows-script install would refuse %s:\n%s", name, out)
			}
		}
	}
}

// Both scripts install a package the release key signed and refuse anything
// else: another key's signature, or bytes changed after signing.
func TestPackageCheckTakesOnlyTheReleaseKey(t *testing.T) {
	newKey := func() *ecdsa.PrivateKey {
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		return k
	}
	release, other := newKey(), newKey()
	der, err := x509.MarshalPKIXPublicKey(&release.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	pub := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	const pkg = "ominull-agent_1.2.3_amd64.deb"
	data := []byte("package bytes")
	sign := func(k *ecdsa.PrivateKey) []byte {
		sum := sha256.Sum256(data)
		sig, err := ecdsa.SignASN1(rand.Reader, k, sum[:])
		if err != nil {
			t.Fatal(err)
		}
		return sig
	}
	bash := verifyBlock(t, GenerateBash(Options{HubURL: "https://hub.example.invalid"}))
	ps := verifyBlock(t, GeneratePowerShell(Options{HubURL: "https://hub.example.invalid"}))
	pwsh := pwshPath()
	for _, tc := range []struct {
		name string
		sig  []byte
		body []byte
		want bool
	}{
		{"signed by the release key", sign(release), data, true},
		{"signed by another key", sign(other), data, false},
		{"changed after signing", sign(release), []byte("other bytes"), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			for name, b := range map[string][]byte{pkg: tc.body, pkg + ".sig": tc.sig, "release.pub": pub} {
				if err := os.WriteFile(filepath.Join(dir, name), b, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if ok, out := runBashVerify(t, bash, dir, pkg); ok != tc.want {
				t.Errorf("Linux script: accepted=%v, want %v\n%s", ok, tc.want, out)
			}
			if pwsh != "" {
				if ok, out := runPwshVerify(t, pwsh, ps, dir, pkg); ok != tc.want {
					t.Errorf("Windows script: accepted=%v, want %v\n%s", ok, tc.want, out)
				}
			}
		})
	}
}

// Both rendered scripts still parse after the check was added.
func TestRenderedScriptsParse(t *testing.T) {
	opts := Options{HubURL: "https://hub.example.invalid"}
	dir := t.TempDir()
	sh := filepath.Join(dir, "install.sh")
	if err := os.WriteFile(sh, []byte(GenerateBash(opts)), 0o600); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("bash", "-n", sh).CombinedOutput(); err != nil {
		t.Fatalf("bash -n: %v\n%s", err, out)
	}
	pwsh := pwshPath()
	if pwsh == "" {
		t.Skip("PowerShell 7 not found (set OMINULL_PWSH)")
	}
	ps := filepath.Join(dir, "install.ps1")
	if err := os.WriteFile(ps, []byte(GeneratePowerShell(opts)), 0o600); err != nil {
		t.Fatal(err)
	}
	check := `$e = $null; [void][System.Management.Automation.Language.Parser]::ParseFile('` + ps + `', [ref]$null, [ref]$e); if ($e.Count) { $e | ForEach-Object { $_.ToString() }; exit 1 }`
	if out, err := exec.Command(pwsh, "-NoProfile", "-NonInteractive", "-Command", check).CombinedOutput(); err != nil {
		t.Fatalf("PowerShell parse: %v\n%s", err, out)
	}
}
