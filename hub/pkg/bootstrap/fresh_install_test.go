package bootstrap

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"ominull/hub/pkg/response"
)

// TestPublishedPackagesVerifyForFreshInstall is the release gate for new
// installs: it runs the package check of both bootstrap scripts, with the
// release key this hub embeds, on the signed dist directory
// (OMINULL_FRESH_INSTALL_DIST, set by release.sh; skipped otherwise). A
// release signed with a routine key passes only with dist/routine-keys.json,
// the list the release key signed, as the hub will serve it. The Windows
// script's check runs when PowerShell 7 is found (OMINULL_PWSH or pwsh).
func TestPublishedPackagesVerifyForFreshInstall(t *testing.T) {
	dist := os.Getenv("OMINULL_FRESH_INSTALL_DIST")
	version := os.Getenv("OMINULL_RELEASE_VERSION")
	if dist == "" || version == "" {
		t.Skip("release gate: set OMINULL_FRESH_INSTALL_DIST and OMINULL_RELEASE_VERSION")
	}
	var floor int64
	list, err := os.ReadFile(filepath.Join(dist, "routine-keys.json"))
	if err == nil {
		var rk response.RoutineKeys
		if json.Unmarshal(list, &rk) != nil {
			t.Fatal("dist/routine-keys.json is not a routine key list")
		}
		floor = rk.Epoch // what the hub will hold once deployed
	} else if !os.IsNotExist(err) {
		t.Fatal(err)
	}
	bash := verifyBlock(t, GenerateBash(Options{HubURL: "https://hub.example.invalid", RoutineFloor: floor}))
	ps := verifyBlock(t, GeneratePowerShell(Options{HubURL: "https://hub.example.invalid", RoutineFloor: floor}))
	pwsh := pwshPath()
	if pwsh == "" {
		t.Log("PowerShell 7 not found: only the Linux script's check ran")
	}
	for _, name := range []string{
		"ominull-agent_" + version + "_amd64.deb",
		"ominull-agent-windows-" + version + ".msi",
	} {
		// A copy as the script downloads it: the package, .sig, .release.sig,
		// the hub's routine key list and the embedded key as release.pub.
		dir := t.TempDir()
		for _, f := range []string{name, name + ".sig", name + ".release.sig"} {
			linkOrSkip(t, filepath.Join(dist, f), filepath.Join(dir, f))
		}
		if list != nil {
			if err := os.WriteFile(filepath.Join(dir, "routine-keys.json"), list, 0o600); err != nil {
				t.Fatal(err)
			}
		}
		if err := os.WriteFile(filepath.Join(dir, "release.pub"), []byte(releasePublicKeyPEM), 0o600); err != nil {
			t.Fatal(err)
		}
		if ok, out := runBashVerify(t, bash, dir, name, version, floor); !ok {
			t.Errorf("a fresh Linux-script install would refuse %s:\n%s", name, out)
		}
		if pwsh != "" {
			if ok, out := runPwshVerify(t, pwsh, ps, dir, name, version, floor); !ok {
				t.Errorf("a fresh Windows-script install would refuse %s:\n%s", name, out)
			}
		}
	}
}

// linkOrSkip puts src at dst; a missing src stays missing (the check then
// decides), anything else fails.
func linkOrSkip(t *testing.T, src, dst string) {
	t.Helper()
	if _, err := os.Stat(src); os.IsNotExist(err) {
		return
	}
	if err := os.Symlink(src, dst); err != nil {
		t.Fatal(err)
	}
}

// Both rendered scripts still parse after the check was added.
func TestRenderedScriptsParse(t *testing.T) {
	opts := Options{HubURL: "https://hub.example.invalid", RoutineFloor: 2}
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
