package bootstrap

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"ominull/hub/pkg/response"
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
func runBashVerify(t *testing.T, block, dir, pkg, version string, floor int64) (bool, string) {
	t.Helper()
	cmd := exec.Command("bash", "-c", block+"\nominull_verify_package \"$@\"", "bash", dir, pkg, version, strconv.FormatInt(floor, 10))
	out, err := cmd.CombinedOutput()
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
func runPwshVerify(t *testing.T, pwsh, block, dir, pkg, version string, floor int64) (bool, string) {
	t.Helper()
	q := func(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }
	runner := filepath.Join(dir, "run.ps1")
	body := block + "\n$ErrorActionPreference = 'Stop'\n" +
		"$pem = [IO.File]::ReadAllText(" + q(filepath.Join(dir, "release.pub")) + ")\n" +
		"if (Confirm-OminullPackage -Dir " + q(dir) + " -Package " + q(pkg) + " -Version " + q(version) +
		" -Floor " + strconv.FormatInt(floor, 10) + " -ReleaseKeyPem $pem) { exit 0 } else { exit 1 }\n"
	if err := os.WriteFile(runner, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command(pwsh, "-NoProfile", "-NonInteractive", "-File", runner).CombinedOutput()
	return err == nil, string(out)
}

func newP256(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func pubPEM(t *testing.T, k *ecdsa.PrivateKey) []byte {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(&k.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
}

func xyHex(k *ecdsa.PrivateKey) string {
	out := make([]byte, 64)
	k.X.FillBytes(out[:32])
	k.Y.FillBytes(out[32:])
	return hex.EncodeToString(out)
}

func signDER(t *testing.T, k *ecdsa.PrivateKey, msg []byte) []byte {
	t.Helper()
	sum := sha256.Sum256(msg)
	sig, err := ecdsa.SignASN1(rand.Reader, k, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	return sig
}

// routineList is the hub's /download/routine-keys.json body: keysLine
// signed (statement for epoch and keysLine) by signer.
func routineList(t *testing.T, signer *ecdsa.PrivateKey, epoch int64, keysLine string) []byte {
	t.Helper()
	stmt := "OMINULL-ROUTINE-KEYS-V1\nepoch=" + strconv.FormatInt(epoch, 10) + "\nkeys=" + keysLine + "\n"
	raw, err := json.Marshal(response.RoutineKeys{Epoch: epoch, Keys: keysLine, Sig: base64.StdEncoding.EncodeToString(signDER(t, signer, []byte(stmt)))})
	if err != nil {
		t.Fatal(err)
	}
	return append(raw, '\n')
}

func keysLine(t *testing.T, keys ...*ecdsa.PrivateKey) string {
	t.Helper()
	var list []response.RoutineKey
	for i, k := range keys {
		list = append(list, response.RoutineKey{ID: fmt.Sprintf("%016x", 0x1000+i), XY: xyHex(k)})
	}
	line, err := response.FormatRoutineKeyList(list)
	if err != nil {
		t.Fatal(err)
	}
	return line
}

const testVersion = "1.2.3"

type freshInstallCase struct {
	name   string
	floor  int64
	accept bool
	setup  func(t *testing.T, w *fixtureWriter)
}

type fixtureWriter struct {
	dir, pkg string
	data     []byte
	release  *ecdsa.PrivateKey
	routine  *ecdsa.PrivateKey
	other    *ecdsa.PrivateKey
}

func (w *fixtureWriter) write(t *testing.T, name string, b []byte) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(w.dir, name), b, 0o600); err != nil {
		t.Fatal(err)
	}
}

// signedBy writes the package's .sig and .release.sig (for version) by k.
func (w *fixtureWriter) signedBy(t *testing.T, k *ecdsa.PrivateKey, version string) {
	t.Helper()
	sum := sha256.Sum256(w.data)
	w.write(t, w.pkg+".sig", signDER(t, k, w.data))
	w.write(t, w.pkg+".release.sig", signDER(t, k, []byte(response.ReleaseStatement(w.pkg, version, hex.EncodeToString(sum[:])))))
}

func freshInstallCases() []freshInstallCase {
	return []freshInstallCase{
		{name: "release-key package installs", accept: true, setup: func(t *testing.T, w *fixtureWriter) {
			w.write(t, w.pkg+".sig", signDER(t, w.release, w.data))
		}},
		{name: "routine-key package with the signed list installs", floor: 1, accept: true, setup: func(t *testing.T, w *fixtureWriter) {
			w.signedBy(t, w.routine, testVersion)
			w.write(t, "routine-keys.json", routineList(t, w.release, 1, keysLine(t, w.routine)))
		}},
		{name: "routine-key package, second of two listed keys, installs", accept: true, setup: func(t *testing.T, w *fixtureWriter) {
			w.signedBy(t, w.routine, testVersion)
			w.write(t, "routine-keys.json", routineList(t, w.release, 3, keysLine(t, w.other, w.routine)))
		}},
		{name: "missing list", setup: func(t *testing.T, w *fixtureWriter) {
			w.signedBy(t, w.routine, testVersion)
		}},
		{name: "tampered list", setup: func(t *testing.T, w *fixtureWriter) {
			w.signedBy(t, w.other, testVersion)
			good := routineList(t, w.release, 1, keysLine(t, w.routine))
			w.write(t, "routine-keys.json", []byte(strings.Replace(string(good), xyHex(w.routine), xyHex(w.other), 1)))
		}},
		{name: "list signed by a routine key", setup: func(t *testing.T, w *fixtureWriter) {
			w.signedBy(t, w.routine, testVersion)
			w.write(t, "routine-keys.json", routineList(t, w.routine, 1, keysLine(t, w.routine)))
		}},
		{name: "package signed by an unlisted key", setup: func(t *testing.T, w *fixtureWriter) {
			w.signedBy(t, w.other, testVersion)
			w.write(t, "routine-keys.json", routineList(t, w.release, 1, keysLine(t, w.routine)))
		}},
		{name: "list older than the hub's (retired epoch)", floor: 2, setup: func(t *testing.T, w *fixtureWriter) {
			w.signedBy(t, w.routine, testVersion)
			w.write(t, "routine-keys.json", routineList(t, w.release, 1, keysLine(t, w.routine)))
		}},
		{name: "every routine key retired", floor: 1, setup: func(t *testing.T, w *fixtureWriter) {
			w.signedBy(t, w.routine, testVersion)
			w.write(t, "routine-keys.json", routineList(t, w.release, 2, ""))
		}},
		{name: "release statement for another version", setup: func(t *testing.T, w *fixtureWriter) {
			w.signedBy(t, w.routine, "1.2.2")
			w.write(t, "routine-keys.json", routineList(t, w.release, 1, keysLine(t, w.routine)))
		}},
		{name: "no release statement signature", setup: func(t *testing.T, w *fixtureWriter) {
			w.write(t, w.pkg+".sig", signDER(t, w.routine, w.data))
			w.write(t, "routine-keys.json", routineList(t, w.release, 1, keysLine(t, w.routine)))
		}},
		{name: "unsorted list", setup: func(t *testing.T, w *fixtureWriter) {
			w.signedBy(t, w.routine, testVersion)
			line := "00000000000000b0:" + xyHex(w.routine) + ",00000000000000a0:" + xyHex(w.other)
			w.write(t, "routine-keys.json", routineList(t, w.release, 1, line))
		}},
	}
}

func runFreshInstallCases(t *testing.T, check func(t *testing.T, dir, pkg string, floor int64) (bool, string)) {
	release, routine, other := newP256(t), newP256(t), newP256(t)
	for _, c := range freshInstallCases() {
		t.Run(c.name, func(t *testing.T) {
			w := &fixtureWriter{dir: t.TempDir(), pkg: "ominull-agent_" + testVersion + "_amd64.deb",
				data: []byte("package " + c.name), release: release, routine: routine, other: other}
			w.write(t, w.pkg, w.data)
			w.write(t, "release.pub", pubPEM(t, release))
			c.setup(t, w)
			ok, out := check(t, w.dir, w.pkg, c.floor)
			if ok != c.accept {
				t.Fatalf("accepted=%v, want %v:\n%s", ok, c.accept, out)
			}
			if !ok && !strings.Contains(out, "Refused.") { // refused by the check itself, not by a script error
				t.Fatalf("refused without the check's own reason:\n%s", out)
			}
		})
	}
}

// A new Linux install takes a package signed by a routine key only through a
// list the embedded release key signed, at the hub's epoch or later.
func TestBashFreshInstallRoutineKeys(t *testing.T) {
	block := verifyBlock(t, GenerateBash(Options{HubURL: "https://hub.example.invalid", RoutineFloor: 4}))
	if !strings.Contains(GenerateBash(Options{HubURL: "https://hub.example.invalid", RoutineFloor: 4}), "ROUTINE_FLOOR=4") {
		t.Fatal("the floor is not rendered")
	}
	runFreshInstallCases(t, func(t *testing.T, dir, pkg string, floor int64) (bool, string) {
		return runBashVerify(t, block, dir, pkg, testVersion, floor)
	})
}

// The same for a new Windows install (needs PowerShell 7: OMINULL_PWSH or pwsh).
func TestPowerShellFreshInstallRoutineKeys(t *testing.T) {
	pwsh := pwshPath()
	if pwsh == "" {
		t.Skip("PowerShell 7 not found (set OMINULL_PWSH)")
	}
	script := GeneratePowerShell(Options{HubURL: "https://hub.example.invalid", RoutineFloor: 4})
	if !strings.Contains(script, "$RoutineFloor = 4") {
		t.Fatal("the floor is not rendered")
	}
	block := verifyBlock(t, script)
	runFreshInstallCases(t, func(t *testing.T, dir, pkg string, floor int64) (bool, string) {
		return runPwshVerify(t, pwsh, block, dir, pkg, testVersion, floor)
	})
}
