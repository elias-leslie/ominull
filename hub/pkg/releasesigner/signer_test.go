package releasesigner

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// testdata/fixture.json: a throwaway seal and keys made once with Python's cryptography in Nightshift's
// store format (release key "test release", routine key "session test", both wrapped for root and p1).
const (
	deb = "!<arch>\ndebian-binary\x00rest of a package"
	ver = "0.0.1-t"
	pkA = "ominull-agent_0.0.1-t_amd64.deb"
	pkB = "ominull-hub_0.0.1-t_amd64.deb"
)

type tenv struct {
	cfg   Config
	store *storeFile
	now   time.Time
}

func newEnv(t *testing.T) *tenv {
	t.Helper()
	b, err := os.ReadFile("testdata/fixture.json")
	if err != nil {
		t.Fatal(err)
	}
	var fx struct {
		SealHex string          `json:"seal_hex"`
		Store   json.RawMessage `json:"store"`
	}
	if err := json.Unmarshal(b, &fx); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	seal, _ := hex.DecodeString(fx.SealHex)
	must(t, os.WriteFile(filepath.Join(dir, "store.json"), fx.Store, 0o600))
	must(t, os.WriteFile(filepath.Join(dir, rootSealFile), seal, 0o600))
	e := &tenv{now: time.Unix(1_800_000_000, 0)}
	e.cfg = Config{Store: dir, Run: filepath.Join(t.TempDir(), "run"), Now: func() time.Time { return e.now }}
	e.store, err = loadStore(dir)
	must(t, err)
	return e
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func pub(t *testing.T, k keyRec) *ecdsa.PublicKey {
	blk, _ := pem.Decode([]byte(k.Pubkey))
	p, err := x509.ParsePKIXPublicKey(blk.Bytes)
	must(t, err)
	return p.(*ecdsa.PublicKey)
}

func (e *tenv) begin(t *testing.T, r Request) string {
	t.Helper()
	id, err := e.cfg.Begin(r)
	must(t, err)
	return id
}

func (e *tenv) sign(id, kind, name string, data []byte) ([]byte, error) {
	return e.cfg.Sign(id, kind, name, int64(len(data)), bytes.NewReader(data))
}

func release(routine bool, pkgs ...string) Request {
	return Request{Op: "release", Routine: routine, Key: "test release", Version: ver, Packages: pkgs}
}

func sum(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }

func wantErr(t *testing.T, err error, sub string) {
	t.Helper()
	if err == nil || !strings.Contains(err.Error(), sub) {
		t.Fatalf("want error containing %q, got %v", sub, err)
	}
}

func TestUnwrapAndSignWithFixtureKeys(t *testing.T) {
	e := newEnv(t)
	for _, routine := range []bool{false, true} {
		id := e.begin(t, release(routine, pkA))
		sig, err := e.sign(id, "package", pkA, []byte(deb))
		must(t, err)
		d := sha256.Sum256([]byte(deb))
		k := e.store.Keys[0]
		if routine {
			k = e.store.RoutineKeys[0]
		}
		if !ecdsa.VerifyASN1(pub(t, k), d[:], sig) {
			t.Fatalf("routine=%v: signature does not verify against the fixture public key", routine)
		}
		st := releaseStatement(pkA, ver, sum([]byte(deb)))
		sig, err = e.sign(id, "statement", pkA, st)
		must(t, err)
		d = sha256.Sum256(st)
		if !ecdsa.VerifyASN1(pub(t, k), d[:], sig) {
			t.Fatal("statement signature does not verify")
		}
		if _, err := os.Stat(e.cfg.path(id)); !os.IsNotExist(err) {
			t.Fatal("a finished session should be deleted")
		}
	}
}

func TestSealChecks(t *testing.T) {
	e := newEnv(t)
	id := e.begin(t, release(false, pkA))
	p := filepath.Join(e.cfg.Store, rootSealFile)
	must(t, os.Chmod(p, 0o640))
	_, err := e.sign(id, "package", pkA, []byte(deb))
	wantErr(t, err, "unexpected owner/mode/size")
	must(t, os.Chmod(p, 0o600))
	e.store.Seals[rootSeal] = struct{ Pub string }{"00"}
	b, _ := json.Marshal(e.store)
	must(t, os.WriteFile(filepath.Join(e.cfg.Store, "store.json"), b, 0o600))
	_, err = e.sign(id, "package", pkA, []byte(deb))
	wantErr(t, err, "does not match the store")
}

func TestHardenFailureRefuses(t *testing.T) {
	e := newEnv(t)
	e.cfg.Harden = func() error { return os.ErrPermission }
	id := e.begin(t, release(false, pkA))
	_, err := e.sign(id, "package", pkA, []byte(deb))
	wantErr(t, err, "cannot lock memory")
}

func TestSessionRules(t *testing.T) {
	e := newEnv(t)
	id := e.begin(t, release(false, pkA, pkB+"="+sum([]byte(deb+"B"))))
	st := releaseStatement(pkA, ver, sum([]byte(deb)))

	_, err := e.sign(id, "statement", pkA, st)
	wantErr(t, err, "comes once, after the package")
	_, err = e.sign(id, "package", pkA, []byte("not a deb at all"))
	wantErr(t, err, "not a deb or MSI")
	_, err = e.sign(id, "package", "other_0.0.1-t.deb", []byte(deb))
	wantErr(t, err, "not one of the requested packages")
	_, err = e.sign(id, "package", pkB, []byte(deb+"changed"))
	wantErr(t, err, "changed since the request")
	_, err = e.sign(id, "trust", pkA, []byte("x"))
	wantErr(t, err, "kind must be")

	_, err = e.sign(id, "package", pkA, []byte(deb))
	must(t, err)
	_, err = e.sign(id, "package", pkA, []byte(deb))
	wantErr(t, err, "already signed")
	_, err = e.sign(id, "statement", pkA, releaseStatement(pkA, ver, sum([]byte("other"))))
	wantErr(t, err, "does not match the signed package")
	_, err = e.sign(id, "statement", pkA, releaseStatement(pkA, "9.9.9", sum([]byte(deb))))
	wantErr(t, err, "does not match the signed package")
	_, err = e.sign(id, "statement", pkA, st)
	must(t, err)
	_, err = e.sign(id, "statement", pkA, st)
	wantErr(t, err, "comes once")

	// MSI magic is accepted; the sha pin passes when it matches.
	msi := append([]byte{0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1}, "x"...)
	id2 := e.begin(t, release(false, "a_0.0.1-t.msi="+sum(msi)))
	_, err = e.sign(id2, "package", "a_0.0.1-t.msi", msi)
	must(t, err)
}

func TestTrustOnce(t *testing.T) {
	e := newEnv(t)
	text := "OMINULL-TRUST-BUNDLE-V1\ntenant=acme\nepoch=3\nkey-a\nkey-b\nkey-c\n"
	id := e.begin(t, Request{Op: "trust", Key: "test release", Tenant: "acme", Statement: text})
	_, err := e.sign(id, "trust", "-", []byte(text+"extra"))
	wantErr(t, err, "only the approved trust statement")
	_, err = e.sign(id, "package", pkA, []byte(deb))
	wantErr(t, err, "only the approved trust statement")
	sig, err := e.sign(id, "trust", "-", []byte(text))
	must(t, err)
	d := sha256.Sum256([]byte(text))
	if !ecdsa.VerifyASN1(pub(t, e.store.Keys[0]), d[:], sig) {
		t.Fatal("trust signature does not verify")
	}
	_, err = e.sign(id, "trust", "-", []byte(text))
	wantErr(t, err, "no such signing session")
}

func TestExpiry(t *testing.T) {
	e := newEnv(t)
	id := e.begin(t, release(false, pkA))
	e.now = e.now.Add(SessionTTL - time.Second)
	_, err := e.sign(id, "package", pkA, []byte(deb))
	must(t, err)
	e.now = e.now.Add(2 * time.Second)
	_, err = e.sign(id, "statement", pkA, releaseStatement(pkA, ver, sum([]byte(deb))))
	wantErr(t, err, "signing time is over")
	if _, err := os.Stat(e.cfg.path(id)); !os.IsNotExist(err) {
		t.Fatal("an expired session should be removed")
	}
}

func TestBeginValidation(t *testing.T) {
	e := newEnv(t)
	good := "OMINULL-TRUST-BUNDLE-V1\ntenant=acme\nepoch=3\na\nb\nc\n"
	cases := []struct {
		name string
		r    Request
		want string
	}{
		{"bad version", Request{Op: "release", Key: "test release", Version: "v1", Packages: []string{"a_v1.deb"}}, "bad version"},
		{"name lacks version", release(false, "ominull-agent_9.9.9_amd64.deb"), "carries the version"},
		{"name with slash", release(false, "../x_0.0.1-t.deb"), "carries the version"},
		{"no packages", release(false), "name 1-8 packages"},
		{"nine packages", release(false, "a1_0.0.1-t", "a2_0.0.1-t", "a3_0.0.1-t", "a4_0.0.1-t", "a5_0.0.1-t", "a6_0.0.1-t", "a7_0.0.1-t", "a8_0.0.1-t", "a9_0.0.1-t"), "name 1-8"},
		{"bad sha", release(false, pkA+"=ABC"), "64 hex"},
		{"twice", release(false, pkA, pkA), "named twice"},
		{"unknown key", Request{Op: "release", Key: "nope", Version: ver, Packages: []string{pkA}}, "0 stored keys"},
		{"bad op", Request{Op: "other"}, "op must be"},
		{"bad tenant", Request{Op: "trust", Key: "test release", Tenant: "a b", Statement: good}, "bad tenant"},
		{"no statement", Request{Op: "trust", Key: "test release", Tenant: "acme"}, "statement is missing"},
		{"wrong tenant", Request{Op: "trust", Key: "test release", Tenant: "other", Statement: good}, "not an OMINULL-TRUST"},
		{"short statement", Request{Op: "trust", Key: "test release", Tenant: "acme", Statement: "OMINULL-TRUST-BUNDLE-V1\ntenant=acme\n"}, "not an OMINULL-TRUST"},
		{"epoch 0", Request{Op: "trust", Key: "test release", Tenant: "acme", Statement: strings.Replace(good, "epoch=3", "epoch=0", 1)}, "not an OMINULL-TRUST"},
	}
	for _, c := range cases {
		if _, err := e.cfg.Begin(c.r); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: want %q, got %v", c.name, c.want, err)
		}
	}
	// A routine key the release key's list does not name is refused.
	e.store.RoutineList.Keys = "ffffffffffffffff:00"
	b, _ := json.Marshal(e.store)
	must(t, os.WriteFile(filepath.Join(e.cfg.Store, "store.json"), b, 0o600))
	_, err := e.cfg.Begin(release(true, pkA))
	wantErr(t, err, "not listed the routine key")
}

func TestEndAndTokenFormat(t *testing.T) {
	e := newEnv(t)
	id := e.begin(t, release(false, pkA))
	must(t, e.cfg.End(id))
	must(t, e.cfg.End(id))
	_, err := e.sign(id, "package", pkA, []byte(deb))
	wantErr(t, err, "no such signing session")
	wantErr(t, e.cfg.End("../x"), "no signing session")
	_, err = e.sign("zz", "package", pkA, []byte(deb))
	wantErr(t, err, "no signing session")
	_, err = e.cfg.Sign(id, "package", pkA, MaxPackage+1, bytes.NewReader(nil))
	wantErr(t, err, "bad size")
}

func TestPubkeyCommand(t *testing.T) {
	e := newEnv(t)
	b, _ := json.Marshal(map[string]any{"keys": e.store.Keys, "routine_keys": e.store.RoutineKeys})
	p := filepath.Join(t.TempDir(), "pub.json")
	must(t, os.WriteFile(p, b, 0o644))
	t.Setenv("OMINULL_SIGNING_PUBLIC", p)
	var out, errb bytes.Buffer
	if rc := Main([]string{"pubkey"}, nil, &out, &errb); rc != 0 || out.String() != e.store.Keys[0].Pubkey {
		t.Fatalf("pubkey rc=%d out=%q err=%q", rc, out.String(), errb.String())
	}
	out.Reset()
	if rc := Main([]string{"pubkey", "routine"}, nil, &out, &errb); rc != 0 || out.String() != e.store.RoutineKeys[0].Pubkey {
		t.Fatalf("pubkey routine rc=%d", rc)
	}
	if rc := Main([]string{"bogus"}, nil, &out, &errb); rc != 64 {
		t.Fatalf("usage rc=%d", rc)
	}
}
