package responseauth_test

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
	"strings"
	"testing"

	"ominull/hub/pkg/response"
	"ominull/hub/pkg/responseauth"
)

type releaseKey struct {
	priv *ecdsa.PrivateKey
	pem  []byte
}

func newReleaseKey(t *testing.T) *releaseKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&k.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return &releaseKey{priv: k, pem: pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})}
}

// evidence signs the release statements of both agent packages of version.
func (k *releaseKey) evidence(t *testing.T, version string) []responseauth.ReleaseEvidence {
	t.Helper()
	var out []responseauth.ReleaseEvidence
	for _, name := range []string{"ominull-agent_" + version + "_amd64.deb", "ominull-agent-windows-" + version + ".msi"} {
		pkg := sha256.Sum256([]byte("package " + name))
		sha := hex.EncodeToString(pkg[:])
		sum := sha256.Sum256([]byte(responseauth.ReleaseStatement(name, version, sha)))
		sig, err := ecdsa.SignASN1(rand.Reader, k.priv, sum[:])
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, responseauth.ReleaseEvidence{Package: name, SHA256: sha, Sig: base64.StdEncoding.EncodeToString(sig)})
	}
	return out
}

func rolloutRequest(version string, targets, canary []string, ev []responseauth.ReleaseEvidence) *responseauth.AuthorizeInput {
	body := map[string]interface{}{"endpoint_ids": targets, "version": version}
	if len(canary) > 0 {
		body["canary"] = canary
	}
	payload, _ := json.Marshal(map[string]interface{}{"route": "/api/v1/agents/update", "body": body, "targets": targets})
	return &responseauth.AuthorizeInput{TenantID: "default", Requester: "admin", Kind: responseauth.ActionKindAgentUpdate,
		Targets: targets, Payload: payload, Release: ev}
}

func newReleaseAuthority(t *testing.T) (*responseauth.Authority, *releaseKey) {
	t.Helper()
	auth := newTestAuthority(t)
	key := newReleaseKey(t)
	auth.SetReleaseKey(key.pem)
	return auth, key
}

// A routine key's signed list, as the hub passes it to the authority, and the
// evidence that key signs for a version.
func routineList(t *testing.T, rel, routine *releaseKey) *response.RoutineKeys {
	t.Helper()
	xy, err := response.RoutineKeyXY(string(routine.pem))
	if err != nil {
		t.Fatal(err)
	}
	line, err := response.FormatRoutineKeyList([]response.RoutineKey{{ID: "0123456789abcdef", XY: xy}})
	if err != nil {
		t.Fatal(err)
	}
	stmt, err := response.RoutineKeysStatement(1, line)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(stmt))
	sig, err := ecdsa.SignASN1(rand.Reader, rel.priv, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	return &response.RoutineKeys{Epoch: 1, Keys: line, Sig: base64.StdEncoding.EncodeToString(sig)}
}

// A release signed with the pinned key rolls out at once: the authority signs
// the grants and names the release it read.
func TestRolloutOfAnOwnerSignedReleaseIsSignedAtOnce(t *testing.T) {
	auth, key := newReleaseAuthority(t)
	au, err := auth.Authorize(rolloutRequest("1.8.72", []string{"ep-1", "ep-2"}, nil, key.evidence(t, "1.8.72")))
	if err != nil {
		t.Fatal(err)
	}
	if len(au.Grants) != 2 || !strings.Contains(au.Summary, "release 1.8.72 owner-signed") {
		t.Fatalf("grants %d summary %q", len(au.Grants), au.Summary)
	}
}

// A release the authority cannot verify is still signed (agents check the
// package signature themselves); the audit words say it was not verified.
func TestRolloutWithUnverifiedReleaseIsSignedAndSaysSo(t *testing.T) {
	auth, key := newReleaseAuthority(t)
	other := newReleaseKey(t)
	tampered := key.evidence(t, "1.8.74")
	tampered[0].SHA256 = strings.Repeat("0", 64)
	cases := map[string][]responseauth.ReleaseEvidence{
		"no evidence":                   nil,
		"signed with another key":       other.evidence(t, "1.8.74"),
		"signature for another version": key.evidence(t, "1.8.73"),
		"digest not the signed one":     tampered,
		"only one package signed":       key.evidence(t, "1.8.74")[:1],
	}
	for name, ev := range cases {
		au, err := auth.Authorize(rolloutRequest("1.8.74", []string{"ep-1"}, nil, ev))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if len(au.Grants) != 1 || !strings.Contains(au.Summary, "not verified") {
			t.Errorf("%s: grants %d summary %q", name, len(au.Grants), au.Summary)
		}
	}
}

// Evidence never turns another kind of action into a rollout.
func TestEvidenceDoesNotMakeAnIsolationARollout(t *testing.T) {
	auth, key := newReleaseAuthority(t)
	in := isolateRequestFor("ep-1")
	in.Release = key.evidence(t, "1.8.74")
	au, err := auth.Authorize(in)
	if err != nil || strings.Contains(au.Summary, "release") {
		t.Fatalf("%+v %v", au, err)
	}
}

// A release signed with a routine key always rolls out canaries first.
func TestRoutineKeyReleaseNeedsCanaries(t *testing.T) {
	auth, key := newReleaseAuthority(t)
	routine := newReleaseKey(t)
	list := routineList(t, key, routine)
	targets := []string{"ep-1", "ep-2", "ep-3"}
	in := rolloutRequest("1.8.75", targets, nil, routine.evidence(t, "1.8.75"))
	in.RoutineKeys = list
	if _, err := auth.Authorize(in); err == nil || !strings.Contains(err.Error(), "canar") {
		t.Fatalf("a routine-key release to several hosts without canaries was signed: %v", err)
	}
	in = rolloutRequest("1.8.75", targets, []string{"ep-1"}, routine.evidence(t, "1.8.75"))
	in.RoutineKeys = list
	au, err := auth.Authorize(in)
	if err != nil || len(au.Grants) != 3 || !strings.Contains(au.Summary, "signed in the owner's session") {
		t.Fatalf("with a canary: %+v %v", au, err)
	}
	// One endpoint needs no canary; a list the release key did not sign
	// counts for nothing, so the evidence is then unverified and signed as such.
	in = rolloutRequest("1.8.75", []string{"ep-1"}, nil, routine.evidence(t, "1.8.75"))
	in.RoutineKeys = list
	if _, err := auth.Authorize(in); err != nil {
		t.Fatalf("one endpoint: %v", err)
	}
	forged := *list
	forged.Epoch = 2
	in = rolloutRequest("1.8.75", targets, nil, routine.evidence(t, "1.8.75"))
	in.RoutineKeys = &forged
	au, err = auth.Authorize(in)
	if err != nil || !strings.Contains(au.Summary, "not verified") {
		t.Fatalf("forged list: %+v %v", au, err)
	}
}
