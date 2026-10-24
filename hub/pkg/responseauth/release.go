package responseauth

// Agent rollouts: what the authority checks about the release an agent update
// installs. Every agent package of the version carries a release statement
// (OMINULL-RELEASE-V1, package, version, sha256) signed with the release key
// compiled into this authority (the key agents pin) or with a routine key that
// key listed. The authority approves the rollout either way (agents install
// only packages signed with the release key), and it holds one rule beyond
// that: a release signed with a routine key, rolled out to more than one
// endpoint, names canaries, so the hub installs on those first and halts on a
// bad canary.

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"ominull/hub/pkg/response"
)

const rolloutRoute = "/api/v1/agents/update"

var releaseVersionRE = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+$`)

// ReleaseEvidence is one signed agent package of the release an agent update
// installs, as the hub publishes it: name, digest and the release signature
// over the statement that binds them to the version.
type ReleaseEvidence struct {
	Package string `json:"package"`
	SHA256  string `json:"sha256"`
	Sig     string `json:"sig"` // base64 DER ECDSA P-256 / SHA-256
}

// SetReleaseKey replaces the pinned release public key (tests).
func (a *Authority) SetReleaseKey(pem []byte) {
	a.mu.Lock()
	a.releaseKey = append([]byte(nil), pem...)
	a.mu.Unlock()
}

func (a *Authority) releasePublicKey() []byte {
	a.mu.RLock()
	defer a.mu.RUnlock()
	if len(a.releaseKey) > 0 {
		return a.releaseKey
	}
	return []byte(response.ReleasePublicKeyPEM)
}

// ReleaseStatement is what the release key signs for one package
// (scripts/sign-release.sh; agents rebuild it byte for byte).
func ReleaseStatement(pkg, version, sha string) string {
	return fmt.Sprintf("OMINULL-RELEASE-V1\npackage=%s\nversion=%s\nsha256=%s\n", pkg, version, sha)
}

// rolloutEvidence checks an agent rollout's release evidence: every agent
// package of the version signed with the pinned release key, or with a
// routine key the pinned release key listed (response.RoutineKeys, which
// the hub passes and this authority verifies itself). routine says a
// routine key signed it; such a release always rolls out canaries first.
func (a *Authority) rolloutEvidence(in *AuthorizeInput) (string, string, bool, []string, error) {
	if in.Kind != ActionKindAgentUpdate {
		return "", "", false, nil, errors.New("not an agent rollout")
	}
	var p routedPayload
	if err := decodeJSON(in.Payload, &p); err != nil || p.Route != rolloutRoute {
		return "", "", false, nil, errors.New("not the agent rollout route")
	}
	var body struct {
		Version string   `json:"version"`
		Canary  []string `json:"canary"`
	}
	if err := decodeJSON(p.Body, &body); err != nil || !releaseVersionRE.MatchString(body.Version) {
		return "", "", false, nil, errors.New("the rollout names no release version")
	}
	canary := sortedUnique(body.Canary)
	want := map[string]bool{
		"ominull-agent_" + body.Version + "_amd64.deb":   false,
		"ominull-agent-windows-" + body.Version + ".msi": false,
	}
	if len(in.Release) != len(want) {
		return "", "", false, nil, errors.New("the release evidence must cover every agent package of the version")
	}
	pub := a.releasePublicKey()
	var routineKeys []response.RoutineKey
	if in.RoutineKeys != nil {
		// An unverifiable list is ignored: only the pinned key then counts.
		routineKeys, _ = response.VerifyRoutineKeys(pub, in.RoutineKeys)
	}
	var parts []string
	signers := map[string]bool{}
	for _, ev := range in.Release {
		seen, ok := want[ev.Package]
		if !ok || seen {
			return "", "", false, nil, fmt.Errorf("release evidence names an unexpected package %q", cleanText(ev.Package, 80))
		}
		want[ev.Package] = true
		sha := strings.ToLower(ev.SHA256)
		if b, err := hex.DecodeString(sha); err != nil || len(b) != sha256.Size {
			return "", "", false, nil, fmt.Errorf("%s: digest is not SHA-256", ev.Package)
		}
		der, err := base64.StdEncoding.DecodeString(ev.Sig)
		if err != nil || len(der) == 0 || len(der) > 512 {
			return "", "", false, nil, fmt.Errorf("%s: release signature unreadable", ev.Package)
		}
		signer, err := response.VerifyReleaseWithRoutine(pub, routineKeys, []byte(ReleaseStatement(ev.Package, body.Version, sha)), der)
		if err != nil {
			return "", "", false, nil, fmt.Errorf("%s %s is not signed with the pinned release key or a routine key it listed", ev.Package, body.Version)
		}
		signers[signer] = true
		parts = append(parts, ev.Package+"="+sha[:16])
	}
	sort.Strings(parts)
	routine := !signers["release"] || len(signers) > 1
	how := "owner-signed"
	if routine {
		var names []string
		for s := range signers {
			names = append(names, s)
		}
		sort.Strings(names)
		how = "signed in the owner's session (" + strings.Join(names, ", ") + ")"
	}
	return "release " + body.Version + " " + how + " (" + strings.Join(parts, ", ") + ")", body.Version, routine, canary, nil
}
