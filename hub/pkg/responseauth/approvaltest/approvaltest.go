// Package approvaltest makes software owner approvers for tests and for a
// supervised live check: a P-256 key standing in for the owner's passkey.
// Production approvals come only from the passkey root pins on the authority
// host; a software approver is pinned only for a test and removed after.
package approvaltest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"os"

	"ominull/hub/pkg/responseauth"
)

// Approver is a software stand-in for a passkey.
type Approver struct {
	ID, RPID, Origin, CredentialID string
	Key                            *ecdsa.PrivateKey
	Count                          uint32
	Flags                          byte
}

// New makes an approver for rpID/origin.
func New(id, rpID, origin string) *Approver {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	cred := make([]byte, 16)
	_, _ = rand.Read(cred)
	return &Approver{ID: id, RPID: rpID, Origin: origin, CredentialID: base64.RawURLEncoding.EncodeToString(cred), Key: k, Flags: 0x05}
}

// Pinned is the approver entry root would pin.
func (a *Approver) Pinned() responseauth.Approver {
	x := a.Key.PublicKey.X.FillBytes(make([]byte, 32))
	y := a.Key.PublicKey.Y.FillBytes(make([]byte, 32))
	return responseauth.Approver{ID: a.ID, Label: "test approver", RPID: a.RPID, Origin: a.Origin, CredentialID: a.CredentialID,
		X: base64.RawURLEncoding.EncodeToString(x), Y: base64.RawURLEncoding.EncodeToString(y)}
}

// WriteFile writes an approver file pinning the given approvers.
func WriteFile(path string, approvers ...*Approver) error {
	list := []responseauth.Approver{}
	for _, a := range approvers {
		list = append(list, a.Pinned())
	}
	b, err := json.Marshal(map[string]interface{}{"approvers": list})
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o600)
}

// Assert signs the decision challenge for an approval like a browser would.
func (a *Approver) Assert(challengeHex, decision string) *responseauth.ApprovalAssertion {
	return a.AssertWith(challengeHex, decision, a.Origin, a.RPID, a.Flags)
}

// AssertWith allows tests to vary origin, RP ID and flags.
func (a *Approver) AssertWith(challengeHex, decision, origin, rpID string, flags byte) *responseauth.ApprovalAssertion {
	cd, _ := json.Marshal(map[string]interface{}{
		"type":      "webauthn.get",
		"challenge": base64.RawURLEncoding.EncodeToString(responseauth.DecisionChallenge(challengeHex, decision)),
		"origin":    origin,
	})
	rp := sha256.Sum256([]byte(rpID))
	if a.Count > 0 {
		a.Count++
	}
	auth := append(append([]byte{}, rp[:]...), flags)
	cnt := make([]byte, 4)
	binary.BigEndian.PutUint32(cnt, a.Count)
	auth = append(auth, cnt...)
	cdHash := sha256.Sum256(cd)
	msg := sha256.Sum256(append(append([]byte{}, auth...), cdHash[:]...))
	sig, err := ecdsa.SignASN1(rand.Reader, a.Key, msg[:])
	if err != nil {
		panic(err)
	}
	enc := base64.RawURLEncoding.EncodeToString
	return &responseauth.ApprovalAssertion{CredentialID: a.CredentialID, AuthenticatorData: enc(auth), ClientDataJSON: enc(cd), Signature: enc(sig)}
}
