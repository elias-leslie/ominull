package server

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// A Cloudflare Access assertion is the only thing standing between the public
// internet and this console once the admin key stops being required, so the
// checks that make it trustworthy are tested individually. Each one of these
// tests fails open if its check is removed.

// testVerifier builds a verifier over an in-memory operator list. The real one
// reads the operators table, and reads it per request rather than once at
// startup, so revoking someone takes effect on their next request.
func testVerifier(t *testing.T, operators map[string]string) (*accessVerifier, *rsa.PrivateKey) {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating a signing key: %v", err)
	}

	v := &accessVerifier{
		team: "testteam",
		aud:  "aud-for-this-application",
		lookup: func(email string) (string, bool) {
			role, ok := operators[email]
			return role, ok
		},
		keys:      map[string]*rsa.PublicKey{"kid-1": &key.PublicKey},
		fetchedAt: time.Now(),
		client:    &http.Client{Timeout: time.Second},
	}
	return v, key
}

func oneAdmin() map[string]string {
	return map[string]string{"operator@example.com": "admin"}
}

func signToken(t *testing.T, key *rsa.PrivateKey, alg, kid string, claims map[string]interface{}) string {
	t.Helper()

	header, err := json.Marshal(map[string]string{"alg": alg, "kid": kid, "typ": "JWT"})
	if err != nil {
		t.Fatalf("marshalling the header: %v", err)
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshalling the claims: %v", err)
	}

	signing := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload)
	digest := sha256.Sum256([]byte(signing))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatalf("signing: %v", err)
	}
	return signing + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func requestWith(token string) *http.Request {
	r := httptest.NewRequest("GET", "/", nil)
	if token != "" {
		r.Header.Set("Cf-Access-Jwt-Assertion", token)
	}
	return r
}

func validClaims() map[string]interface{} {
	return map[string]interface{}{
		"email": "operator@example.com",
		"aud":   []string{"aud-for-this-application"},
		"exp":   time.Now().Add(time.Hour).Unix(),
		"nbf":   time.Now().Add(-time.Minute).Unix(),
	}
}

func TestAValidAccessAssertionIdentifiesTheOperator(t *testing.T) {
	v, key := testVerifier(t, oneAdmin())

	op, ok := v.Verify(requestWith(signToken(t, key, "RS256", "kid-1", validClaims())))
	if !ok {
		t.Fatalf("a valid assertion from a listed operator was refused")
	}
	if op.Email != "operator@example.com" || op.Role != "admin" {
		t.Errorf("got %+v, want operator@example.com/admin", op)
	}
}

// TestATokenForAnotherApplicationIsRefused is the audience pin. Every application
// in a Cloudflare Access team is signed by the same keys, so without this check
// any other application in the team - including one someone adds later with a
// laxer policy - mints tokens that open this console.
func TestATokenForAnotherApplicationIsRefused(t *testing.T) {
	v, key := testVerifier(t, oneAdmin())

	claims := validClaims()
	claims["aud"] = []string{"aud-for-some-other-application"}

	if _, ok := v.Verify(requestWith(signToken(t, key, "RS256", "kid-1", claims))); ok {
		t.Errorf("an assertion minted for a different Access application opened this console")
	}
}

// TestAnUnsignedTokenIsRefused. Trusting the algorithm the token names is the
// classic JWT failure: "none" asks the verifier to skip the signature entirely.
func TestAnUnsignedTokenIsRefused(t *testing.T) {
	v, key := testVerifier(t, oneAdmin())

	if _, ok := v.Verify(requestWith(signToken(t, key, "none", "kid-1", validClaims()))); ok {
		t.Errorf("a token declaring alg=none was accepted")
	}
	if _, ok := v.Verify(requestWith(signToken(t, key, "HS256", "kid-1", validClaims()))); ok {
		t.Errorf("a token declaring a symmetric algorithm was accepted")
	}
}

func TestATokenSignedByTheWrongKeyIsRefused(t *testing.T) {
	v, _ := testVerifier(t, oneAdmin())

	other, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating an impostor key: %v", err)
	}
	if _, ok := v.Verify(requestWith(signToken(t, other, "RS256", "kid-1", validClaims()))); ok {
		t.Errorf("a token signed by a key this team does not publish was accepted")
	}
}

func TestAnExpiredTokenIsRefused(t *testing.T) {
	v, key := testVerifier(t, oneAdmin())

	claims := validClaims()
	claims["exp"] = time.Now().Add(-time.Minute).Unix()

	if _, ok := v.Verify(requestWith(signToken(t, key, "RS256", "kid-1", claims))); ok {
		t.Errorf("an expired assertion was accepted")
	}
}

// TestAnIdentityNotOnTheOperatorListIsRefused. Access decides who reaches the
// origin; this list decides who runs the fleet. They are deliberately not the
// same decision, so widening an Access policy cannot hand out admin on its own.
func TestAnIdentityNotOnTheOperatorListIsRefused(t *testing.T) {
	v, key := testVerifier(t, oneAdmin())

	claims := validClaims()
	claims["email"] = "someone.else@example.com"

	if _, ok := v.Verify(requestWith(signToken(t, key, "RS256", "kid-1", claims))); ok {
		t.Errorf("an authenticated identity absent from the operator list was let in")
	}
}

// TestThePlaintextIdentityHeaderIsNotTrusted. This hub answers directly on the
// LAN with no Cloudflare in front of it, so an unsigned header naming an operator
// is something any local caller can simply assert.
func TestThePlaintextIdentityHeaderIsNotTrusted(t *testing.T) {
	v, _ := testVerifier(t, oneAdmin())

	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Cf-Access-Authenticated-User-Email", "operator@example.com")
	r.Header.Set("CF-Access-Authenticated-User-Email", "operator@example.com")

	if _, ok := v.Verify(r); ok {
		t.Errorf("an unsigned identity header was accepted as proof of identity")
	}
}

func TestNoAssertionIsRefused(t *testing.T) {
	v, _ := testVerifier(t, oneAdmin())
	if _, ok := v.Verify(requestWith("")); ok {
		t.Errorf("a request with no assertion was treated as authenticated")
	}
	var unconfigured *accessVerifier
	if _, ok := unconfigured.Verify(requestWith("anything")); ok {
		t.Errorf("an unconfigured verifier accepted an assertion")
	}
}

// TestAccessNeedsBothHalvesOfItsIdentity. Half a configuration is the dangerous
// one: a team with no audience to pin accepts tokens minted for any other
// application in that team.
func TestAccessNeedsBothHalvesOfItsIdentity(t *testing.T) {
	lookup := func(string) (string, bool) { return "admin", true }
	if _, err := newAccessVerifier(AccessOptions{Team: "t"}, lookup); err == nil {
		t.Errorf("Access was configured with no audience to pin")
	}
	if _, err := newAccessVerifier(AccessOptions{AUD: "a"}, lookup); err == nil {
		t.Errorf("Access was configured with no team to fetch keys from")
	}
	if _, err := newAccessVerifier(AccessOptions{Team: "t", AUD: "a"}, nil); err == nil {
		t.Errorf("Access was configured with no way to resolve an operator's role")
	}
	v, err := newAccessVerifier(AccessOptions{}, lookup)
	if err != nil || v != nil {
		t.Errorf("an unconfigured hub should leave Access off, got %v %v", v, err)
	}
}

// TestARevokedOperatorLosesAccessImmediately. The role is read per request, not
// snapshotted at startup: removing someone at ten in the morning must not leave
// them running the fleet until the hub is next restarted.
func TestARevokedOperatorLosesAccessImmediately(t *testing.T) {
	ops := oneAdmin()
	v, key := testVerifier(t, ops)

	token := signToken(t, key, "RS256", "kid-1", validClaims())
	if _, ok := v.Verify(requestWith(token)); !ok {
		t.Fatalf("a listed operator was refused")
	}

	delete(ops, "operator@example.com")
	if _, ok := v.Verify(requestWith(token)); ok {
		t.Errorf("an operator removed from the list kept the console with the token they already held")
	}
}

// TestTheRoleComesFromTheListAndNotTheToken. Nothing in an Access assertion says
// what someone is allowed to do here, and a claim that did would be a claim the
// identity provider controls.
func TestTheRoleComesFromTheListAndNotTheToken(t *testing.T) {
	v, key := testVerifier(t, map[string]string{"operator@example.com": "auditor"})

	claims := validClaims()
	claims["role"] = "admin"

	op, ok := v.Verify(requestWith(signToken(t, key, "RS256", "kid-1", claims)))
	if !ok {
		t.Fatalf("a listed operator was refused")
	}
	if op.Role != "auditor" {
		t.Errorf("role is %q; a claim in the token decided it instead of the operator list", op.Role)
	}
}
