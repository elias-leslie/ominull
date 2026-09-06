package server

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Cloudflare Access as a first-class identity for the console.
//
// Access already authenticates an operator against the identity provider and
// forwards a signed assertion to this origin. The hub used to discard it and ask
// for the admin key anyway, so unlocking the console meant typing a fleet-wide
// credential into a browser - the same credential the served document then
// embeds. Verifying the assertion means a Google login is enough on the public
// hostname, and the admin key goes back to being what it should be: the fallback
// for reaching the hub directly, and the credential for API and CLI callers.
//
// Two things make this safe to trust, and both are load-bearing:
//
//   - The signed JWT is checked, never the plaintext CF-Access-Authenticated-User-Email
//     header. This hub is reachable on the LAN with no Cloudflare in front of it,
//     so a plaintext identity header is something any local caller can simply
//     assert. A signature cannot be.
//   - The aud claim is pinned to one application. Without that check, a token
//     minted for any other Access application in the same team would open this
//     console.
//
// Access is the first gate and the operator list is the second. Widening an
// Access policy - or pointing a second application at this origin - must not by
// itself hand anyone admin over the fleet.

// accessJWKSTTL is how long a fetched key set is reused. Cloudflare publishes the
// current and previously-rotated keys, so a stale set keeps verifying across a
// rotation rather than locking every operator out at the moment it happens.
const accessJWKSTTL = time.Hour

// accessJWKSMinRefresh rate-limits the out-of-band refetch triggered by an
// unknown key id, so a stream of tokens naming key ids that do not exist cannot
// turn into a stream of outbound requests.
const accessJWKSMinRefresh = time.Minute

// accessRefusalLogEvery rate-limits the line explaining why an assertion was
// refused, so a stream of invalid tokens cannot fill the journal.
const accessRefusalLogEvery = time.Minute

// accessAcceptLogEvery does the same for the line that records a verified
// assertion. Every console request carries one, so without a limit a single
// operator with the page open would write a line every five seconds.
const accessAcceptLogEvery = 5 * time.Minute

// accessLastSuccessSetting is the durable marker saying that a signed assertion
// from this Access application has verified at least once. Without it the
// diagnostic can only report that Access is configured, which is exactly the
// claim an operator already doubts when they come to look: the interesting
// question is whether Cloudflare is really forwarding an identity this hub can
// check, and only a verification that actually happened answers it.
const accessLastSuccessSetting = "access.last_success"

// accessSuccessRecordEvery rate-limits writing that marker. Every console
// request carries an assertion, so recording each one would be a database write
// per request; the diagnostic only needs to know that one verified and roughly
// when.
const accessSuccessRecordEvery = time.Minute

// AccessOptions configures Cloudflare Access verification. Team and AUD are the
// deployment's own identifiers, so they are given at run time and never live in
// the repository. Who holds which role is managed in the console and stored in
// the database, not configured here.
type AccessOptions struct {
	Team           string // e.g. "acme" for acme.cloudflareaccess.com
	AUD            string // the Access application's Application Audience tag
	BootstrapAdmin string // optional: an address guaranteed to hold admin at startup
}

type accessOperator struct {
	Email   string
	Role    string
	Issuer  string
	Subject string
}

type accessVerifier struct {
	team   string
	aud    string
	issuer string
	// lookup resolves an email to a role. It reads the operators table on every
	// request rather than a snapshot, so revoking someone in the console takes
	// effect on their next request instead of at the next restart.
	lookup func(email string) (string, bool)

	// record persists the moment an assertion verified. It is a callback rather
	// than a store handle so the verifier keeps knowing nothing about storage,
	// and a verifier built without one simply records nothing.
	record func(time.Time)

	mu           sync.RWMutex
	keys         map[string]*rsa.PublicKey
	fetchedAt    time.Time
	lastAttempt  time.Time
	lastRefusal  time.Time
	lastAccepted time.Time
	lastRecorded time.Time

	client *http.Client
}

// newAccessVerifier returns nil when Access verification is not configured, which
// is the default: a hub with no Access in front of it must not start trusting a
// header that nothing is producing.
func newAccessVerifier(opts AccessOptions, lookup func(string) (string, bool)) (*accessVerifier, error) {
	team := strings.TrimSpace(opts.Team)
	aud := strings.TrimSpace(opts.AUD)
	if team == "" && aud == "" {
		return nil, nil
	}
	if team == "" || aud == "" {
		return nil, errors.New("both --access-team and --access-aud are required to verify Cloudflare Access assertions")
	}
	if lookup == nil {
		return nil, errors.New("no operator lookup was provided")
	}
	return &accessVerifier{
		team:   team,
		aud:    aud,
		issuer: "https://" + team + ".cloudflareaccess.com",
		lookup: lookup,
		keys:   map[string]*rsa.PublicKey{},
		client: &http.Client{Timeout: 10 * time.Second},
	}, nil
}

// Verify checks the Access assertion on a request and returns the operator it
// identifies. Any failure returns ok=false; there is no degraded mode, because
// the only thing a half-verified assertion could do is open the console.
func (a *accessVerifier) Verify(r *http.Request) (accessOperator, bool) {
	if a == nil {
		return accessOperator{}, false
	}
	// The header, not the CF_Authorization cookie: Cloudflare does not guarantee
	// the cookie reaches the origin, and the header is the documented one to
	// validate.
	raw := strings.TrimSpace(r.Header.Get("Cf-Access-Jwt-Assertion"))
	if raw == "" {
		return accessOperator{}, false
	}
	claims, err := a.verifyToken(raw)
	if err != nil {
		// A refused assertion is silent from the operator's side: Access says
		// they signed in, the hub shows them the gate, and nothing anywhere says
		// why. The commonest cause is a mistyped --access-aud, which no amount of
		// retrying fixes. Rate-limited because an attacker posting junk tokens
		// must not be able to write the journal full.
		a.mu.Lock()
		quiet := time.Since(a.lastRefusal) < accessRefusalLogEvery
		if !quiet {
			a.lastRefusal = time.Now()
		}
		a.mu.Unlock()
		if !quiet {
			log.Printf("[!] A Cloudflare Access assertion was refused: %v. If this is every sign-in, check that --access-aud matches this application's Application Audience tag and that --access-team names the right team.", err)
		}
		return accessOperator{}, false
	}
	email := strings.ToLower(strings.TrimSpace(claims.Email))
	if email == "" {
		return accessOperator{}, false
	}
	// Recorded here rather than after the operator lookup, because the two
	// answer different questions. This marker says the Cloudflare side works -
	// the assertion was signed by this team's keys and minted for this
	// application. Whether the person it names may then use the console is the
	// operator list's business, and it already logs its own refusal below.
	a.noteVerified(time.Now().UTC())
	role, listed := a.lookup(email)
	if !listed {
		// Worth a line: the person authenticated successfully and was still
		// turned away, which is confusing from their side unless someone can see
		// why.
		log.Printf("[!] %s signed in through Cloudflare Access but is not in the operator list, so the console was refused.", email)
		return accessOperator{}, false
	}
	// The positive counterpart to the refusal line above. Without it the journal
	// could say an assertion was rejected but never that one was accepted, so
	// "is Cloudflare actually forwarding a signed identity, or am I just riding
	// an old session cookie?" had no answer on the hub at all. Rate-limited the
	// same way, because every page load carries an assertion.
	a.mu.Lock()
	quiet := time.Since(a.lastAccepted) < accessAcceptLogEvery
	if !quiet {
		a.lastAccepted = time.Now()
	}
	a.mu.Unlock()
	if !quiet {
		log.Printf("[+] Cloudflare Access verified %s as %s.", email, role)
	}

	subject := strings.TrimSpace(claims.Sub)
	if subject == "" {
		subject = email
	}
	return accessOperator{Email: email, Role: role, Issuer: a.issuer, Subject: subject}, true
}

type accessClaims struct {
	Iss   string `json:"iss"`
	Sub   string `json:"sub"`
	Email string `json:"email"`
	Exp   int64  `json:"exp"`
	Nbf   int64  `json:"nbf"`
	Aud   []string
}

// UnmarshalJSON handles aud being either a string or an array of strings, which
// is what the JWT spec permits and what different issuers actually emit.
func (c *accessClaims) UnmarshalJSON(b []byte) error {
	var raw struct {
		Iss   string          `json:"iss"`
		Sub   string          `json:"sub"`
		Email string          `json:"email"`
		Exp   int64           `json:"exp"`
		Nbf   int64           `json:"nbf"`
		Aud   json.RawMessage `json:"aud"`
	}
	if err := json.Unmarshal(b, &raw); err != nil {
		return err
	}
	c.Iss, c.Sub, c.Email, c.Exp, c.Nbf = raw.Iss, raw.Sub, raw.Email, raw.Exp, raw.Nbf
	if len(raw.Aud) == 0 {
		return nil
	}
	var list []string
	if err := json.Unmarshal(raw.Aud, &list); err == nil {
		c.Aud = list
		return nil
	}
	var one string
	if err := json.Unmarshal(raw.Aud, &one); err == nil {
		c.Aud = []string{one}
		return nil
	}
	return errors.New("aud is neither a string nor an array of strings")
}

func (a *accessVerifier) verifyToken(raw string) (*accessClaims, error) {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return nil, errors.New("not a three-part JWT")
	}

	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, errors.New("undecodable header")
	}
	var header struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return nil, errors.New("unparseable header")
	}
	// Only RS256. Accepting the algorithm the token names would accept "none",
	// and would accept HS256 signed with the public key as its secret.
	if header.Alg != "RS256" {
		return nil, fmt.Errorf("unsupported algorithm %q", header.Alg)
	}
	if header.Kid == "" {
		return nil, errors.New("no key id")
	}

	key, err := a.keyFor(header.Kid)
	if err != nil {
		return nil, err
	}

	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, errors.New("undecodable signature")
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(key, crypto.SHA256, digest[:], sig); err != nil {
		return nil, errors.New("signature does not verify")
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, errors.New("undecodable payload")
	}
	var claims accessClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, errors.New("unparseable payload")
	}

	now := time.Now().Unix()
	if claims.Exp == 0 || now >= claims.Exp {
		return nil, errors.New("expired")
	}
	if claims.Nbf != 0 && now < claims.Nbf {
		return nil, errors.New("not yet valid")
	}
	if claims.Iss != a.issuer {
		return nil, errors.New("issuer does not match this Access team")
	}

	// The audience pin. Without it, any Access application in this team issues
	// tokens this console accepts.
	audOK := false
	for _, aud := range claims.Aud {
		if aud == a.aud {
			audOK = true
			break
		}
	}
	if !audOK {
		return nil, errors.New("audience does not match this application")
	}

	return &claims, nil
}

// keyFor returns the signing key with the given id, refetching the key set if the
// id is unknown and the last attempt was not a moment ago.
func (a *accessVerifier) keyFor(kid string) (*rsa.PublicKey, error) {
	a.mu.RLock()
	key, ok := a.keys[kid]
	fresh := time.Since(a.fetchedAt) < accessJWKSTTL
	a.mu.RUnlock()
	if ok && fresh {
		return key, nil
	}
	if err := a.refresh(); err != nil {
		// A key set we already hold outlives a failed refresh: Cloudflare being
		// briefly unreachable should not sign everyone out.
		if ok {
			return key, nil
		}
		return nil, err
	}
	a.mu.RLock()
	key, ok = a.keys[kid]
	a.mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("no Access signing key with id %s", kid)
	}
	return key, nil
}

type jwk struct {
	Kid string `json:"kid"`
	Kty string `json:"kty"`
	Alg string `json:"alg"`
	N   string `json:"n"`
	E   string `json:"e"`
}

func (a *accessVerifier) refresh() error {
	a.mu.Lock()
	if time.Since(a.lastAttempt) < accessJWKSMinRefresh {
		a.mu.Unlock()
		return errors.New("key set was refreshed a moment ago")
	}
	a.lastAttempt = time.Now()
	a.mu.Unlock()

	keys, err := a.fetchKeys(context.Background())
	if err != nil {
		return err
	}

	a.mu.Lock()
	a.keys = keys
	a.fetchedAt = time.Now()
	a.mu.Unlock()
	return nil
}

// jwksURL is where Cloudflare publishes this team's signing keys.
func (a *accessVerifier) jwksURL() string {
	return "https://" + a.team + ".cloudflareaccess.com/cdn-cgi/access/certs"
}

// fetchKeys reads and parses the published key set without touching any cached
// state, so a diagnostic can ask whether Cloudflare is reachable without
// disturbing the keys live sign-ins are verifying against - or being turned away
// by the refetch rate limit that protects them.
func (a *accessVerifier) fetchKeys(ctx context.Context) (map[string]*rsa.PublicKey, error) {
	url := a.jwksURL()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("fetching %s: %w", url, err)
	}
	resp, err := a.client.Do(request)
	if err != nil {
		return nil, fmt.Errorf("fetching %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s answered %d", url, resp.StatusCode)
	}

	var doc struct {
		Keys []jwk `json:"keys"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 256*1024)).Decode(&doc); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", url, err)
	}

	keys := map[string]*rsa.PublicKey{}
	for _, k := range doc.Keys {
		if k.Kty != "RSA" || k.Kid == "" {
			continue
		}
		pub, err := rsaKeyFromJWK(k)
		if err != nil {
			continue
		}
		keys[k.Kid] = pub
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("%s returned no usable RSA keys", url)
	}
	return keys, nil
}

// accessStatus is a point-in-time reading of the verifier for the diagnostic.
type accessStatus struct {
	Team      string
	AUD       string
	Issuer    string
	JWKSURL   string
	KeysHeld  int
	FetchedAt time.Time
}

// status reports what the live verifier is configured with and what it is
// currently holding. It is the runtime answer rather than the saved one: a hub
// that has not been restarted since the configuration changed is exactly the
// case the diagnostic exists to catch.
func (a *accessVerifier) status() accessStatus {
	if a == nil {
		return accessStatus{}
	}
	a.mu.RLock()
	defer a.mu.RUnlock()
	return accessStatus{
		Team:      a.team,
		AUD:       a.aud,
		Issuer:    a.issuer,
		JWKSURL:   a.jwksURL(),
		KeysHeld:  len(a.keys),
		FetchedAt: a.fetchedAt,
	}
}

// probeSigningKeys reports how many usable signing keys Cloudflare publishes for
// this team right now.
func (a *accessVerifier) probeSigningKeys(ctx context.Context) (int, error) {
	if a == nil {
		return 0, errors.New("Cloudflare Access verification is not configured")
	}
	keys, err := a.fetchKeys(ctx)
	if err != nil {
		return 0, err
	}
	return len(keys), nil
}

// noteVerified records that an assertion verified, at most once per interval.
func (a *accessVerifier) noteVerified(now time.Time) {
	if a == nil || a.record == nil {
		return
	}
	a.mu.Lock()
	quiet := !a.lastRecorded.IsZero() && now.Sub(a.lastRecorded) < accessSuccessRecordEvery
	if !quiet {
		a.lastRecorded = now
	}
	a.mu.Unlock()
	if quiet {
		return
	}
	a.record(now)
}

func rsaKeyFromJWK(k jwk) (*rsa.PublicKey, error) {
	nBytes, err := base64.RawURLEncoding.DecodeString(k.N)
	if err != nil {
		return nil, err
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(k.E)
	if err != nil {
		return nil, err
	}
	if len(eBytes) == 0 || len(eBytes) > 8 {
		return nil, errors.New("implausible RSA exponent")
	}
	e := 0
	for _, b := range eBytes {
		e = e<<8 | int(b)
	}
	if e <= 0 {
		return nil, errors.New("non-positive RSA exponent")
	}
	return &rsa.PublicKey{N: new(big.Int).SetBytes(nBytes), E: e}, nil
}
