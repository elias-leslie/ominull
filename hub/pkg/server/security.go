package server

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// secretEqual compares two credentials without leaking their contents through
// how long the comparison takes. Go's == on strings returns at the first
// differing byte, which over enough samples is a usable oracle for a key that
// is presented on every request; subtle.ConstantTimeCompare is not.
//
// The length check is deliberately outside the constant-time path: length is
// not the secret, and hashing first would only move the same leak.
func secretEqual(given, want string) bool {
	if want == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(given), []byte(want)) == 1
}

// KeyFingerprint identifies a credential in a log line without disclosing it.
// Operators need to tell one key from another across a rotation; nobody needs
// the key itself in a journal that is world-readable on most systems.
func KeyFingerprint(key string) string {
	if key == "" {
		return "none"
	}
	sum := sha256.Sum256([]byte(key))
	return "sha256:" + hex.EncodeToString(sum[:4])
}

// requireAdmin gates a route to the admin credential. authMiddleware has
// already resolved the caller; this only reads its verdict.
//
// The distinction it enforces is the one the deployment depends on: the tenant
// key is on every endpoint in the fleet, so anything a tenant key can do is
// something a single compromised host can do. Fleet-wide controls - creating
// tenants, quarantining a peer on every agent, pushing a deploy, pointing the
// copilot at another server - are operator actions and must not be reachable
// with a credential that ships to endpoints.
func requireAdmin(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Role") != "admin" {
			writeJSONError(w, http.StatusForbidden, "admin credential required for this route")
			return
		}
		next(w, r)
	}
}

// writeJSONError emits an error the console and the CLI can both parse. Hand
// building the body with string concatenation is how a caller-supplied id ends
// up breaking out of the JSON it was pasted into.
func writeJSONError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

// writeJSON emits a success body through the encoder for the same reason.
func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// clientIP is the address a rate limit and an audit entry are attributed to.
// strings.Split(RemoteAddr, ":")[0] - what the audit trail used - returns ""
// for an IPv6 peer, collapsing every IPv6 caller onto one bucket.
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// validateIP accepts only a bare IP literal.
//
// This is load-bearing rather than cosmetic. A quarantined peer's address is
// handed to every agent on the fleet and reaches a privileged command there, so
// anything the hub stores in that field is something the fleet will act on.
func validateIP(v string) (string, error) {
	v = strings.TrimSpace(v)
	ip := net.ParseIP(v)
	if ip == nil {
		return "", fmt.Errorf("%q is not an IP address", v)
	}
	return ip.String(), nil
}

// validateMAC accepts only a hardware address, normalised.
func validateMAC(v string) (string, error) {
	v = strings.TrimSpace(v)
	if v == "" {
		return "", nil
	}
	hw, err := net.ParseMAC(v)
	if err != nil {
		return "", fmt.Errorf("%q is not a hardware address", v)
	}
	return strings.ToUpper(hw.String()), nil
}

// maxScanHosts caps one discovery sweep. A /16 is 65534 addresses and already
// takes minutes; the enumeration below it materialises one string per address
// before probing anything, so an unbounded prefix is a memory exhaustion bug
// reachable from a single request body.
const maxScanHosts = 65536

// validateSubnet accepts a CIDR the scanner can actually sweep.
func validateSubnet(v string) (string, error) {
	v = strings.TrimSpace(v)
	if v == "" {
		return "", fmt.Errorf("a subnet in CIDR form is required")
	}
	_, ipNet, err := net.ParseCIDR(v)
	if err != nil {
		return "", fmt.Errorf("%q is not a CIDR subnet", v)
	}
	ones, bits := ipNet.Mask.Size()
	if bits-ones > 32 || uint64(1)<<uint(bits-ones) > maxScanHosts {
		return "", fmt.Errorf("%s covers more than %d addresses; scan it in smaller blocks", v, maxScanHosts)
	}
	return ipNet.String(), nil
}

// validateHTTPURL accepts an absolute http(s) URL and nothing else.
//
// The copilot dials whatever this configures, from inside the management
// network, and sends it the fleet context it was asked about. A file:// or a
// bare host would either fail obscurely or point at something local.
func validateHTTPURL(v string) (string, error) {
	v = strings.TrimSpace(v)
	u, err := url.Parse(v)
	if err != nil {
		return "", fmt.Errorf("%q is not a URL", v)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", fmt.Errorf("%q must be an http:// or https:// URL", v)
	}
	if u.Host == "" {
		return "", fmt.Errorf("%q has no host", v)
	}
	return u.String(), nil
}

// securityHeaders are set on every console response.
//
// Referrer-Policy is the one that matters most here: the console is unlocked
// with the admin key in the query string, so any outbound navigation from that
// document would otherwise carry the key in a Referer header to a third party.
// The CSP matches what the console actually loads - its own stylesheet, its own
// script, its own embedded fonts, and a websocket back to the hub - so it costs
// nothing and closes the injection routes that a future template change could
// open.
func setConsoleSecurityHeaders(w http.ResponseWriter, scriptNonce string) {
	h := w.Header()
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("X-Frame-Options", "DENY")

	scriptSrc := "'self'"
	if scriptNonce != "" {
		scriptSrc += " 'nonce-" + scriptNonce + "'"
	}
	h.Set("Content-Security-Policy",
		"default-src 'none'; script-src "+scriptSrc+"; style-src 'self'; font-src 'self'; "+
			"img-src 'self' data:; connect-src 'self' ws: wss:; form-action 'self'; "+
			"frame-ancestors 'none'; base-uri 'none'")
}

// authThrottle bounds how fast a credential can be guessed.
//
// The admin key is a 256-bit random string, so this is not what stands between
// an attacker and the hub - but the console gate takes a key from a form, the
// API takes one from a header, and neither costs the caller anything to retry.
// A failure counter per source address turns an unlimited online guess into a
// rate the logs will show long before it matters, and it is cheap enough to
// apply on every authenticated route.
type authThrottle struct {
	mu       sync.Mutex
	failures map[string]*failureWindow
	limit    int
	window   time.Duration
	lockout  time.Duration
}

type failureWindow struct {
	count       int
	windowStart time.Time
	blockedTill time.Time
}

func newAuthThrottle() *authThrottle {
	return &authThrottle{
		failures: make(map[string]*failureWindow),
		limit:    20,
		window:   time.Minute,
		lockout:  time.Minute,
	}
}

// blocked reports whether this address is currently in a lockout, and takes the
// opportunity to forget addresses nobody is failing from any more.
func (t *authThrottle) blocked(addr string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()

	now := time.Now()
	f, ok := t.failures[addr]
	if !ok {
		return false
	}
	if now.After(f.blockedTill) && now.Sub(f.windowStart) > t.window {
		delete(t.failures, addr)
		return false
	}
	return now.Before(f.blockedTill)
}

// fail records one rejected credential and reports whether that tripped the
// lockout, so the caller can log the transition once rather than per attempt.
func (t *authThrottle) fail(addr string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()

	now := time.Now()
	f, ok := t.failures[addr]
	if !ok || now.Sub(f.windowStart) > t.window {
		t.failures[addr] = &failureWindow{count: 1, windowStart: now}
		return false
	}
	f.count++
	if f.count >= t.limit && now.After(f.blockedTill) {
		f.blockedTill = now.Add(t.lockout)
		return true
	}
	return false
}

// succeed clears the counter for an address that has just proved it holds a
// credential, so a fat-fingered operator is not locked out behind their own
// successful login.
func (t *authThrottle) succeed(addr string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.failures, addr)
}
