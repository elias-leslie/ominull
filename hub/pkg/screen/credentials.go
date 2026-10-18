package screen

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"sync"
	"time"
)

// Credentials holds the screen-only operator credentials the shared manager
// does not: console launch codes (REMOTE_SCREEN.md 9.2), one-use watch
// tokens, and who minted the current control token (an agent's input is
// audited). Everything is stored hashed and in memory: a hub restart ends
// every live session anyway.

const (
	// LaunchCodeTTL is how long a launch code can be redeemed.
	LaunchCodeTTL = 60 * time.Second
	// WatchTokenTTL is how long a watch token waits for its attach.
	WatchTokenTTL = 5 * time.Minute
	// RedeemLimit is how many redeem attempts one source address gets per
	// RedeemWindow. SessionRedeemLimit is a much higher backstop per session:
	// someone who only knows a session id cannot lock its owner out of
	// redeeming from their own address without RedeemLimit-many addresses
	// of their own.
	RedeemLimit        = 10
	SessionRedeemLimit = 100
	RedeemWindow       = time.Minute
)

// Attachment kinds.
const (
	AttachControl = "control"
	AttachWatch   = "watch"
)

var (
	ErrCodeInvalid = errors.New("launch code invalid, expired, already used or for another session")
	ErrRedeemLimit = errors.New("too many launch code attempts; wait a minute")
)

type launchEntry struct {
	sessionID, operator, kind string
	expires                   time.Time
}

type watchEntry struct {
	sessionID, who string
	expires        time.Time
}

// Credentials is safe for concurrent use.
type Credentials struct {
	mu       sync.Mutex
	codes    map[string]launchEntry // by sha256 of the code
	watch    map[string]watchEntry  // by sha256 of the token
	attempts map[string][]time.Time // redeem attempts by "ip:..." / "session:..."
	byAgent  map[string]string      // session -> agent who minted its control token
	now      func() time.Time
}

// NewCredentials makes an empty store.
func NewCredentials() *Credentials {
	return &Credentials{codes: map[string]launchEntry{}, watch: map[string]watchEntry{},
		attempts: map[string][]time.Time{}, byAgent: map[string]string{}, now: time.Now}
}

func secret() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func hashOf(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

func (c *Credentials) sweepLocked(now time.Time) {
	for k, e := range c.codes {
		if now.After(e.expires) {
			delete(c.codes, k)
		}
	}
	for k, e := range c.watch {
		if now.After(e.expires) {
			delete(c.watch, k)
		}
	}
	for k, ts := range c.attempts {
		keep := ts[:0]
		for _, t := range ts {
			if now.Sub(t) < RedeemWindow {
				keep = append(keep, t)
			}
		}
		if len(keep) == 0 {
			delete(c.attempts, k)
		} else {
			c.attempts[k] = keep
		}
	}
}

// IssueLaunchCode mints a one-use code for a control or watch attachment to
// sessionID, bound to operator, valid LaunchCodeTTL. Only its hash is kept.
func (c *Credentials) IssueLaunchCode(sessionID, operator, kind string) string {
	code := secret()
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	c.sweepLocked(now)
	c.codes[hashOf(code)] = launchEntry{sessionID: sessionID, operator: operator, kind: kind, expires: now.Add(LaunchCodeTTL)}
	return code
}

// RedeemLaunchCode spends a code for sessionID once, returning the operator
// and attachment kind it was issued for. Failed attempts are limited per
// source address (RedeemLimit) and, far more loosely, per session
// (SessionRedeemLimit). Only failures count, and a live code for its own
// session always redeems: the code is 256 random bits, so the limit is not
// what keeps it from being guessed - it bounds the noise - and someone
// else's bad guesses (or a shared NAT address) must never lock the owner out.
func (c *Credentials) RedeemLaunchCode(sessionID, code, ip string) (operator, kind string, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	c.sweepLocked(now)
	h := hashOf(code)
	e, ok := c.codes[h]
	if ok && code != "" && subtle.ConstantTimeCompare([]byte(e.sessionID), []byte(sessionID)) == 1 && !now.After(e.expires) {
		delete(c.codes, h)
		return e.operator, e.kind, nil
	}
	limits := map[string]int{"ip:" + ip: RedeemLimit, "session:" + sessionID: SessionRedeemLimit}
	for k, limit := range limits {
		if len(c.attempts[k]) >= limit {
			return "", "", ErrRedeemLimit
		}
	}
	for k := range limits {
		c.attempts[k] = append(c.attempts[k], now)
	}
	if ok {
		// One use: a code is spent by any redeem that names it, right or
		// wrong session, so a guessed session id cannot be retried against it.
		delete(c.codes, h)
	}
	return "", "", ErrCodeInvalid
}

// ResetAttempts clears the redeem rate limit counters. The hub's store is
// process-wide, so a test that runs into the limit clears it after itself
// rather than leaving the next test locked out.
func (c *Credentials) ResetAttempts() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.attempts = map[string][]time.Time{}
}

// IssueWatchToken mints a one-use watch token for sessionID.
func (c *Credentials) IssueWatchToken(sessionID, who string) string {
	tok := secret()
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	c.sweepLocked(now)
	c.watch[hashOf(tok)] = watchEntry{sessionID: sessionID, who: who, expires: now.Add(WatchTokenTTL)}
	return tok
}

// TakeWatchToken spends a watch token for sessionID, returning who it was
// issued to; ok is false when it is not a live watch token for that session.
func (c *Credentials) TakeWatchToken(sessionID, token string) (who string, ok bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	h := hashOf(token)
	e, found := c.watch[h]
	if !found || e.sessionID != sessionID || c.now().After(e.expires) {
		return "", false
	}
	delete(c.watch, h)
	return e.who, true
}

// SetControlMinter records who minted a session's current control token:
// agent is the agent's name when the hub admin key did (its input is then
// audited), "" for a person.
func (c *Credentials) SetControlMinter(sessionID, agent string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if agent == "" {
		delete(c.byAgent, sessionID)
	} else {
		c.byAgent[sessionID] = agent
	}
}

// ControlAgent is the agent that minted the session's control token, or "".
func (c *Credentials) ControlAgent(sessionID string) string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.byAgent[sessionID]
}

// Forget drops everything held for an ended session.
func (c *Credentials) Forget(sessionID string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.byAgent, sessionID)
	for k, e := range c.codes {
		if e.sessionID == sessionID {
			delete(c.codes, k)
		}
	}
	for k, e := range c.watch {
		if e.sessionID == sessionID {
			delete(c.watch, k)
		}
	}
}
