package releasesigner

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"
)

const (
	SessionTTL  = 600 * time.Second
	MaxPackage  = 1 << 30
	maxPackages = 8
	maxText     = 4096
)

var (
	versionRe = regexp.MustCompile(`^[0-9][0-9A-Za-z.+~-]{0,39}$`)
	pkgNameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+~-]{0,120}$`)
	tenantRe  = regexp.MustCompile(`^[A-Za-z0-9._-]{1,80}$`)
	sha256Re  = regexp.MustCompile(`^[0-9a-f]{64}$`)
	epochRe   = regexp.MustCompile(`^epoch=[1-9][0-9]{0,9}$`)
	trustLnRe = regexp.MustCompile(`^[ -~]{1,200}$`)
	idRe      = regexp.MustCompile(`^[0-9a-f]{32}$`)
	// deb and MSI (OLE compound file): a package can never double as a statement.
	magics = [][]byte{[]byte("!<arch>\ndebian-binary"), {0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1}}
)

// Config locates the key store and the session directory and says how the root half hardens itself.
type Config struct {
	Store, Run string
	Now        func() time.Time
	Harden     func() error // nil: none (tests); the command sets Harden
}

func (c Config) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

type pkg struct {
	Name   string `json:"name"`
	Sha256 string `json:"sha256,omitempty"`
}

type signed struct {
	Kind string `json:"kind"`
	Name string `json:"name"`
}

// session is the frozen request plus what has been signed so far (one JSON file, root 0600).
type session struct {
	ID        string            `json:"id"`
	Op        string            `json:"op"` // release or trust
	UID       string            `json:"uid,omitempty"`
	Expires   int64             `json:"expires"`
	KeyID     string            `json:"key_id"`
	Version   string            `json:"version,omitempty"`
	Packages  []pkg             `json:"packages,omitempty"`
	Tenant    string            `json:"tenant,omitempty"`
	Statement string            `json:"statement,omitempty"`
	Digests   map[string]string `json:"digests,omitempty"`
	Signed    []signed          `json:"signed,omitempty"`
}

func (s *session) total() int {
	if s.Op == "release" {
		return 2 * len(s.Packages)
	}
	return 1
}

func releaseStatement(name, version, sha string) []byte {
	return []byte("OMINULL-RELEASE-V1\npackage=" + name + "\nversion=" + version + "\nsha256=" + sha + "\n")
}

// payload is what the caller sent for one signature: a package is streamed (head + digest), a statement is held whole.
type payload struct {
	head []byte
	sha  string
	body []byte
}

func payloadOf(data []byte) payload {
	sum := sha256.Sum256(data)
	return payload{head: data[:min(len(data), 32)], sha: hex.EncodeToString(sum[:]), body: data}
}

// check applies the session rules and returns the SHA-256 (hex) to sign.
func (s *session) check(kind, name string, p payload) (string, error) {
	if s.Op == "trust" {
		if kind != "trust" || !bytes.Equal(p.body, []byte(s.Statement)) || len(s.Signed) > 0 {
			return "", errors.New("only the approved trust statement, once")
		}
		return p.sha, nil
	}
	var pk *pkg
	for i := range s.Packages {
		if s.Packages[i].Name == name {
			pk = &s.Packages[i]
		}
	}
	if pk == nil {
		return "", fmt.Errorf("%q is not one of the requested packages", name)
	}
	switch kind {
	case "package":
		if _, done := s.Digests[name]; done {
			return "", fmt.Errorf("%s was already signed", name)
		}
		if !hasMagic(p.head) {
			return "", fmt.Errorf("%s is not a deb or MSI package", name)
		}
		if pk.Sha256 != "" && p.sha != pk.Sha256 {
			return "", fmt.Errorf("%s changed since the request", name)
		}
		return p.sha, nil
	case "statement":
		d, ok := s.Digests[name]
		if !ok || s.has("statement", name) {
			return "", fmt.Errorf("the statement for %s comes once, after the package", name)
		}
		if !bytes.Equal(p.body, releaseStatement(name, s.Version, d)) {
			return "", fmt.Errorf("the statement for %s does not match the signed package", name)
		}
		return p.sha, nil
	}
	return "", errors.New("kind must be package, statement or trust")
}

func (s *session) has(kind, name string) bool {
	for _, x := range s.Signed {
		if x.Kind == kind && x.Name == name {
			return true
		}
	}
	return false
}

func hasMagic(head []byte) bool {
	for _, m := range magics {
		if bytes.HasPrefix(head, m) {
			return true
		}
	}
	return false
}

// record notes a signature that was made.
func (s *session) record(kind, name, sha string) {
	if kind == "package" {
		if s.Digests == nil {
			s.Digests = map[string]string{}
		}
		s.Digests[name] = sha
	}
	s.Signed = append(s.Signed, signed{kind, name})
}

// ---------------------------------------------------------------- freezing a request (begin)

// Request is what begin freezes: release VERSION NAME[=SHA]... or trust TENANT with the statement text.
type Request struct {
	Op        string
	Key       string // release key id or label
	Version   string
	Packages  []string // NAME[=SHA256]
	Tenant    string
	Statement string
}

func trustLines(text, tenant string) error {
	lines := strings.Split(text, "\n")
	if lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	if len(lines) != 6 || lines[0] != "OMINULL-TRUST-BUNDLE-V1" || lines[1] != "tenant="+tenant || !epochRe.MatchString(lines[2]) {
		return errors.New("not an OMINULL-TRUST-BUNDLE-V1 statement for that tenant")
	}
	for _, l := range lines[3:] {
		if !trustLnRe.MatchString(l) {
			return errors.New("not an OMINULL-TRUST-BUNDLE-V1 statement for that tenant")
		}
	}
	return nil
}

// freeze validates a request against the store and returns the session to write.
func freeze(s *storeFile, r Request, now time.Time) (*session, error) {
	out := &session{Op: r.Op, Expires: now.Add(SessionTTL).Unix(), UID: os.Getenv("SUDO_UID")}
	k, err := s.findKey(r.Key)
	if err != nil {
		return nil, err
	}
	if _, ok := k.Wraps[rootSeal]; !ok {
		return nil, errors.New("root does not hold this key")
	}
	out.KeyID = k.ID
	switch r.Op {
	case "release":
		if !versionRe.MatchString(r.Version) {
			return nil, errors.New("bad version")
		}
		if len(r.Packages) == 0 || len(r.Packages) > maxPackages {
			return nil, fmt.Errorf("name 1-%d packages", maxPackages)
		}
		seen := map[string]bool{}
		for _, a := range r.Packages {
			name, sha, _ := strings.Cut(a, "=")
			if !pkgNameRe.MatchString(name) || !strings.Contains(name, r.Version) {
				return nil, errors.New("each package needs a file name that carries the version")
			}
			if sha != "" && !sha256Re.MatchString(sha) {
				return nil, errors.New("a package digest is 64 hex characters")
			}
			if seen[name] {
				return nil, errors.New("a package is named twice")
			}
			seen[name] = true
			out.Packages = append(out.Packages, pkg{name, sha})
		}
		out.Version = r.Version
	case "trust":
		if !tenantRe.MatchString(r.Tenant) {
			return nil, errors.New("bad tenant")
		}
		if r.Statement == "" || len(r.Statement) > maxText {
			return nil, errors.New("the trust statement is missing")
		}
		if err := trustLines(r.Statement, r.Tenant); err != nil {
			return nil, err
		}
		out.Tenant, out.Statement = r.Tenant, r.Statement
	default:
		return nil, errors.New("op must be release or trust")
	}
	return out, nil
}

// ---------------------------------------------------------------- session files (Run, root 0700, one lock)

func (c Config) lock() (*os.File, error) {
	if err := os.MkdirAll(c.Run, 0o700); err != nil {
		return nil, err
	}
	if err := os.Chmod(c.Run, 0o700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(filepath.Join(c.Run, "lock"), os.O_RDWR|os.O_CREATE|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		f.Close()
		return nil, err
	}
	return f, nil
}

func (c Config) path(id string) string { return filepath.Join(c.Run, id+".json") }

func (c Config) save(s *session) error {
	b, _ := json.Marshal(s)
	tmp := c.path(s.ID) + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, c.path(s.ID))
}

// load returns a live session; an expired one is removed.
func (c Config) load(id string) (*session, error) {
	if !idRe.MatchString(id) {
		return nil, errors.New("no signing session (OMINULL_SIGNING_SESSION from 'begin')")
	}
	b, err := os.ReadFile(c.path(id))
	if err != nil {
		return nil, errors.New("no such signing session (finished, ended or expired)")
	}
	var s session
	if err := json.Unmarshal(b, &s); err != nil {
		return nil, err
	}
	if c.now().Unix() >= s.Expires {
		os.Remove(c.path(id))
		return nil, errors.New("the signing time is over")
	}
	if s.UID != "" && s.UID != os.Getenv("SUDO_UID") {
		return nil, errors.New("that signing session belongs to another user")
	}
	return &s, nil
}

func (c Config) prune() {
	es, _ := os.ReadDir(c.Run)
	for _, e := range es {
		id, ok := strings.CutSuffix(e.Name(), ".json")
		if !ok || !idRe.MatchString(id) {
			continue
		}
		if b, err := os.ReadFile(c.path(id)); err == nil {
			var s session
			if json.Unmarshal(b, &s) != nil || c.now().Unix() >= s.Expires {
				os.Remove(c.path(id))
			}
		}
	}
}

// Begin freezes the request and returns the session token.
func (c Config) Begin(r Request) (string, error) {
	st, err := loadStore(c.Store)
	if err != nil {
		return "", err
	}
	s, err := freeze(st, r, c.now())
	if err != nil {
		return "", err
	}
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	s.ID = hex.EncodeToString(raw)
	lk, err := c.lock()
	if err != nil {
		return "", err
	}
	defer lk.Close()
	c.prune()
	return s.ID, c.save(s)
}

// End deletes a session (no error when it is already gone).
func (c Config) End(id string) error {
	if !idRe.MatchString(id) {
		return errors.New("no signing session (OMINULL_SIGNING_SESSION from 'begin')")
	}
	lk, err := c.lock()
	if err != nil {
		return err
	}
	defer lk.Close()
	if _, err := c.load(id); err != nil && !strings.HasPrefix(err.Error(), "no such") {
		return err
	}
	os.Remove(c.path(id))
	return nil
}

// Sign reads size bytes of data, applies the session rules, signs and records it. Returns the DER signature.
func (c Config) Sign(id, kind, name string, size int64, data io.Reader) ([]byte, error) {
	if size <= 0 || size > MaxPackage || (kind != "package" && size > maxText) {
		return nil, errors.New("bad size")
	}
	lk, err := c.lock()
	if err != nil {
		return nil, err
	}
	defer lk.Close()
	s, err := c.load(id)
	if err != nil {
		return nil, err
	}
	h := sha256.New()
	var head, body bytes.Buffer
	var w io.Writer = io.MultiWriter(h, &limited{&head, 32})
	if kind != "package" {
		w = io.MultiWriter(h, &body)
	}
	if n, err := io.CopyN(w, data, size); err != nil {
		return nil, fmt.Errorf("short read: got %d of %d bytes", n, size)
	}
	p := payload{head: head.Bytes(), sha: hex.EncodeToString(h.Sum(nil)), body: body.Bytes()}
	sha, err := s.check(kind, name, p)
	if err != nil {
		return nil, err
	}
	if c.now().Unix() >= s.Expires {
		return nil, errors.New("the signing time is over")
	}
	key, err := c.openKey(s)
	if err != nil {
		return nil, err
	}
	digest, _ := hex.DecodeString(sha)
	sig, err := ecdsa.SignASN1(rand.Reader, key, digest)
	if err != nil {
		return nil, err
	}
	s.record(kind, name, sha)
	if len(s.Signed) >= s.total() {
		os.Remove(c.path(id))
	} else if err := c.save(s); err != nil {
		return nil, err
	}
	return sig, nil
}

// openKey hardens the process (no core dump, memory locked) and opens the session's key with root's seal.
func (c Config) openKey(s *session) (*ecdsa.PrivateKey, error) {
	if c.Harden != nil {
		if err := c.Harden(); err != nil {
			return nil, fmt.Errorf("cannot lock memory for the key: %w", err)
		}
	}
	st, err := loadStore(c.Store)
	if err != nil {
		return nil, err
	}
	rec := st.keyByID(s.KeyID)
	if rec == nil {
		return nil, errors.New("the session's key is gone from the store")
	}
	return openKey(c.Store, st, rec)
}

// limited keeps only the first n bytes written.
type limited struct {
	b *bytes.Buffer
	n int
}

func (l *limited) Write(p []byte) (int, error) {
	if room := l.n - l.b.Len(); room > 0 {
		l.b.Write(p[:min(room, len(p))])
	}
	return len(p), nil
}
