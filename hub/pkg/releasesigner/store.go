// Package releasesigner is OmniNull's own release signer: the root half opens the
// release (or routine) key from the on-disk key store with root's seal and signs
// one frozen session's files; the user half is the OMINULL_SIGNING_COMMAND.
package releasesigner

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/hkdf"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// Defaults, overridable with OMINULL_SIGNING_STORE / _PUBLIC / _RUN.
const (
	DefaultStore  = "/var/lib/nightshift/release-signing"
	DefaultPublic = "/var/lib/nightshift/release-signing.json"
	DefaultRun    = "/run/ominull-signing"
	rootSealFile  = "root-seal.key"
	rootSeal      = "root"
)

type wrap struct {
	Epk   string `json:"epk"`
	Nonce string `json:"nonce"`
	Ct    string `json:"ct"`
}

type keyRec struct {
	ID     string          `json:"id"`
	Label  string          `json:"label"`
	Pubkey string          `json:"pubkey"`
	Wraps  map[string]wrap `json:"wraps"`
}

type storeFile struct {
	Seals       map[string]struct{ Pub string } `json:"seals"`
	Keys        []keyRec                        `json:"keys"`
	RoutineKeys []keyRec                        `json:"routine_keys"`
	RoutineList *struct {
		Keys string `json:"keys"`
	} `json:"routine_list"`
}

func loadStore(dir string) (*storeFile, error) {
	b, err := os.ReadFile(filepath.Join(dir, "store.json"))
	if err != nil {
		return nil, err
	}
	var s storeFile
	if err := json.Unmarshal(b, &s); err != nil {
		return nil, fmt.Errorf("store.json: %w", err)
	}
	return &s, nil
}

func (s *storeFile) routineListed(id string) bool {
	if s.RoutineList == nil {
		return false
	}
	for _, e := range strings.Split(s.RoutineList.Keys, ",") {
		if e != "" && strings.SplitN(e, ":", 2)[0] == id {
			return true
		}
	}
	return false
}

// findKey picks a release key by id prefix or label ("" means the only one).
func (s *storeFile) findKey(want string) (*keyRec, error) {
	var hit []*keyRec
	for i := range s.Keys {
		k := &s.Keys[i]
		if want == "" || strings.HasPrefix(k.ID, want) || k.Label == want || strings.HasPrefix(k.Label, want+" ") {
			hit = append(hit, k)
		}
	}
	if len(hit) != 1 {
		return nil, fmt.Errorf("%d stored keys match %q; name one by id or label", len(hit), want)
	}
	return hit[0], nil
}

// keyByID finds a release or routine key by its exact id.
func (s *storeFile) keyByID(id string) *keyRec {
	for _, g := range [][]keyRec{s.Keys, s.RoutineKeys} {
		for i := range g {
			if g[i].ID == id {
				return &g[i]
			}
		}
	}
	return nil
}

// keyID is the first 16 hex characters of the SHA-256 of the public key's SPKI DER.
func keyID(pub *ecdsa.PublicKey) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:])[:16], nil
}

// readRootSeal reads root's raw X25519 seal; it must be a root-owned 0600-or-tighter 32-byte file
// whose public half is the one the store records for "root".
func readRootSeal(dir string, s *storeFile) (*ecdh.PrivateKey, error) {
	p := filepath.Join(dir, rootSealFile)
	fd, err := syscall.Open(p, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("root seal: %w", err)
	}
	f := os.NewFile(uintptr(fd), p)
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	sys, _ := st.Sys().(*syscall.Stat_t)
	if !st.Mode().IsRegular() || sys == nil || int(sys.Uid) != os.Geteuid() || st.Mode().Perm()&0o077 != 0 || st.Size() != 32 {
		return nil, fmt.Errorf("%s has unexpected owner/mode/size", p)
	}
	raw := make([]byte, 32)
	if _, err := f.Read(raw); err != nil {
		return nil, err
	}
	seal, err := ecdh.X25519().NewPrivateKey(raw)
	clear(raw)
	if err != nil {
		return nil, err
	}
	had, ok := s.Seals[rootSeal]
	if !ok || had.Pub != hex.EncodeToString(seal.PublicKey().Bytes()) {
		return nil, errors.New("root's signing seal does not match the store; nothing was opened")
	}
	return seal, nil
}

// unwrap opens one key copy: X25519 with the ephemeral key, HKDF-SHA256 (salt epk||seal pub,
// info "nightshift-key-wrap-v1:{kid}:{cid}"), AES-256-GCM with AAD "{kid}:{cid}".
func unwrap(w wrap, kid, cid string, seal *ecdh.PrivateKey) ([]byte, error) {
	epk, err := hex.DecodeString(w.Epk)
	if err != nil {
		return nil, err
	}
	nonce, err := hex.DecodeString(w.Nonce)
	if err != nil {
		return nil, err
	}
	ct, err := hex.DecodeString(w.Ct)
	if err != nil {
		return nil, err
	}
	epub, err := ecdh.X25519().NewPublicKey(epk)
	if err != nil {
		return nil, err
	}
	shared, err := seal.ECDH(epub)
	if err != nil {
		return nil, err
	}
	salt := append(append([]byte{}, epk...), seal.PublicKey().Bytes()...)
	k, err := hkdf.Key(sha256.New, shared, salt, "nightshift-key-wrap-v1:"+kid+":"+cid, 32)
	if err != nil {
		return nil, err
	}
	blk, err := aes.NewCipher(k)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(blk)
	if err != nil {
		return nil, err
	}
	return gcm.Open(nil, nonce, ct, []byte(kid+":"+cid))
}

// openKey opens rec with root's copy and checks the key against its id.
func openKey(dir string, s *storeFile, rec *keyRec) (*ecdsa.PrivateKey, error) {
	w, ok := rec.Wraps[rootSeal]
	if !ok {
		return nil, errors.New("root does not hold this key")
	}
	seal, err := readRootSeal(dir, s)
	if err != nil {
		return nil, err
	}
	der, err := unwrap(w, rec.ID, rootSeal, seal)
	if err != nil {
		return nil, errors.New("the stored key would not open with root's seal")
	}
	defer clear(der)
	parsed, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, err
	}
	key, ok := parsed.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New("the stored key is not an ECDSA key")
	}
	if id, err := keyID(&key.PublicKey); err != nil || id != rec.ID {
		return nil, errors.New("the stored key does not match its id")
	}
	return key, nil
}
