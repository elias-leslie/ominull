// Package grants signs what agents act on: enforcement, forensic and script
// grants, automatic isolations and capability manifests, each verified on the
// agent against keys it pinned from a trust bundle the release key signed.
//
// The signer runs inside the hub, which decides what may run; agents still check
// each grant themselves and enforce their own locks and capability limits. Its
// state is a directory (keys, manifests, the enforcement clock, trust epochs)
// the hub alone reads.
package grants

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"ominull/hub/pkg/response"
)

// Config says where the signer keeps its state.
type Config struct {
	StateDir string
	// TrustEpochFloor is the lowest trust bundle epoch handed out. After a
	// rotation that lost the state, set it above every epoch ever signed so the
	// new bundle outranks the retired one.
	TrustEpochFloor int64
	// RequireKeys says agents may already pin this hub's keys (a trust bundle
	// was signed), so a missing default key is lost or unmigrated state, never a
	// first run.
	RequireKeys bool
}

// Signer holds the tenant keys and the books that keep agents' counters rising.
type Signer struct {
	mu          sync.RWMutex
	cfg         Config
	keyDir      string
	tenantKeys  map[string]ed25519.PrivateKey // tenant or tenant#slot -> signing key
	autoIso     *autoIsolateBook              // the detector's isolation budget
	manifests   *manifestBook                 // capability manifests, one per endpoint
	enfClock    *enforcementClock             // strictly ordered enforcement grant times
	trustEpochs *trustEpochs                  // trust bundle epoch per tenant
}

// Open loads the signer's state, creating the directory on first use. An
// unreadable key or manifest file is an error rather than a new start, and so
// is a missing key under RequireKeys: new keys or lost manifest numbers would
// leave every agent refusing what the hub signs.
func Open(cfg Config) (*Signer, error) {
	if cfg.StateDir == "" {
		return nil, errors.New("the grant signer needs a state directory")
	}
	keyDir := filepath.Join(cfg.StateDir, "keys")
	if err := os.MkdirAll(keyDir, 0o700); err != nil {
		return nil, fmt.Errorf("create the grant key directory: %w", err)
	}
	manifests, err := newManifestBook(cfg.StateDir)
	if err != nil {
		return nil, err
	}
	s := &Signer{
		cfg:         cfg,
		keyDir:      keyDir,
		tenantKeys:  map[string]ed25519.PrivateKey{},
		autoIso:     &autoIsolateBook{byTenant: map[string][]time.Time{}, byEndpoint: map[string]time.Time{}},
		manifests:   manifests,
		enfClock:    newEnforcementClock(cfg.StateDir),
		trustEpochs: newTrustEpochs(cfg.StateDir, cfg.TrustEpochFloor),
	}
	entries, err := os.ReadDir(keyDir)
	if err != nil {
		return nil, fmt.Errorf("read the grant key directory: %w", err)
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".key") {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(keyDir, entry.Name()))
		if err != nil {
			return nil, fmt.Errorf("read grant key %s: %w", entry.Name(), err)
		}
		key, err := hex.DecodeString(strings.TrimSpace(string(raw)))
		if err != nil || len(key) != ed25519.PrivateKeySize {
			return nil, fmt.Errorf("grant key %s is not an ed25519 private key", entry.Name())
		}
		s.tenantKeys[strings.TrimSuffix(entry.Name(), ".key")] = ed25519.PrivateKey(key)
	}
	if cfg.RequireKeys {
		for _, id := range []string{"default", "default" + keySlotAutoIsolate, "default" + keySlotPolicy} {
			if _, ok := s.tenantKeys[id]; !ok {
				return nil, fmt.Errorf("a trust bundle is signed but grant key %s is missing from %s: restore it; new keys would leave every agent refusing grants", id, keyDir)
			}
		}
	}
	return s, nil
}

// GetOrCreateTenantKey returns the tenant's response key, generating it the
// first time. Tenant ids never contain '#': that separator names the tenant's
// internal keys (auto-isolation, policy), which no caller may reach this way.
func (a *Signer) GetOrCreateTenantKey(tenantID string) (ed25519.PublicKey, string, error) {
	if strings.Contains(tenantID, "#") {
		return nil, "", errors.New("invalid tenant ID")
	}
	return a.getOrCreateKey(tenantID)
}

func (a *Signer) getOrCreateKey(id string) (ed25519.PublicKey, string, error) {
	if id == "" || id == "." || id == ".." || strings.ContainsAny(id, "/\\\x00") {
		return nil, "", errors.New("invalid tenant ID")
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if priv, ok := a.tenantKeys[id]; ok {
		pub := priv.Public().(ed25519.PublicKey)
		return pub, keyFingerprint(pub), nil
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, "", fmt.Errorf("generate an ed25519 key: %w", err)
	}
	if err := writeDurable(filepath.Join(a.keyDir, id+".key"), []byte(hex.EncodeToString(priv))); err != nil {
		return nil, "", fmt.Errorf("save grant key: %w", err)
	}
	a.tenantKeys[id] = priv
	log.Printf("[+] Generated grant key %s (%s)", id, keyFingerprint(pub))
	return pub, keyFingerprint(pub), nil
}

func keyFingerprint(pub ed25519.PublicKey) string {
	fp := sha256.Sum256(pub)
	return hex.EncodeToString(fp[:])
}

// SignGrantRequest asks for one forensic or script grant.
type SignGrantRequest struct {
	TenantID     string
	OperatorID   string
	EndpointID   string
	ActionKind   response.ActionKind
	ActionDigest string
	TTLSeconds   int64
}

// SignGrant signs one forensic collection or one script run. A terminal or
// screen session goes through Authorize, which reads what it opens.
func (a *Signer) SignGrant(req *SignGrantRequest) (*response.EndpointGrant, error) {
	if req == nil {
		return nil, errors.New("missing sign grant request")
	}
	if !validTenant(req.TenantID) {
		return nil, errors.New("invalid tenant ID")
	}
	switch req.ActionKind {
	case response.ActionKindForensicCollect, response.ActionKindScriptExec:
	default:
		return nil, fmt.Errorf("action kind %q is not signed this way", req.ActionKind)
	}
	priv, keyID, err := a.tenantSigningKey(req.TenantID)
	if err != nil {
		return nil, err
	}
	ttl := req.TTLSeconds
	if ttl <= 0 || ttl > 3600 {
		ttl = 300
	}
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	now := time.Now().Unix()
	id := uuid.New().String()
	g := &response.EndpointGrant{
		Version:           response.GrantVersion,
		GrantID:           id,
		TenantID:          req.TenantID,
		EndpointID:        req.EndpointID,
		ActionKind:        req.ActionKind,
		ActionDigest:      req.ActionDigest,
		OperatorID:        agentOperatorID(req.OperatorID),
		ResponseSessionID: "approval:" + strings.ReplaceAll(id, "-", ""),
		IssuedAt:          now,
		ExpiresAt:         now + ttl,
		Nonce:             hex.EncodeToString(nonce),
		SignerKeyID:       keyID,
	}
	g.Signature = hex.EncodeToString(ed25519.Sign(priv, g.CanonicalBytes()))
	a.auditAction(req.TenantID, req.OperatorID, "grant_signed", string(req.ActionKind), req.EndpointID, id, "success", "")
	return g, nil
}
