package response

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"
)

// Agent trust: what an endpoint verifies before it changes its own state.
// The agent side lives in agent/include/agent_trust.h; both must agree on
// every byte of the canonical forms below.

// Enforcement kinds. An isolation change, an agent update and a mesh
// quarantine are owner-approved (tenant response key). The detector's
// automatic isolation has its own narrow key and kind.
const (
	ActionKindIsolationChange ActionKind = "isolation_change"
	ActionKindAgentUpdate     ActionKind = "agent_update"
	ActionKindMeshQuarantine  ActionKind = "mesh_quarantine"
	ActionKindAutoIsolate     ActionKind = "auto_isolate"
	ActionKindCapability      ActionKind = "capability_change"
	// ActionKindDetectionPolicy is an owner-approved loosening of the hub's
	// own detection policy (tuning, exclusions). The hub applies it; no agent
	// ever receives a grant of this kind.
	ActionKindDetectionPolicy ActionKind = "detection_policy"
)

// AutoIsolateRoute is the route field of the detector's isolation payload.
const AutoIsolateRoute = "auto-isolate"

// Capability names a manifest can carry. The agent maps each action kind to
// one of these (agent_trust.h Trust_CapabilityFor).
const (
	CapUpdate   = "update"
	CapIsolate  = "isolate"
	CapMesh     = "mesh"
	CapCollect  = "collect"
	CapTerminal = "terminal"
	CapScript   = "script"
	// CapScreen is remote screen view/control. It sits beside the terminal:
	// each session still takes its own owner approval.
	CapScreen = "screen"
)

// Profiles. monitor: telemetry and updates only (hypervisors, hosts that must
// never be cut off). respond: containment and collection; the terminal is
// here by the owner's decision (2026-10-14: home machines keep a full
// terminal, each session still takes its own phone approval). engagement:
// adds hub-pushed scripts. monitor-scripts: a hypervisor's profile under the
// monitor-signed-scripts lock level: evidence collection, updates and scripts,
// no isolation, mesh, terminal or screen, so it stands while the hub keeps the
// host monitor-only (it adds no isolation).
var profileCaps = map[string][]string{
	"monitor":         {CapUpdate},
	"monitor-scripts": {CapCollect, CapScript, CapUpdate},
	"respond":         {CapCollect, CapIsolate, CapMesh, CapScreen, CapTerminal, CapUpdate},
	"engagement":      {CapCollect, CapIsolate, CapMesh, CapScreen, CapScript, CapTerminal, CapUpdate},
}

// ProfileCaps returns the sorted capability list of a profile.
func ProfileCaps(profile string) ([]string, bool) {
	c, ok := profileCaps[profile]
	if !ok {
		return nil, false
	}
	out := append([]string(nil), c...)
	sort.Strings(out)
	return out, true
}

// MatchesProfile reports whether the manifest holds exactly what its profile
// holds in this release. A manifest signed before a release changed the
// profile does not, and is re-signed.
func (m *CapabilityManifest) MatchesProfile() bool {
	want, ok := ProfileCaps(m.Profile)
	if !ok || len(want) != len(m.Caps) {
		return false
	}
	have := append([]string(nil), m.Caps...)
	sort.Strings(have)
	for i := range want {
		if have[i] != want[i] {
			return false
		}
	}
	return true
}

// ProfileNarrows reports whether moving from profile from to profile to only
// takes capabilities away (to's set is a strict subset of from's). Profiles
// are not a line: monitor-scripts adds scripts to what monitor holds but lacks
// respond's isolation, so a move between those is a raise either way.
func ProfileNarrows(from, to string) bool {
	f, ok1 := profileCaps[from]
	t, ok2 := profileCaps[to]
	if !ok1 || !ok2 || len(t) >= len(f) {
		return false
	}
	for _, c := range t {
		if !ProfileHas(from, c) {
			return false
		}
	}
	return true
}

// ProfileHas reports whether a profile holds a capability.
func ProfileHas(profile, capability string) bool {
	for _, c := range profileCaps[profile] {
		if c == capability {
			return true
		}
	}
	return false
}

// MonitorOnlyProfile: the profiles that add no isolation, so they may stand
// while the hub keeps a host monitor-only.
func MonitorOnlyProfile(profile string) bool {
	_, ok := profileCaps[profile]
	return ok && !ProfileHas(profile, CapIsolate) && !ProfileHas(profile, CapMesh) &&
		!ProfileHas(profile, CapTerminal) && !ProfileHas(profile, CapScreen)
}

// CapabilityManifest is what one endpoint may be asked to do, signed by the
// tenant's policy key. Seq only grows; an agent refuses an older one.
type CapabilityManifest struct {
	V           int      `json:"v"`
	TenantID    string   `json:"tenant_id"`
	EndpointID  string   `json:"endpoint_id"`
	Profile     string   `json:"profile"`
	Caps        []string `json:"caps"`
	Seq         int64    `json:"seq"`
	IssuedAt    int64    `json:"issued_at"`
	SignerKeyID string   `json:"signer_key_id"`
	Signature   string   `json:"signature"`
}

// CanonicalBytes is the signed form (OMINULL-CAPABILITY-MANIFEST-V1).
func (m *CapabilityManifest) CanonicalBytes() []byte {
	enc := NewCanonicalEncoder("OMINULL-CAPABILITY-MANIFEST-V1")
	enc.WriteUint32(uint32(m.V))
	enc.WriteString(m.TenantID)
	enc.WriteString(m.EndpointID)
	enc.WriteString(m.Profile)
	enc.WriteStringSlice(m.Caps)
	enc.WriteInt64(m.Seq)
	enc.WriteInt64(m.IssuedAt)
	enc.WriteHexNormalized(m.SignerKeyID)
	return enc.Bytes()
}

// Sign fills SignerKeyID and Signature.
func (m *CapabilityManifest) Sign(priv ed25519.PrivateKey) {
	pub := priv.Public().(ed25519.PublicKey)
	fp := sha256.Sum256(pub)
	m.SignerKeyID = hex.EncodeToString(fp[:])
	m.Signature = hex.EncodeToString(ed25519.Sign(priv, m.CanonicalBytes()))
}

// Verify checks the manifest against a policy public key.
func (m *CapabilityManifest) Verify(pub ed25519.PublicKey) error {
	if m.V != 1 || m.Seq <= 0 || m.EndpointID == "" {
		return errors.New("malformed capability manifest")
	}
	if !sort.StringsAreSorted(m.Caps) {
		return errors.New("manifest capabilities must be sorted")
	}
	for i := 1; i < len(m.Caps); i++ {
		if m.Caps[i] == m.Caps[i-1] {
			return errors.New("manifest capabilities must be unique")
		}
	}
	sig, err := hex.DecodeString(m.Signature)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return errors.New("manifest signature unreadable")
	}
	if !ed25519.Verify(pub, m.CanonicalBytes(), sig) {
		return errors.New("manifest signature does not verify")
	}
	return nil
}

// Has reports whether the manifest grants a capability.
func (m *CapabilityManifest) Has(c string) bool {
	if m == nil {
		return c == CapUpdate
	}
	for _, x := range m.Caps {
		if x == c {
			return true
		}
	}
	return false
}

// TrustKeys are the three public keys an agent pins (hex, 32 bytes each).
// Agents pin them only with BundleSig: the release key's signature over
// TrustBundleStatement, which the hub cannot make.
type TrustKeys struct {
	ResponseKey    string `json:"response_key"`
	AutoIsolateKey string `json:"auto_isolate_key"`
	PolicyKey      string `json:"policy_key"`
	TenantID       string `json:"tenant_id"`
	// Epoch orders bundles: agents never pin one older than any they pinned
	// (or than their build's floor), so a bundle for retired keys cannot be
	// replayed after a rotation. Raised whenever the authority's keys change.
	Epoch     int64  `json:"epoch"`
	BundleSig string `json:"bundle_sig,omitempty"` // base64 DER ECDSA P-256 / SHA-256
}

// ReleasePublicKeyPEM is the release signing key pinned into every agent
// (agent/include/release_key.h; release.sh refuses a signing key that differs).
const ReleasePublicKeyPEM = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEUczKMOE8yfDzAWxOC6WPJiSTz/Oo
j/YnhRtusQqVxGVFFgcfxN1KqkCaLO2ZoYokeanZyJXzmJPzbq8woDaXfg==
-----END PUBLIC KEY-----
`

// TrustBundleStatement is what the release key signs to let agents pin a
// tenant's authority keys. Agents rebuild it byte for byte.
func TrustBundleStatement(k *TrustKeys) string {
	return fmt.Sprintf("OMINULL-TRUST-BUNDLE-V1\ntenant=%s\nepoch=%d\nresponse_key=%s\nauto_isolate_key=%s\npolicy_key=%s\n",
		k.TenantID, k.Epoch, strings.ToLower(k.ResponseKey), strings.ToLower(k.AutoIsolateKey), strings.ToLower(k.PolicyKey))
}

// VerifyReleaseSignature checks a DER ECDSA P-256 / SHA-256 signature over msg
// against a PEM public key (the release key agents pin).
func VerifyReleaseSignature(pubPEM []byte, msg, der []byte) error {
	blk, _ := pem.Decode(pubPEM)
	if blk == nil {
		return errors.New("release public key is not PEM")
	}
	k, err := x509.ParsePKIXPublicKey(blk.Bytes)
	if err != nil {
		return err
	}
	ec, ok := k.(*ecdsa.PublicKey)
	if !ok || ec.Curve != elliptic.P256() {
		return errors.New("release public key is not P-256")
	}
	sum := sha256.Sum256(msg)
	if !ecdsa.VerifyASN1(ec, sum[:], der) {
		return errors.New("signature does not verify against the release key")
	}
	return nil
}

// EnforcementGrant is a grant plus the exact payload bytes it digests, as
// delivered to an agent (payload base64 so no JSON string escaping can
// change a byte).
type EnforcementGrant struct {
	Grant      *EndpointGrant `json:"grant"`
	PayloadB64 string         `json:"payload_b64"`
}

// AgentTrustReport is what an agent says about its trust state each beat.
type AgentTrustReport struct {
	V               int    `json:"v"`
	Keys            string `json:"keys"`
	ResponseKey     bool   `json:"response_key"`
	AutoIsolateKey  bool   `json:"auto_isolate_key"`
	PolicyKey       bool   `json:"policy_key"`
	ManifestSeq     int64  `json:"manifest_seq"`
	Profile         string `json:"profile"`
	IsoSeen         int64  `json:"iso_seen"`
	MeshSeen        int64  `json:"mesh_seen"`
	Isolated        bool   `json:"isolated"`
	IsolationSource string `json:"isolation_source"`
	Peers           int    `json:"peers"`
	Refused         string `json:"refused"`
	RefusedAt       int64  `json:"refused_at"`
	Ceiling         string `json:"ceiling"` // local capability ceiling set on the host, "" = none
	// Host authority (agents from 1.8.81): keys pinned on the host itself
	// (Nightshift's), whose grants alone run scripts there.
	HostAuthority bool              `json:"host_authority"`
	HostKeys      []HostKeyReport   `json:"host_keys,omitempty"`
	HostAllow     []HostAllowReport `json:"host_allow,omitempty"`
	HostError     string            `json:"host_error,omitempty"`
	// UTCOffset is the machine's clock offset east of UTC in minutes (agents
	// from 1.8.82), for maintenance windows in machine time.
	UTCOffset *int `json:"utc_offset_minutes,omitempty"`
}

// HostKeyReport is one pinned host-authority key: its signer_key_id and role
// (tap: any script; auto: allow-listed packages only).
type HostKeyReport struct {
	ID   string `json:"id"`
	Role string `json:"role"`
}

// HostAllowReport is one package auto grants may run on the host.
type HostAllowReport struct {
	Name   string   `json:"name"`
	SHA256 string   `json:"sha256"`
	Modes  []string `json:"modes"`
}

// HostKey returns the reported host key with this signer id.
func (r *AgentTrustReport) HostKey(signerKeyID string) *HostKeyReport {
	for i := range r.HostKeys {
		if strings.EqualFold(r.HostKeys[i].ID, signerKeyID) {
			return &r.HostKeys[i]
		}
	}
	return nil
}

// IsolationBaseline binds the exceptions an isolation leaves open (DNS, DHCP,
// NTP, custom) into the payload the owner approves, for the endpoints named.
// Agents use only these while isolated, never the heartbeat's copy. Field
// order is alphabetical so the struct encodes canonically.
type IsolationBaseline struct {
	Endpoints []string        `json:"endpoints"`
	Rules     []IsolationRule `json:"rules"`
}

// IsolationRule is one exception: traffic to destination:port over protocol.
type IsolationRule struct {
	Destination string `json:"destination"`
	Port        int    `json:"port"`
	Protocol    string `json:"protocol"`
	Service     string `json:"service"`
}

// MaxIsolationRules is what an agent holds per isolation (TRUST_MAX_RULES).
const MaxIsolationRules = 64

// Valid is the agent's own rule check (agent_trust.h Trust_RuleValid): an
// exception list with one invalid rule is refused whole there.
func (r IsolationRule) Valid() bool {
	if r.Service == "" || len(r.Service) > 15 || len(r.Destination) >= 64 {
		return false
	}
	for _, c := range r.Service {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			return false
		}
	}
	for _, c := range r.Destination {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F' || c == '.' || c == ':') {
			return false
		}
	}
	if net.ParseIP(r.Destination) == nil || strings.Contains(r.Destination, ":") && strings.Contains(r.Destination, ".") {
		return false
	}
	return (r.Protocol == "tcp" || r.Protocol == "udp") && r.Port >= 1 && r.Port <= 65535
}

// ReleaseStatement is what the release key signs besides the package bytes:
// the version an agent installs is signed, not only the file.
func ReleaseStatement(pkg, version, sha256Hex string) string {
	return fmt.Sprintf("OMINULL-RELEASE-V1\npackage=%s\nversion=%s\nsha256=%s\n", pkg, version, strings.ToLower(sha256Hex))
}
