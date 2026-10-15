package response

// Cross-language agent trust fixtures. This test signs grants, manifests and
// heartbeat answers with the hub's own encoders (deterministic keys and times)
// and writes them as a C header the agent's trust test compiles in
// (agent/tests/test_agent_trust.c). It fails when the committed header is not
// what the Go side produces now, so the two implementations cannot drift.
// Regenerate with: OMINULL_UPDATE_FIXTURES=1 go test ./pkg/response -run TestAgentTrustFixtures

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

const (
	fixtureEndpoint = "ep-trust-1"
	fixtureTenant   = "default"
	fixtureT0       = int64(1800000000)
)

func fixtureKey(name string) ed25519.PrivateKey {
	seed := sha256.Sum256([]byte("ominull-trust-fixture:" + name))
	return ed25519.NewKeyFromSeed(seed[:])
}

func pubHex(k ed25519.PrivateKey) string {
	return hex.EncodeToString(k.Public().(ed25519.PublicKey))
}

// routed builds the payload exactly as the hub's ownerApproved does.
func routed(route string, body map[string]interface{}, targets []string) []byte {
	canon, _ := json.Marshal(body)
	raw, _ := json.Marshal(map[string]interface{}{"route": route, "body": json.RawMessage(canon), "targets": targets})
	return raw
}

// routedWithBaselines adds the isolation exceptions the hub binds into an
// isolation it asks the owner to approve (sorted keys at every level).
func routedWithBaselines(route string, body map[string]interface{}, targets []string, baselines []interface{}) []byte {
	canon, _ := json.Marshal(body)
	raw, _ := json.Marshal(map[string]interface{}{"route": route, "body": json.RawMessage(canon), "targets": targets, "baselines": baselines})
	return raw
}

func rule(service, dest, proto string, port int) map[string]interface{} {
	return map[string]interface{}{"service": service, "destination": dest, "protocol": proto, "port": port}
}

type fixtureGrant struct {
	key      ed25519.PrivateKey
	id       string
	endpoint string
	kind     ActionKind
	payload  []byte
	issued   int64
	ttl      int64
	tamper   bool // payload changed after signing
}

func (f fixtureGrant) wire() string {
	sum := sha256.Sum256(f.payload)
	nonce := sha256.Sum256([]byte("nonce:" + f.id))
	g := &EndpointGrant{
		Version: GrantVersion, GrantID: f.id, TenantID: fixtureTenant, EndpointID: f.endpoint,
		ActionKind: f.kind, ActionDigest: hex.EncodeToString(sum[:]), OperatorID: "owner",
		ResponseSessionID: "approval:fixture", IssuedAt: f.issued, ExpiresAt: f.issued + f.ttl,
		Nonce: hex.EncodeToString(nonce[:16]),
	}
	fp := sha256.Sum256(f.key.Public().(ed25519.PublicKey))
	g.SignerKeyID = hex.EncodeToString(fp[:])
	g.Signature = hex.EncodeToString(ed25519.Sign(f.key, g.CanonicalBytes()))
	payload := f.payload
	if f.tamper {
		payload = bytes.Replace(payload, []byte("10.0.0.9"), []byte("10.0.0.8"), 1)
	}
	raw, _ := json.Marshal(EnforcementGrant{Grant: g, PayloadB64: base64.StdEncoding.EncodeToString(payload)})
	return string(raw)
}

func manifestJSON(key ed25519.PrivateKey, endpoint, profile string, seq int64) string {
	caps, _ := ProfileCaps(profile)
	m := &CapabilityManifest{V: 1, TenantID: fixtureTenant, EndpointID: endpoint, Profile: profile, Caps: caps, Seq: seq, IssuedAt: fixtureT0 + seq}
	m.Sign(key)
	raw, _ := json.Marshal(m)
	return string(raw)
}

// fixtureBundle is one trust offer in the fixtures (keys without the
// signature; the C test adds bundle_sig).
type fixtureBundle struct {
	name            string
	resp, auto, pol ed25519.PrivateKey
	tenant          string
	epoch           int64
}

func (b fixtureBundle) keys() *TrustKeys {
	return &TrustKeys{ResponseKey: pubHex(b.resp), AutoIsolateKey: pubHex(b.auto), PolicyKey: pubHex(b.pol), TenantID: b.tenant, Epoch: b.epoch}
}

func (b fixtureBundle) json() string {
	raw, _ := json.Marshal(b.keys())
	return string(raw)
}

func fixtureBundles() []fixtureBundle {
	resp, auto, pol, evil := fixtureKey("response"), fixtureKey("auto"), fixtureKey("policy"), fixtureKey("attacker")
	return []fixtureBundle{
		{"", resp, auto, pol, fixtureTenant, 2},
		{"_OTHER_KEYS", evil, evil, evil, fixtureTenant, 2},
		{"_OLD", resp, auto, pol, fixtureTenant, 1},
		{"_NEXT", resp, auto, pol, fixtureTenant, 3},
		{"_TENANT", evil, evil, evil, "other", 3},
	}
}

// fixtureReleaseKey stands in for the release key in the trust-bundle
// fixtures (a P-256 scalar derived from a label; test-only).
func fixtureReleaseKey(name string) *ecdsa.PrivateKey {
	d := sha256.Sum256([]byte("ominull-release-fixture:" + name))
	k, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), d[:])
	if err != nil {
		panic(err)
	}
	return k
}

func fixtureReleasePubPEM() string {
	der, _ := x509.MarshalPKIXPublicKey(&fixtureReleaseKey("release").PublicKey)
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

func bundleSig(signer *ecdsa.PrivateKey, k *TrustKeys) string {
	stmt := TrustBundleStatement(k)
	sum := sha256.Sum256([]byte(stmt))
	der, err := ecdsa.SignASN1(rand.Reader, signer, sum[:])
	if err != nil {
		panic(err)
	}
	return base64.StdEncoding.EncodeToString(der)
}

// ECDSA signatures are randomized, so these lines are checked by verifying
// them, not by comparing bytes.
const bundleSigPrefix = "#define FX_TB_SIG"

func cString(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range []byte(s) {
		switch {
		case r == '"' || r == '\\':
			b.WriteByte('\\')
			b.WriteByte(r)
		case r < 0x20 || r > 0x7e:
			fmt.Fprintf(&b, "\\x%02x\"\"", r)
		default:
			b.WriteByte(r)
		}
	}
	b.WriteByte('"')
	return b.String()
}

func buildTrustFixtures() []byte {
	resp, auto, pol, evil := fixtureKey("response"), fixtureKey("auto"), fixtureKey("policy"), fixtureKey("attacker")
	ep := fixtureEndpoint
	day, tenMin := int64(86400), int64(600)
	iso := func(allow []string) []byte {
		return routed("/api/v1/endpoints/isolate", map[string]interface{}{"endpoint_id": ep, "allow_ips": allow, "force": false}, []string{ep})
	}
	rel := routed("/api/v1/endpoints/unisolate", map[string]interface{}{"endpoint_id": ep}, []string{ep})
	bulkIso := routed("/api/v1/endpoints/isolate-bulk", map[string]interface{}{"scope": "ids", "ids": []string{ep, "ep-other"}}, []string{"ep-other", ep})
	autoPayload, _ := json.Marshal(map[string]interface{}{"route": AutoIsolateRoute, "body": map[string]string{"endpoint_id": ep, "reason": "lateral port sweep <fixture>"}, "targets": []string{ep}})
	meshOn := routed("/api/v1/mesh/quarantine", map[string]interface{}{"target_ip": "10.0.0.66", "reason": "beaconing & scanning"}, []string{"mesh:10.0.0.66"})
	meshOff := routed("/api/v1/mesh/unquarantine", map[string]interface{}{"target_ip": "10.0.0.66"}, []string{"mesh:10.0.0.66"})
	upd := routed("/api/v1/agents/update", map[string]interface{}{"endpoint_ids": []string{ep}, "version": "9.9.9"}, []string{ep})

	// Payloads two JSON readers could read differently. The authority's
	// strictPayload refuses these before an owner ever sees them; the agent
	// must refuse them too.
	dupRoute := []byte(`{"body":{"endpoint_id":"` + ep + `"},"route":"/api/v1/endpoints/isolate","route":"/api/v1/endpoints/unisolate","targets":["` + ep + `"]}`)
	caseRoute := []byte(`{"Route":"/api/v1/endpoints/unisolate","body":{"endpoint_id":"` + ep + `"},"route":"/api/v1/endpoints/isolate","targets":["` + ep + `"]}`)
	escRoute := []byte(`{"body":{"endpoint_id":"` + ep + `"},"rout\u0065":"/api/v1/endpoints/isolate","targets":["` + ep + `"]}`)

	isoBody := map[string]interface{}{"endpoint_id": ep, "allow_ips": []string{"10.0.0.9"}, "force": false}
	site := []interface{}{rule("dns", "192.0.2.53", "udp", 53), rule("dhcp", "255.255.255.255", "udp", 67)}
	isoRules := routedWithBaselines("/api/v1/endpoints/isolate", isoBody, []string{ep},
		[]interface{}{map[string]interface{}{"endpoints": []string{ep, "ep-other"}, "rules": site}})
	isoRulesBad := routedWithBaselines("/api/v1/endpoints/isolate", isoBody, []string{ep},
		[]interface{}{map[string]interface{}{"endpoints": []string{ep}, "rules": []interface{}{rule("custom", "0.0.0.0/0", "tcp", 443)}}})
	isoRulesTwice := routedWithBaselines("/api/v1/endpoints/isolate", isoBody, []string{ep},
		[]interface{}{map[string]interface{}{"endpoints": []string{ep}, "rules": site}, map[string]interface{}{"endpoints": []string{ep}, "rules": []interface{}{}}})
	g := map[string]string{
		"G_ISO_RULES":       fixtureGrant{key: resp, id: "g-iso-rules", endpoint: ep, kind: ActionKindIsolationChange, payload: isoRules, issued: fixtureT0 + 120, ttl: day}.wire(),
		"G_ISO_RULES_BAD":   fixtureGrant{key: resp, id: "g-iso-rules-bad", endpoint: ep, kind: ActionKindIsolationChange, payload: isoRulesBad, issued: fixtureT0 + 121, ttl: day}.wire(),
		"G_ISO_RULES_TWICE": fixtureGrant{key: resp, id: "g-iso-rules-2x", endpoint: ep, kind: ActionKindIsolationChange, payload: isoRulesTwice, issued: fixtureT0 + 122, ttl: day}.wire(),
		"G_REL_RULES":       fixtureGrant{key: resp, id: "g-rel-rules", endpoint: ep, kind: ActionKindIsolationChange, payload: rel, issued: fixtureT0 + 123, ttl: day}.wire(),
		// Refused, issued before the first genuine one so the order of the
		// C test does not depend on watermark effects.
		"G_ISO_FORGED":        fixtureGrant{key: evil, id: "g-forged", endpoint: ep, kind: ActionKindIsolationChange, payload: iso(nil), issued: fixtureT0 + 9_000_000, ttl: day}.wire(),
		"G_ISO_OTHER_EP_LATE": fixtureGrant{key: resp, id: "g-other-ep-late", endpoint: "ep-other", kind: ActionKindIsolationChange, payload: routed("/api/v1/endpoints/unisolate", map[string]interface{}{"endpoint_id": "ep-other"}, []string{"ep-other"}), issued: fixtureT0 + 15, ttl: day}.wire(),
		"G_ISO_OTHER_EP":      fixtureGrant{key: resp, id: "g-other-ep", endpoint: "ep-other", kind: ActionKindIsolationChange, payload: routed("/api/v1/endpoints/isolate", map[string]interface{}{"endpoint_id": "ep-other"}, []string{"ep-other"}), issued: fixtureT0 + 2, ttl: day}.wire(),
		"G_ISO_TAMPERED":      fixtureGrant{key: resp, id: "g-tampered", endpoint: ep, kind: ActionKindIsolationChange, payload: iso([]string{"10.0.0.9"}), issued: fixtureT0 + 3, ttl: day, tamper: true}.wire(),
		"G_ISO_DUP_ROUTE":     fixtureGrant{key: resp, id: "g-dup", endpoint: ep, kind: ActionKindIsolationChange, payload: dupRoute, issued: fixtureT0 + 4, ttl: day}.wire(),
		"G_ISO_CASE_ROUTE":    fixtureGrant{key: resp, id: "g-case", endpoint: ep, kind: ActionKindIsolationChange, payload: caseRoute, issued: fixtureT0 + 5, ttl: day}.wire(),
		"G_ISO_ESC_ROUTE":     fixtureGrant{key: resp, id: "g-esc", endpoint: ep, kind: ActionKindIsolationChange, payload: escRoute, issued: fixtureT0 + 6, ttl: day}.wire(),
		"G_MESH_KIND_ISO":     fixtureGrant{key: resp, id: "g-kindmix", endpoint: ep, kind: ActionKindMeshQuarantine, payload: iso(nil), issued: fixtureT0 + 7, ttl: day}.wire(),
		"G_AUTO_SIGNED_OWNER": fixtureGrant{key: resp, id: "g-auto-by-owner", endpoint: ep, kind: ActionKindAutoIsolate, payload: autoPayload, issued: fixtureT0 + 8, ttl: tenMin}.wire(),
		"G_OWNER_SIGNED_AUTO": fixtureGrant{key: auto, id: "g-owner-by-auto", endpoint: ep, kind: ActionKindIsolationChange, payload: iso(nil), issued: fixtureT0 + 8, ttl: day}.wire(),
		"G_ISO_EXPIRED":       fixtureGrant{key: resp, id: "g-expired", endpoint: ep, kind: ActionKindIsolationChange, payload: iso(nil), issued: fixtureT0 - 3*day, ttl: day}.wire(),
		// Genuine, in order.
		"G_ISO":           fixtureGrant{key: resp, id: "g-iso", endpoint: ep, kind: ActionKindIsolationChange, payload: iso([]string{"10.0.0.9"}), issued: fixtureT0 + 10, ttl: day}.wire(),
		"G_AUTO_RELEASE":  fixtureGrant{key: auto, id: "g-auto-release", endpoint: ep, kind: ActionKindAutoIsolate, payload: rel, issued: fixtureT0 + 15, ttl: tenMin}.wire(),
		"G_REL":           fixtureGrant{key: resp, id: "g-rel", endpoint: ep, kind: ActionKindIsolationChange, payload: rel, issued: fixtureT0 + 20, ttl: day}.wire(),
		"G_AUTO":          fixtureGrant{key: auto, id: "g-auto", endpoint: ep, kind: ActionKindAutoIsolate, payload: autoPayload, issued: fixtureT0 + 30, ttl: tenMin}.wire(),
		"G_MESH_ON":       fixtureGrant{key: resp, id: "g-mesh-on", endpoint: "mesh:10.0.0.66", kind: ActionKindMeshQuarantine, payload: meshOn, issued: fixtureT0 + 40, ttl: day}.wire(),
		"G_MESH_OFF":      fixtureGrant{key: resp, id: "g-mesh-off", endpoint: "mesh:10.0.0.66", kind: ActionKindMeshQuarantine, payload: meshOff, issued: fixtureT0 + 50, ttl: day}.wire(),
		"G_REL_AUTO":      fixtureGrant{key: resp, id: "g-rel-auto", endpoint: ep, kind: ActionKindIsolationChange, payload: rel, issued: fixtureT0 + 55, ttl: day}.wire(),
		"G_BULK_ISO":      fixtureGrant{key: resp, id: "g-bulk", endpoint: ep, kind: ActionKindIsolationChange, payload: bulkIso, issued: fixtureT0 + 60, ttl: day}.wire(),
		"G_REL_2":         fixtureGrant{key: resp, id: "g-rel-2", endpoint: ep, kind: ActionKindIsolationChange, payload: rel, issued: fixtureT0 + 70, ttl: day}.wire(),
		"G_FUTURE_FORGED": fixtureGrant{key: evil, id: "g-future", endpoint: ep, kind: ActionKindIsolationChange, payload: rel, issued: fixtureT0 + 9_999_999, ttl: day}.wire(),
		"G_ISO_3":         fixtureGrant{key: resp, id: "g-iso-3", endpoint: ep, kind: ActionKindIsolationChange, payload: iso(nil), issued: fixtureT0 + 80, ttl: day}.wire(),
		// Update grants.
		"G_UPDATE":          fixtureGrant{key: resp, id: "g-upd", endpoint: ep, kind: ActionKindAgentUpdate, payload: upd, issued: fixtureT0 + 90, ttl: 7 * day}.wire(),
		"G_UPDATE_FORGED":   fixtureGrant{key: evil, id: "g-upd-forged", endpoint: ep, kind: ActionKindAgentUpdate, payload: upd, issued: fixtureT0 + 90, ttl: 7 * day}.wire(),
		"G_UPDATE_OTHER_EP": fixtureGrant{key: resp, id: "g-upd-other", endpoint: "ep-other", kind: ActionKindAgentUpdate, payload: routed("/api/v1/agents/update", map[string]interface{}{"version": "9.9.9"}, []string{"ep-other"}), issued: fixtureT0 + 90, ttl: 7 * day}.wire(),
		"G_UPDATE_AS_ISO":   fixtureGrant{key: resp, id: "g-upd-kind", endpoint: ep, kind: ActionKindIsolationChange, payload: upd, issued: fixtureT0 + 90, ttl: 7 * day}.wire(),
		"G_TERMINAL_AS_ISO": fixtureGrant{key: resp, id: "g-term-kind", endpoint: ep, kind: ActionKindIsolationChange, payload: []byte(`{"program":"/bin/bash"}`), issued: fixtureT0 + 91, ttl: 300}.wire(),
	}

	m := map[string]string{
		"M_RESPOND_1":    manifestJSON(pol, ep, "respond", 1),
		"M_MONITOR_2":    manifestJSON(pol, ep, "monitor", 2),
		"M_ENGAGEMENT_1": manifestJSON(pol, ep, "engagement", 1),
		"M_FORGED_3":     manifestJSON(evil, ep, "engagement", 3),
		"M_OTHER_EP_3":   manifestJSON(pol, "ep-other", "engagement", 3),
		"M_RESPOND_3":    manifestJSON(pol, ep, "respond", 3),
	}

	var out bytes.Buffer
	out.WriteString("/* Generated by hub/pkg/response/trust_fixtures_test.go. Do not edit. */\n")
	out.WriteString("#ifndef OMINULL_TRUST_FIXTURES_H\n#define OMINULL_TRUST_FIXTURES_H\n\n")
	fmt.Fprintf(&out, "#define FX_ENDPOINT %s\n#define FX_T0 %dLL\n", cString(ep), fixtureT0)
	fmt.Fprintf(&out, "#define FX_RESPONSE_PUB %s\n#define FX_AUTO_PUB %s\n#define FX_POLICY_PUB %s\n", cString(pubHex(resp)), cString(pubHex(auto)), cString(pubHex(pol)))
	fmt.Fprintf(&out, "#define FX_ATTACKER_PUB %s\n", cString(pubHex(evil)))
	fmt.Fprintf(&out, "#define FX_RELEASE_STATEMENT %s\n", cString(ReleaseStatement("ominull-agent_9.9.9_amd64.deb", "9.9.9", strings.Repeat("AB", 32))))
	fmt.Fprintf(&out, "#define FX_TB_PUB_PEM %s\n", cString(fixtureReleasePubPEM()))
	relKey, wrong := fixtureReleaseKey("release"), fixtureReleaseKey("not-the-release-key")
	for _, b := range fixtureBundles() {
		fmt.Fprintf(&out, "#define FX_KEYS%s_JSON %s\n", b.name, cString(b.json()))
		fmt.Fprintf(&out, "#define FX_TB_STATEMENT%s %s\n", b.name, cString(TrustBundleStatement(b.keys())))
		fmt.Fprintf(&out, "%s%s %s\n", bundleSigPrefix, b.name, cString(bundleSig(relKey, b.keys())))
	}
	fmt.Fprintf(&out, "%s_WRONG_SIGNER %s\n", bundleSigPrefix, cString(bundleSig(wrong, fixtureBundles()[0].keys())))
	names := make([]string, 0, len(g)+len(m))
	all := map[string]string{}
	for k, v := range g {
		all[k] = v
		names = append(names, k)
	}
	for k, v := range m {
		all[k] = v
		names = append(names, k)
	}
	sort.Strings(names)
	for _, n := range names {
		fmt.Fprintf(&out, "#define FX_%s %s\n", n, cString(all[n]))
	}
	out.WriteString("\n#endif\n")
	return out.Bytes()
}

func TestAgentTrustFixtures(t *testing.T) {
	want := buildTrustFixtures()
	path := filepath.Join("..", "..", "..", "agent", "tests", "trust_fixtures.h")
	if os.Getenv("OMINULL_UPDATE_FIXTURES") == "1" {
		if err := os.WriteFile(path, want, 0644); err != nil {
			t.Fatal(err)
		}
		return
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v (regenerate with OMINULL_UPDATE_FIXTURES=1)", path, err)
	}
	gotFixed, gotSigs := splitBundleSigs(got)
	wantFixed, _ := splitBundleSigs(want)
	if !bytes.Equal(gotFixed, wantFixed) || len(gotSigs) != len(fixtureBundles())+1 {
		t.Fatalf("%s is stale; regenerate with OMINULL_UPDATE_FIXTURES=1 go test ./pkg/response -run TestAgentTrustFixtures", path)
	}
	pub := []byte(fixtureReleasePubPEM())
	check := func(name string, k *TrustKeys, wantOK bool) {
		der, err := base64.StdEncoding.DecodeString(gotSigs[name])
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if ok := VerifyReleaseSignature(pub, []byte(TrustBundleStatement(k)), der) == nil; ok != wantOK {
			t.Fatalf("committed %s verifies=%v, want %v; regenerate the fixtures", name, ok, wantOK)
		}
	}
	for _, b := range fixtureBundles() {
		check("FX_TB_SIG"+b.name, b.keys(), true)
	}
	check("FX_TB_SIG_WRONG_SIGNER", fixtureBundles()[0].keys(), false)
}

func splitBundleSigs(h []byte) ([]byte, map[string]string) {
	var fixed bytes.Buffer
	sigs := map[string]string{}
	for _, line := range strings.SplitAfter(string(h), "\n") {
		if strings.HasPrefix(line, bundleSigPrefix) {
			f := strings.Fields(line)
			if len(f) == 3 {
				sigs[f[1]] = strings.Trim(f[2], `"`)
			}
			continue
		}
		fixed.WriteString(line)
	}
	return fixed.Bytes(), sigs
}

// The release statement and the manifest form are part of the contract.
func TestReleaseStatementForm(t *testing.T) {
	got := ReleaseStatement("p.deb", "1.2.3", "ABCDEF")
	if got != "OMINULL-RELEASE-V1\npackage=p.deb\nversion=1.2.3\nsha256=abcdef\n" {
		t.Fatalf("release statement %q", got)
	}
}

func TestCapabilityManifestVerify(t *testing.T) {
	pol := fixtureKey("policy")
	caps, _ := ProfileCaps("respond")
	m := &CapabilityManifest{V: 1, TenantID: "default", EndpointID: "e", Profile: "respond", Caps: caps, Seq: 1, IssuedAt: 1}
	m.Sign(pol)
	if err := m.Verify(pol.Public().(ed25519.PublicKey)); err != nil {
		t.Fatal(err)
	}
	if err := m.Verify(fixtureKey("attacker").Public().(ed25519.PublicKey)); err == nil {
		t.Fatal("verified under the wrong key")
	}
	m.Caps = append(m.Caps, "script")
	if err := m.Verify(pol.Public().(ed25519.PublicKey)); err == nil {
		t.Fatal("widened manifest verified")
	}
	if !m.Has(CapTerminal) || (*CapabilityManifest)(nil).Has(CapIsolate) || !(*CapabilityManifest)(nil).Has(CapUpdate) {
		t.Fatal("Has")
	}
}
