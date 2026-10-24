package server

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"ominull/hub/pkg/response"
)

func pemOf(t *testing.T, k *ecdsa.PrivateKey) string {
	t.Helper()
	der, _ := x509.MarshalPKIXPublicKey(&k.PublicKey)
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

// The pinned release key lists the routine keys; agents get the list in the
// heartbeat; a release signed with a routine key rolls out canaries first
// (the authority signs a staged one at once), and retiring it halts the rollout, drops its queued updates and refuses to
// roll it again.
func TestRoutineKeysSignedReleaseRollsStaged(t *testing.T) {
	s, db := setupTestServer(t)
	defer db.Close()
	auth := authorityOf(t, s).auth
	rel, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	routine, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	s.trust.mu.Lock()
	s.trust.releasePub = []byte(pemOf(t, rel))
	s.trust.mu.Unlock()
	auth.SetReleaseKey([]byte(pemOf(t, rel)))
	call := func(method, path, body string) (int, map[string]any) {
		t.Helper()
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		r.Header.Set("X-API-Key", "mock_admin_token")
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		var m map[string]any
		_ = json.Unmarshal(w.Body.Bytes(), &m)
		return w.Code, m
	}
	keyJSON, _ := json.Marshal(pemOf(t, routine))
	proposal := `{"epoch":1,"keys":[{"id":"0123456789abcdef","public_key":` + string(keyJSON) + `}]`
	code, m := call("POST", "/api/v1/trust/routine-keys/statement", proposal+"}")
	stmt, _ := m["statement"].(string)
	if code != 200 || !strings.HasPrefix(stmt, "OMINULL-ROUTINE-KEYS-V1\nepoch=1\nkeys=0123456789abcdef:") {
		t.Fatalf("statement: %d %v", code, m)
	}
	sign := func(k *ecdsa.PrivateKey, msg string) string {
		sum := sha256.Sum256([]byte(msg))
		sig, _ := ecdsa.SignASN1(rand.Reader, k, sum[:])
		return base64.StdEncoding.EncodeToString(sig)
	}
	if code, m := call("POST", "/api/v1/trust/routine-keys", proposal+`,"signature":"`+sign(routine, stmt)+`"}`); code != 400 {
		t.Fatalf("a routine key signed its own list: %d %v", code, m)
	}
	if code, m := call("POST", "/api/v1/trust/routine-keys", proposal+`,"signature":"`+sign(rel, stmt)+`"}`); code != 200 {
		t.Fatalf("store: %d %v", code, m)
	}
	if code, m := call("GET", "/api/v1/trust/routine-keys", ""); code != 200 || m["epoch"] != float64(1) {
		t.Fatalf("view: %d %v", code, m)
	}
	empty := `{"epoch":1,"keys":[]}`
	_, em := call("POST", "/api/v1/trust/routine-keys/statement", empty)
	if code, _ := call("POST", "/api/v1/trust/routine-keys", `{"epoch":1,"keys":[],"signature":"`+sign(rel, em["statement"].(string))+`"}`); code != http.StatusConflict {
		t.Fatalf("a different list at the same epoch: %d", code)
	}

	seedEndpointWithCapability(t, db, "canary", "Linux", "1.1.0", "deb")
	seedEndpointWithCapability(t, db, "rest", "Linux", "1.1.0", "deb")
	ep, _ := db.GetEndpoint("canary")
	resp := map[string]interface{}{}
	s.addTrustControl(context.Background(), resp, ep, &response.AgentTrustReport{V: 1, Keys: "pinned"})
	if rk, ok := resp["routine_keys"].(*response.RoutineKeys); !ok || rk.Epoch != 1 {
		t.Fatalf("heartbeat lacks the routine keys: %v", resp)
	}
	resp = map[string]interface{}{}
	s.addTrustControl(context.Background(), resp, ep, &response.AgentTrustReport{V: 1, Keys: "pinned", RoutineEpoch: 1})
	if _, ok := resp["routine_keys"]; ok {
		t.Fatal("sent again to an agent that pinned this epoch")
	}

	s.agentVersion = "1.2.0"
	seedOwnerSignedRelease(t, s.binaryDir, "1.2.0", routine)
	if code, m := call("POST", "/api/v1/agents/update", `{"endpoint_ids":["canary","rest"],"version":"1.2.0"}`); code != http.StatusConflict || !strings.Contains(fmt.Sprint(m["error"]), "canaries first") {
		t.Fatalf("an unstaged routine-signed rollout: %d %v", code, m)
	}
	if code, m := call("POST", "/api/v1/agents/update", `{"endpoint_ids":["canary","rest"],"version":"1.2.0","canary":["canary"]}`); code != http.StatusOK {
		t.Fatalf("a staged routine-signed rollout is authorized on the first request: %d %v", code, m)
	}
	if job, _ := db.GetAgentUpdateJob("canary"); job == nil || job.DesiredVersion != "1.2.0" {
		t.Fatalf("canary not queued: %+v", job)
	}
	if !authorizedAuditHas(t, s.store, "canary") {
		t.Fatalf("no ACTION_AUTHORIZED row for the staged rollout: %+v", authorizedAudit(t, s.store))
	}

	code, m = call("POST", "/api/v1/agents/rollback", `{"version":"1.2.0","reason":"canary misbehaves"}`)
	if code != 200 || m["halted"] != float64(1) || m["cancelled"] != float64(1) {
		t.Fatalf("rollback: %d %v", code, m)
	}
	if job, _ := db.GetAgentUpdateJob("canary"); job != nil {
		t.Fatalf("the queued update survived: %+v", job)
	}
	if code, m := call("POST", "/api/v1/agents/update", `{"endpoint_ids":["canary"],"version":"1.2.0"}`); code != http.StatusConflict || !strings.Contains(fmt.Sprint(m["error"]), "retired") {
		t.Fatalf("a retired version rolled again: %d %v", code, m)
	}
}

// New installs fetch the held routine key list (no credential) and the
// package's release statement signature; their script carries the held epoch
// as its floor.
func TestRoutineKeysServedToNewInstalls(t *testing.T) {
	s, db := setupTestServer(t)
	defer db.Close()
	get := func(path string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, httptest.NewRequest("GET", path, nil))
		return w
	}
	if w := get("/download/routine-keys.json"); w.Code != http.StatusNotFound {
		t.Fatalf("no list held: %d", w.Code)
	}
	if w := get("/bootstrap.sh"); !strings.Contains(w.Body.String(), "ROUTINE_FLOOR=0") {
		t.Fatal("bootstrap.sh without a held list should carry floor 0")
	}
	rel, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	routine, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	s.trust.mu.Lock()
	s.trust.releasePub = []byte(pemOf(t, rel))
	s.trust.mu.Unlock()
	xy, _ := response.RoutineKeyXY(pemOf(t, routine))
	line, _ := response.FormatRoutineKeyList([]response.RoutineKey{{ID: "0123456789abcdef", XY: xy}})
	stmt, _ := response.RoutineKeysStatement(2, line)
	sum := sha256.Sum256([]byte(stmt))
	sig, _ := ecdsa.SignASN1(rand.Reader, rel, sum[:])
	held := response.RoutineKeys{Epoch: 2, Keys: line, Sig: base64.StdEncoding.EncodeToString(sig)}
	raw, _ := json.Marshal(held)
	if err := s.store.SetSetting(routineKeysSetting, string(raw)); err != nil {
		t.Fatal(err)
	}
	w := get("/download/routine-keys.json")
	var got response.RoutineKeys
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &got) != nil || got != held || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("held list: %d %q", w.Code, w.Body.String())
	}
	if _, err := response.VerifyRoutineKeys([]byte(pemOf(t, rel)), &got); err != nil {
		t.Fatalf("served list does not verify: %v", err)
	}
	if w := get("/bootstrap.sh"); !strings.Contains(w.Body.String(), "ROUTINE_FLOOR=2") {
		t.Fatal("bootstrap.sh does not carry the held epoch")
	}
	if w := get("/bootstrap.ps1"); !strings.Contains(w.Body.String(), "$RoutineFloor = 2") {
		t.Fatal("bootstrap.ps1 does not carry the held epoch")
	}
	if !downloadAllowed("ominull-agent_1.8.90_amd64.deb.release.sig") || !downloadAllowed("ominull-agent-windows-1.8.90.msi.release.sig") {
		t.Fatal("release statement signatures are not downloadable")
	}
	// A list that no longer verifies (another release key) is not served.
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	s.trust.mu.Lock()
	s.trust.releasePub = []byte(pemOf(t, other))
	s.trust.mu.Unlock()
	if w := get("/download/routine-keys.json"); w.Code != http.StatusNotFound {
		t.Fatalf("a list the release key did not sign was served: %d", w.Code)
	}
}
