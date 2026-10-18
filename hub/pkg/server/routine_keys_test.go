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
// (the default rows approve it without asking, as an owner-signed rollout),
// and retiring it halts the rollout, drops its queued updates and refuses to
// roll it again.
func TestRoutineKeysSignedReleaseRollsStaged(t *testing.T) {
	s, db := setupTestServer(t)
	defer db.Close()
	owner := ownerOf(t, s)
	rel, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	routine, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	s.trust.mu.Lock()
	s.trust.releasePub = []byte(pemOf(t, rel))
	s.trust.mu.Unlock()
	owner.auth.SetReleaseKey([]byte(pemOf(t, rel)))
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
		t.Fatalf("a staged routine-signed rollout runs under the agent_update row: %d %v", code, m)
	}
	if job, _ := db.GetAgentUpdateJob("canary"); job == nil || job.DesiredVersion != "1.2.0" {
		t.Fatalf("canary not queued: %+v", job)
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
