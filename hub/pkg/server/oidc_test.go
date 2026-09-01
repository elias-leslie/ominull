package server

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
)

func TestOIDCStartAndCallbackUseDiscoveryPKCEAndStableIdentity(t *testing.T) {
	srv, store := setupTestServer(t)
	defer store.Close()
	if err := store.UpsertOperator("operator@example.invalid", "admin", "test"); err != nil {
		t.Fatal(err)
	}
	if err := store.SetSetting("oidc.client_id", "ominull-test"); err != nil {
		t.Fatal(err)
	}
	if err := store.SetSetting("oidc.redirect_url", "http://127.0.0.1/oidc/callback"); err != nil {
		t.Fatal(err)
	}

	signingKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	jwk := jose.JSONWebKey{Key: &signingKey.PublicKey, KeyID: "oidc-test", Algorithm: string(jose.RS256), Use: "sig"}
	var expectedNonce string
	var fake *httptest.Server
	fake = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		issuer := fake.URL
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]string{
				"issuer": issuer, "authorization_endpoint": issuer + "/authorize",
				"token_endpoint": issuer + "/token", "jwks_uri": issuer + "/jwks",
			})
		case "/jwks":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"keys": []jose.JSONWebKey{jwk}})
		case "/token":
			if err := r.ParseForm(); err != nil || r.Form.Get("code") != "valid-code" || r.Form.Get("code_verifier") == "" {
				http.Error(w, "bad authorization-code exchange", http.StatusBadRequest)
				return
			}
			opts := (&jose.SignerOptions{}).WithType("JWT").WithHeader(jose.HeaderKey("kid"), "oidc-test")
			signer, signErr := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: signingKey}, opts)
			if signErr != nil {
				http.Error(w, "signer unavailable", http.StatusInternalServerError)
				return
			}
			claims := map[string]interface{}{
				"iss": issuer, "sub": "operator-subject", "aud": "ominull-test",
				"email": "operator@example.invalid", "nonce": expectedNonce,
				"iat": time.Now().Unix(), "exp": time.Now().Add(5 * time.Minute).Unix(),
			}
			payload, marshalErr := json.Marshal(claims)
			if marshalErr != nil {
				http.Error(w, "claims unavailable", http.StatusInternalServerError)
				return
			}
			rawToken, signErr := signer.Sign(payload)
			if signErr != nil {
				http.Error(w, "token unavailable", http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]string{
				"access_token": "test-access-token", "token_type": "Bearer",
				"id_token": mustCompact(t, rawToken),
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer fake.Close()
	if err := store.SetSetting("oidc.issuer", fake.URL); err != nil {
		t.Fatal(err)
	}

	start := httptest.NewRecorder()
	srv.Handler().ServeHTTP(start, httptest.NewRequest(http.MethodGet, "/oidc/start", nil))
	if start.Code != http.StatusFound {
		t.Fatalf("OIDC start returned %d: %s", start.Code, start.Body.String())
	}
	location, err := url.Parse(start.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	query := location.Query()
	state, expectedNonce := query.Get("state"), query.Get("nonce")
	if state == "" || expectedNonce == "" || query.Get("code_challenge") == "" || query.Get("code_challenge_method") != "S256" {
		t.Fatalf("OIDC start omitted state, nonce, or S256 PKCE: %s", location.Redacted())
	}
	cookies := start.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Name != "ominull_oidc_state" {
		t.Fatalf("OIDC state cookie missing: %#v", cookies)
	}

	callback := httptest.NewRequest(http.MethodGet, "/oidc/callback?state="+url.QueryEscape(state)+"&code=valid-code", nil)
	callback.AddCookie(cookies[0])
	result := httptest.NewRecorder()
	srv.Handler().ServeHTTP(result, callback)
	if result.Code != http.StatusSeeOther || result.Header().Get("Location") != "/" {
		t.Fatalf("OIDC callback returned %d %q: %s", result.Code, result.Header().Get("Location"), result.Body.String())
	}
	lastSuccess, err := store.GetSetting("oidc.last_success")
	if err != nil || strings.TrimSpace(lastSuccess) == "" {
		t.Fatalf("OIDC callback did not record last success: %q %v", lastSuccess, err)
	}
	identities, err := store.ListOperatorIdentities()
	if err != nil || len(identities) != 1 || identities[0].Subject != "operator-subject" {
		t.Fatalf("OIDC stable identity was not stored: %+v %v", identities, err)
	}
}

func mustCompact(t *testing.T, object *jose.JSONWebSignature) string {
	t.Helper()
	compact, err := object.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}
	return compact
}
