package responseauth

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"testing"
)

func TestWebAuthn_FullLifecycle_Ed25519(t *testing.T) {
	tempDir := t.TempDir()
	tenantID := "tenant-fido"
	operatorID := "alice@example.invalid"

	cfg := Config{
		StateDir:        tempDir,
		SignerPartition: "portable-local",
	}
	auth, err := NewAuthority(cfg)
	if err != nil {
		t.Fatalf("NewAuthority failed: %v", err)
	}
	defer auth.Close()

	// 1. Begin Registration
	regOpts, err := auth.BeginWebAuthnRegistration(tenantID, operatorID)
	if err != nil {
		t.Fatalf("BeginWebAuthnRegistration failed: %v", err)
	}
	if regOpts.Challenge == "" {
		t.Fatalf("empty challenge returned")
	}

	// 2. Client simulates security key credential creation (Ed25519)
	credPub, credPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey failed: %v", err)
	}
	credID := base64.RawURLEncoding.EncodeToString([]byte("cred-123456789"))

	clientData := ClientDataJSON{
		Type:      "webauthn.create",
		Challenge: regOpts.Challenge,
		Origin:    "https://ominull.example.invalid:8443",
	}
	rawClientData, _ := json.Marshal(clientData)
	clientDataBase64 := base64.RawURLEncoding.EncodeToString(rawClientData)

	regReq := &WebAuthnRegistrationRequest{
		TenantID:        tenantID,
		OperatorID:      operatorID,
		CredentialID:    credID,
		ClientDataJSON:  clientDataBase64,
		PublicKeyPEM:    hex.EncodeToString(credPub),
		KeyType:         "Ed25519",
		AttestationData: "none",
	}

	authRec, err := auth.FinishWebAuthnRegistration(regReq)
	if err != nil {
		t.Fatalf("FinishWebAuthnRegistration failed: %v", err)
	}
	if authRec.Type != AuthMethodWebAuthn {
		t.Fatalf("expected AuthMethodWebAuthn, got %s", authRec.Type)
	}
	if authRec.Label != SecurityLabelWebAuthn {
		t.Fatalf("expected security label %q, got %q", SecurityLabelWebAuthn, authRec.Label)
	}

	// 3. Begin Authentication
	authOpts, err := auth.BeginWebAuthnAuthentication(tenantID, operatorID)
	if err != nil {
		t.Fatalf("BeginWebAuthnAuthentication failed: %v", err)
	}
	if len(authOpts.AllowCredentials) != 1 || authOpts.AllowCredentials[0].ID != credID {
		t.Fatalf("expected allowed credential %s, got %+v", credID, authOpts.AllowCredentials)
	}

	// 4. Client generates assertion
	authClientData := ClientDataJSON{
		Type:      "webauthn.get",
		Challenge: authOpts.Challenge,
		Origin:    "https://ominull.example.invalid:8443",
	}
	rawAuthClientData, _ := json.Marshal(authClientData)
	authClientDataBase64 := base64.RawURLEncoding.EncodeToString(rawAuthClientData)

	// Build authenticatorData: 32 bytes RP ID hash, 1 byte flags (UP=0x01), 4 bytes counter
	rpHdr := sha256.Sum256([]byte("localhost"))
	authData := make([]byte, 37)
	copy(authData[0:32], rpHdr[:])
	authData[32] = 0x01 // User Present
	binary.BigEndian.PutUint32(authData[33:37], 1) // Sign counter 1
	authDataBase64 := base64.RawURLEncoding.EncodeToString(authData)

	// Signature over authenticatorData || sha256(clientDataJSON)
	cdHash := sha256.Sum256(rawAuthClientData)
	signedData := append(authData, cdHash[:]...)
	sig := ed25519.Sign(credPriv, signedData)
	sigBase64 := base64.RawURLEncoding.EncodeToString(sig)

	browserPub, _, _ := ed25519.GenerateKey(rand.Reader)
	browserPubHex := hex.EncodeToString(browserPub)

	authReq := &WebAuthnAuthenticationRequest{
		TenantID:          tenantID,
		OperatorID:        operatorID,
		BrowserSessionID:  "browser-fido-1",
		BrowserPublicKey:  browserPubHex,
		CredentialID:      credID,
		ClientDataJSON:    authClientDataBase64,
		AuthenticatorData: authDataBase64,
		Signature:         sigBase64,
	}

	sess, err := auth.FinishWebAuthnAuthentication(authReq)
	if err != nil {
		t.Fatalf("FinishWebAuthnAuthentication failed: %v", err)
	}
	if sess.AuthMethod != AuthMethodWebAuthn {
		t.Fatalf("expected session AuthMethodWebAuthn, got %s", sess.AuthMethod)
	}

	// 5. Anti-Cloning / Sign count rollback protection
	// Generating a new assertion with sign count 1 (not > 1) MUST FAIL
	authOpts2, _ := auth.BeginWebAuthnAuthentication(tenantID, operatorID)
	authClientData2 := ClientDataJSON{
		Type:      "webauthn.get",
		Challenge: authOpts2.Challenge,
		Origin:    "https://ominull.example.invalid:8443",
	}
	rawAuthClientData2, _ := json.Marshal(authClientData2)
	cdHash2 := sha256.Sum256(rawAuthClientData2)

	// Reusing counter 1
	signedData2 := append(authData, cdHash2[:]...)
	sig2 := ed25519.Sign(credPriv, signedData2)

	authReq2 := &WebAuthnAuthenticationRequest{
		TenantID:          tenantID,
		OperatorID:        operatorID,
		BrowserSessionID:  "browser-fido-2",
		BrowserPublicKey:  browserPubHex,
		CredentialID:      credID,
		ClientDataJSON:    base64.RawURLEncoding.EncodeToString(rawAuthClientData2),
		AuthenticatorData: authDataBase64, // counter still 1
		Signature:         base64.RawURLEncoding.EncodeToString(sig2),
	}
	_, err = auth.FinishWebAuthnAuthentication(authReq2)
	if err == nil || !errors.Is(err, ErrWebAuthnCloned) {
		t.Fatalf("expected ErrWebAuthnCloned on non-incrementing counter, got: %v", err)
	}
}

func TestWebAuthn_SecurityEnforcement(t *testing.T) {
	mgr := NewWebAuthnManager(WebAuthnRPConfig{
		RPID: "localhost",
		AllowedOrigins: []string{
			"https://ominull.example.invalid:8443",
		},
	})

	tenantID := "tenant-sec"
	operatorID := "sec@example.invalid"

	// 1. Origin Mismatch
	ch, _ := mgr.GenerateChallenge(tenantID, operatorID, "create")
	badOriginClientData, _ := json.Marshal(ClientDataJSON{
		Type:      "webauthn.create",
		Challenge: ch,
		Origin:    "https://evil-phishing-site.attacker.invalid",
	})
	_, err := mgr.VerifyRegistration(&WebAuthnRegistrationRequest{
		TenantID:       tenantID,
		OperatorID:     operatorID,
		CredentialID:   "cred-bad",
		ClientDataJSON: base64.RawURLEncoding.EncodeToString(badOriginClientData),
	})
	if err == nil || !errors.Is(err, ErrWebAuthnOriginMismatch) {
		t.Fatalf("expected ErrWebAuthnOriginMismatch, got: %v", err)
	}

	// 2. User Presence Missing (UP bit == 0)
	ecPriv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pubDER, _ := x509.MarshalPKIXPublicKey(&ecPriv.PublicKey)

	stored := &StoredWebAuthnCredential{
		CredentialID: "cred-up",
		KeyType:      "ES256",
		PublicKeyPEM: hex.EncodeToString(pubDER),
		SignCount:    0,
	}

	chAuth, _ := mgr.GenerateChallenge(tenantID, operatorID, "get")
	validClientData, _ := json.Marshal(ClientDataJSON{
		Type:      "webauthn.get",
		Challenge: chAuth,
		Origin:    "https://ominull.example.invalid:8443",
	})

	noUPAuthData := make([]byte, 37)
	rpHdr := sha256.Sum256([]byte("localhost"))
	copy(noUPAuthData[0:32], rpHdr[:])
	noUPAuthData[32] = 0x00 // UP bit 0 NOT set!
	binary.BigEndian.PutUint32(noUPAuthData[33:37], 1)

	cdHash := sha256.Sum256(validClientData)
	signedData := append(noUPAuthData, cdHash[:]...)
	h := sha256.Sum256(signedData)
	sigBytes, err := ecdsa.SignASN1(rand.Reader, ecPriv, h[:])
	if err != nil {
		t.Fatalf("ecdsa.SignASN1 failed: %v", err)
	}

	err = mgr.VerifyAssertion(&WebAuthnAuthenticationRequest{
		TenantID:          tenantID,
		OperatorID:        operatorID,
		CredentialID:      "cred-up",
		ClientDataJSON:    base64.RawURLEncoding.EncodeToString(validClientData),
		AuthenticatorData: base64.RawURLEncoding.EncodeToString(noUPAuthData),
		Signature:         base64.RawURLEncoding.EncodeToString(sigBytes),
	}, stored)

	if err == nil || !errors.Is(err, ErrWebAuthnUserNotPresent) {
		t.Fatalf("expected ErrWebAuthnUserNotPresent, got: %v", err)
	}
}

func TestWebAuthn_FullLifecycle_ES256(t *testing.T) {
	tempDir := t.TempDir()
	tenantID := "tenant-es256"
	operatorID := "carol@example.invalid"

	auth, err := NewAuthority(Config{StateDir: tempDir})
	if err != nil {
		t.Fatalf("NewAuthority failed: %v", err)
	}
	defer auth.Close()

	// 1. Register ES256 credential
	ecPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey failed: %v", err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(&ecPriv.PublicKey)
	if err != nil {
		t.Fatalf("MarshalPKIXPublicKey failed: %v", err)
	}

	regOpts, err := auth.BeginWebAuthnRegistration(tenantID, operatorID)
	if err != nil {
		t.Fatalf("BeginWebAuthnRegistration failed: %v", err)
	}

	clientData, _ := json.Marshal(ClientDataJSON{
		Type:      "webauthn.create",
		Challenge: regOpts.Challenge,
		Origin:    "https://ominull.example.invalid:8443",
	})
	credID := base64.RawURLEncoding.EncodeToString([]byte("cred-es256-1"))

	_, err = auth.FinishWebAuthnRegistration(&WebAuthnRegistrationRequest{
		TenantID:       tenantID,
		OperatorID:     operatorID,
		CredentialID:   credID,
		ClientDataJSON: base64.RawURLEncoding.EncodeToString(clientData),
		PublicKeyPEM:   hex.EncodeToString(pubDER),
		KeyType:        "ES256",
	})
	if err != nil {
		t.Fatalf("FinishWebAuthnRegistration failed: %v", err)
	}

	// 2. Authenticate ES256 credential
	authOpts, err := auth.BeginWebAuthnAuthentication(tenantID, operatorID)
	if err != nil {
		t.Fatalf("BeginWebAuthnAuthentication failed: %v", err)
	}

	authClientData, _ := json.Marshal(ClientDataJSON{
		Type:      "webauthn.get",
		Challenge: authOpts.Challenge,
		Origin:    "https://ominull.example.invalid:8443",
	})

	authData := make([]byte, 37)
	rpHdr := sha256.Sum256([]byte("localhost"))
	copy(authData[0:32], rpHdr[:])
	authData[32] = 0x01 // UP
	binary.BigEndian.PutUint32(authData[33:37], 1)

	cdHash := sha256.Sum256(authClientData)
	signedData := append(authData, cdHash[:]...)
	h := sha256.Sum256(signedData)
	sigBytes, err := ecdsa.SignASN1(rand.Reader, ecPriv, h[:])
	if err != nil {
		t.Fatalf("SignASN1 failed: %v", err)
	}

	browserPub, _, _ := ed25519.GenerateKey(rand.Reader)
	sess, err := auth.FinishWebAuthnAuthentication(&WebAuthnAuthenticationRequest{
		TenantID:          tenantID,
		OperatorID:        operatorID,
		BrowserSessionID:  "browser-es256",
		BrowserPublicKey:  hex.EncodeToString(browserPub),
		CredentialID:      credID,
		ClientDataJSON:    base64.RawURLEncoding.EncodeToString(authClientData),
		AuthenticatorData: base64.RawURLEncoding.EncodeToString(authData),
		Signature:         base64.RawURLEncoding.EncodeToString(sigBytes),
	})
	if err != nil {
		t.Fatalf("FinishWebAuthnAuthentication ES256 failed: %v", err)
	}
	if sess.AuthMethod != AuthMethodWebAuthn {
		t.Fatalf("expected AuthMethodWebAuthn, got %s", sess.AuthMethod)
	}
}
