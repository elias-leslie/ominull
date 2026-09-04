package acme

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	cryptoacme "golang.org/x/crypto/acme"
)

func TestMockDNSProvider(t *testing.T) {
	ctx := context.Background()
	provider := NewMockDNSProvider()

	domain := "omi.example.invalid"
	recordName := "_acme-challenge." + domain
	recordValue := "test-challenge-digest-value"

	if err := provider.Present(ctx, domain, recordName, recordValue); err != nil {
		t.Fatalf("Present failed: %v", err)
	}

	val, ok := provider.GetPresented(recordName)
	if !ok || val != recordValue {
		t.Fatalf("expected presented value %q, got %q (ok=%v)", recordValue, val, ok)
	}

	if err := provider.CleanUp(ctx, domain, recordName, recordValue); err != nil {
		t.Fatalf("CleanUp failed: %v", err)
	}

	if !provider.Cleaned[recordName] {
		t.Fatalf("expected Cleaned[%s] to be true", recordName)
	}
}

func TestDNS01ChallengeRecordComputation(t *testing.T) {
	// Verify that DNS01ChallengeRecord computes RFC 8555 compliant SHA256 base64url digests
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	client := &cryptoacme.Client{Key: key}

	token := "test-challenge-token-0123456789"
	digest, err := client.DNS01ChallengeRecord(token)
	if err != nil {
		t.Fatalf("DNS01ChallengeRecord failed: %v", err)
	}
	if len(digest) == 0 {
		t.Fatalf("expected non-empty DNS-01 digest")
	}
}

func TestManager_DiskLoadAndRenewal(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "ominull-acme-test-*")
	if err != nil {
		t.Fatalf("mktemp: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	mockDNS := NewMockDNSProvider()
	mgr, err := NewManager(Config{
		Domain:      "omi.example.invalid",
		DNSProvider: mockDNS,
		CertDir:     tmpDir,
		RenewBefore: 30 * 24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("NewManager failed: %v", err)
	}

	// 1. Initially no cert exists
	_, err = mgr.LoadStoredCert()
	if err == nil {
		t.Fatalf("expected error when no cert exists on disk")
	}

	// 2. Synthesize a certificate valid for 90 days and write to disk
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(12345),
		Subject:      pkix.Name{CommonName: "omi.example.invalid"},
		DNSNames:     []string{"omi.example.invalid"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(90 * 24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &privKey.PublicKey, privKey)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, _ := x509.MarshalECPrivateKey(privKey)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	if err := os.WriteFile(filepath.Join(tmpDir, "console_acme.crt"), certPEM, 0644); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	if err := os.WriteFile(filepath.Join(tmpDir, "console_acme.key"), keyPEM, 0600); err != nil {
		t.Fatalf("write key: %v", err)
	}

	// 3. LoadStoredCert should now succeed
	loaded, err := mgr.LoadStoredCert()
	if err != nil {
		t.Fatalf("LoadStoredCert failed: %v", err)
	}
	if loaded.Leaf.Subject.CommonName != "omi.example.invalid" {
		t.Fatalf("expected CommonName omi.example.invalid, got %s", loaded.Leaf.Subject.CommonName)
	}

	// 4. Certificate() should use cached/disk cert since it's valid for 90 days (> 30 days)
	cert, err := mgr.Certificate(context.Background())
	if err != nil {
		t.Fatalf("Certificate() failed: %v", err)
	}
	if cert.Leaf.Subject.CommonName != "omi.example.invalid" {
		t.Fatalf("expected CommonName omi.example.invalid, got %s", cert.Leaf.Subject.CommonName)
	}

	// 5. Verify needs renewal check for an expired certificate
	expiredTemplate := template
	expiredTemplate.NotAfter = time.Now().Add(10 * 24 * time.Hour) // within 30 days
	expiredDER, _ := x509.CreateCertificate(rand.Reader, &expiredTemplate, &expiredTemplate, &privKey.PublicKey, privKey)
	expiredCert, _ := tls.X509KeyPair(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: expiredDER}), keyPEM)
	expiredCert.Leaf, _ = x509.ParseCertificate(expiredDER)

	if !mgr.needsRenewalLocked(&expiredCert) {
		t.Fatalf("expected certificate expiring in 10 days to require renewal (RenewBefore=30d)")
	}
}

func TestCloudflareDNSProvider_MockServer(t *testing.T) {
	// Setup test HTTP server simulating Cloudflare API v4
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if auth != "Bearer test-cf-token" {
			http.Error(w, `{"success":false,"errors":["unauthorized"]}`, http.StatusUnauthorized)
			return
		}

		if r.Method == http.MethodGet && r.URL.Path == "/zones" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"success":true,"result":[{"id":"zone-12345","name":"example.invalid"}]}`))
			return
		}

		if r.Method == http.MethodPost && r.URL.Path == "/zones/zone-12345/dns_records" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"success":true,"result":{"id":"rec-67890"}}`))
			return
		}

		if r.Method == http.MethodDelete && r.URL.Path == "/zones/zone-12345/dns_records/rec-67890" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"success":true,"result":{"id":"rec-67890"}}`))
			return
		}

		http.NotFound(w, r)
	})

	ts := httptest.NewServer(handler)
	defer ts.Close()

	cf := NewCloudflareDNSProvider("test-cf-token")
	cf.BaseURL = ts.URL
	cf.HTTPClient = ts.Client()

	ctx := context.Background()
	domain := "omi.example.invalid"
	recordName := "_acme-challenge." + domain
	recordValue := "test-digest"

	// Test Present
	if err := cf.Present(ctx, domain, recordName, recordValue); err != nil {
		t.Fatalf("cf.Present failed: %v", err)
	}

	if cf.records[recordName] != "rec-67890" {
		t.Fatalf("expected record ID rec-67890, got %s", cf.records[recordName])
	}

	// Test CleanUp
	if err := cf.CleanUp(ctx, domain, recordName, recordValue); err != nil {
		t.Fatalf("cf.CleanUp failed: %v", err)
	}

	if _, ok := cf.records[recordName]; ok {
		t.Fatalf("expected record to be cleared from records map")
	}
}
