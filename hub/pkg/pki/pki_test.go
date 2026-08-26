package pki

import (
	"crypto/x509"
	"encoding/pem"
	"testing"
)

func TestPKIManager(t *testing.T) {
	certDir := t.TempDir()

	mgr, err := New(certDir)
	if err != nil {
		t.Fatalf("New PKI failed: %v", err)
	}

	caPEM := mgr.GetCAPEM()
	if len(caPEM) == 0 {
		t.Fatalf("expected non-empty CA PEM")
	}

	// Issue client cert
	bundle, err := mgr.IssueClientCert("win11-corp-pc", "192.168.1.100")
	if err != nil {
		t.Fatalf("IssueClientCert failed: %v", err)
	}

	// Parse client certificate
	block, _ := pem.Decode(bundle.CertPEM)
	if block == nil {
		t.Fatalf("failed to decode client cert PEM")
	}
	clientCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("ParseCertificate failed: %v", err)
	}

	if clientCert.Subject.CommonName != "win11-corp-pc" {
		t.Errorf("expected CN win11-corp-pc, got %s", clientCert.Subject.CommonName)
	}

	// Verify client certificate against Root CA
	roots := x509.NewCertPool()
	roots.AddCert(mgr.caCert)

	opts := x509.VerifyOptions{
		Roots:     roots,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	if _, err := clientCert.Verify(opts); err != nil {
		t.Fatalf("client cert verification failed against Root CA: %v", err)
	}
}
