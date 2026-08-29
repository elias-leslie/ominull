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

// TestServerCertificateReuseAndReissue covers the two things the HTTPS listener
// depends on: a certificate that survives a restart (so a pinned fleet is not
// churned for nothing) and one that is replaced the moment it stops covering an
// address an agent might dial - the DHCP case that would otherwise present a
// certificate no client accepts.
func TestServerCertificateReuseAndReissue(t *testing.T) {
	certDir := t.TempDir()
	mgr, err := New(certDir)
	if err != nil {
		t.Fatalf("New PKI failed: %v", err)
	}

	first, err := mgr.ServerCertificate([]string{"localhost", "127.0.0.1", "10.0.0.58"})
	if err != nil {
		t.Fatalf("ServerCertificate failed: %v", err)
	}

	roots := x509.NewCertPool()
	roots.AddCert(mgr.caCert)
	if _, err := first.Leaf.Verify(x509.VerifyOptions{
		Roots:     roots,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}); err != nil {
		t.Fatalf("hub leaf does not verify against the hub CA: %v", err)
	}
	if err := first.Leaf.VerifyHostname("10.0.0.58"); err != nil {
		t.Errorf("leaf is not valid for the LAN address an agent dials: %v", err)
	}

	// A hub restarting with the same addresses must present the same leaf.
	again, err := mgr.ServerCertificate([]string{"localhost", "127.0.0.1", "10.0.0.58"})
	if err != nil {
		t.Fatalf("second ServerCertificate failed: %v", err)
	}
	if again.Leaf.SerialNumber.Cmp(first.Leaf.SerialNumber) != 0 {
		t.Errorf("an unchanged host list reissued the certificate: %s -> %s",
			first.Leaf.SerialNumber, again.Leaf.SerialNumber)
	}

	// A new address it does not cover must force a reissue.
	moved, err := mgr.ServerCertificate([]string{"localhost", "127.0.0.1", "10.0.0.77"})
	if err != nil {
		t.Fatalf("ServerCertificate after an address change failed: %v", err)
	}
	if moved.Leaf.SerialNumber.Cmp(first.Leaf.SerialNumber) == 0 {
		t.Fatalf("the hub kept a certificate that does not cover its own address")
	}
	if err := moved.Leaf.VerifyHostname("10.0.0.77"); err != nil {
		t.Errorf("reissued leaf still does not cover the new address: %v", err)
	}

	// And a hub with nothing to be named by should say so rather than serve a
	// certificate no client can match.
	if _, err := mgr.ServerCertificate([]string{"", "   "}); err == nil {
		t.Errorf("expected an error when no SAN could be derived")
	}
}
