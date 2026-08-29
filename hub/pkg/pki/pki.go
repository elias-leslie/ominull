package pki

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type Manager struct {
	certDir  string
	caCert   *x509.Certificate
	caKey    *rsa.PrivateKey
	caPEM    []byte
	caKeyPEM []byte
	mu       sync.RWMutex
}

func New(certDir string) (*Manager, error) {
	if err := os.MkdirAll(certDir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create certs dir: %w", err)
	}

	m := &Manager{certDir: certDir}
	if err := m.initOrLoadCA(); err != nil {
		return nil, err
	}
	return m, nil
}

func (m *Manager) initOrLoadCA() error {
	caCertPath := filepath.Join(m.certDir, "ca.crt")
	caKeyPath := filepath.Join(m.certDir, "ca.key")

	if fileExists(caCertPath) && fileExists(caKeyPath) {
		certBytes, err := os.ReadFile(caCertPath)
		if err != nil {
			return err
		}
		keyBytes, err := os.ReadFile(caKeyPath)
		if err != nil {
			return err
		}

		block, _ := pem.Decode(certBytes)
		if block == nil {
			return fmt.Errorf("failed to parse CA cert PEM")
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return err
		}

		keyBlock, _ := pem.Decode(keyBytes)
		if keyBlock == nil {
			return fmt.Errorf("failed to parse CA key PEM")
		}
		key, err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
		if err != nil {
			return err
		}

		m.caCert = cert
		m.caKey = key
		m.caPEM = certBytes
		m.caKeyPEM = keyBytes
		return nil
	}

	// Generate new Root CA
	privKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return fmt.Errorf("failed to generate CA private key: %w", err)
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return fmt.Errorf("failed to generate serial number: %w", err)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization:  []string{"Ominull Enterprise Trust Network"},
			CommonName:    "Ominull Autonomous Root CA",
			Country:       []string{"US"},
			Province:      []string{"Security"},
			Locality:      []string{"ZeroTrust"},
		},
		NotBefore:             time.Now().Add(-10 * time.Minute),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour), // 10 years
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &privKey.PublicKey, privKey)
	if err != nil {
		return fmt.Errorf("failed to create CA certificate: %w", err)
	}

	caCert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		return err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privKey)})

	_ = os.WriteFile(caCertPath, certPEM, 0644)
	_ = os.WriteFile(caKeyPath, keyPEM, 0600)

	m.caCert = caCert
	m.caKey = privKey
	m.caPEM = certPEM
	m.caKeyPEM = keyPEM
	return nil
}

func (m *Manager) GetCAPEM() []byte {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.caPEM
}

type ClientCertBundle struct {
	CertPEM []byte `json:"cert_pem"`
	KeyPEM  []byte `json:"key_pem"`
	CAPEM   []byte `json:"ca_pem"`
}

func (m *Manager) IssueClientCert(hostname, ipStr string) (*ClientCertBundle, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	clientKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, err
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Ominull Enrolled Fleet"},
			CommonName:   hostname,
		},
		NotBefore:    time.Now().Add(-10 * time.Minute),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour), // 1 year
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	if ip := net.ParseIP(ipStr); ip != nil {
		template.IPAddresses = append(template.IPAddresses, ip)
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, m.caCert, &clientKey.PublicKey, m.caKey)
	if err != nil {
		return nil, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(clientKey)})

	return &ClientCertBundle{
		CertPEM: certPEM,
		KeyPEM:  keyPEM,
		CAPEM:   m.caPEM,
	}, nil
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

// ---------------------------------------------------------------------------
// Server certificates
//
// The CA above already anchored the fleet's trust; what was missing was a leaf
// for the hub itself, so agent traffic stayed on plain HTTP. ServerCertificate
// issues that leaf and keeps it on disk beside the CA, because a certificate
// regenerated on every boot would force every pinned agent to re-learn nothing
// while breaking session resumption for no gain.
//
// SANs are the whole point of the reissue check: an agent dials the hub by IP
// on the LAN, so a lease change or a new interface makes the stored leaf wrong
// for the address it is actually reached on. Rather than ask an operator to
// notice that, the hub compares the stored SAN set against the one it wants and
// reissues when it no longer covers it.

const (
	serverCertFile = "server.crt"
	serverKeyFile  = "server.key"

	// Reissue this far ahead of expiry. A hub that only renewed on the day
	// would hand out an expired leaf to any agent that connected while it
	// was down.
	serverCertRenewBefore = 30 * 24 * time.Hour
	serverCertLifetime    = 2 * 365 * 24 * time.Hour
)

// ServerCertificate returns a TLS leaf signed by the hub CA and valid for every
// name and address in hosts, loading the stored one when it still fits and
// issuing a replacement when it does not.
func (m *Manager) ServerCertificate(hosts []string) (*tls.Certificate, error) {
	dnsNames, ips := splitHosts(hosts)
	if len(dnsNames) == 0 && len(ips) == 0 {
		return nil, fmt.Errorf("no hostnames or addresses to issue a server certificate for")
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if cert, ok := m.loadServerCertLocked(dnsNames, ips); ok {
		return cert, nil
	}
	return m.issueServerCertLocked(dnsNames, ips)
}

// loadServerCertLocked reports whether the stored leaf is still usable: signed
// by the CA currently in hand, not near expiry, and covering every requested
// name. Anything else is treated as absent rather than repaired in place.
func (m *Manager) loadServerCertLocked(dnsNames []string, ips []net.IP) (*tls.Certificate, bool) {
	certPath := filepath.Join(m.certDir, serverCertFile)
	keyPath := filepath.Join(m.certDir, serverKeyFile)
	if !fileExists(certPath) || !fileExists(keyPath) {
		return nil, false
	}

	pair, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, false
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return nil, false
	}
	if time.Now().Add(serverCertRenewBefore).After(leaf.NotAfter) {
		return nil, false
	}
	if err := leaf.CheckSignatureFrom(m.caCert); err != nil {
		return nil, false
	}
	if !certCovers(leaf, dnsNames, ips) {
		return nil, false
	}

	pair.Leaf = leaf
	return &pair, true
}

func (m *Manager) issueServerCertLocked(dnsNames []string, ips []net.IP) (*tls.Certificate, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, err
	}

	commonName := "ominull-hub"
	if len(dnsNames) > 0 {
		commonName = dnsNames[0]
	} else if len(ips) > 0 {
		commonName = ips[0].String()
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Ominull Enterprise Trust Network"},
			CommonName:   commonName,
		},
		NotBefore:   time.Now().Add(-10 * time.Minute),
		NotAfter:    time.Now().Add(serverCertLifetime),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:    dnsNames,
		IPAddresses: ips,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, m.caCert, &key.PublicKey, m.caKey)
	if err != nil {
		return nil, fmt.Errorf("failed to sign hub server certificate: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})

	if err := os.WriteFile(filepath.Join(m.certDir, serverCertFile), certPEM, 0644); err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(m.certDir, serverKeyFile), keyPEM, 0600); err != nil {
		return nil, err
	}

	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}
	leaf, err := x509.ParseCertificate(derBytes)
	if err != nil {
		return nil, err
	}
	pair.Leaf = leaf
	return &pair, nil
}

// splitHosts sorts a mixed list of hostnames and addresses into the two SAN
// fields x509 keeps them in, dropping duplicates and empties so the covering
// check compares like with like.
func splitHosts(hosts []string) ([]string, []net.IP) {
	var dnsNames []string
	var ips []net.IP
	seenDNS := map[string]bool{}
	seenIP := map[string]bool{}

	for _, h := range hosts {
		h = strings.TrimSpace(h)
		if h == "" {
			continue
		}
		if ip := net.ParseIP(h); ip != nil {
			if !seenIP[ip.String()] {
				seenIP[ip.String()] = true
				ips = append(ips, ip)
			}
			continue
		}
		h = strings.ToLower(h)
		if !seenDNS[h] {
			seenDNS[h] = true
			dnsNames = append(dnsNames, h)
		}
	}
	return dnsNames, ips
}

func certCovers(leaf *x509.Certificate, dnsNames []string, ips []net.IP) bool {
	for _, name := range dnsNames {
		if err := leaf.VerifyHostname(name); err != nil {
			return false
		}
	}
	for _, ip := range ips {
		if err := leaf.VerifyHostname(ip.String()); err != nil {
			return false
		}
	}
	return true
}
