package pki

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
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
