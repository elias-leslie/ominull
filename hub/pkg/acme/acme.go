// Package acme provides automated ACME TLS certificate provisioning and renewal
// using DNS-01 challenges (RFC 8555) for public domain console installations.
package acme

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/acme"
)

// DefaultLetsEncryptDirectory is the production Let's Encrypt directory URL.
const DefaultLetsEncryptDirectory = "https://acme-v02.api.letsencrypt.org/directory"

// LetsEncryptStagingDirectory is the Let's Encrypt staging directory URL for testing.
const LetsEncryptStagingDirectory = "https://acme-staging-v02.api.letsencrypt.org/directory"

// DNSProvider manages DNS TXT records for DNS-01 challenge completion.
type DNSProvider interface {
	// Present provisions a DNS TXT record for the DNS-01 challenge.
	Present(ctx context.Context, domain, recordName, recordValue string) error
	// CleanUp removes the DNS TXT record after challenge validation.
	CleanUp(ctx context.Context, domain, recordName, recordValue string) error
}

// Config configures the ACME certificate manager.
type Config struct {
	DirectoryURL string        // ACME directory URL (defaults to Let's Encrypt production)
	Email        string        // Account registration email
	Domain       string        // Canonical console domain (e.g. omi.example.com)
	DNSProvider  DNSProvider   // DNS provider for DNS-01 challenges
	CertDir      string        // Directory to store account key and issued certificates
	RenewBefore  time.Duration // Duration before expiration to renew (default: 30 days)
	HTTPClient   *http.Client  // Optional HTTP client
}

// Manager manages ACME account registration, order finalization, and certificate renewal.
type Manager struct {
	cfg        Config
	client     *acme.Client
	accountKey crypto.Signer
	mu         sync.RWMutex
	cachedCert *tls.Certificate
}

// NewManager creates a new ACME Manager.
func NewManager(cfg Config) (*Manager, error) {
	if strings.TrimSpace(cfg.Domain) == "" {
		return nil, errors.New("acme: domain is required")
	}
	if strings.TrimSpace(cfg.DirectoryURL) == "" {
		cfg.DirectoryURL = DefaultLetsEncryptDirectory
	}
	if cfg.RenewBefore <= 0 {
		cfg.RenewBefore = 30 * 24 * time.Hour
	}
	if cfg.CertDir == "" {
		cfg.CertDir = "/var/lib/ominull/certs"
	}
	if err := os.MkdirAll(cfg.CertDir, 0700); err != nil {
		return nil, fmt.Errorf("acme: create cert dir %s: %w", cfg.CertDir, err)
	}

	m := &Manager{cfg: cfg}
	return m, nil
}

// Certificate returns the current valid certificate, loading from disk or
// obtaining a new one via ACME DNS-01 if expired or missing.
func (m *Manager) Certificate(ctx context.Context) (*tls.Certificate, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.cachedCert != nil && !m.needsRenewalLocked(m.cachedCert) {
		return m.cachedCert, nil
	}

	cert, err := m.loadFromDiskLocked()
	if err == nil && !m.needsRenewalLocked(cert) {
		m.cachedCert = cert
		return cert, nil
	}

	cert, err = m.obtainCertificateLocked(ctx)
	if err != nil {
		return nil, err
	}
	m.cachedCert = cert
	return cert, nil
}

// LoadStoredCert loads an existing certificate from disk if present and valid.
func (m *Manager) LoadStoredCert() (*tls.Certificate, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.loadFromDiskLocked()
}

func (m *Manager) needsRenewalLocked(cert *tls.Certificate) bool {
	if cert == nil || len(cert.Certificate) == 0 || cert.Leaf == nil {
		return true
	}
	return time.Now().Add(m.cfg.RenewBefore).After(cert.Leaf.NotAfter)
}

func (m *Manager) certPath() string {
	return filepath.Join(m.cfg.CertDir, "console_acme.crt")
}

func (m *Manager) keyPath() string {
	return filepath.Join(m.cfg.CertDir, "console_acme.key")
}

func (m *Manager) accountKeyPath() string {
	return filepath.Join(m.cfg.CertDir, "acme_account.key")
}

func (m *Manager) loadFromDiskLocked() (*tls.Certificate, error) {
	certFile := m.certPath()
	keyFile := m.keyPath()
	if !fileExists(certFile) || !fileExists(keyFile) {
		return nil, errors.New("certificate files not found on disk")
	}

	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, err
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return nil, err
	}
	cert.Leaf = leaf
	return &cert, nil
}

func (m *Manager) initClientLocked(ctx context.Context) error {
	if m.client != nil {
		return nil
	}

	key, err := m.loadOrGenerateAccountKey()
	if err != nil {
		return fmt.Errorf("load account key: %w", err)
	}
	m.accountKey = key

	m.client = &acme.Client{
		Key:          key,
		DirectoryURL: m.cfg.DirectoryURL,
		HTTPClient:   m.cfg.HTTPClient,
	}

	// Register account or retrieve existing account
	acct := &acme.Account{}
	if m.cfg.Email != "" {
		acct.Contact = []string{"mailto:" + m.cfg.Email}
	}

	_, err = m.client.Register(ctx, acct, acme.AcceptTOS)
	if err != nil {
		// Ignore conflict if account already registered
		var acmeErr *acme.Error
		if !errors.As(err, &acmeErr) || acmeErr.StatusCode != http.StatusConflict {
			if !strings.Contains(strings.ToLower(err.Error()), "already registered") &&
				!strings.Contains(strings.ToLower(err.Error()), "account already exists") {
				return fmt.Errorf("register acme account: %w", err)
			}
		}
	}

	return nil
}

func (m *Manager) obtainCertificateLocked(ctx context.Context) (*tls.Certificate, error) {
	if m.cfg.DNSProvider == nil {
		return nil, errors.New("acme: DNS provider is required for DNS-01 challenges")
	}

	if err := m.initClientLocked(ctx); err != nil {
		return nil, err
	}

	log.Printf("[*] ACME: Starting DNS-01 certificate order for %s", m.cfg.Domain)

	// 1. Create order
	order, err := m.client.AuthorizeOrder(ctx, []acme.AuthzID{{Type: "dns", Value: m.cfg.Domain}})
	if err != nil {
		return nil, fmt.Errorf("authorize order for %s: %w", m.cfg.Domain, err)
	}

	// 2. Complete challenges for each authorization
	recordName := "_acme-challenge." + m.cfg.Domain
	for _, authzURL := range order.AuthzURLs {
		authz, err := m.client.GetAuthorization(ctx, authzURL)
		if err != nil {
			return nil, fmt.Errorf("get authorization %s: %w", authzURL, err)
		}
		if authz.Status == acme.StatusValid {
			continue
		}

		var chal *acme.Challenge
		for _, c := range authz.Challenges {
			if c.Type == "dns-01" {
				chal = c
				break
			}
		}
		if chal == nil {
			return nil, fmt.Errorf("no dns-01 challenge offered for authorization %s", authzURL)
		}

		recordValue, err := m.client.DNS01ChallengeRecord(chal.Token)
		if err != nil {
			return nil, fmt.Errorf("compute dns-01 challenge record: %w", err)
		}

		log.Printf("[*] ACME: Presenting DNS-01 TXT record %s = %s", recordName, recordValue)
		if err := m.cfg.DNSProvider.Present(ctx, m.cfg.Domain, recordName, recordValue); err != nil {
			return nil, fmt.Errorf("present dns record: %w", err)
		}

		// Ensure cleanup after authorization completes
		defer func(val string) {
			cleanCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			_ = m.cfg.DNSProvider.CleanUp(cleanCtx, m.cfg.Domain, recordName, val)
		}(recordValue)

		// Inform ACME CA that challenge is ready
		if _, err := m.client.Accept(ctx, chal); err != nil {
			return nil, fmt.Errorf("accept challenge: %w", err)
		}

		// Wait for authorization to reach valid status
		authzFinal, err := m.client.WaitAuthorization(ctx, authzURL)
		if err != nil {
			return nil, fmt.Errorf("wait authorization failed: %w", err)
		}
		if authzFinal.Status != acme.StatusValid {
			return nil, fmt.Errorf("authorization failed with status %s", authzFinal.Status)
		}
	}

	// 3. Wait for order to be ready for finalization
	order, err = m.client.WaitOrder(ctx, order.URI)
	if err != nil {
		return nil, fmt.Errorf("wait order: %w", err)
	}

	// 4. Generate certificate private key and CSR
	certKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate certificate key: %w", err)
	}

	csrTemplate := x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: m.cfg.Domain},
		DNSNames: []string{m.cfg.Domain},
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &csrTemplate, certKey)
	if err != nil {
		return nil, fmt.Errorf("create CSR: %w", err)
	}

	// 5. Finalize order and retrieve certificate
	derCerts, certURL, err := m.client.CreateOrderCert(ctx, order.FinalizeURL, csrDER, true)
	if err != nil {
		return nil, fmt.Errorf("finalize order cert: %w", err)
	}
	_ = certURL

	if len(derCerts) == 0 {
		return nil, errors.New("no certificates returned from ACME order")
	}

	// 6. Encode and write cert and key atomically
	var certPEM bytes.Buffer
	for _, der := range derCerts {
		if err := pem.Encode(&certPEM, &pem.Block{Type: "CERTIFICATE", Bytes: der}); err != nil {
			return nil, err
		}
	}

	keyDER, err := x509.MarshalECPrivateKey(certKey)
	if err != nil {
		return nil, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	if err := os.WriteFile(m.certPath(), certPEM.Bytes(), 0644); err != nil {
		return nil, fmt.Errorf("write cert file: %w", err)
	}
	if err := os.WriteFile(m.keyPath(), keyPEM, 0600); err != nil {
		return nil, fmt.Errorf("write key file: %w", err)
	}

	tlsCert, err := tls.X509KeyPair(certPEM.Bytes(), keyPEM)
	if err != nil {
		return nil, fmt.Errorf("parse issued tls cert: %w", err)
	}
	leaf, err := x509.ParseCertificate(tlsCert.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("parse issued leaf: %w", err)
	}
	tlsCert.Leaf = leaf

	log.Printf("[+] ACME: Successfully obtained certificate for %s (valid until %s)",
		m.cfg.Domain, leaf.NotAfter.UTC().Format(time.RFC3339))
	return &tlsCert, nil
}

func (m *Manager) loadOrGenerateAccountKey() (crypto.Signer, error) {
	keyPath := m.accountKeyPath()
	if fileExists(keyPath) {
		raw, err := os.ReadFile(keyPath)
		if err != nil {
			return nil, err
		}
		block, _ := pem.Decode(raw)
		if block == nil {
			return nil, errors.New("failed to decode account key PEM")
		}
		if key, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
			return key, nil
		}
		if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
			return key, nil
		}
		if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
			if signer, ok := key.(crypto.Signer); ok {
				return signer, nil
			}
		}
	}

	// Generate new account key
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, err
	}
	block := &pem.Block{Type: "EC PRIVATE KEY", Bytes: der}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(block), 0600); err != nil {
		return nil, err
	}
	return key, nil
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

// ---------------------------------------------------------------------------
// Cloudflare DNS Provider
// ---------------------------------------------------------------------------

// CloudflareDNSProvider implements DNSProvider via Cloudflare API v4.
type CloudflareDNSProvider struct {
	APIToken   string
	BaseURL    string // defaults to https://api.cloudflare.com/client/v4
	HTTPClient *http.Client
	mu         sync.Mutex
	records    map[string]string // recordName -> recordID
}

// NewCloudflareDNSProvider creates a new Cloudflare DNS-01 provider.
func NewCloudflareDNSProvider(apiToken string) *CloudflareDNSProvider {
	return &CloudflareDNSProvider{
		APIToken:   apiToken,
		BaseURL:    "https://api.cloudflare.com/client/v4",
		HTTPClient: &http.Client{Timeout: 30 * time.Second},
		records:    make(map[string]string),
	}
}

func (p *CloudflareDNSProvider) getZoneID(ctx context.Context, domain string) (string, error) {
	parts := strings.Split(domain, ".")
	for i := 0; i < len(parts)-1; i++ {
		candidate := strings.Join(parts[i:], ".")
		u := fmt.Sprintf("%s/zones?name=%s&status=active", strings.TrimRight(p.BaseURL, "/"), url.QueryEscape(candidate))
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			return "", err
		}
		req.Header.Set("Authorization", "Bearer "+p.APIToken)
		req.Header.Set("Content-Type", "application/json")

		resp, err := p.HTTPClient.Do(req)
		if err != nil {
			return "", err
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			continue
		}

		var res struct {
			Success bool `json:"success"`
			Result  []struct {
				ID   string `json:"id"`
				Name string `json:"name"`
			} `json:"result"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
			continue
		}
		if res.Success && len(res.Result) > 0 {
			return res.Result[0].ID, nil
		}
	}
	return "", fmt.Errorf("no active Cloudflare zone found for %s", domain)
}

func (p *CloudflareDNSProvider) Present(ctx context.Context, domain, recordName, recordValue string) error {
	zoneID, err := p.getZoneID(ctx, domain)
	if err != nil {
		return err
	}

	payload, err := json.Marshal(map[string]interface{}{
		"type":    "TXT",
		"name":    recordName,
		"content": recordValue,
		"ttl":     120,
	})
	if err != nil {
		return err
	}

	u := fmt.Sprintf("%s/zones/%s/dns_records", strings.TrimRight(p.BaseURL, "/"), zoneID)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+p.APIToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := p.HTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	var res struct {
		Success bool `json:"success"`
		Result  struct {
			ID string `json:"id"`
		} `json:"result"`
		Errors []interface{} `json:"errors"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		return err
	}
	if !res.Success {
		return fmt.Errorf("cloudflare create dns record failed: %v", res.Errors)
	}

	p.mu.Lock()
	p.records[recordName] = res.Result.ID
	p.mu.Unlock()

	time.Sleep(2 * time.Second)
	return nil
}

func (p *CloudflareDNSProvider) CleanUp(ctx context.Context, domain, recordName, recordValue string) error {
	_ = recordValue
	p.mu.Lock()
	recordID, ok := p.records[recordName]
	delete(p.records, recordName)
	p.mu.Unlock()

	if !ok {
		return nil
	}

	zoneID, err := p.getZoneID(ctx, domain)
	if err != nil {
		return err
	}

	u := fmt.Sprintf("%s/zones/%s/dns_records/%s", strings.TrimRight(p.BaseURL, "/"), zoneID, recordID)
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, u, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+p.APIToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := p.HTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return nil
}

// ---------------------------------------------------------------------------
// Mock DNS Provider (for testing)
// ---------------------------------------------------------------------------

// MockDNSProvider records DNS-01 challenge presentations and cleanups in memory.
type MockDNSProvider struct {
	mu        sync.Mutex
	Presented map[string]string
	Cleaned   map[string]bool
}

// NewMockDNSProvider creates an empty MockDNSProvider.
func NewMockDNSProvider() *MockDNSProvider {
	return &MockDNSProvider{
		Presented: make(map[string]string),
		Cleaned:   make(map[string]bool),
	}
}

func (m *MockDNSProvider) Present(ctx context.Context, domain, recordName, recordValue string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.Presented[recordName] = recordValue
	return nil
}

func (m *MockDNSProvider) CleanUp(ctx context.Context, domain, recordName, recordValue string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.Cleaned[recordName] = true
	return nil
}

func (m *MockDNSProvider) GetPresented(recordName string) (string, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	val, ok := m.Presented[recordName]
	return val, ok
}
