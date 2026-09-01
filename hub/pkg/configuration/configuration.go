// Package configuration owns the durable, non-secret hub setup contract.
// Package scripts and the wizard both write this format; neither edits a
// systemd unit. Secret values live in separate root-only files.
package configuration

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const CurrentVersion = 1

type Config struct {
	Version         int      `json:"version"`
	NetworkMode     string   `json:"network_mode"` // lan, direct, cloudflare
	ConsoleURL      string   `json:"console_url"`
	AgentURL        string   `json:"agent_url"`
	TLSMode         string   `json:"tls_mode"` // self-issued, acme, custom
	TLSCertFile     string   `json:"tls_cert_file,omitempty"`
	TLSKeyFile      string   `json:"tls_key_file,omitempty"`
	TLSHosts        []string `json:"tls_hosts,omitempty"`
	ClientCerts     string   `json:"client_certs"` // off, optional, required
	OIDCIssuer      string   `json:"oidc_issuer,omitempty"`
	OIDCClientID    string   `json:"oidc_client_id,omitempty"`
	OIDCRedirectURL string   `json:"oidc_redirect_url,omitempty"`
	AccessTeam      string   `json:"access_team,omitempty"`
	AccessAudience  string   `json:"access_audience,omitempty"`
	Cloudflare      bool     `json:"cloudflare"`
	SetupComplete   bool     `json:"setup_complete"`
	UpdatedAt       string   `json:"updated_at"`
}

type ValidationError struct{ Problems []string }

func (e *ValidationError) Error() string { return strings.Join(e.Problems, "; ") }

func (c Config) Validate() error {
	var problems []string
	mode := strings.ToLower(strings.TrimSpace(c.NetworkMode))
	if mode == "" {
		mode = "lan"
	}
	if mode != "lan" && mode != "direct" && mode != "cloudflare" {
		problems = append(problems, "network_mode must be lan, direct, or cloudflare")
	}
	tlsMode := strings.ToLower(strings.TrimSpace(c.TLSMode))
	if tlsMode == "" {
		tlsMode = "self-issued"
	}
	if tlsMode != "self-issued" && tlsMode != "acme" && tlsMode != "custom" {
		problems = append(problems, "tls_mode must be self-issued, acme, or custom")
	}
	clientCerts := strings.ToLower(strings.TrimSpace(c.ClientCerts))
	if clientCerts == "" {
		clientCerts = "optional"
	}
	if clientCerts != "off" && clientCerts != "optional" && clientCerts != "required" {
		problems = append(problems, "client_certs must be off, optional, or required")
	}
	for name, value := range map[string]string{"console_url": c.ConsoleURL, "agent_url": c.AgentURL} {
		if strings.TrimSpace(value) == "" {
			continue
		}
		u, err := url.Parse(strings.TrimSpace(value))
		if err != nil || u.Scheme == "" || u.Host == "" || u.User != nil {
			problems = append(problems, name+" must be an absolute URL without userinfo")
			continue
		}
		if name == "agent_url" && u.Scheme != "https" {
			problems = append(problems, name+" must use https; agent credentials are never sent over HTTP")
		}
		if mode == "direct" || mode == "cloudflare" {
			if u.Scheme != "https" {
				problems = append(problems, name+" must use https in direct or cloudflare mode")
			}
		}
	}
	if mode == "cloudflare" {
		if strings.TrimSpace(c.ConsoleURL) == "" || strings.TrimSpace(c.AgentURL) == "" {
			problems = append(problems, "cloudflare mode needs separate console and agent HTTPS URLs")
		}
		if !c.Cloudflare {
			problems = append(problems, "cloudflare mode must enable the optional Cloudflare adapter")
		}
	}
	if (tlsMode == "custom" || tlsMode == "acme") && (strings.TrimSpace(c.TLSCertFile) == "" || strings.TrimSpace(c.TLSKeyFile) == "") {
		problems = append(problems, tlsMode+" TLS needs both certificate and key paths")
	}
	if c.OIDCIssuer != "" {
		u, err := url.Parse(strings.TrimSpace(c.OIDCIssuer))
		if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil {
			problems = append(problems, "oidc_issuer must be an HTTPS issuer URL without userinfo")
		}
		if strings.TrimSpace(c.OIDCClientID) == "" {
			problems = append(problems, "oidc_client_id is required when OIDC is configured")
		}
		if strings.TrimSpace(c.OIDCRedirectURL) == "" {
			problems = append(problems, "oidc_redirect_url is required when OIDC is configured")
		}
	} else if strings.TrimSpace(c.OIDCClientID) != "" || strings.TrimSpace(c.OIDCRedirectURL) != "" {
		problems = append(problems, "oidc_issuer is required when OIDC client settings are supplied")
	}
	if c.OIDCRedirectURL != "" {
		u, err := url.Parse(strings.TrimSpace(c.OIDCRedirectURL))
		if err != nil || u.Scheme == "" || u.Host == "" || u.User != nil {
			problems = append(problems, "oidc_redirect_url must be an absolute URL")
		} else if u.Scheme != "https" && !strings.EqualFold(u.Hostname(), "localhost") && !net.ParseIP(u.Hostname()).IsLoopback() {
			problems = append(problems, "oidc_redirect_url must use https except for loopback development")
		}
	}
	if c.Version != 0 && c.Version != CurrentVersion {
		problems = append(problems, fmt.Sprintf("unsupported configuration version %d", c.Version))
	}
	if len(problems) > 0 {
		return &ValidationError{Problems: problems}
	}
	return nil
}

func (c Config) Normalized() Config {
	if c.Version == 0 {
		c.Version = CurrentVersion
	}
	if strings.TrimSpace(c.NetworkMode) == "" {
		c.NetworkMode = "lan"
	}
	if strings.TrimSpace(c.TLSMode) == "" {
		c.TLSMode = "self-issued"
	}
	if strings.TrimSpace(c.ClientCerts) == "" {
		c.ClientCerts = "optional"
	}
	c.NetworkMode = strings.ToLower(strings.TrimSpace(c.NetworkMode))
	c.TLSMode = strings.ToLower(strings.TrimSpace(c.TLSMode))
	c.ClientCerts = strings.ToLower(strings.TrimSpace(c.ClientCerts))
	c.ConsoleURL = strings.TrimRight(strings.TrimSpace(c.ConsoleURL), "/")
	c.AgentURL = strings.TrimRight(strings.TrimSpace(c.AgentURL), "/")
	c.OIDCIssuer = strings.TrimRight(strings.TrimSpace(c.OIDCIssuer), "/")
	c.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	sort.Strings(c.TLSHosts)
	return c
}

// Environment renders only non-secret service settings. OIDC client secrets,
// enrollment tokens, device credentials, and Cloudflare credentials are never
// accepted here.
func (c Config) Environment(dbPath, adminKeyFile, binaryDir, setupTokenFile string) string {
	c = c.Normalized()
	if strings.TrimSpace(adminKeyFile) == "" {
		adminKeyFile = "/etc/ominull/admin.key"
	}
	lines := []string{
		"# Managed by ominullctl and the Ominull setup wizard. Do not edit.",
		"OMINULL_DB=" + dbPath,
		"OMINULL_ADMIN_KEY_FILE=" + adminKeyFile,
		"OMINULL_BINARY_DIR=" + binaryDir,
		"OMINULL_SETUP_TOKEN_FILE=" + setupTokenFile,
		"OMINULL_LISTEN=:9999",
		"OMINULL_TLS_LISTEN=:9443",
		"OMINULL_NETWORK_MODE=" + c.NetworkMode,
		"OMINULL_TLS_MODE=" + c.TLSMode,
		"OMINULL_CLIENT_CERTS=" + c.ClientCerts,
		"OMINULL_HUB_URL=" + c.ConsoleURL,
		"OMINULL_AGENT_HUB_URL=" + c.AgentURL,
		"OMINULL_TLS_CERT=" + c.TLSCertFile,
		"OMINULL_TLS_KEY=" + c.TLSKeyFile,
		"OMINULL_TLS_HOSTS=" + strings.Join(c.TLSHosts, ","),
		"OMINULL_ACCESS_TEAM=" + c.AccessTeam,
		"OMINULL_ACCESS_AUD=" + c.AccessAudience,
	}
	return strings.Join(lines, "\n") + "\n"
}

// WriteEnvironmentAtomic replaces the package-owned environment file without
// exposing partially written configuration to systemd or a concurrent read.
func WriteEnvironmentAtomic(path, contents string) error {
	if strings.TrimSpace(path) == "" {
		return errors.New("configuration path is required")
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	var suffix [8]byte
	if _, err := rand.Read(suffix[:]); err != nil {
		return err
	}
	tmp := filepath.Join(dir, "."+filepath.Base(path)+"."+hex.EncodeToString(suffix[:])+".tmp")
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	ok := false
	defer func() {
		_ = f.Close()
		if !ok {
			_ = os.Remove(tmp)
		}
	}()
	if _, err := f.WriteString(contents); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmp, 0600); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	ok = true
	return nil
}
