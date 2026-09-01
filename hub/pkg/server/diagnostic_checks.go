package server

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/google/uuid"
	"ominull/hub/pkg/configuration"
	"ominull/hub/pkg/diagnostics"
	"ominull/hub/pkg/storage"
)

// diagnosticChecks is shared by the first-run wizard and /status. Checks are
// deliberately local and bounded; provider-specific probes only run when the
// operator selected that provider.
func (s *Server) diagnosticChecks() []diagnostics.Check {
	return []diagnostics.Check{
		s.checkHost,
		s.checkPackage,
		s.checkService,
		s.checkListeners,
		s.checkStorage,
		s.checkPKI,
		s.checkEnrollment,
		s.checkDeviceIdentity,
		s.checkNetwork,
		s.checkDNS,
		s.checkTLS,
		s.checkNativeTransport,
		s.checkOIDC,
		s.checkCloudflare,
		s.checkBootstrap,
		s.checkHeartbeats,
		s.checkBackups,
	}
}

func (s *Server) effectiveConfiguration() configuration.Config {
	cfg := s.setupConfiguration()
	if cfg.NetworkMode == "" {
		cfg.NetworkMode = "lan"
	}
	if cfg.ConsoleURL == "" {
		cfg.ConsoleURL = s.hubURL
	}
	if cfg.AgentURL == "" {
		cfg.AgentURL = s.agentHubURL
	}
	return cfg.Normalized()
}

func diag(id, title string, state diagnostics.State, summary, evidence, remediation string) diagnostics.Result {
	return diagnostics.Result{ID: id, Title: title, State: state, Summary: summary, Evidence: evidence, Remediation: remediation}
}

func (s *Server) checkHost(context.Context) diagnostics.Result {
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" {
		return diag("host", "Hub host", diagnostics.Fail,
			fmt.Sprintf("hub package requires Linux amd64; runtime is %s/%s", runtime.GOOS, runtime.GOARCH),
			"runtime "+runtime.GOOS+"/"+runtime.GOARCH, "install the native hub package on a supported Debian or Ubuntu amd64 host")
	}
	host, err := os.Hostname()
	if err != nil || strings.TrimSpace(host) == "" {
		return diag("host", "Hub host", diagnostics.Warn, "host name is unavailable", "Linux amd64", "set a stable host name if certificates need it")
	}
	return diag("host", "Hub host", diagnostics.Pass, "supported Linux amd64 runtime", host, "")
}

func (s *Server) checkPackage(context.Context) diagnostics.Result {
	version := strings.TrimPrefix(strings.TrimSpace(s.agentVersion), "v")
	if version == "" {
		return diag("package", "Hub package", diagnostics.Fail, "bundled release version is empty", "", "install a versioned native hub release")
	}
	paths := []string{
		filepath.Join(s.binaryDir, "ominull-hub"),
		"/usr/bin/ominullctl",
		filepath.Join(s.binaryDir, "ominull-agent_"+version+"_amd64.deb"),
		filepath.Join(s.binaryDir, "ominull-agent_"+version+"_amd64.deb.sig"),
		filepath.Join(s.binaryDir, "ominull-agent_"+version+"_amd64.deb.sha256"),
		filepath.Join(s.binaryDir, "ominull-agent-windows-"+version+".msi"),
		filepath.Join(s.binaryDir, "ominull-agent-windows-"+version+".msi.sig"),
		filepath.Join(s.binaryDir, "ominull-agent-windows-"+version+".msi.sha256"),
	}
	missing := make([]string, 0)
	for _, path := range paths {
		info, err := os.Stat(path)
		if err != nil || info.IsDir() || info.Size() == 0 {
			missing = append(missing, filepath.Base(path))
		}
	}
	if len(missing) > 0 {
		return diag("package", "Native packages", diagnostics.Fail,
			fmt.Sprintf("release v%s is missing %d package or signature file(s)", version, len(missing)),
			strings.Join(missing, ", "), "publish the signed Linux and Windows artifacts into the package download directory")
	}
	return diag("package", "Native packages", diagnostics.Pass,
		fmt.Sprintf("hub control utility and signed Linux/Windows artifacts are present for v%s", version),
		"hub binary, ominullctl, .deb/.msi, detached signatures, and SHA-256 sidecars", "")
}

func (s *Server) checkService(ctx context.Context) diagnostics.Result {
	if _, err := os.Stat("/run/systemd/system"); errors.Is(err, os.ErrNotExist) {
		return diag("service", "Package service", diagnostics.NotConfigured, "systemd is not present in this runtime", "non-systemd process", "run the package-owned hub service on a systemd host")
	}
	command := exec.CommandContext(ctx, "systemctl", "is-active", "--quiet", "ominull-hub.service")
	if err := command.Run(); err != nil {
		return diag("service", "Package service", diagnostics.Fail, "ominull-hub.service is not active", "systemctl is-active returned failure", "start or restart ominull-hub.service through the package manager")
	}
	return diag("service", "Package service", diagnostics.Pass, "one package-owned hub service is active", "ominull-hub.service", "")
}

func (s *Server) checkListeners(context.Context) diagnostics.Result {
	if strings.TrimSpace(s.tlsOpts.Listen) == "" {
		return diag("listeners", "Hub listeners", diagnostics.Fail, "agent TLS listener is disabled", "no configured TLS listener", "keep the package default TLS listener enabled for agent traffic")
	}
	if s.httpServer == nil && s.tlsServer == nil {
		return diag("listeners", "Hub listeners", diagnostics.Warn, "hub listener configuration exists but the server has not started", s.tlsOpts.Listen, "restart the package-owned service")
	}
	return diag("listeners", "Hub listeners", diagnostics.Pass, "TLS agent listener is configured and the hub is serving", "TLS "+s.tlsOpts.Listen, "")
}

func (s *Server) checkStorage(context.Context) diagnostics.Result {
	path := strings.TrimSpace(s.setupDBPath)
	if path == "" {
		return diag("storage", "Database and disk", diagnostics.Pass, "SQLite store is open and schema migrations completed", "open store; package path not supplied to this process", "")
	}
	info, err := os.Stat(path)
	if err != nil || info.IsDir() {
		return diag("storage", "Database and disk", diagnostics.Fail, "configured database path is unavailable", filepath.Base(path), "restore the preserved database path or correct package configuration")
	}
	var stat syscall.Statfs_t
	if err := syscall.Statfs(filepath.Dir(path), &stat); err != nil {
		return diag("storage", "Database and disk", diagnostics.Warn, "database is open; free-space check is unavailable", filepath.Base(path), "check the filesystem containing the database")
	}
	free := uint64(stat.Bavail) * uint64(stat.Bsize)
	if free < 64*1024*1024 {
		return diag("storage", "Database and disk", diagnostics.Fail, "less than 64 MiB remains on the database filesystem", fmt.Sprintf("%d bytes free", free), "free space or extend the filesystem before telemetry retention fills it")
	}
	return diag("storage", "Database and disk", diagnostics.Pass, "SQLite database is readable and the filesystem has space", fmt.Sprintf("%d bytes free", free), "")
}

func (s *Server) checkPKI(context.Context) diagnostics.Result {
	if s.pki == nil {
		return diag("pki", "Ominull device CA", diagnostics.Fail, "hub PKI manager is unavailable", "", "preserve the hub certificate directory and restart the package-owned service")
	}
	caBlock, _ := pem.Decode(s.pki.GetCAPEM())
	ca, err := parseCertificateBlock(caBlock)
	if err != nil || !ca.IsCA {
		return diag("pki", "Ominull device CA", diagnostics.Fail, "device CA is not a valid CA certificate", "certificate parse failed", "restore the preserved PKI directory or use the documented recovery procedure")
	}
	keyPath := filepath.Join(s.binaryDir, "certs", "ca.key")
	if info, err := os.Stat(keyPath); err == nil && info.Mode().Perm()&0077 != 0 {
		return diag("pki", "Ominull device CA", diagnostics.Fail, "device CA private key is readable by group or other", fmt.Sprintf("mode %04o", info.Mode().Perm()), "chmod the preserved CA key to 0600 and restart the service")
	}
	sum := sha256.Sum256(ca.Raw)
	return diag("pki", "Ominull device CA", diagnostics.Pass, "device CA parses and its private key is protected", "SHA-256 "+hex.EncodeToString(sum[:8]), "")
}

func parseCertificateBlock(block *pem.Block) (*x509.Certificate, error) {
	if block == nil {
		return nil, errors.New("certificate PEM block missing")
	}
	return x509.ParseCertificate(block.Bytes)
}

func (s *Server) checkEnrollment(context.Context) diagnostics.Result {
	profiles, err := s.store.ListEnrollmentProfiles()
	if err != nil {
		return diag("enrollment", "Enrollment store", diagnostics.Fail, "enrollment profile schema is unavailable", "", "allow the package-owned service to complete schema migration")
	}
	return diag("enrollment", "Enrollment store", diagnostics.Pass, fmt.Sprintf("one-use, campaign, and persistent enrollment profiles are ready (%d retained)", len(profiles)), "profile codes are stored as one-way hashes", "")
}

func (s *Server) checkDeviceIdentity(context.Context) diagnostics.Result {
	credentials, err := s.store.ListDeviceCredentials()
	if err != nil {
		return diag("device_identity", "Device identity", diagnostics.Fail, "device credential store is unavailable", "", "allow the package-owned service to complete schema migration")
	}
	return diag("device_identity", "Device identity", diagnostics.Pass, fmt.Sprintf("unique device credentials are ready (%d issued)", len(credentials)), "only one-way credential hashes are stored", "")
}

func (s *Server) checkNetwork(context.Context) diagnostics.Result {
	cfg := s.effectiveConfiguration()
	if err := cfg.Validate(); err != nil {
		return diag("network", "Network mode", diagnostics.Fail, "stored network configuration is invalid", err.Error(), "correct the network mode and separate console/agent URLs in setup")
	}
	if strings.TrimSpace(cfg.ConsoleURL) == "" || strings.TrimSpace(cfg.AgentURL) == "" {
		return diag("network", "Network mode", diagnostics.Fail, "console and agent URLs are not both configured", cfg.NetworkMode, "save separate console and agent URLs in setup; LAN mode may use a local console URL")
	}
	return diag("network", "Network mode", diagnostics.Pass, "network mode and separate console/agent URLs are valid", cfg.NetworkMode+"; console and agent addresses stored separately", "")
}

func (s *Server) checkDNS(ctx context.Context) diagnostics.Result {
	cfg := s.effectiveConfiguration()
	values := []string{cfg.ConsoleURL, cfg.AgentURL}
	var hosts []string
	for _, raw := range values {
		u, err := url.Parse(strings.TrimSpace(raw))
		if err != nil || u.Hostname() == "" {
			continue
		}
		host := u.Hostname()
		if net.ParseIP(host) != nil || strings.EqualFold(host, "localhost") {
			hosts = append(hosts, host+" (literal)")
			continue
		}
		lookupCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
		_, err = net.DefaultResolver.LookupHost(lookupCtx, host)
		cancel()
		if err != nil {
			if cfg.NetworkMode == "lan" {
				return diag("dns", "Console and agent DNS", diagnostics.Warn, "a configured LAN hostname did not resolve from the hub", host, "verify local DNS or use a reachable LAN address; direct and Cloudflare modes require resolution")
			}
			return diag("dns", "Console and agent DNS", diagnostics.Fail, "a configured public hostname did not resolve", host, "publish the A/AAAA/CNAME record before using direct WAN or Cloudflare mode")
		}
		hosts = append(hosts, host)
	}
	if len(hosts) == 0 {
		return diag("dns", "Console and agent DNS", diagnostics.NotConfigured, "no hostname is configured to resolve", "", "save console and agent URLs in setup")
	}
	return diag("dns", "Console and agent DNS", diagnostics.Pass, "configured console and agent names resolve or are literal LAN addresses", strings.Join(hosts, ", "), "")
}

func (s *Server) checkTLS(context.Context) diagnostics.Result {
	if strings.TrimSpace(s.tlsOpts.Listen) == "" {
		return diag("tls", "Server certificate", diagnostics.Fail, "TLS listener is disabled", "", "enable the package TLS listener")
	}
	cfg := s.effectiveConfiguration()
	mode := strings.ToLower(strings.TrimSpace(cfg.TLSMode))
	if mode == "" {
		mode = "self-issued"
	}
	if mode == "custom" || mode == "acme" {
		if strings.TrimSpace(s.tlsOpts.CertFile) == "" || strings.TrimSpace(s.tlsOpts.KeyFile) == "" {
			return diag("tls", "Server certificate", diagnostics.Fail, mode+" TLS is selected but certificate paths are not active", "", "install the certificate and key, then restart the package-owned service")
		}
		pair, err := tls.LoadX509KeyPair(s.tlsOpts.CertFile, s.tlsOpts.KeyFile)
		if err != nil {
			return diag("tls", "Server certificate", diagnostics.Fail, "configured server certificate and key do not match", "key-pair load failed", "replace the certificate/key pair and restart the service")
		}
		leaf, err := x509.ParseCertificate(pair.Certificate[0])
		if err != nil {
			return diag("tls", "Server certificate", diagnostics.Fail, "configured server certificate is not parseable", "certificate parse failed", "install a PEM server certificate with its full chain")
		}
		return s.tlsCertificateResult(leaf, cfg, mode)
	}
	if s.pki == nil {
		return diag("tls", "Server certificate", diagnostics.Fail, "self-issued TLS needs the hub PKI manager", "", "restore PKI or configure a valid operator certificate")
	}
	hosts := append([]string{}, s.tlsOpts.Hosts...)
	for _, raw := range []string{cfg.ConsoleURL, cfg.AgentURL} {
		if u, err := url.Parse(raw); err == nil && u.Hostname() != "" {
			hosts = append(hosts, u.Hostname())
		}
	}
	cert, err := s.pki.ServerCertificate(hubSANs(s.hubURL, hosts))
	if err != nil || cert == nil || len(cert.Certificate) == 0 {
		return diag("tls", "Server certificate", diagnostics.Fail, "hub could not issue its self-signed server certificate", "", "preserve the PKI directory and restart the package-owned service")
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return diag("tls", "Server certificate", diagnostics.Fail, "hub-issued server certificate is not parseable", "certificate parse failed", "restore PKI and restart the service")
	}
	return s.tlsCertificateResult(leaf, cfg, "self-issued")
}

func (s *Server) tlsCertificateResult(leaf *x509.Certificate, cfg configuration.Config, mode string) diagnostics.Result {
	if time.Now().After(leaf.NotAfter) {
		return diag("tls", "Server certificate", diagnostics.Fail, "server certificate is expired", leaf.NotAfter.UTC().Format(time.RFC3339), "renew or replace the server certificate")
	}
	if time.Until(leaf.NotAfter) < 30*24*time.Hour {
		return diag("tls", "Server certificate", diagnostics.Warn, "server certificate expires within 30 days", leaf.NotAfter.UTC().Format(time.RFC3339), "renew the ACME certificate or replace the operator certificate before expiry")
	}
	hosts := []string{}
	for _, raw := range []string{cfg.ConsoleURL, cfg.AgentURL} {
		if u, err := url.Parse(raw); err == nil && u.Hostname() != "" {
			hosts = append(hosts, u.Hostname())
		}
	}
	for _, host := range hosts {
		if err := leaf.VerifyHostname(host); err != nil {
			return diag("tls", "Server certificate", diagnostics.Fail, "server certificate does not cover a configured hostname", host, "add the hostname to the certificate SANs and restart the service")
		}
	}
	sum := sha256.Sum256(leaf.Raw)
	return diag("tls", "Server certificate", diagnostics.Pass, mode+" server certificate is valid for configured names", "SHA-256 "+hex.EncodeToString(sum[:8])+"; expires "+leaf.NotAfter.UTC().Format(time.RFC3339), "")
}

// checkNativeTransport performs the proof the wizard is meant to establish:
// a disposable endpoint presents a hub-issued client certificate and its
// unique device credential to the actual TLS listener, receives the normal
// telemetry response, and is then removed. It never uses a production
// endpoint or stores a credential beyond this request.
func (s *Server) checkNativeTransport(ctx context.Context) (result diagnostics.Result) {
	if s.tlsServer == nil || strings.TrimSpace(s.tlsServer.Addr) == "" {
		return diag("native_transport", "Native device transport", diagnostics.NotConfigured,
			"the package TLS listener is not running in this process", "no live TLS listener", "restart the package-owned hub service and run checks again")
	}
	if s.pki == nil {
		return diag("native_transport", "Native device transport", diagnostics.Fail,
			"native transport proof cannot issue a client certificate", "PKI manager unavailable", "restore the preserved PKI directory and restart the hub")
	}
	if strings.EqualFold(string(s.tlsOpts.ClientCerts), string(ClientCertsOff)) {
		return diag("native_transport", "Native device transport", diagnostics.Fail,
			"TLS client certificates are disabled", "client certificate proof is off", "set client certificate proof to optional while migrating, then required after every agent is proven")
	}
	host, port, err := net.SplitHostPort(s.tlsServer.Addr)
	if err != nil {
		return diag("native_transport", "Native device transport", diagnostics.Fail,
			"TLS listener address cannot be parsed", "configured listener address is invalid", "correct the package TLS listen address and restart the service")
	}
	portNumber, err := strconv.Atoi(port)
	if err != nil || portNumber <= 0 || portNumber > 65535 {
		return diag("native_transport", "Native device transport", diagnostics.NotConfigured,
			"TLS listener has no fixed port for a local proof", port, "restart with the package TLS listener on a fixed port")
	}
	dialHost := strings.Trim(host, "[]")
	if dialHost == "" || dialHost == "0.0.0.0" || dialHost == "::" {
		dialHost = "127.0.0.1"
	}
	serverName := dialHost
	if net.ParseIP(serverName) == nil && serverName == "" {
		serverName = "localhost"
	}
	probeID := strings.ReplaceAll(uuid.NewString(), "-", "")
	endpointID := "diagnostic-" + probeID
	// UpsertEndpoint projects every row into the asset graph. Use a locally
	// administered, probe-unique MAC rather than loopback, which could join an
	// existing asset on a production hub and make cleanup unsafe.
	diagnosticMAC := fmt.Sprintf("02:00:%s:%s:%s:%s", probeID[0:2], probeID[2:4], probeID[4:6], probeID[6:8])
	now := time.Now().UTC()
	if err := s.store.UpsertEndpoint(storage.Endpoint{
		ID: endpointID, TenantID: "default", LocationID: "loc-home", Hostname: endpointID,
		OS: "Linux", MAC: diagnosticMAC, RoleTag: "diagnostic", DriverVersion: "diagnostic",
		Status: "offline", CreatedAt: now, LastSeenAt: now,
	}); err != nil {
		return diag("native_transport", "Native device transport", diagnostics.Fail,
			"disposable diagnostic endpoint could not be created", "endpoint store write failed", "restore the SQLite store and rerun diagnostics")
	}
	defer func() {
		if err := s.store.DeleteDisposableEndpoint(endpointID); err != nil && result.State == diagnostics.Pass {
			result = diag("native_transport", "Native device transport", diagnostics.Fail,
				"native transport passed but its disposable identity could not be removed", "diagnostic cleanup failed", "remove only the generated diagnostic endpoint after checking the SQLite store")
		}
	}()
	certBundle, err := s.pki.IssueClientCert(endpointID, "")
	if err != nil {
		return diag("native_transport", "Native device transport", diagnostics.Fail,
			"disposable client certificate could not be issued", "client certificate issuance failed", "restore the preserved PKI directory and rerun diagnostics")
	}
	credential, _, err := s.store.IssueDeviceCredential(endpointID)
	if err != nil {
		return diag("native_transport", "Native device transport", diagnostics.Fail,
			"disposable device credential could not be issued", "device credential issuance failed", "allow the package schema migration to finish and rerun diagnostics")
	}
	clientCert, err := tls.X509KeyPair(certBundle.CertPEM, certBundle.KeyPEM)
	if err != nil {
		return diag("native_transport", "Native device transport", diagnostics.Fail,
			"disposable client certificate could not be loaded", "client certificate key pair failed to load", "restore the preserved PKI directory and rerun diagnostics")
	}
	roots := s.pki.ClientCAPool()
	cfg := s.effectiveConfiguration()
	if !strings.EqualFold(strings.TrimSpace(cfg.TLSMode), "self-issued") && strings.TrimSpace(cfg.TLSMode) != "" {
		roots, err = x509.SystemCertPool()
		if err != nil || roots == nil {
			return diag("native_transport", "Native device transport", diagnostics.Warn,
				"native client proof is ready; the operator certificate trust store could not be loaded", "system certificate pool unavailable", "verify the operator or ACME certificate with the host trust store")
		}
	}
	transport := &http.Transport{TLSClientConfig: &tls.Config{
		MinVersion: tls.VersionTLS12, RootCAs: roots, ServerName: serverName,
		Certificates: []tls.Certificate{clientCert},
	}}
	client := &http.Client{Transport: transport, Timeout: 4 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	body, err := json.Marshal(TelemetryBatchMessage{
		Type: "telemetry", EndpointID: endpointID, TenantID: "default", Hostname: endpointID,
		OS: "Linux", DriverVersion: "diagnostic", Events: []storage.Event{},
	})
	if err != nil {
		return diag("native_transport", "Native device transport", diagnostics.Fail,
			"native diagnostic request could not be encoded", "telemetry body encoding failed", "rerun diagnostics after checking the hub build")
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost,
		"https://"+net.JoinHostPort(dialHost, strconv.Itoa(portNumber))+"/api/v1/events", strings.NewReader(string(body)))
	if err != nil {
		return diag("native_transport", "Native device transport", diagnostics.Fail,
			"native diagnostic request could not be created", "request construction failed", "rerun diagnostics after checking the hub listener")
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set(deviceCredentialHeader, credential)
	response, err := client.Do(request)
	if err != nil {
		return diag("native_transport", "Native device transport", diagnostics.Fail,
			"the live TLS listener rejected the disposable device proof", "TLS or device authentication request failed", "verify the package TLS listener, client certificate mode, and hub-issued device CA")
	}
	defer response.Body.Close()
	responseBody, readErr := io.ReadAll(io.LimitReader(response.Body, 16*1024))
	if readErr != nil || response.StatusCode != http.StatusOK {
		return diag("native_transport", "Native device transport", diagnostics.Fail,
			"the live TLS listener did not accept the disposable device proof", response.Status, "verify matching device credential and client certificate identity")
	}
	var reply struct {
		Status string `json:"status"`
	}
	if err := json.Unmarshal(responseBody, &reply); err != nil || reply.Status != "ok" {
		return diag("native_transport", "Native device transport", diagnostics.Fail,
			"the live TLS listener returned an unexpected telemetry response", response.Status, "rerun diagnostics after checking hub request handling")
	}
	return diag("native_transport", "Native device transport", diagnostics.Pass,
		"a disposable Linux device credential and matching client certificate completed a live TLS heartbeat", "TLS, client certificate, device credential, and telemetry response verified", "")
}

func (s *Server) checkOIDC(ctx context.Context) diagnostics.Result {
	cfg := s.effectiveConfiguration()
	if strings.TrimSpace(cfg.OIDCIssuer) == "" {
		return diag("oidc", "OIDC", diagnostics.NotConfigured, "native OIDC is optional; local recovery remains available", "", "configure an HTTPS issuer, client id, redirect URL, and root-only client secret when desired")
	}
	provider, err := s.oidcSettings(ctx)
	if err != nil {
		return diag("oidc", "OIDC", diagnostics.Fail, "OIDC discovery or configuration failed", safeURL(cfg.OIDCIssuer), "verify HTTPS discovery, client id, redirect URL, and provider reachability")
	}
	lastSuccess, _ := s.store.GetSetting("oidc.last_success")
	if _, err := time.Parse(time.RFC3339, strings.TrimSpace(lastSuccess)); err != nil {
		return diag("oidc", "OIDC", diagnostics.Warn, "OIDC discovery succeeded; no verified operator callback has completed", safeURL(provider.Issuer), "complete one OIDC callback and keep the operator identity listed in Ominull")
	}
	return diag("oidc", "OIDC", diagnostics.Pass, "OIDC discovery and a verified operator callback succeeded", safeURL(provider.Issuer)+"; last success "+strings.TrimSpace(lastSuccess), "")
}

func (s *Server) checkCloudflare(ctx context.Context) diagnostics.Result {
	cfg := s.effectiveConfiguration()
	adapter, _ := s.store.GetSetting("cloudflare.adapter")
	if !cfg.Cloudflare && strings.TrimSpace(adapter) == "" {
		return diag("cloudflare", "Cloudflare adapter", diagnostics.NotConfigured, "direct native access is active; Cloudflare remains optional", "", "select Cloudflare mode only when a free-tier Tunnel and separate agent route are prepared")
	}
	if strings.TrimSpace(cfg.AccessTeam) == "" || strings.TrimSpace(cfg.AccessAudience) == "" || s.access == nil {
		return diag("cloudflare", "Cloudflare adapter", diagnostics.Fail, "Cloudflare mode lacks a configured signed Access console verifier", "team, audience, or live verifier missing", "configure the Access team and application audience, restart the hub, and keep the agent hostname separate")
	}
	if cfg.AgentURL == "" {
		return diag("cloudflare", "Cloudflare adapter", diagnostics.Fail, "Cloudflare mode has no separate agent URL", "", "configure an agent hostname without an interactive Access redirect")
	}
	probe := publicJSONProbe(ctx, cfg.AgentURL+"/api/v1/events")
	if probe.err != nil {
		return diag("cloudflare", "Cloudflare adapter", diagnostics.Warn, "Cloudflare Access verifier is configured; agent route probe was inconclusive", probe.err.Error(), "verify the separate Tunnel agent route from outside the hub network")
	}
	if probe.redirect {
		return diag("cloudflare", "Cloudflare adapter", diagnostics.Fail, "agent hostname redirects an unauthenticated machine to interactive Access", probe.status, "exclude the agent hostname from browser Access redirects; it must return bounded Ominull JSON")
	}
	if probe.jsonRefusal {
		return diag("cloudflare", "Cloudflare adapter", diagnostics.Pass, "Cloudflare console verifier is active and the unauthenticated agent route returns bounded JSON", probe.status, "")
	}
	return diag("cloudflare", "Cloudflare adapter", diagnostics.Warn, "Cloudflare route answered but not with the expected unauthenticated JSON refusal", probe.status, "check Tunnel origin routing and keep interactive Access redirects off the agent hostname")
}

type publicProbe struct {
	status      string
	err         error
	redirect    bool
	jsonRefusal bool
}

func publicJSONProbe(ctx context.Context, rawURL string) publicProbe {
	u, err := url.Parse(rawURL)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil {
		return publicProbe{err: errors.New("agent URL is not a valid HTTPS URL")}
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return publicProbe{err: err}
	}
	client := &http.Client{Timeout: 3 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	response, err := client.Do(request)
	if err != nil {
		return publicProbe{err: err}
	}
	defer response.Body.Close()
	body, readErr := io.ReadAll(io.LimitReader(response.Body, 4096))
	result := publicProbe{status: response.Status, redirect: response.StatusCode >= 300 && response.StatusCode < 400}
	if readErr != nil {
		result.err = readErr
		return result
	}
	result.jsonRefusal = response.StatusCode >= 400 && response.StatusCode < 500 && strings.Contains(strings.ToLower(response.Header.Get("Content-Type")), "json") && json.Valid(body)
	return result
}

func (s *Server) checkBootstrap(ctx context.Context) diagnostics.Result {
	cfg := s.effectiveConfiguration()
	if cfg.ConsoleURL == "" {
		return diag("bootstrap", "Public install surface", diagnostics.NotConfigured, "console URL is not configured", "", "save a console URL in setup")
	}
	probe := publicScriptProbe(ctx, strings.TrimRight(cfg.ConsoleURL, "/")+"/bootstrap.sh")
	if probe.err != nil {
		return diag("bootstrap", "Public install surface", diagnostics.Warn, "bootstrap route could not be checked from the hub", probe.err.Error(), "check the console route from the operator network; split-horizon or NAT hairpin can make this inconclusive")
	}
	if probe.redirect || probe.html {
		return diag("bootstrap", "Public install surface", diagnostics.Fail, "bootstrap route returned a redirect or HTML page instead of an installer", probe.status, "exclude bootstrap and download routes from interactive login redirects")
	}
	if !probe.installer {
		return diag("bootstrap", "Public install surface", diagnostics.Fail, "bootstrap route did not contain the body-only enrollment flow", probe.status, "serve the current signed native bootstrap script")
	}
	return diag("bootstrap", "Public install surface", diagnostics.Pass, "public bootstrap route serves the retained Linux installer flow", probe.status, "")
}

type scriptProbe struct {
	status    string
	err       error
	redirect  bool
	html      bool
	installer bool
}

func publicScriptProbe(ctx context.Context, rawURL string) scriptProbe {
	u, err := url.Parse(rawURL)
	if err != nil || u.Scheme == "" || u.Host == "" || u.User != nil {
		return scriptProbe{err: errors.New("console URL is not a valid absolute URL")}
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return scriptProbe{err: err}
	}
	client := &http.Client{Timeout: 3 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	response, err := client.Do(request)
	if err != nil {
		return scriptProbe{err: err}
	}
	defer response.Body.Close()
	body, readErr := io.ReadAll(io.LimitReader(response.Body, 128*1024))
	if readErr != nil {
		return scriptProbe{err: readErr}
	}
	text := string(body)
	return scriptProbe{
		status: response.Status, redirect: response.StatusCode >= 300 && response.StatusCode < 400,
		html:      strings.Contains(strings.ToLower(response.Header.Get("Content-Type")), "html") || strings.HasPrefix(strings.TrimSpace(text), "<!doctype html"),
		installer: response.StatusCode == http.StatusOK && strings.Contains(text, "/api/v1/enrollment/redeem"),
	}
}

func (s *Server) checkHeartbeats(context.Context) diagnostics.Result {
	endpoints, err := s.store.ListEndpoints("")
	if err != nil {
		return diag("heartbeats", "Agent proof", diagnostics.Fail, "endpoint inventory could not be read", "", "restore the SQLite database and restart the service")
	}
	online := 0
	issues := 0
	for _, endpoint := range endpoints {
		// checkNativeTransport creates a short-lived endpoint in this same
		// diagnostic run. It is intentionally not a fleet member and has no
		// package receipt, so counting it here would turn a successful mTLS
		// probe into a false provenance failure when the checks overlap.
		if endpoint.Status == "retired" || strings.HasPrefix(endpoint.ID, "diagnostic-") {
			continue
		}
		if time.Since(endpoint.LastSeenAt) < 30*time.Second {
			online++
			if reason := provenanceIssue(endpoint, s.agentVersion); reason != "" {
				issues++
			}
		}
	}
	if online == 0 {
		return diag("heartbeats", "Agent proof", diagnostics.Fail, "no Linux or Windows agent has completed a current heartbeat", "0 online", "install a retained native package from /install and redeem a one-use enrollment code")
	}
	if issues > 0 {
		return diag("heartbeats", "Agent proof", diagnostics.Fail, fmt.Sprintf("%d current agent(s) lack native package provenance", issues), fmt.Sprintf("%d online", online), "finish native package update and wait for a heartbeat with matching package provenance")
	}
	return diag("heartbeats", "Agent proof", diagnostics.Pass, fmt.Sprintf("%d Linux/Windows agent(s) online with native package provenance", online), fmt.Sprintf("%d online", online), "")
}

func (s *Server) checkBackups(context.Context) diagnostics.Result {
	path := "/var/lib/ominull/backups"
	if s.setupDBPath != "" {
		path = filepath.Join(filepath.Dir(s.setupDBPath), "backups")
	}
	info, err := os.Stat(path)
	if errors.Is(err, os.ErrNotExist) {
		return diag("backups", "Backup path", diagnostics.NotConfigured, "no backup directory is configured", "", "configure an operator-managed backup job when durable recovery copies are required")
	}
	if err != nil || !info.IsDir() {
		return diag("backups", "Backup path", diagnostics.Warn, "configured backup path is not readable", filepath.Base(path), "restore the package-owned backup directory or correct its permissions")
	}
	return diag("backups", "Backup path", diagnostics.Pass, "package backup directory is present", filepath.Base(path), "")
}
