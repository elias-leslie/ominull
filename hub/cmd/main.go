package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"ominull/hub/pkg/configuration"
	"ominull/hub/pkg/dns"
	"ominull/hub/pkg/server"
	"ominull/hub/pkg/setup"
	"ominull/hub/pkg/storage"
)

const banner = `
   ____  __  __ ___ _   _ _   _ _     _     
  / __ \|  \/  |_ _| \ | | | | | |   | |    
 | |  | | |\/| || ||  \| | | | | |   | |    
 | |  | | |  | || || |\  | |_| | |___| |___ 
  \____/|_|  |_|___|_| \_|\___/|_____|_____|
  Ominull Fleet Management Hub
`

// defaultAgentVersion is the agent release bundled with this hub build. It must track
// VERSION in scripts/build-packages.sh so endpoints are only offered packages that the
// hub can actually serve from its download directory.
const (
	defaultAgentVersion = "1.8.3"
	defaultDNSListen    = "disabled"
)

func main() {
	configPath := findConfigArg(os.Args[1:])
	if configPath != "" {
		if err := loadConfigEnv(configPath); err != nil {
			log.Fatalf("[-] --config %s: %v", configPath, err)
		}
	}
	listenAddr := flag.String("listen", envOr("OMINULL_LISTEN", ":9999"), "HTTP listen address")
	dbPath := flag.String("db", envOr("OMINULL_DB", "ominull.db"), "Path to SQLite database file")
	adminKey := flag.String("admin-key", envOr("OMINULL_ADMIN_KEY", ""), "Master Admin API Key. Prefer --admin-key-file: every argument of every process is readable by every local account.")
	adminKeyFile := flag.String("admin-key-file", envOr("OMINULL_ADMIN_KEY_FILE", ""), "File whose first line is the admin API key (mode 0600). Preferred over --admin-key, which puts the credential in /proc/<pid>/cmdline and in systemctl show output.")
	binaryDir := flag.String("binary-dir", envOr("OMINULL_BINARY_DIR", "./build"), "Path to directory containing signed package artifacts")
	hubURL := flag.String("hub-url", envOr("OMINULL_HUB_URL", ""), "Public Hub URL for bootstrap scripts (e.g. https://hub.example.invalid)")
	agentHubURL := flag.String("agent-hub-url", envOr("OMINULL_AGENT_HUB_URL", ""), "TLS URL enrolled agents report to; defaults to --hub-url")
	agentVersion := flag.String("agent-version", envOr("OMINULL_AGENT_VERSION", defaultAgentVersion), "Agent version bundled with this hub build (offered to outdated endpoints)")
	tlsListen := flag.String("tls-listen", envOr("OMINULL_TLS_LISTEN", ":9443"), "HTTPS listen address for agent traffic (empty disables TLS)")
	tlsCert := flag.String("tls-cert", envOr("OMINULL_TLS_CERT", ""), "PEM certificate for the HTTPS listener (default: issued by the hub's own CA)")
	tlsKey := flag.String("tls-key", envOr("OMINULL_TLS_KEY", ""), "PEM private key for --tls-cert")
	tlsHosts := flag.String("tls-hosts", envOr("OMINULL_TLS_HOSTS", ""), "Comma-separated extra SANs for the self-issued certificate")
	consoleTLSListen := flag.String("console-tls-listen", envOr("OMINULL_CONSOLE_TLS_LISTEN", ""), "Dedicated HTTPS listen address for operator console (e.g. :8443)")
	consoleTLSCert := flag.String("console-tls-cert", envOr("OMINULL_CONSOLE_TLS_CERT", ""), "PEM certificate for the console HTTPS listener")
	consoleTLSKey := flag.String("console-tls-key", envOr("OMINULL_CONSOLE_TLS_KEY", ""), "PEM private key for --console-tls-cert")
	consoleHostname := flag.String("console-hostname", envOr("OMINULL_CONSOLE_HOSTNAME", ""), "Canonical DNS hostname for the operator console (required for WebAuthn RP ID)")
	retentionDays := flag.Int("retention-days", envInt("OMINULL_RETENTION_DAYS", 14), "Days of raw flow telemetry to keep (0 disables pruning)")
	commRetentionDays := flag.Int("comm-retention-days", envInt("OMINULL_COMM_RETENTION_DAYS", 14), "Days of aggregated communication profiles to keep (0 disables pruning)")
	alertRetentionDays := flag.Int("alert-retention-days", envInt("OMINULL_ALERT_RETENTION_DAYS", 30), "Days of alerts to keep (0 disables pruning)")
	auditRetentionDays := flag.Int("audit-retention-days", envInt("OMINULL_AUDIT_RETENTION_DAYS", 365), "Days of audit log to keep (0 disables pruning)")
	accessTeam := flag.String("access-team", envOr("OMINULL_ACCESS_TEAM", ""), "Cloudflare Access team name")
	accessAUD := flag.String("access-aud", envOr("OMINULL_ACCESS_AUD", ""), "Cloudflare Access application audience")
	accessAdmin := flag.String("access-bootstrap-admin", envOr("OMINULL_ACCESS_BOOTSTRAP_ADMIN", ""), "Email guaranteed to hold the admin role at startup")
	clientCerts := flag.String("client-certs", envOr("OMINULL_CLIENT_CERTS", "optional"), "Agent client-certificate mode: off, optional, or required")
	dnsListen := flag.String("dns-listen", envOr("OMINULL_DNS_LISTEN", defaultDNSListen), "DNS forwarder and threat sinkhole listen address (disabled by default; for example :53)")
	dhcpSnoop := flag.Bool("dhcp-snoop", envBool("OMINULL_DHCP_SNOOP", false), "Passively observe DHCP broadcasts on UDP/67 (disabled by default)")
	setupTokenFile := flag.String("setup-token-file", envOr("OMINULL_SETUP_TOKEN_FILE", "/var/lib/ominull/setup.token"), "Root-only first-run setup token file")
	enableResponse := flag.Bool("enable-unreleased-response", envBool("OMINULL_ENABLE_UNRELEASED_RESPONSE", false), "Enable unreleased response, evidence, terminal, script, and vulnerability routes (disabled by default)")
	flag.String("config", configPath, "Package-owned hub environment file")
	flag.Parse()

	resolvedAgentVersion := *agentVersion
	if env := os.Getenv("OMINULL_AGENT_VERSION"); env != "" && *agentVersion == defaultAgentVersion {
		resolvedAgentVersion = env
	}

	fmt.Print(banner)
	log.Printf("[*] Initializing Ominull Multi-Tenant Storage: %s", *dbPath)

	absBinDir, err := filepath.Abs(*binaryDir)
	if err != nil {
		absBinDir = *binaryDir
	}

	store, err := storage.New(*dbPath)
	if err != nil {
		log.Fatalf("[-] Failed to open database: %v", err)
	}
	defer store.Close()

	// The hub holds itself to the same rule its agents do: a credential is
	// never an argument. --admin-key still works, because a deployment that
	// uses it must keep working across an upgrade, but it warns, and every
	// generated unit names a file instead.
	resolvedAdminKey := *adminKey
	if *adminKeyFile != "" {
		key, err := readKeyFile(*adminKeyFile)
		if err != nil {
			log.Fatalf("[-] --admin-key-file %s: %v", *adminKeyFile, err)
		}
		if resolvedAdminKey != "" && resolvedAdminKey != key {
			log.Printf("[!] Both --admin-key and --admin-key-file were given and they differ. The file wins.")
		}
		resolvedAdminKey = key
	} else if resolvedAdminKey != "" {
		log.Printf("[!] The admin key was passed as --admin-key, so it is in this process's command line: readable by any local account through /proc/%d/cmdline and printed by systemctl show. Move it to a 0600 file and pass --admin-key-file.", os.Getpid())
	}
	if resolvedAdminKey == "" {
		log.Fatalf("[-] no admin key configured; install the package-owned admin.key or set --admin-key-file")
	}
	// A fingerprint, not the key. This line used to print the admin credential
	// in full on every start, into a journal that is readable by more accounts
	// than the key is - and into any log shipper pointed at it. The digest is
	// enough to tell one key from another across a rotation, which is the only
	// thing an operator reads it for.
	log.Printf("[+] Admin API key active: %s (fingerprint, not the key)", server.KeyFingerprint(resolvedAdminKey))
	if err := setup.Ensure(*setupTokenFile); err != nil {
		log.Fatalf("[-] setup token: %v", err)
	}
	if setupState, err := store.GetSetting("setup.complete"); err == nil && strings.TrimSpace(setupState) == "" {
		if endpoints, endpointErr := store.ListEndpoints(""); endpointErr == nil && len(endpoints) > 0 {
			// Existing production data is already configured. Upgrades must not
			// reopen first-run setup or replace its identity model in place.
			_ = store.SetSetting("setup.complete", "true")
			_ = store.SetSetting("legacy_agent_auth", "migration")
		}
	}
	// Older package installs kept their non-secret setup in hub.env flags. On
	// the first start after this package is installed, project those flags into
	// the wizard's durable configuration so recovery shows the real deployment
	// instead of an empty form. Never replace a configuration the wizard has
	// already saved, and never copy a credential into the database.
	if raw, configErr := store.GetSetting("setup.configuration"); configErr == nil && strings.TrimSpace(raw) == "" {
		mode := envOr("OMINULL_NETWORK_MODE", "lan")
		agentURL := strings.TrimRight(strings.TrimSpace(*agentHubURL), "/")
		consoleURL := strings.TrimRight(strings.TrimSpace(*hubURL), "/")
		if agentURL == "" {
			agentURL = consoleURL
		}
		tlsMode := envOr("OMINULL_TLS_MODE", "")
		if tlsMode == "" {
			tlsMode = "self-issued"
			if strings.TrimSpace(*tlsCert) != "" || strings.TrimSpace(*tlsKey) != "" {
				tlsMode = "custom"
			}
		}
		legacyConfig := configuration.Config{
			NetworkMode: mode, ConsoleURL: consoleURL, AgentURL: agentURL,
			TLSMode: tlsMode, TLSCertFile: *tlsCert, TLSKeyFile: *tlsKey,
			TLSHosts: splitList(*tlsHosts), ClientCerts: *clientCerts,
			AccessTeam: *accessTeam, AccessAudience: *accessAUD,
			Cloudflare: strings.EqualFold(strings.TrimSpace(mode), "cloudflare"),
		}.Normalized()
		if legacyConfig.ConsoleURL != "" || legacyConfig.AgentURL != "" {
			if err := legacyConfig.Validate(); err != nil {
				log.Printf("[!] Existing hub.env was not copied into setup state because it needs operator review: %v", err)
			} else if encoded, err := json.Marshal(legacyConfig); err != nil {
				log.Printf("[!] Existing hub.env setup state could not be encoded: %v", err)
			} else if err := store.SetSetting("setup.configuration", string(encoded)); err != nil {
				log.Printf("[!] Existing hub.env setup state could not be saved: %v", err)
			}
		}
	}

	clientCertMode, err := server.ParseClientCertMode(*clientCerts)
	if err != nil {
		log.Fatalf("[-] %v", err)
	}

	// Retention runs from here rather than inside the server so it is tied to
	// the store's lifetime, and it prunes once immediately: a hub that has been
	// running without it has the whole backlog to clear, and the disk it is
	// filling does not necessarily have another hour in it.
	retention := storage.RetentionPolicy{
		Events:        time.Duration(*retentionDays) * 24 * time.Hour,
		CommProfiles:  time.Duration(*commRetentionDays) * 24 * time.Hour,
		AnomalyAlerts: time.Duration(*alertRetentionDays) * 24 * time.Hour,
		Alerts:        time.Duration(*alertRetentionDays) * 24 * time.Hour,
		AuditLogs:     time.Duration(*auditRetentionDays) * 24 * time.Hour,
	}
	stopRetention := store.StartRetention(retention, time.Hour)
	defer stopRetention()
	log.Printf("[+] Retention: telemetry %dd, communication profiles %dd, alerts %dd, audit %dd (0 = keep everything)",
		*retentionDays, *commRetentionDays, *alertRetentionDays, *auditRetentionDays)

	srv := server.New(store, resolvedAdminKey, absBinDir, *hubURL, resolvedAgentVersion)
	srv.SetTLS(server.TLSOptions{
		Listen:      *tlsListen,
		CertFile:    *tlsCert,
		KeyFile:     *tlsKey,
		Hosts:       splitList(*tlsHosts),
		ClientCerts: clientCertMode,
	})
	if *consoleTLSListen != "" {
		srv.SetConsoleTLS(server.ConsoleTLSOptions{
			Listen:   *consoleTLSListen,
			CertFile: *consoleTLSCert,
			KeyFile:  *consoleTLSKey,
			Hostname: *consoleHostname,
			Hosts:    splitList(*tlsHosts),
		})
	}
	srv.SetAgentHubURL(*agentHubURL)
	srv.SetSetupPaths(*setupTokenFile, configPath, *dbPath, *adminKeyFile, absBinDir)
	srv.SetResponseEnabled(*enableResponse)
	if err := srv.SetAccess(server.AccessOptions{
		Team:           *accessTeam,
		AUD:            *accessAUD,
		BootstrapAdmin: *accessAdmin,
	}); err != nil {
		log.Fatalf("[-] Cloudflare Access: %v", err)
	}
	if *dhcpSnoop {
		if err := srv.StartDHCPSnooping(); err != nil {
			log.Printf("[!] Warning: passive DHCP snooping could not start: %v", err)
		} else {
			log.Printf("[+] Passive DHCP snooping active on UDP/67 (explicitly enabled)")
		}
	} else {
		log.Printf("[*] Passive DHCP snooping disabled (enable explicitly with --dhcp-snoop)")
	}
	go func() {
		if err := srv.Start(*listenAddr); err != nil && err != os.ErrClosed {
			log.Fatalf("[-] Hub server error: %v", err)
		}
	}()

	if *dnsListen != "" && *dnsListen != "off" && *dnsListen != "disabled" {
		dnsServer := dns.NewServer(*dnsListen, []string{"1.1.1.1:53", "8.8.8.8:53", "9.9.9.9:53"}, store, srv.ThreatIntel())
		srv.SetDNSServer(dnsServer)
		if err := dnsServer.Start(); err != nil {
			log.Printf("[!] Warning: DNS Forwarder could not bind to %s: %v (skipping port 53 listener)", *dnsListen, err)
		} else {
			defer dnsServer.Stop()
		}
	}

	// --listen may be ":9999" or "127.0.0.1:9999". Pasting "localhost" in front
	// of the second form printed "http://localhost127.0.0.1:9999", a URL nobody
	// can paste anywhere.
	consoleHost := *listenAddr
	if strings.HasPrefix(consoleHost, ":") {
		consoleHost = "localhost" + consoleHost
	}
	if srv.AccessConfigured() {
		admins, err := store.CountAdmins()
		if err != nil {
			log.Fatalf("[-] Counting administrators: %v", err)
		}
		if admins == 0 {
			log.Printf("[!] Cloudflare Access is configured but no operator holds the admin role, so nobody can sign in through it and nobody can grant it from the console. Restart once with --access-bootstrap-admin <your email>.")
		}
		log.Printf("[+] Console sign-in:          Cloudflare Access identity, checked against the operator list (%d administrator(s)), plus the admin key for direct access", admins)
	} else {
		log.Printf("[*] Console sign-in:          admin key only. Behind Cloudflare Access, set --access-team, --access-aud and --access-bootstrap-admin so an operator does not have to type a fleet-wide credential into a browser.")
	}
	log.Printf("[+] Bundled agent release:      v%s (endpoints below this are offered an update)", resolvedAgentVersion)
	log.Printf("[+] Bootstrap script endpoint: http://%s/bootstrap.ps1", consoleHost)
	// The agent URL is what every install command uses for bootstrap, package
	// download, and enrollment; --hub-url remains the compatibility fallback.
	// A value that does not serve this hub produces a command that
	// pipes someone else's error page into a shell, and the operator sees a
	// shell syntax error with nothing pointing at the URL. Checked once here,
	// in the background so a slow or dead public URL cannot delay startup.
	installURL := strings.TrimRight(strings.TrimSpace(*agentHubURL), "/")
	if installURL == "" {
		installURL = strings.TrimRight(strings.TrimSpace(*hubURL), "/")
	}
	if installURL != "" {
		go func(u string) {
			// After the listener is up: when the URL points back at this
			// process, probing sooner races Start and refuses itself.
			time.Sleep(2 * time.Second)
			if srv.PublicURLServesHub() {
				log.Printf("[+] HTTPS agent URL for installs: %s (verified: it answers as this hub)", u)
				return
			}
			log.Printf("[!] Agent URL %s does not answer as this hub does. Install commands are still built from it because split-horizon DNS or NAT hairpin can make a valid address unreachable from the hub. Verify /bootstrap.*, /download/, and /api/v1/enrollment/redeem from an endpoint network; the agent hostname must not return an interactive login page.", u)
		}(installURL)
	}
	log.Printf("[+] Multi-Tenant REST API:    http://%s/api/v1/", consoleHost)
	if *tlsListen != "" {
		agentTarget := *agentHubURL
		if agentTarget == "" {
			agentTarget = *hubURL
		}
		log.Printf("[+] Agent TLS transport:      %s (enrolment writes %q into agent config)", *tlsListen, agentTarget)
		switch clientCertMode {
		case server.ClientCertsRequired:
			log.Printf("[+] Agent authentication:     client certificate required, verified against the hub CA")
		case server.ClientCertsOff:
			log.Printf("[!] Agent authentication:     unique device credential only; direct native mTLS is not an additional proof. Move to --client-certs optional to add certificate proof.")
		default:
			log.Printf("[*] Agent authentication:     unique device credential, with client certificate verified when offered. Set --client-certs required once every endpoint presents one.")
		}
		if agentTarget == "" || !strings.HasPrefix(agentTarget, "https://") {
			log.Printf("[!] Agents are being enrolled against %q, which is not an https:// URL. Telemetry and the API key will cross the network in the clear; set --agent-hub-url to this hub's TLS address.", agentTarget)
		}
	} else {
		log.Printf("[!] TLS listener disabled (--tls-listen is empty): all agent traffic to this hub is in the clear.")
	}
	if *consoleTLSListen != "" {
		log.Printf("[+] Console TLS transport:    %s (dedicated browser listener, HSTS enabled, no client-cert requirement)", *consoleTLSListen)
	}

	// Graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	log.Println("\n[*] Shutting down Ominull Hub gracefully...")
	srv.Close()
}

func findConfigArg(args []string) string {
	for i, arg := range args {
		if arg == "--config" && i+1 < len(args) {
			return args[i+1]
		}
		if strings.HasPrefix(arg, "--config=") {
			return strings.TrimPrefix(arg, "--config=")
		}
	}
	return ""
}

// loadConfigEnv reads the package-owned EnvironmentFile format before flags
// are declared, so a service started only with --config has the same behavior
// as an interactive invocation with explicit flags. It accepts namespaced
// OMINULL_* variables only; shell syntax and command substitution are not
// evaluated.
func loadConfigEnv(path string) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok || !strings.HasPrefix(key, "OMINULL_") {
			continue
		}
		os.Setenv(key, strings.TrimSpace(value))
	}
	return nil
}

func envOr(name, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(name)); value != "" {
		return value
	}
	return fallback
}

func envInt(name string, fallback int) int {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return fallback
	}
	parsed, err := strconv.Atoi(value)
	if err != nil {
		log.Printf("[!] Ignoring invalid %s value; using %d.", name, fallback)
		return fallback
	}
	return parsed
}

func envBool(name string, fallback bool) bool {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return fallback
	}
	parsed, err := strconv.ParseBool(value)
	if err != nil {
		log.Printf("[!] Ignoring invalid %s value; using %t.", name, fallback)
		return fallback
	}
	return parsed
}

// readKeyFile takes the first line of a file as a credential, and refuses a file
// any other account can read: a key file that is world-readable is no better
// than the command line it replaced.
func readKeyFile(path string) (string, error) {
	info, err := os.Stat(path)
	if err != nil {
		return "", err
	}
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		return "", fmt.Errorf("mode is %04o; a credential file must not be readable by group or other (chmod 600 %s)", perm, path)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	key := strings.TrimSpace(strings.SplitN(string(raw), "\n", 2)[0])
	if key == "" {
		return "", fmt.Errorf("file is empty")
	}
	return key, nil
}

// splitList turns a comma-separated flag value into a trimmed, non-empty slice.
func splitList(v string) []string {
	var out []string
	for _, part := range strings.Split(v, ",") {
		if part = strings.TrimSpace(part); part != "" {
			out = append(out, part)
		}
	}
	return out
}
