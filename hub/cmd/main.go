package main

import (
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

	"ominull/hub/pkg/server"
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
const defaultAgentVersion = "1.7.20"

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
	retentionDays := flag.Int("retention-days", envInt("OMINULL_RETENTION_DAYS", 14), "Days of raw flow telemetry to keep (0 disables pruning)")
	commRetentionDays := flag.Int("comm-retention-days", envInt("OMINULL_COMM_RETENTION_DAYS", 14), "Days of aggregated communication profiles to keep (0 disables pruning)")
	alertRetentionDays := flag.Int("alert-retention-days", envInt("OMINULL_ALERT_RETENTION_DAYS", 30), "Days of alerts to keep (0 disables pruning)")
	auditRetentionDays := flag.Int("audit-retention-days", envInt("OMINULL_AUDIT_RETENTION_DAYS", 365), "Days of audit log to keep (0 disables pruning)")
	accessTeam := flag.String("access-team", envOr("OMINULL_ACCESS_TEAM", ""), "Cloudflare Access team name")
	accessAUD := flag.String("access-aud", envOr("OMINULL_ACCESS_AUD", ""), "Cloudflare Access application audience")
	accessAdmin := flag.String("access-bootstrap-admin", envOr("OMINULL_ACCESS_BOOTSTRAP_ADMIN", ""), "Email guaranteed to hold the admin role at startup")
	clientCerts := flag.String("client-certs", envOr("OMINULL_CLIENT_CERTS", "optional"), "Agent client-certificate mode: off, optional, or required")
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
	adoptedTenantKey := false
	if resolvedAdminKey == "" {
		if t, err := store.GetTenant("default"); err == nil && t != nil {
			resolvedAdminKey = t.APIKey
			adoptedTenantKey = true
		}
	}
	if resolvedAdminKey == "" {
		resolvedAdminKey = os.Getenv("OMINULL_ADMIN_KEY")
		adoptedTenantKey = false
	}
	// A fingerprint, not the key. This line used to print the admin credential
	// in full on every start, into a journal that is readable by more accounts
	// than the key is - and into any log shipper pointed at it. The digest is
	// enough to tell one key from another across a rotation, which is the only
	// thing an operator reads it for.
	log.Printf("[+] Admin API key active: %s (fingerprint, not the key)", server.KeyFingerprint(resolvedAdminKey))
	if adoptedTenantKey {
		log.Printf("[!] No --admin-key was given, so the default tenant's API key is being used as the admin key. Agents are enrolled with the tenant key, so on this hub every endpoint holds an admin credential. Pass a distinct --admin-key.")
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
	srv.SetAgentHubURL(*agentHubURL)
	if err := srv.SetAccess(server.AccessOptions{
		Team:           *accessTeam,
		AUD:            *accessAUD,
		BootstrapAdmin: *accessAdmin,
	}); err != nil {
		log.Fatalf("[-] Cloudflare Access: %v", err)
	}
	go func() {
		if err := srv.Start(*listenAddr); err != nil && err != os.ErrClosed {
			log.Fatalf("[-] Hub server error: %v", err)
		}
	}()

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
	// --hub-url is what every install link an operator pastes onto a host is
	// built from. A value that does not serve this hub produces a command that
	// pipes someone else's error page into a shell, and the operator sees a
	// shell syntax error with nothing pointing at the URL. Checked once here,
	// in the background so a slow or dead public URL cannot delay startup.
	if *hubURL != "" {
		go func(u string) {
			// After the listener is up: when --hub-url points back at this
			// process, probing sooner races Start and refuses itself.
			time.Sleep(2 * time.Second)
			if srv.PublicURLServesHub() {
				log.Printf("[+] Public URL for install links: %s (verified: it answers as this hub)", u)
				return
			}
			log.Printf("[!] Public URL %s does not answer as this hub does. Install links are still built from it, because a hub often cannot reach its own public address (split-horizon DNS, hairpin NAT) and that is harmless - but if a CDN or identity proxy is in front of it, it will hand installers a sign-in page instead of the script and the one-line command will pipe HTML into a shell. The console shows this warning beside any link it mints, with an alternate. Exempt /bootstrap.* and /download/ at the proxy, or correct --hub-url.", u)
		}(*hubURL)
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
			log.Printf("[!] Agent authentication:     tenant API key only. No certificate is asked for, so any agent holding the key can report as any endpoint. Move to --client-certs optional once the fleet can answer the request.")
		default:
			log.Printf("[*] Agent authentication:     client certificate verified when offered, API key otherwise. Set --client-certs required once every endpoint presents one.")
		}
		if agentTarget == "" || !strings.HasPrefix(agentTarget, "https://") {
			log.Printf("[!] Agents are being enrolled against %q, which is not an https:// URL. Telemetry and the API key will cross the network in the clear; set --agent-hub-url to this hub's TLS address.", agentTarget)
		}
	} else {
		log.Printf("[!] TLS listener disabled (--tls-listen is empty): all agent traffic to this hub is in the clear.")
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
