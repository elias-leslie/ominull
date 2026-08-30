package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
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
  Universal Kernel Threat Nullification Hub
`

// defaultAgentVersion is the agent release bundled with this hub build. It must track
// VERSION in scripts/build-packages.sh so endpoints are only offered packages that the
// hub can actually serve from its download directory.
const defaultAgentVersion = "1.7.7"

func main() {
	listenAddr := flag.String("listen", ":9999", "HTTP/WebSocket listen address")
	dbPath := flag.String("db", "ominull.db", "Path to SQLite database file")
	adminKey := flag.String("admin-key", "", "Master Admin API Key. Prefer --admin-key-file: every argument of every process is readable by every local account.")
	adminKeyFile := flag.String("admin-key-file", "", "File whose first line is the admin API key (mode 0600). Preferred over --admin-key, which puts the credential in /proc/<pid>/cmdline and in systemctl show output.")
	binaryDir := flag.String("binary-dir", "./build", "Path to directory containing driver and agent binaries")
	hubURL := flag.String("hub-url", "", "Public Hub URL for bootstrap scripts (e.g. https://omi.example.com)")
	agentHubURL := flag.String("agent-hub-url", "", "TLS URL enrolled agents report to (e.g. https://10.0.0.58:9443); defaults to --hub-url")
	agentVersion := flag.String("agent-version", defaultAgentVersion, "Agent version bundled with this hub build (offered to outdated endpoints)")
	tlsListen := flag.String("tls-listen", ":9443", "HTTPS listen address for agent traffic (empty disables TLS)")
	tlsCert := flag.String("tls-cert", "", "PEM certificate for the HTTPS listener (default: issued by the hub's own CA)")
	tlsKey := flag.String("tls-key", "", "PEM private key for --tls-cert")
	tlsHosts := flag.String("tls-hosts", "", "Comma-separated extra SANs for the self-issued certificate (e.g. a VIP the hub cannot see)")
	retentionDays := flag.Int("retention-days", 14, "Days of raw flow telemetry to keep (0 disables pruning). Nothing pruned it before, and the file only ever grew.")
	alertRetentionDays := flag.Int("alert-retention-days", 30, "Days of anomaly alerts and alerts to keep (0 disables pruning).")
	auditRetentionDays := flag.Int("audit-retention-days", 365, "Days of audit log to keep (0 disables pruning). Kept far longer than telemetry: it is small, and it is the record of who did what.")
	clientCerts := flag.String("client-certs", "optional", "How agents identify themselves: off (never asked - no endpoint can be told from another holding the same tenant key), optional (verified when presented, endpoints without one still report), required (refused at the handshake without one; only once every endpoint has one).")
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
		AnomalyAlerts: time.Duration(*alertRetentionDays) * 24 * time.Hour,
		Alerts:        time.Duration(*alertRetentionDays) * 24 * time.Hour,
		AuditLogs:     time.Duration(*auditRetentionDays) * 24 * time.Hour,
	}
	stopRetention := store.StartRetention(retention, time.Hour)
	defer stopRetention()
	log.Printf("[+] Retention: telemetry %dd, alerts %dd, audit %dd (0 = keep everything)",
		*retentionDays, *alertRetentionDays, *auditRetentionDays)

	srv := server.New(store, resolvedAdminKey, absBinDir, *hubURL, resolvedAgentVersion)
	srv.SetTLS(server.TLSOptions{
		Listen:      *tlsListen,
		CertFile:    *tlsCert,
		KeyFile:     *tlsKey,
		Hosts:       splitList(*tlsHosts),
		ClientCerts: clientCertMode,
	})
	srv.SetAgentHubURL(*agentHubURL)
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
	log.Printf("[+] Bundled agent release:      v%s (endpoints below this are offered an update)", resolvedAgentVersion)
	log.Printf("[+] Bootstrap script endpoint: http://%s/bootstrap.ps1", consoleHost)
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
