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
const defaultAgentVersion = "1.4.1"

func main() {
	listenAddr := flag.String("listen", ":9999", "HTTP/WebSocket listen address")
	dbPath := flag.String("db", "ominull.db", "Path to SQLite database file")
	adminKey := flag.String("admin-key", "", "Master Admin API Key (defaults to auto-generated key in DB)")
	binaryDir := flag.String("binary-dir", "./build", "Path to directory containing driver and agent binaries")
	hubURL := flag.String("hub-url", "", "Public Hub URL for bootstrap scripts (e.g. https://omi.example.com)")
	agentHubURL := flag.String("agent-hub-url", "", "TLS URL enrolled agents report to (e.g. https://10.0.0.58:9443); defaults to --hub-url")
	agentVersion := flag.String("agent-version", defaultAgentVersion, "Agent version bundled with this hub build (offered to outdated endpoints)")
	tlsListen := flag.String("tls-listen", ":9443", "HTTPS listen address for agent traffic (empty disables TLS)")
	tlsCert := flag.String("tls-cert", "", "PEM certificate for the HTTPS listener (default: issued by the hub's own CA)")
	tlsKey := flag.String("tls-key", "", "PEM private key for --tls-cert")
	tlsHosts := flag.String("tls-hosts", "", "Comma-separated extra SANs for the self-issued certificate (e.g. a VIP the hub cannot see)")
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

	resolvedAdminKey := *adminKey
	if resolvedAdminKey == "" {
		if t, err := store.GetTenant("default"); err == nil && t != nil {
			resolvedAdminKey = t.APIKey
		}
	}
	if resolvedAdminKey == "" {
		resolvedAdminKey = os.Getenv("OMINULL_ADMIN_KEY")
	}
	log.Printf("[+] Cryptographic Master API Key Active: %s", resolvedAdminKey)

	srv := server.New(store, resolvedAdminKey, absBinDir, *hubURL, resolvedAgentVersion)
	srv.SetTLS(server.TLSOptions{
		Listen:   *tlsListen,
		CertFile: *tlsCert,
		KeyFile:  *tlsKey,
		Hosts:    splitList(*tlsHosts),
	})
	srv.SetAgentHubURL(*agentHubURL)
	go func() {
		if err := srv.Start(*listenAddr); err != nil && err != os.ErrClosed {
			log.Fatalf("[-] Hub server error: %v", err)
		}
	}()

	log.Printf("[+] Bundled agent release:      v%s (endpoints below this are offered an update)", resolvedAgentVersion)
	log.Printf("[+] Bootstrap script endpoint: http://localhost%s/bootstrap.ps1", *listenAddr)
	log.Printf("[+] Multi-Tenant REST API:    http://localhost%s/api/v1/", *listenAddr)
	if *tlsListen != "" {
		agentTarget := *agentHubURL
		if agentTarget == "" {
			agentTarget = *hubURL
		}
		log.Printf("[+] Agent TLS transport:      %s (enrolment writes %q into agent config)", *tlsListen, agentTarget)
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
