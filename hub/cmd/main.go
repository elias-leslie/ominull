package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
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
const defaultAgentVersion = "1.2.0"

func main() {
	listenAddr := flag.String("listen", ":9999", "HTTP/WebSocket listen address")
	dbPath := flag.String("db", "ominull.db", "Path to SQLite database file")
	adminKey := flag.String("admin-key", "", "Master Admin API Key (defaults to auto-generated key in DB)")
	binaryDir := flag.String("binary-dir", "./build", "Path to directory containing driver and agent binaries")
	hubURL := flag.String("hub-url", "", "Public Hub URL for bootstrap scripts (e.g. https://omi.example.com)")
	agentVersion := flag.String("agent-version", defaultAgentVersion, "Agent version bundled with this hub build (offered to outdated endpoints)")
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
	go func() {
		if err := srv.Start(*listenAddr); err != nil && err != os.ErrClosed {
			log.Fatalf("[-] Hub server error: %v", err)
		}
	}()

	log.Printf("[+] Bundled agent release:      v%s (endpoints below this are offered an update)", resolvedAgentVersion)
	log.Printf("[+] Bootstrap script endpoint: http://localhost%s/bootstrap.ps1", *listenAddr)
	log.Printf("[+] Multi-Tenant REST API:    http://localhost%s/api/v1/", *listenAddr)

	// Graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	log.Println("\n[*] Shutting down Ominull Hub gracefully...")
	srv.Close()
}
