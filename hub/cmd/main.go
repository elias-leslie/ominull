package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
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

func main() {
	listenAddr := flag.String("listen", ":9999", "HTTP/WebSocket listen address")
	dbPath := flag.String("db", "ominull.db", "Path to SQLite database file")
	adminKey := flag.String("admin-key", "ominull-master-admin-key", "Master Admin API Key")
	binaryDir := flag.String("binary-dir", "./build", "Path to directory containing driver and agent binaries")
	hubURL := flag.String("hub-url", "", "Public Hub URL for bootstrap scripts (e.g. http://10.0.0.57:9999)")
	flag.Parse()

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

	// Seed default MSP tenant if no tenants exist
	tenants, _ := store.ListTenants()
	if len(tenants) == 0 {
		defaultTenant := storage.Tenant{
			ID:        "tenant-default",
			Name:      "Default IR Operations",
			APIKey:    "ominull-default-api-key",
			CreatedAt: time.Now().UTC(),
		}
		if err := store.CreateTenant(defaultTenant); err == nil {
			log.Printf("[+] Initialized Default Tenant: %s (API Key: %s)", defaultTenant.Name, defaultTenant.APIKey)
		}
	}

	srv := server.New(store, *adminKey, absBinDir, *hubURL)

	// Background real-time telemetry stream logger
	go func() {
		for ev := range srv.Events() {
			color := "\033[32m" // Green for PERMIT
			if ev.Action == "BLOCK" {
				color = "\033[31m" // Red for BLOCK
			}
			reset := "\033[0m"

			log.Printf("%s[%s][%s]%s %s %s:%d -> %s:%d | Proto:%d PID:%d (%s)",
				color, ev.Layer, ev.Action, reset,
				ev.Direction, ev.SrcIP, ev.SrcPort, ev.DstIP, ev.DstPort,
				ev.Protocol, ev.ProcessID, ev.ProcessPath,
			)
		}
	}()

	go func() {
		if err := srv.Start(*listenAddr); err != nil && err != os.ErrClosed {
			log.Fatalf("[-] Hub server error: %v", err)
		}
	}()

	log.Printf("[+] Bootstrap script endpoint: http://localhost%s/bootstrap.ps1", *listenAddr)
	log.Printf("[+] Multi-Tenant REST API:    http://localhost%s/api/v1/", *listenAddr)

	// Graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	log.Println("\n[*] Shutting down Ominull Hub gracefully...")
	srv.Close()
}
