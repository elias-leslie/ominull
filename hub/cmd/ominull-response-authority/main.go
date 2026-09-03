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

	"ominull/hub/pkg/responseauth"
)

func main() {
	socketPath := flag.String("socket", envOr("OMINULL_AUTH_SOCKET", "/run/ominull-response-authority/authority.sock"), "Unix domain socket path")
	stateDir := flag.String("state-dir", envOr("OMINULL_AUTH_STATE_DIR", "/var/lib/ominull-response-authority"), "Authority state directory")
	partition := flag.String("partition", envOr("OMINULL_AUTH_PARTITION", "portable-local"), "Signer partition name")
	flag.Parse()

	if err := os.MkdirAll(filepath.Dir(*socketPath), 0755); err != nil {
		log.Fatalf("failed to create socket directory: %v", err)
	}
	if err := os.MkdirAll(*stateDir, 0700); err != nil {
		log.Fatalf("failed to create state directory: %v", err)
	}

	auth, err := responseauth.NewAuthority(responseauth.Config{
		StateDir:        *stateDir,
		SignerPartition: *partition,
	})
	if err != nil {
		log.Fatalf("failed to initialize response authority: %v", err)
	}

	server, err := responseauth.NewServer(auth, *socketPath)
	if err != nil {
		log.Fatalf("failed to create authority server: %v", err)
	}

	if err := server.Start(); err != nil {
		log.Fatalf("failed to start authority server on %s: %v", *socketPath, err)
	}
	fmt.Printf("[+] ominull-response-authority listening on %s (state: %s)\n", *socketPath, *stateDir)

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	<-sigChan

	fmt.Println("\n[*] Shutting down response authority...")
	if err := server.Close(); err != nil {
		log.Printf("error closing server: %v", err)
	}
}

func envOr(name, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(name)); v != "" {
		return v
	}
	return fallback
}
