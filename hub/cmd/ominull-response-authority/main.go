package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"ominull/hub/pkg/response"
	"ominull/hub/pkg/responseauth"
)

func main() {
	socketPath := flag.String("socket", envOr("OMINULL_AUTH_SOCKET", "/run/ominull-response-authority/authority.sock"), "Unix domain socket path")
	stateDir := flag.String("state-dir", envOr("OMINULL_AUTH_STATE_DIR", "/var/lib/ominull-response-authority"), "Authority state directory")
	partition := flag.String("partition", envOr("OMINULL_AUTH_PARTITION", "portable-local"), "Signer partition name")
	epochFloor := flag.Int64("trust-epoch-floor", envInt("OMINULL_AUTH_TRUST_EPOCH_FLOOR"), "Lowest trust bundle epoch to hand out (raise after a rotation that lost the authority state)")
	trustStatement := flag.String("trust-statement", "", "Print the trust bundle statement for TENANT (asked of the running authority) and exit")
	flag.Parse()

	if *trustStatement != "" {
		// The release key signs this to let agents pin the tenant's keys. It is
		// read here, on the authority's host, so the statement an owner signs
		// does not have to come from the hub.
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		k, err := responseauth.NewUDSClient(*socketPath).TrustKeys(ctx, *trustStatement)
		if err != nil {
			log.Fatalf("trust keys for %q: %v", *trustStatement, err)
		}
		if k.TenantID != *trustStatement {
			log.Fatalf("authority answered for tenant %q", k.TenantID)
		}
		if k.Epoch < 1 {
			log.Fatal("the authority reported no trust epoch")
		}
		fmt.Print(response.TrustBundleStatement(k))
		return
	}

	if err := os.MkdirAll(filepath.Dir(*socketPath), 0755); err != nil {
		log.Fatalf("failed to create socket directory: %v", err)
	}
	if err := os.MkdirAll(*stateDir, 0700); err != nil {
		log.Fatalf("failed to create state directory: %v", err)
	}

	auth, err := responseauth.NewAuthority(responseauth.Config{
		StateDir:        *stateDir,
		SignerPartition: *partition,
		TrustEpochFloor: *epochFloor,
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

func envInt(name string) int64 {
	var v int64
	fmt.Sscanf(strings.TrimSpace(os.Getenv(name)), "%d", &v)
	return v
}

func envOr(name, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(name)); v != "" {
		return v
	}
	return fallback
}
