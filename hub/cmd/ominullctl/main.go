package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"ominull/hub/pkg/evidence"
	"ominull/hub/pkg/setup"
)

const (
	defaultSetupTokenPath = "/var/lib/ominull/setup.token"
	defaultAdminKeyPath   = "/etc/ominull/admin.key"
	defaultHubURL         = "http://127.0.0.1:9999"
)

type CLIConfig struct {
	HubURL     string
	APIKey     string
	APIKeyFile string
	JSONOutput bool
	TenantID   string
	Limit      int
}

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(2)
	}

	cmd := os.Args[1]
	if cmd == "help" || cmd == "--help" || cmd == "-h" {
		printUsage()
		return
	}

	// Handle local setup commands directly before full API client initialization
	if cmd == "setup-token" || cmd == "setup-status" {
		handleSetupCommands(cmd, os.Args[2:])
		return
	}

	// Parse flags for API client commands
	cfg, subArgs := parseGlobalFlags(os.Args[1:])
	if len(subArgs) == 0 {
		printUsage()
		os.Exit(2)
	}

	client := newAPIClient(cfg)
	subcmd := subArgs[0]
	rest := subArgs[1:]

	var err error
	switch subcmd {
	case "status":
		err = client.cmdStatus(rest)
	case "endpoints":
		err = client.cmdEndpoints(rest)
	case "scanner":
		err = client.cmdScanner(rest)
	case "scan":
		err = client.cmdScanner(append([]string{"scan"}, rest...))
	case "assets":
		err = client.cmdScanner([]string{"assets"})
	case "train":
		err = client.cmdScanner(append([]string{"train"}, rest...))
	case "alerts":
		err = client.cmdAlerts(rest)
	case "mesh":
		err = client.cmdMesh(rest)
	case "quarantine-mesh":
		err = client.cmdMesh(append([]string{"quarantine"}, rest...))
	case "unquarantine-mesh":
		err = client.cmdMesh(append([]string{"release"}, rest...))
	case "agents":
		err = client.cmdAgents(rest)
	case "agent-versions":
		err = client.cmdAgents([]string{"versions"})
	case "agent-update":
		err = client.cmdAgents(append([]string{"update"}, rest...))
	case "install":
		err = client.cmdInstall(rest)
	case "install-errors", "reports":
		err = client.cmdInstall(append([]string{"reports"}, rest...))
	case "response":
		err = client.cmdResponse(rest)
	case "response-auth":
		err = client.cmdResponseAuth(rest)
	case "forensics":
		err = client.cmdForensics(rest)
	case "scripts":
		err = client.cmdScripts(rest)
	case "shell":
		err = client.cmdShell(rest)
	case "software":
		err = client.cmdSoftware(rest)
	case "vulnerabilities":
		err = client.cmdVulnerabilities(rest)
	case "console":
		err = client.cmdConsole(rest)
	case "learning":
		err = client.cmdLearning(rest)
	case "help", "--help", "-h":
		printUsage()
		return
	default:
		fmt.Fprintf(os.Stderr, "ominullctl: unknown command %q\n", subcmd)
		printUsage()
		os.Exit(2)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "ominullctl error: %v\n", err)
		os.Exit(1)
	}
}

func handleSetupCommands(cmd string, args []string) {
	fs := flag.NewFlagSet(cmd, flag.ExitOnError)
	path := fs.String("path", envOr("OMINULL_SETUP_TOKEN_FILE", defaultSetupTokenPath), "private setup-token file")
	rotate := fs.Bool("rotate", false, "rotate token")
	_ = fs.Parse(args)

	switch cmd {
	case "setup-token":
		if *rotate {
			token, err := setup.Rotate(*path)
			fatalIf(err)
			fmt.Println(token)
			return
		}
		token, err := currentToken(*path)
		if err != nil {
			if err := setup.Ensure(*path); err != nil {
				fatalIf(err)
			}
			token, err = currentToken(*path)
		}
		fatalIf(err)
		fmt.Println(token)
	case "setup-status":
		available, err := setup.Available(*path)
		fatalIf(err)
		if available {
			fmt.Println("pending")
		} else {
			fmt.Println("consumed-or-not-created")
		}
	}
}

type APIClient struct {
	cfg        CLIConfig
	httpClient *http.Client
}

func newAPIClient(cfg CLIConfig) *APIClient {
	return &APIClient{
		cfg: cfg,
		httpClient: &http.Client{
			Timeout: 15 * time.Second,
		},
	}
}

func parseGlobalFlags(args []string) (CLIConfig, []string) {
	var cfg CLIConfig
	fs := flag.NewFlagSet("ominullctl", flag.ExitOnError)
	fs.StringVar(&cfg.HubURL, "url", envOr("OMINULL_HUB_URL", defaultHubURL), "Hub API base URL")
	fs.StringVar(&cfg.APIKeyFile, "api-key-file", envOr("OMINULL_API_KEY_FILE", defaultAdminKeyPath), "Path to API key file")
	fs.BoolVar(&cfg.JSONOutput, "json", false, "Emit machine-readable JSON output")
	fs.StringVar(&cfg.TenantID, "tenant", "default", "Tenant ID context")
	fs.IntVar(&cfg.Limit, "limit", 50, "Pagination limit")

	_ = fs.Parse(args)

	// Read API key from file if present (first line if multi-line)
	if data, err := os.ReadFile(cfg.APIKeyFile); err == nil {
		lines := strings.Split(strings.TrimSpace(string(data)), "\n")
		if len(lines) > 0 {
			cfg.APIKey = strings.TrimSpace(lines[0])
		}
	}

	return cfg, fs.Args()
}

func (c *APIClient) doRequest(method, endpoint string, body interface{}) ([]byte, error) {
	var reqBody io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		reqBody = bytes.NewReader(b)
	}

	fullURL := strings.TrimRight(c.cfg.HubURL, "/") + endpoint
	req, err := http.NewRequest(method, fullURL, reqBody)
	if err != nil {
		return nil, err
	}

	if c.cfg.APIKey != "" {
		req.Header.Set("X-API-Key", c.cfg.APIKey)
	}
	req.Header.Set("Content-Type", "application/json")
	if c.cfg.TenantID != "" {
		req.Header.Set("X-Tenant-ID", c.cfg.TenantID)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("HTTP request failed: %w", err)
	}
	defer resp.Body.Close()

	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("API returned status %d: %s", resp.StatusCode, string(respBytes))
	}

	return respBytes, nil
}

func (c *APIClient) printOutput(data interface{}, humanFunc func()) {
	if c.cfg.JSONOutput {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(data)
	} else {
		humanFunc()
	}
}

func (c *APIClient) cmdStatus(args []string) error {
	_ = args
	rawHierarchy, err := c.doRequest(http.MethodGet, "/api/v1/hierarchy", nil)
	if err != nil {
		return err
	}
	rawEndpoints, _ := c.doRequest(http.MethodGet, "/api/v1/endpoints", nil)

	var hRes, epRes interface{}
	_ = json.Unmarshal(rawHierarchy, &hRes)
	if len(rawEndpoints) > 0 {
		_ = json.Unmarshal(rawEndpoints, &epRes)
	}

	c.printOutput(map[string]interface{}{
		"hierarchy": hRes,
		"endpoints": epRes,
	}, func() {
		fmt.Printf("=== Ominull Hub Status (%s) ===\n", c.cfg.HubURL)
		fmt.Println(string(rawHierarchy))
		if len(rawEndpoints) > 0 {
			fmt.Println("\n=== Online Endpoints ===")
			var eps []map[string]interface{}
			if err := json.Unmarshal(rawEndpoints, &eps); err == nil && len(eps) > 0 {
				for _, ep := range eps {
					fmt.Printf("- %-24v %-16v %-15v %v\n", ep["id"], ep["hostname"], ep["ip"], ep["status"])
				}
			} else {
				fmt.Println(string(rawEndpoints))
			}
		}
	})
	return nil
}

func (c *APIClient) cmdEndpoints(args []string) error {
	if len(args) == 0 || args[0] == "list" {
		raw, err := c.doRequest(http.MethodGet, "/api/v1/endpoints", nil)
		if err != nil {
			return err
		}
		var endpoints []map[string]interface{}
		_ = json.Unmarshal(raw, &endpoints)
		c.printOutput(endpoints, func() {
			fmt.Println("=== Managed Endpoints ===")
			for _, ep := range endpoints {
				fmt.Printf("- %-24s %-16s %-15s %s\n", ep["id"], ep["hostname"], ep["ip"], ep["status"])
			}
		})
		return nil
	}
	if args[0] == "show" && len(args) > 1 {
		raw, err := c.doRequest(http.MethodGet, fmt.Sprintf("/api/v1/endpoints?id=%s", url.QueryEscape(args[1])), nil)
		if err != nil {
			return err
		}
		var res interface{}
		_ = json.Unmarshal(raw, &res)
		c.printOutput(res, func() {
			fmt.Println(string(raw))
		})
		return nil
	}
	return fmt.Errorf("usage: ominullctl endpoints list|show <id>")
}

func (c *APIClient) cmdScanner(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: ominullctl scanner scan|status|assets|train")
	}
	action := args[0]
	switch action {
	case "assets":
		raw, err := c.doRequest(http.MethodGet, "/api/v1/scanner/results", nil)
		if err != nil {
			return err
		}
		var res interface{}
		_ = json.Unmarshal(raw, &res)
		c.printOutput(res, func() {
			fmt.Println("=== Discovered Subnet Assets ===")
			fmt.Println(string(raw))
		})
		return nil
	case "scan":
		subnet := "10.0.0.0/24"
		profile := "standard"
		if len(args) > 1 {
			subnet = args[1]
		}
		if len(args) > 2 {
			profile = args[2]
		}
		raw, err := c.doRequest(http.MethodPost, "/api/v1/scanner/scan", map[string]string{
			"subnet":  subnet,
			"profile": profile,
		})
		if err != nil {
			return err
		}
		var res interface{}
		_ = json.Unmarshal(raw, &res)
		c.printOutput(res, func() {
			fmt.Printf("[+] Initiated %s sweep on %s\n", profile, subnet)
			fmt.Println(string(raw))
		})
		return nil
	case "status":
		id := ""
		if len(args) > 1 {
			id = args[1]
		}
		raw, err := c.doRequest(http.MethodGet, fmt.Sprintf("/api/v1/scanner/status?id=%s", url.QueryEscape(id)), nil)
		if err != nil {
			return err
		}
		var res interface{}
		_ = json.Unmarshal(raw, &res)
		c.printOutput(res, func() {
			fmt.Println(string(raw))
		})
		return nil
	case "train":
		if len(args) < 5 {
			return fmt.Errorf("usage: ominullctl scanner train <ip> <name> <vendor> <category>")
		}
		raw, err := c.doRequest(http.MethodPost, "/api/v1/scanner/feedback", map[string]string{
			"ip":       args[1],
			"name":     args[2],
			"vendor":   args[3],
			"category": args[4],
		})
		if err != nil {
			return err
		}
		var res interface{}
		_ = json.Unmarshal(raw, &res)
		c.printOutput(res, func() {
			fmt.Printf("[+] Trained fingerprint for %s\n", args[1])
		})
		return nil
	default:
		return fmt.Errorf("unknown scanner action %q", action)
	}
}

func (c *APIClient) cmdAlerts(args []string) error {
	raw, err := c.doRequest(http.MethodGet, "/api/v1/alerts", nil)
	if err != nil {
		return err
	}
	var res interface{}
	_ = json.Unmarshal(raw, &res)
	c.printOutput(res, func() {
		fmt.Println("=== Active Security Alerts ===")
		fmt.Println(string(raw))
	})
	return nil
}

func (c *APIClient) cmdMesh(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: ominullctl mesh quarantine|release [args]")
	}
	switch args[0] {
	case "quarantine":
		if len(args) < 2 {
			return fmt.Errorf("usage: ominullctl mesh quarantine <ip> [mac] [reason]")
		}
		tip := args[1]
		tmac := ""
		reason := "Subnet quarantine from ominullctl"
		if len(args) > 2 {
			tmac = args[2]
		}
		if len(args) > 3 {
			reason = args[3]
		}
		raw, err := c.doRequest(http.MethodPost, "/api/v1/mesh/quarantine", map[string]string{
			"target_ip":  tip,
			"target_mac": tmac,
			"reason":     reason,
		})
		if err != nil {
			return err
		}
		var res interface{}
		_ = json.Unmarshal(raw, &res)
		c.printOutput(res, func() {
			fmt.Printf("[+] Enforced Subnet Quarantine Mesh on %s\n", tip)
		})
		return nil
	case "release", "unquarantine":
		if len(args) < 2 {
			return fmt.Errorf("usage: ominullctl mesh release <ip>")
		}
		tip := args[1]
		raw, err := c.doRequest(http.MethodPost, "/api/v1/mesh/unquarantine", map[string]string{
			"target_ip": tip,
		})
		if err != nil {
			return err
		}
		var res interface{}
		_ = json.Unmarshal(raw, &res)
		c.printOutput(res, func() {
			fmt.Printf("[+] Lifted Subnet Quarantine Mesh on %s\n", tip)
		})
		return nil
	default:
		return fmt.Errorf("unknown mesh action %q", args[0])
	}
}

func (c *APIClient) cmdAgents(args []string) error {
	if len(args) == 0 || args[0] == "versions" {
		raw, err := c.doRequest(http.MethodGet, "/api/v1/agents/update-status", nil)
		if err != nil {
			return err
		}
		var res interface{}
		_ = json.Unmarshal(raw, &res)
		c.printOutput(res, func() {
			fmt.Println("=== Fleet Agent Version Currency ===")
			fmt.Println(string(raw))
		})
		return nil
	}
	if args[0] == "update" {
		if len(args) < 2 {
			return fmt.Errorf("usage: ominullctl agents update <endpoint_id|all> [version]")
		}
		target := args[1]
		ver := ""
		if len(args) > 2 {
			ver = args[2]
		}
		var body map[string]interface{}
		if target == "all" {
			body = map[string]interface{}{"all": true, "version": ver}
		} else {
			body = map[string]interface{}{"endpoint_ids": []string{target}, "version": ver}
		}
		raw, err := c.doRequest(http.MethodPost, "/api/v1/agents/update", body)
		if err != nil {
			return err
		}
		var res interface{}
		_ = json.Unmarshal(raw, &res)
		c.printOutput(res, func() {
			fmt.Printf("[+] Dispatched agent update for %s\n", target)
		})
		return nil
	}
	return fmt.Errorf("usage: ominullctl agents versions|update")
}

func (c *APIClient) cmdInstall(args []string) error {
	id := ""
	if len(args) > 1 {
		id = args[1]
	} else if len(args) == 1 && args[0] != "reports" && args[0] != "errors" && args[0] != "list" {
		id = args[0]
	}
	endpoint := "/api/v1/enrolment/install-errors"
	if id != "" {
		endpoint += "?id=" + url.QueryEscape(id)
	}
	raw, err := c.doRequest(http.MethodGet, endpoint, nil)
	if err != nil {
		return err
	}
	var res interface{}
	_ = json.Unmarshal(raw, &res)
	c.printOutput(res, func() {
		if id != "" {
			fmt.Printf("=== Installer Error Report: %s ===\n", id)
		} else {
			fmt.Println("=== Recent Installer Error Reports ===")
		}
		fmt.Println(string(raw))
	})
	return nil
}

func (c *APIClient) cmdResponse(args []string) error {
	if len(args) == 0 || args[0] == "jobs" {
		sub := "list"
		if len(args) > 1 {
			sub = args[1]
		}
		if sub == "list" {
			raw, err := c.doRequest(http.MethodGet, fmt.Sprintf("/api/v1/response/jobs?limit=%d", c.cfg.Limit), nil)
			if err != nil {
				return err
			}
			var res interface{}
			_ = json.Unmarshal(raw, &res)
			c.printOutput(res, func() {
				fmt.Println("=== Response Jobs ===")
				fmt.Println(string(raw))
			})
			return nil
		}
		if sub == "cancel" && len(args) > 2 {
			raw, err := c.doRequest(http.MethodPost, "/api/v1/response/jobs/cancel", map[string]string{
				"job_id": args[2],
			})
			if err != nil {
				return err
			}
			var res interface{}
			_ = json.Unmarshal(raw, &res)
			c.printOutput(res, func() {
				fmt.Printf("[+] Cancel requested for job %s\n", args[2])
			})
			return nil
		}
	}
	return fmt.Errorf("usage: ominullctl response jobs list|cancel <job_id>")
}

func (c *APIClient) cmdResponseAuth(args []string) error {
	if len(args) == 0 || args[0] == "status" {
		raw, err := c.doRequest(http.MethodGet, "/api/v1/response/auth/status", nil)
		if err != nil {
			return err
		}
		var res interface{}
		_ = json.Unmarshal(raw, &res)
		c.printOutput(res, func() {
			fmt.Println("=== Response Authority Status ===")
			fmt.Println(string(raw))
		})
		return nil
	}
	if args[0] == "recovery-token" {
		opID := "admin"
		if len(args) > 1 {
			opID = args[1]
		}
		token, err := setup.Rotate(defaultSetupTokenPath)
		if err != nil {
			return err
		}
		c.printOutput(map[string]string{
			"recovery_token": token,
			"operator_id":    opID,
			"tenant_id":      c.cfg.TenantID,
		}, func() {
			fmt.Printf("[+] Issued recovery token for %s: %s\n", opID, token)
		})
		return nil
	}
	return fmt.Errorf("usage: ominullctl response-auth status|recovery-token")
}

func (c *APIClient) cmdForensics(args []string) error {
	action := "list"
	if len(args) > 0 {
		action = args[0]
	}
	if action == "launch" || action == "collect" {
		return fmt.Errorf("forensic collection launch is console-only and requires dual-operator authorization")
	}
	switch action {
	case "list":
		raw, err := c.doRequest(http.MethodGet, fmt.Sprintf("/api/v1/response/jobs?kind=forensic_collection&limit=%d", c.cfg.Limit), nil)
		if err != nil {
			return err
		}
		var res interface{}
		_ = json.Unmarshal(raw, &res)
		c.printOutput(res, func() {
			fmt.Println("=== Forensic Evidence Collections ===")
			fmt.Println(string(raw))
		})
		return nil
	case "verify":
		if len(args) < 2 {
			return fmt.Errorf("usage: ominullctl forensics verify <manifest_file> [--key <pubkey_or_file>] [--receipt <receipt_file>] [--hub-key <pubkey_or_file>]")
		}
		manifestPath := args[1]
		data, err := os.ReadFile(manifestPath)
		if err != nil {
			return fmt.Errorf("failed to read manifest file: %w", err)
		}
		var manifest evidence.Manifest
		if err := json.Unmarshal(data, &manifest); err != nil {
			return fmt.Errorf("invalid manifest JSON: %w", err)
		}

		keyFlag := ""
		receiptPath := ""
		hubKeyFlag := ""
		for i := 2; i < len(args); i++ {
			switch args[i] {
			case "--key":
				if i+1 < len(args) {
					keyFlag = args[i+1]
					i++
				}
			case "--receipt":
				if i+1 < len(args) {
					receiptPath = args[i+1]
					i++
				}
			case "--hub-key":
				if i+1 < len(args) {
					hubKeyFlag = args[i+1]
					i++
				}
			}
		}

		manifestSigValid := false
		if keyFlag != "" {
			keyData := keyFlag
			if fileBytes, err := os.ReadFile(keyFlag); err == nil {
				keyData = strings.TrimSpace(string(fileBytes))
			}
			if err := evidence.VerifyManifestSignature(&manifest, keyData); err != nil {
				return fmt.Errorf("endpoint manifest signature verification FAILED: %w", err)
			}
			manifestSigValid = true
		}

		manifestDir := filepath.Dir(manifestPath)
		itemsChecked := 0
		for _, it := range manifest.Items {
			localFile := filepath.Join(manifestDir, it.Name)
			if fData, err := os.ReadFile(localFile); err == nil {
				if int64(len(fData)) != it.SizeBytes {
					return fmt.Errorf("artifact %s size mismatch: expected %d bytes, got %d bytes", it.Name, it.SizeBytes, len(fData))
				}
				actualSHA := evidence.ComputeDigest(fData)
				if actualSHA != it.SHA256 {
					return fmt.Errorf("artifact %s SHA-256 mismatch: expected %s, got %s", it.Name, it.SHA256, actualSHA)
				}
				itemsChecked++
			}
		}

		receiptSigValid := false
		if receiptPath != "" {
			rData, err := os.ReadFile(receiptPath)
			if err != nil {
				return fmt.Errorf("failed to read receipt file: %w", err)
			}
			var receipt evidence.EvidenceReceipt
			if err := json.Unmarshal(rData, &receipt); err != nil {
				return fmt.Errorf("invalid receipt JSON: %w", err)
			}
			manifestSHA := evidence.ComputeDigest(manifest.CanonicalBytes())
			if receipt.ManifestSHA256 != manifestSHA {
				return fmt.Errorf("receipt manifest hash mismatch: receipt=%s actual=%s", receipt.ManifestSHA256, manifestSHA)
			}
			if hubKeyFlag != "" {
				hubKeyData := hubKeyFlag
				if fBytes, err := os.ReadFile(hubKeyFlag); err == nil {
					hubKeyData = strings.TrimSpace(string(fBytes))
				}
				if err := evidence.VerifyReceiptSignature(&receipt, hubKeyData); err != nil {
					return fmt.Errorf("hub receipt signature verification FAILED: %w", err)
				}
				receiptSigValid = true
			}
		}

		res := map[string]interface{}{
			"verified":           true,
			"manifest":           filepath.Base(manifestPath),
			"bundle_id":          manifest.BundleID,
			"endpoint_id":        manifest.EndpointID,
			"total_items":        len(manifest.Items),
			"items_checked":      itemsChecked,
			"endpoint_sig_valid": manifestSigValid,
			"receipt_sig_valid":  receiptSigValid,
		}

		c.printOutput(res, func() {
			fmt.Printf("[+] Forensic manifest %s verified successfully\n", filepath.Base(manifestPath))
			fmt.Printf("    Bundle ID:           %s\n", manifest.BundleID)
			fmt.Printf("    Endpoint ID:         %s\n", manifest.EndpointID)
			fmt.Printf("    Items in catalog:    %d\n", len(manifest.Items))
			if itemsChecked > 0 {
				fmt.Printf("    Local files checked: %d (all digests match)\n", itemsChecked)
			}
			if manifestSigValid {
				fmt.Printf("    Endpoint signature:  VERIFIED (Ed25519)\n")
			}
			if receiptSigValid {
				fmt.Printf("    Hub receipt:         VERIFIED (Ed25519)\n")
			}
		})
		return nil
	case "prune":
		raw, err := c.doRequest(http.MethodPost, "/api/v1/evidence/prune", nil)
		if err != nil {
			return err
		}
		var res struct {
			PrunedBundles int    `json:"pruned_bundles"`
			Status        string `json:"status"`
		}
		_ = json.Unmarshal(raw, &res)
		c.printOutput(res, func() {
			fmt.Printf("[+] Pruned %d expired evidence bundle(s)\n", res.PrunedBundles)
		})
		return nil
	default:
		return fmt.Errorf("usage: ominullctl forensics list|show|verify|prune|hold|release")
	}
}

func (c *APIClient) cmdScripts(args []string) error {
	action := "list"
	if len(args) > 0 {
		action = args[0]
	}
	if action == "run" || action == "schedule" {
		return fmt.Errorf("script execution and scheduling are console-only and require dual-operator authorization")
	}
	switch action {
	case "list":
		raw, err := c.doRequest(http.MethodGet, "/api/v1/scripts", nil)
		if err != nil {
			return err
		}
		var res struct {
			Scripts []map[string]interface{} `json:"scripts"`
		}
		_ = json.Unmarshal(raw, &res)
		c.printOutput(res, func() {
			fmt.Println("=== Script Library ===")
			if len(res.Scripts) == 0 {
				fmt.Println("No versioned scripts registered.")
				return
			}
			for _, sc := range res.Scripts {
				retiredMarker := ""
				if r, ok := sc["retired"].(bool); ok && r {
					retiredMarker = " [RETIRED]"
				}
				fmt.Printf("[%s] %s (v%v, %s)%s - %s\n", sc["id"], sc["name"], sc["latest_version"], sc["interpreter"], retiredMarker, sc["description"])
			}
		})
		return nil

	case "show":
		if len(args) < 2 {
			return fmt.Errorf("usage: ominullctl scripts show <id> [--version <v>]")
		}
		id := args[1]
		versionFlag := ""
		for i := 2; i < len(args); i++ {
			if args[i] == "--version" && i+1 < len(args) {
				versionFlag = args[i+1]
				i++
			}
		}

		if versionFlag != "" {
			path := fmt.Sprintf("/api/v1/scripts?id=%s&version=%s", url.QueryEscape(id), url.QueryEscape(versionFlag))
			raw, err := c.doRequest(http.MethodGet, path, nil)
			if err != nil {
				return err
			}
			var sv map[string]interface{}
			_ = json.Unmarshal(raw, &sv)
			c.printOutput(sv, func() {
				fmt.Printf("=== Script Version Details ===\n")
				fmt.Printf("Script ID:        %v\n", sv["script_id"])
				fmt.Printf("Version:          %v\n", sv["version"])
				fmt.Printf("Digest (SHA-256): %v\n", sv["digest_sha256"])
				fmt.Printf("Created At:       %v\n", sv["created_at"])
				fmt.Printf("Created By:       %v\n", sv["created_by"])
				fmt.Printf("Parameter Schema: %v\n", sv["parameter_schema_json"])
				fmt.Printf("--- Source Code ---\n%v\n", sv["source"])
			})
			return nil
		}

		path := fmt.Sprintf("/api/v1/scripts?id=%s", url.QueryEscape(id))
		raw, err := c.doRequest(http.MethodGet, path, nil)
		if err != nil {
			return err
		}
		var sc map[string]interface{}
		_ = json.Unmarshal(raw, &sc)
		c.printOutput(sc, func() {
			fmt.Printf("=== Script Details ===\n")
			fmt.Printf("ID:             %v\n", sc["id"])
			fmt.Printf("Name:           %v\n", sc["name"])
			fmt.Printf("Description:    %v\n", sc["description"])
			fmt.Printf("Interpreter:    %v\n", sc["interpreter"])
			fmt.Printf("Latest Version: %v\n", sc["latest_version"])
			fmt.Printf("Retired:        %v\n", sc["retired"])
			fmt.Printf("Created At:     %v\n", sc["created_at"])
			fmt.Printf("Updated At:     %v\n", sc["updated_at"])
			if versions, ok := sc["versions"].([]interface{}); ok && len(versions) > 0 {
				fmt.Println("--- Versions ---")
				for _, v := range versions {
					if vm, ok := v.(map[string]interface{}); ok {
						fmt.Printf("  v%v (%s): %s by %s\n", vm["version"], vm["created_at"], vm["digest_sha256"], vm["created_by"])
					}
				}
			}
		})
		return nil

	case "create":
		var name, desc, interpreter, sourceFile, schemaFile string
		for i := 1; i < len(args); i++ {
			switch args[i] {
			case "--name":
				if i+1 < len(args) {
					name = args[i+1]
					i++
				}
			case "--desc", "--description":
				if i+1 < len(args) {
					desc = args[i+1]
					i++
				}
			case "--interpreter":
				if i+1 < len(args) {
					interpreter = args[i+1]
					i++
				}
			case "--source-file", "--source":
				if i+1 < len(args) {
					sourceFile = args[i+1]
					i++
				}
			case "--schema-file", "--schema":
				if i+1 < len(args) {
					schemaFile = args[i+1]
					i++
				}
			}
		}

		if name == "" || interpreter == "" || sourceFile == "" {
			return fmt.Errorf("usage: ominullctl scripts create --name <name> --interpreter <interp> [--desc <desc>] --source-file <path|-> [--schema-file <path|->]")
		}

		var sourceBytes []byte
		var err error
		if sourceFile == "-" {
			sourceBytes, err = io.ReadAll(os.Stdin)
		} else {
			sourceBytes, err = os.ReadFile(sourceFile)
		}
		if err != nil {
			return fmt.Errorf("failed to read source file: %w", err)
		}

		var schemaJSON string
		if schemaFile != "" {
			var schemaBytes []byte
			if schemaFile == "-" {
				schemaBytes, err = io.ReadAll(os.Stdin)
			} else {
				schemaBytes, err = os.ReadFile(schemaFile)
			}
			if err != nil {
				return fmt.Errorf("failed to read schema file: %w", err)
			}
			schemaJSON = string(schemaBytes)
		}

		payload := map[string]string{
			"name":                  name,
			"description":           desc,
			"interpreter":           interpreter,
			"source":                string(sourceBytes),
			"parameter_schema_json": schemaJSON,
		}

		raw, err := c.doRequest(http.MethodPost, "/api/v1/scripts", payload)
		if err != nil {
			return err
		}
		var res map[string]interface{}
		_ = json.Unmarshal(raw, &res)
		c.printOutput(res, func() {
			script, _ := res["script"].(map[string]interface{})
			version, _ := res["version"].(map[string]interface{})
			fmt.Printf("[+] Script created successfully\n")
			if script != nil {
				fmt.Printf("    ID:          %v\n", script["id"])
				fmt.Printf("    Name:        %v\n", script["name"])
				fmt.Printf("    Interpreter: %v\n", script["interpreter"])
			}
			if version != nil {
				fmt.Printf("    Version:     %v\n", version["version"])
				fmt.Printf("    Digest:      %v\n", version["digest_sha256"])
			}
		})
		return nil

	case "update":
		if len(args) < 2 {
			return fmt.Errorf("usage: ominullctl scripts update <id> --source-file <path|-> [--schema-file <path|->]")
		}
		id := args[1]
		var sourceFile, schemaFile string
		for i := 2; i < len(args); i++ {
			switch args[i] {
			case "--source-file", "--source":
				if i+1 < len(args) {
					sourceFile = args[i+1]
					i++
				}
			case "--schema-file", "--schema":
				if i+1 < len(args) {
					schemaFile = args[i+1]
					i++
				}
			}
		}

		if sourceFile == "" {
			return fmt.Errorf("usage: ominullctl scripts update <id> --source-file <path|-> [--schema-file <path|->]")
		}

		var sourceBytes []byte
		var err error
		if sourceFile == "-" {
			sourceBytes, err = io.ReadAll(os.Stdin)
		} else {
			sourceBytes, err = os.ReadFile(sourceFile)
		}
		if err != nil {
			return fmt.Errorf("failed to read source file: %w", err)
		}

		var schemaJSON string
		if schemaFile != "" {
			var schemaBytes []byte
			if schemaFile == "-" {
				schemaBytes, err = io.ReadAll(os.Stdin)
			} else {
				schemaBytes, err = os.ReadFile(schemaFile)
			}
			if err != nil {
				return fmt.Errorf("failed to read schema file: %w", err)
			}
			schemaJSON = string(schemaBytes)
		}

		payload := map[string]string{
			"id":                    id,
			"source":                string(sourceBytes),
			"parameter_schema_json": schemaJSON,
		}

		raw, err := c.doRequest(http.MethodPost, "/api/v1/scripts", payload)
		if err != nil {
			return err
		}
		var sv map[string]interface{}
		_ = json.Unmarshal(raw, &sv)
		c.printOutput(sv, func() {
			fmt.Printf("[+] Script updated to new version\n")
			fmt.Printf("    Script ID:   %v\n", sv["script_id"])
			fmt.Printf("    Version:     %v\n", sv["version"])
			fmt.Printf("    Digest:      %v\n", sv["digest_sha256"])
			fmt.Printf("    Created By:  %v\n", sv["created_by"])
		})
		return nil

	case "retire":
		if len(args) < 2 {
			return fmt.Errorf("usage: ominullctl scripts retire <id>")
		}
		id := args[1]
		path := fmt.Sprintf("/api/v1/scripts?id=%s", url.QueryEscape(id))
		raw, err := c.doRequest(http.MethodDelete, path, nil)
		if err != nil {
			return err
		}
		var res map[string]interface{}
		_ = json.Unmarshal(raw, &res)
		c.printOutput(res, func() {
			fmt.Printf("[+] Script %s retired successfully\n", id)
		})
		return nil

	default:
		return fmt.Errorf("usage: ominullctl scripts list|show|create|update|retire")
	}
}

func (c *APIClient) cmdShell(args []string) error {
	action := "sessions"
	if len(args) > 0 {
		action = args[0]
	}
	if action == "open" || action == "exec" || action == "attach" {
		return fmt.Errorf("shell session launch is console-only and requires dual-operator authorization")
	}
	switch action {
	case "sessions":
		raw, err := c.doRequest(http.MethodGet, "/api/v1/terminal/sessions", nil)
		if err != nil {
			return err
		}
		var res struct {
			Sessions []map[string]interface{} `json:"sessions"`
		}
		_ = json.Unmarshal(raw, &res)
		c.printOutput(res, func() {
			fmt.Println("=== Active Interactive Shell Sessions ===")
			if len(res.Sessions) == 0 {
				fmt.Println("No active terminal sessions.")
				return
			}
			for _, s := range res.Sessions {
				fmt.Printf("[%s] Endpoint: %s | Program: %s | State: %s | Frames: %v | Started: %s\n",
					s["session_id"], s["endpoint_id"], s["program"], s["state"], s["frame_count"], s["created_at"])
			}
		})
		return nil

	case "show":
		if len(args) < 2 {
			return fmt.Errorf("usage: ominullctl shell show <session_id>")
		}
		raw, err := c.doRequest(http.MethodGet, fmt.Sprintf("/api/v1/terminal/sessions?id=%s", url.QueryEscape(args[1])), nil)
		if err != nil {
			return err
		}
		var res map[string]interface{}
		_ = json.Unmarshal(raw, &res)
		c.printOutput(res, func() {
			fmt.Println(string(raw))
		})
		return nil

	case "close":
		if len(args) < 2 {
			return fmt.Errorf("usage: ominullctl shell close <session_id>")
		}
		payload := map[string]string{
			"session_id": args[1],
			"reason":     "closed_by_cli",
		}
		_, err := c.doRequest(http.MethodPost, "/api/v1/terminal/sessions/close", payload)
		if err != nil {
			return err
		}
		c.printOutput(map[string]string{"status": "closed", "session_id": args[1]}, func() {
			fmt.Printf("[+] Terminal session %s closed.\n", args[1])
		})
		return nil

	default:
		return fmt.Errorf("usage: ominullctl shell sessions|show|close <session_id>")
	}
}

func (c *APIClient) cmdSoftware(args []string) error {
	raw, err := c.doRequest(http.MethodGet, "/api/v1/vulnerabilities", nil)
	if err != nil {
		return err
	}
	var res map[string]interface{}
	_ = json.Unmarshal(raw, &res)
	c.printOutput(res, func() {
		fmt.Println("=== Installed Software & Vulnerability Inventory ===")
		fmt.Println(string(raw))
	})
	return nil
}

func (c *APIClient) cmdVulnerabilities(args []string) error {
	action := "list"
	if len(args) > 0 {
		action = args[0]
	}
	switch action {
	case "sync":
		_, err := c.doRequest(http.MethodPost, "/api/v1/vulnerabilities/sync", map[string]string{})
		if err != nil {
			return err
		}
		c.printOutput(map[string]string{"status": "synchronized"}, func() {
			fmt.Println("[+] Triggered vulnerability catalog synchronization with NVD / CISA KEV.")
		})
		return nil
	default:
		raw, err := c.doRequest(http.MethodGet, "/api/v1/vulnerabilities", nil)
		if err != nil {
			return err
		}
		var res struct {
			Vulns []map[string]interface{} `json:"vulnerabilities"`
		}
		_ = json.Unmarshal(raw, &res)
		c.printOutput(res, func() {
			fmt.Println("=== Correlated Vulnerabilities (NVD / CISA KEV) ===")
			if len(res.Vulns) == 0 {
				fmt.Println("No active CVE matches found.")
				return
			}
			for _, v := range res.Vulns {
				fmt.Printf("[%s] %s | %s | %s %s\n", v["severity"], v["cve_id"], v["product_name"], v["version"], v["match_reason"])
			}
		})
		return nil
	}
}

func (c *APIClient) cmdConsole(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: ominullctl console export-ca|trust-instructions|status [args...]")
	}
	sub := args[0]
	rest := args[1:]
	switch sub {
	case "export-ca":
		fs := flag.NewFlagSet("console export-ca", flag.ExitOnError)
		outFile := fs.String("out", "", "Write CA certificate to output file path instead of stdout")
		caPath := fs.String("path", envOr("OMINULL_CA_FILE", "/var/lib/ominull/certs/ca.crt"), "Direct path to hub CA certificate on host")
		_ = fs.Parse(rest)

		var caBytes []byte
		// 1. Try local disk path if running locally on the hub
		if data, err := os.ReadFile(*caPath); err == nil && len(data) > 0 {
			caBytes = data
		} else {
			// 2. Fetch from hub API /api/v1/pki/ca.crt
			endpoint := "/api/v1/pki/ca.crt"
			fullURL := strings.TrimRight(c.cfg.HubURL, "/") + endpoint
			resp, err := c.httpClient.Get(fullURL)
			if err != nil {
				return fmt.Errorf("failed to fetch CA from API and local file %s: %w", *caPath, err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				return fmt.Errorf("API /api/v1/pki/ca.crt returned status %d", resp.StatusCode)
			}
			caBytes, err = io.ReadAll(resp.Body)
			if err != nil {
				return fmt.Errorf("failed to read response: %w", err)
			}
		}

		if *outFile != "" {
			if err := os.WriteFile(*outFile, caBytes, 0644); err != nil {
				return fmt.Errorf("write CA to %s: %w", *outFile, err)
			}
			c.printOutput(map[string]string{"status": "exported", "path": *outFile}, func() {
				fmt.Printf("[+] Exported Ominull Hub Root CA certificate to %s (mode 0644)\n", *outFile)
			})
			return nil
		}

		c.printOutput(map[string]string{"ca_pem": string(caBytes)}, func() {
			os.Stdout.Write(caBytes)
		})
		return nil

	case "trust-instructions":
		c.printOutput(map[string]interface{}{
			"instructions": map[string]string{
				"linux_debian": "sudo cp ca.crt /usr/local/share/ca-certificates/ominull-ca.crt && sudo update-ca-certificates",
				"linux_rhel":   "sudo cp ca.crt /etc/pki/ca-trust/source/anchors/ && sudo update-ca-trust",
				"macos":        "sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain ca.crt",
				"windows":      "Import-Certificate -FilePath .\\ca.crt -CertStoreLocation Cert:\\LocalMachine\\Root",
				"chrome":       "Settings -> Privacy and security -> Security -> Manage certificates -> Authorities -> Import ca.crt -> Trust for identifying websites",
				"firefox":      "Settings -> Privacy & Security -> Certificates -> View Certificates -> Authorities -> Import ca.crt -> Trust this CA to identify websites",
			},
			"rationale": "Browsers require a secure context with a trusted root certificate to enable WebCrypto (ActionProof signing) and WebAuthn (FIDO2/passkeys).",
		}, func() {
			fmt.Println("=== Ominull Hub Root CA Trust Installation Instructions ===")
			fmt.Println()
			fmt.Println("1. Linux (Debian / Ubuntu):")
			fmt.Println("   sudo cp ca.crt /usr/local/share/ca-certificates/ominull-ca.crt")
			fmt.Println("   sudo update-ca-certificates")
			fmt.Println()
			fmt.Println("2. Linux (RHEL / CentOS / Fedora):")
			fmt.Println("   sudo cp ca.crt /etc/pki/ca-trust/source/anchors/ominull-ca.crt")
			fmt.Println("   sudo update-ca-trust")
			fmt.Println()
			fmt.Println("3. macOS (System Keychain):")
			fmt.Println("   sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain ca.crt")
			fmt.Println()
			fmt.Println("4. Windows (PowerShell as Administrator):")
			fmt.Println("   Import-Certificate -FilePath .\\ca.crt -CertStoreLocation Cert:\\LocalMachine\\Root")
			fmt.Println()
			fmt.Println("5. Web Browsers (Chrome / Edge / Firefox):")
			fmt.Println("   - Chrome/Edge: Settings -> Privacy and security -> Security -> Manage certificates -> Authorities -> Import ca.crt -> Trust for identifying websites")
			fmt.Println("   - Firefox: Settings -> Privacy & Security -> Certificates -> View Certificates -> Authorities -> Import ca.crt -> Trust this CA to identify websites")
			fmt.Println()
			fmt.Println("Note: A trusted root certificate is required by browsers to maintain a secure context for WebCrypto and WebAuthn passkeys.")
		})
		return nil

	case "status":
		raw, err := c.doRequest(http.MethodGet, "/api/v1/console/status", nil)
		if err != nil {
			return err
		}
		var st map[string]interface{}
		_ = json.Unmarshal(raw, &st)
		c.printOutput(st, func() {
			fmt.Println("=== Ominull Console HTTPS Interface Status ===")
			fmt.Printf("Listener Address:  %v\n", st["listen"])
			fmt.Printf("Console Hostname:  %v\n", st["hostname"])
			fmt.Printf("WebAuthn RP ID:    %v\n", st["webauthn_rp_id"])
			fmt.Printf("Certificate Mode:  %v\n", st["source"])
			fmt.Printf("HSTS Enforced:     %v\n", st["hsts"])
			fmt.Printf("Client Cert Mode:  %v (isolated from agent mTLS)\n", st["client_auth"])
		})
		return nil

	default:
		return fmt.Errorf("unknown console subcommand %q; choose export-ca, trust-instructions, or status", sub)
	}
}

// cmdLearning is the console's Learning section, for an operator working
// without a browser - and for an agent asked to read the proposals, form a
// view, and apply the ones a human agreed to. Every subcommand maps to one API
// call, and "apply" takes explicit ids: there is no "apply all", because the
// point of a proposal is that somebody read it.
func (c *APIClient) cmdLearning(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: ominullctl learning windows|open|close|proposals|apply [args]")
	}

	switch args[0] {
	case "windows":
		query := "/api/v1/learning/windows"
		if len(args) > 1 && args[1] == "open" {
			query += "?open=true"
		}
		raw, err := c.doRequest(http.MethodGet, query, nil)
		if err != nil {
			return err
		}
		var res struct {
			Windows []struct {
				Window struct {
					ID         string    `json:"id"`
					ScopeType  string    `json:"scope_type"`
					ScopeLabel string    `json:"scope_label"`
					EndsAt     time.Time `json:"ends_at"`
					Status     string    `json:"status"`
					Note       string    `json:"note"`
				} `json:"window"`
				Open      bool `json:"open"`
				Remaining int  `json:"remaining_minutes"`
			} `json:"windows"`
		}
		_ = json.Unmarshal(raw, &res)
		c.printOutput(json.RawMessage(raw), func() {
			if len(res.Windows) == 0 {
				fmt.Println("No learning windows.")
				return
			}
			fmt.Println("=== Learning windows ===")
			for _, row := range res.Windows {
				state := row.Window.Status
				if row.Open {
					state = fmt.Sprintf("open, %d minute(s) left", row.Remaining)
				}
				fmt.Printf("%s  %s %s  [%s]\n", row.Window.ID, row.Window.ScopeType, row.Window.ScopeLabel, state)
				if row.Window.Note != "" {
					fmt.Printf("    %s\n", row.Window.Note)
				}
			}
		})
		return nil

	case "open":
		fs := flag.NewFlagSet("learning open", flag.ContinueOnError)
		scope := fs.String("scope", "endpoint", "tenant, location or endpoint")
		id := fs.String("id", "", "the tenant, location or endpoint to watch")
		days := fs.Int("days", 0, "window length in days (default 7)")
		hours := fs.Int("hours", 0, "window length in hours, if shorter than a day")
		note := fs.String("note", "", "why this window is open")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		body := map[string]interface{}{"scope_type": *scope, "scope_id": *id, "note": *note}
		if *hours > 0 {
			body["hours"] = *hours
		}
		if *days > 0 {
			body["days"] = *days
		}
		raw, err := c.doRequest(http.MethodPost, "/api/v1/learning/windows", body)
		if err != nil {
			return err
		}
		c.printOutput(json.RawMessage(raw), func() { fmt.Println(string(raw)) })
		return nil

	case "close":
		fs := flag.NewFlagSet("learning close", flag.ContinueOnError)
		id := fs.String("id", "", "the window to close")
		cancel := fs.Bool("cancel", false, "close it as a mistake rather than as finished")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		raw, err := c.doRequest(http.MethodPost, "/api/v1/learning/windows/close",
			map[string]interface{}{"id": *id, "cancel": *cancel})
		if err != nil {
			return err
		}
		c.printOutput(json.RawMessage(raw), func() { fmt.Println(string(raw)) })
		return nil

	case "proposals":
		fs := flag.NewFlagSet("learning proposals", flag.ContinueOnError)
		window := fs.String("window", "", "the window to read")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		raw, err := c.doRequest(http.MethodGet, "/api/v1/learning/proposals?window="+*window, nil)
		if err != nil {
			return err
		}
		var res struct {
			Proposals []struct {
				ID            string  `json:"id"`
				Kind          string  `json:"kind"`
				Subject       string  `json:"subject"`
				Silences      string  `json:"silences"`
				Technique     string  `json:"technique"`
				Evidence      int64   `json:"evidence"`
				Endpoints     int     `json:"endpoints"`
				Corroboration float64 `json:"corroboration"`
			} `json:"proposals"`
		}
		_ = json.Unmarshal(raw, &res)
		c.printOutput(json.RawMessage(raw), func() {
			if len(res.Proposals) == 0 {
				fmt.Println("This window proposes nothing.")
				return
			}
			fmt.Println("=== Learning proposals ===")
			for _, p := range res.Proposals {
				fmt.Printf("%s\n", p.ID)
				fmt.Printf("    %s: %s\n", p.Kind, p.Subject)
				fmt.Printf("    silences %s (%s)\n", p.Silences, p.Technique)
				fmt.Printf("    %d observation(s) on %d endpoint(s), corroboration %.2f\n",
					p.Evidence, p.Endpoints, p.Corroboration)
			}
		})
		return nil

	case "apply":
		fs := flag.NewFlagSet("learning apply", flag.ContinueOnError)
		window := fs.String("window", "", "the window the proposals came from")
		ids := fs.String("ids", "", "comma-separated proposal ids to apply")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		list := []string{}
		for _, id := range strings.Split(*ids, ",") {
			if trimmed := strings.TrimSpace(id); trimmed != "" {
				list = append(list, trimmed)
			}
		}
		if len(list) == 0 {
			return fmt.Errorf("name the proposals to apply with --ids; there is no apply-all")
		}
		raw, err := c.doRequest(http.MethodPost, "/api/v1/learning/proposals/apply",
			map[string]interface{}{"window": *window, "ids": list})
		if err != nil {
			return err
		}
		c.printOutput(json.RawMessage(raw), func() { fmt.Println(string(raw)) })
		return nil
	}
	return fmt.Errorf("unknown learning subcommand %q", args[0])
}

func currentToken(path string) (string, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return "", err
	}
	if info.Mode()&os.ModeSymlink != 0 || info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return "", fmt.Errorf("%s must be a private regular file", path)
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return "", err
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, 512))
	if err != nil {
		return "", err
	}
	token := strings.TrimSpace(string(raw))
	if token == "" {
		return "", fmt.Errorf("%s is empty", path)
	}
	return token, nil
}

func envOr(name, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(name)); value != "" {
		return value
	}
	return fallback
}

func fatalIf(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "ominullctl:", err)
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Fprintf(os.Stderr, `Ominull Unified Control CLI (ominullctl)

Usage:
  ominullctl [flags] <command> [subcommand] [args...]

Local Setup Commands:
  setup-token [--rotate] [--path FILE]    View or rotate the private local setup token
  setup-status [--path FILE]              Check setup onboarding completion status

Fleet & CyberOps Commands:
  status                                  View fleet hierarchy and overall hub status
  endpoints list|show <id>                Inspect enrolled endpoint agents
  scanner scan|status|assets|train        Subnet discovery, sweeps, and OS fingerprinting
  alerts list                             List active behavioral anomalies and threat alerts
  learning windows|open|close             Inspect, open and close learning windows
  learning proposals|apply                Read what a window learned and apply named proposals
  mesh quarantine|release <ip>            Enforce or lift subnet quarantine mesh
  agents versions|update <id|all>         Inspect fleet version currency and publish releases
  install reports [list|show]             Inspect bootstrap error reports

Forensics & Response Commands:
  response jobs list|cancel <id>          Inspect and manage durable response jobs
  response-auth status|recovery-token     Inspect Response Authority and issue emergency recovery
  forensics list|show|verify <manifest>   Manage and verify forensic evidence collections
  scripts list|show|create|update|retire  Manage versioned immutable script library
  shell sessions|show|close <id>          List and close active terminal sessions
  software list                           Inspect authoritative endpoint package inventory
  vulnerabilities list|show|sync          Correlate endpoint packages with NVD/KEV feeds

Console & Trust Commands:
  console export-ca [--out FILE]          Export the hub Root CA certificate for browser trust
  console trust-instructions              Show per-platform commands to install Root CA into trust stores
  console status                          Inspect console HTTPS listener, certificate source, and RP ID

Global Flags:
  --url URL             Hub API URL (default: http://127.0.0.1:9999 or $OMINULL_HUB_URL)
  --api-key-file FILE   API key file (default: /etc/ominull/admin.key or $OMINULL_API_KEY_FILE)
  --json                Emit versioned JSON output to stdout
  --tenant TENANT_ID    Target tenant scope (default: default)
  --limit N             Page limit for lists (default: 50)
`)
}
