package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// ominullctl host-script run: a released package on a host-authority host
// (docs/HOST_AUTHORITY.md). Runs where Nightshift's signer lives, never on the
// hub: reserve a job for the package's payload, have Nightshift sign a V3
// grant over it (an owner tap, or the always-on signer with --auto), submit
// it, then wait on the job like maint wait.

// Exit codes beyond maint wait's (0 ok, 3 failed, 4 attention, 5 timeout).
const (
	exitHostLocked   = 6 // the endpoint's lock level or manifest refuses scripts, or it pins no host authority
	exitHostLapsed   = 7 // the reservation lapsed or was used before the grant came back
	exitHostRefused  = 8 // the signer refused (owner declined, no standing rule, signer closed)
	exitHostRejected = 9 // the hub refused the signed grant
)

// hostSignerCommand is Nightshift's CLI; OMINULL_HOST_SIGNER overrides it.
func hostSignerCommand() string {
	if s := strings.TrimSpace(os.Getenv("OMINULL_HOST_SIGNER")); s != "" {
		return s
	}
	return "nightshift"
}

func (c *APIClient) cmdHostScript(args []string) error {
	usage := "usage: ominullctl host-script run ENDPOINT --package NAME [--mode audit|enforce|revert] [--auto] [--host LABEL] [--timeout 30m] [--no-wait]"
	if len(args) == 0 || args[0] != "run" {
		return &exitCodeError{2, usage}
	}
	var pos []string
	flags := map[string]string{}
	for i := 1; i < len(args); i++ {
		a := args[i]
		switch a {
		case "--auto", "--no-wait":
			flags[a[2:]] = "1"
		case "--package", "--mode", "--host", "--timeout":
			if i+1 >= len(args) {
				return &exitCodeError{2, a + " needs a value"}
			}
			flags[a[2:]] = args[i+1]
			i++
		default:
			if strings.HasPrefix(a, "--") {
				return &exitCodeError{2, "unknown flag " + a}
			}
			pos = append(pos, a)
		}
	}
	if len(pos) != 1 || flags["package"] == "" {
		return &exitCodeError{2, usage}
	}
	var timeout time.Duration
	if t := flags["timeout"]; t != "" {
		d, err := time.ParseDuration(t)
		if err != nil || d <= 0 {
			return &exitCodeError{2, "--timeout takes a duration such as 30m"}
		}
		timeout = d
	}
	ep := pos[0]
	base := "/api/v1/endpoints/" + url.PathEscape(ep) + "/jobs/signed"

	// 1. Reserve.
	reqBody, _ := json.Marshal(map[string]string{"package": flags["package"], "mode": flags["mode"]})
	raw, status, err := c.doRaw(http.MethodPost, base+"/reserve", reqBody)
	if err != nil {
		return err
	}
	if status != http.StatusOK {
		msg := hubError(raw, status)
		switch status {
		case http.StatusForbidden:
			return &exitCodeError{exitHostLocked, "the endpoint refuses signed scripts: " + msg}
		case http.StatusConflict:
			return &exitCodeError{exitHostLocked, "the endpoint cannot take a signed job now: " + msg}
		}
		return fmt.Errorf("reserve: %s", msg)
	}
	var res struct {
		JobID       string `json:"job_id"`
		PayloadJSON string `json:"payload_json"`
		ExpiresAt   int64  `json:"expires_at"`
	}
	if err := json.Unmarshal(raw, &res); err != nil || res.JobID == "" || res.PayloadJSON == "" {
		return fmt.Errorf("unreadable reserve answer: %s", strings.TrimSpace(string(raw)))
	}
	fmt.Fprintf(os.Stderr, "[*] reserved job %s for %s on %s; asking Nightshift to sign (reservation lapses %s)\n",
		res.JobID, flags["package"], ep, time.Unix(res.ExpiresAt, 0).Local().Format("15:04:05"))

	// 2. Sign: the reserve answer goes to the signer verbatim, in a private file.
	dir, err := os.MkdirTemp("", "ominull-host-grant-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	resFile := filepath.Join(dir, "reservation.json")
	if err := os.WriteFile(resFile, raw, 0o600); err != nil {
		return err
	}
	signArgs := []string{"sign", "host-grant", resFile}
	if h := flags["host"]; h != "" {
		signArgs = append(signArgs, "--host", h)
	}
	if flags["auto"] != "" {
		signArgs = append(signArgs, "--auto")
	}
	cmd := exec.Command(hostSignerCommand(), signArgs...)
	var out, errOut bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errOut
	runErr := cmd.Run()
	var grant map[string]interface{}
	if runErr != nil || json.Unmarshal(bytes.TrimSpace(out.Bytes()), &grant) != nil || grant["signature"] == nil {
		why := strings.TrimSpace(out.String() + " " + errOut.String())
		if why == "" && runErr != nil {
			why = runErr.Error()
		}
		if time.Now().Unix() > res.ExpiresAt {
			return &exitCodeError{exitHostLapsed, "the reservation lapsed before Nightshift signed; run again: " + why}
		}
		return &exitCodeError{exitHostRefused, "Nightshift did not sign: " + why}
	}

	// 3. Submit the payload exactly as reserved, with the grant.
	// Built by hand: an encoder would re-escape the payload's bytes.
	grantJSON := bytes.TrimSpace(out.Bytes())
	submit := []byte(`{"payload":` + res.PayloadJSON + `,"grant":` + string(grantJSON) + `}`)
	raw, status, err = c.doRaw(http.MethodPost, base, submit)
	if err != nil {
		return err
	}
	if status != http.StatusOK {
		msg := hubError(raw, status)
		switch status {
		case http.StatusConflict:
			return &exitCodeError{exitHostLapsed, "the hub no longer holds the reservation (lapsed or used); run again: " + msg}
		case http.StatusForbidden:
			return &exitCodeError{exitHostLocked, "the endpoint refuses signed scripts: " + msg}
		}
		return &exitCodeError{exitHostRejected, "the hub refused the signed grant: " + msg}
	}
	fmt.Printf("job %s %s %s\n", res.JobID, ep, flags["package"])
	if flags["no-wait"] != "" {
		return nil
	}
	// 4. Wait like maint wait (the hub holds each request open).
	return c.waitRuns([]string{res.JobID}, true, timeout)
}

// doRaw sends body as is and returns the answer whatever its status.
func (c *APIClient) doRaw(method, endpoint string, body []byte) ([]byte, int, error) {
	req, err := http.NewRequest(method, strings.TrimRight(c.cfg.HubURL, "/")+endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, 0, err
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
		return nil, 0, fmt.Errorf("HTTP request failed: %w", err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return raw, resp.StatusCode, err
}

// hubError is the hub's error text, or the status.
func hubError(raw []byte, status int) string {
	var e struct {
		Error string `json:"error"`
	}
	if json.Unmarshal(raw, &e) == nil && e.Error != "" {
		return e.Error
	}
	if s := strings.TrimSpace(string(raw)); s != "" {
		return s
	}
	return fmt.Sprintf("HTTP %d", status)
}
