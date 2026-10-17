package main

// ominullctl maint: run maintenance packages under the owner's approval and
// read where each host stands.
//
//	maint run ENDPOINT[,ENDPOINT...] PKG... [--mode audit|enforce] [--no-wait]
//	maint status ENDPOINT
//	maint schedule ENDPOINT[,ENDPOINT...] PKG --every hourly|daily|weekly [--mode audit|enforce]
//	maint rules | maint forget-rule [ID]

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

func (c *APIClient) cmdMaint(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: ominullctl maint run|status|schedule|rules|forget-rule")
	}
	switch args[0] {
	case "run":
		return c.maintRun(args[1:])
	case "status":
		if len(args) != 2 {
			return fmt.Errorf("usage: ominullctl maint status ENDPOINT")
		}
		return c.maintStatus(args[1])
	case "schedule":
		return c.maintSchedule(args[1:])
	case "rules":
		raw, err := c.doRequest(http.MethodGet, "/api/v1/approvals/rules", nil)
		if err != nil {
			return err
		}
		var out struct {
			Rules []struct {
				ID       string    `json:"id"`
				Label    string    `json:"label"`
				EndsAt   time.Time `json:"ends_at"`
				LastUsed time.Time `json:"last_used_at"`
			} `json:"package_rules"`
		}
		if err := json.Unmarshal(raw, &out); err != nil || c.cfg.JSONOutput {
			fmt.Println(string(raw))
			return nil
		}
		if len(out.Rules) == 0 {
			fmt.Println("No approve-all rule for maintenance packages.")
		}
		for _, r := range out.Rules {
			fmt.Printf("%s  %s (ends %s)\n", r.ID, r.Label, r.EndsAt.Local().Format("2006-01-02"))
		}
		return nil
	case "forget-rule":
		q := url.Values{"kind": {"packages"}}
		if len(args) > 1 {
			q.Set("id", args[1])
		}
		raw, err := c.doRequest(http.MethodDelete, "/api/v1/approvals/rules?"+q.Encode(), nil)
		if err == nil {
			fmt.Println(string(raw))
		}
		return err
	}
	return fmt.Errorf("usage: ominullctl maint run|status|schedule|rules|forget-rule")
}

// splitMaintArgs separates --mode/--every/--no-wait from positional words.
func splitMaintArgs(args []string) (pos []string, flags map[string]string, err error) {
	flags = map[string]string{"mode": "audit"}
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--no-wait":
			flags["no-wait"] = "1"
		case a == "--mode" || a == "--every":
			if i+1 >= len(args) {
				return nil, nil, fmt.Errorf("%s needs a value", a)
			}
			flags[strings.TrimPrefix(a, "--")] = args[i+1]
			i++
		case strings.HasPrefix(a, "--mode=") || strings.HasPrefix(a, "--every="):
			k, v, _ := strings.Cut(strings.TrimPrefix(a, "--"), "=")
			flags[k] = v
		case strings.HasPrefix(a, "--"):
			return nil, nil, fmt.Errorf("unknown flag %s", a)
		default:
			pos = append(pos, a)
		}
	}
	if m := flags["mode"]; m != "audit" && m != "enforce" {
		return nil, nil, fmt.Errorf("--mode must be audit or enforce")
	}
	return pos, flags, nil
}

func (c *APIClient) maintRun(args []string) error {
	pos, flags, err := splitMaintArgs(args)
	if err != nil {
		return err
	}
	if len(pos) < 2 {
		return fmt.Errorf("usage: ominullctl maint run ENDPOINT[,ENDPOINT...] PKG... [--mode audit|enforce] [--no-wait]")
	}
	body := map[string]interface{}{"endpoint_ids": strings.Split(pos[0], ","), "packages": pos[1:], "mode": flags["mode"]}
	raw, err := c.ownerApproved(http.MethodPost, "/api/v1/maintenance/run", body)
	if err != nil {
		return err
	}
	var out struct {
		Jobs []struct {
			JobID      string `json:"job_id"`
			EndpointID string `json:"endpoint_id"`
			Package    string `json:"package"`
		} `json:"jobs"`
		Error string `json:"error"`
	}
	if json.Unmarshal(raw, &out) != nil || len(out.Jobs) == 0 {
		return fmt.Errorf("the hub created no jobs: %s", strings.TrimSpace(string(raw)))
	}
	for _, j := range out.Jobs {
		fmt.Fprintf(os.Stderr, "[*] %s on %s: job %s\n", j.Package, j.EndpointID, j.JobID)
	}
	if flags["no-wait"] != "" {
		return nil
	}
	// Each package prints one JSON result line; packages run up to an hour.
	failed := 0
	for _, j := range out.Jobs {
		line, state, err := c.waitPackageJob(j.JobID, 75*time.Minute)
		if err != nil {
			return err
		}
		fmt.Printf("%s %s %s\n", j.EndpointID, j.Package, line)
		if state != "succeeded" {
			failed++
		}
	}
	if failed > 0 {
		return fmt.Errorf("%d of %d package runs did not succeed", failed, len(out.Jobs))
	}
	return nil
}

// waitPackageJob polls one job until it finishes and returns its result line.
func (c *APIClient) waitPackageJob(id string, limit time.Duration) (string, string, error) {
	deadline := time.Now().Add(limit)
	for time.Now().Before(deadline) {
		raw, err := c.doRequest(http.MethodGet, "/api/v1/response/jobs?id="+url.QueryEscape(id), nil)
		if err == nil {
			var job struct {
				State      string `json:"state"`
				ResultJSON string `json:"result_json"`
				ErrorCode  string `json:"error_code"`
			}
			if json.Unmarshal(raw, &job) == nil {
				switch job.State {
				case "succeeded", "failed", "cancelled":
					var res struct {
						Stdout    string `json:"stdout"`
						ErrorCode string `json:"error_code"`
					}
					_ = json.Unmarshal([]byte(job.ResultJSON), &res)
					lines := strings.Split(strings.TrimRight(res.Stdout, "\r\n\t "), "\n")
					last := strings.TrimSpace(lines[len(lines)-1])
					if !strings.HasPrefix(last, "{") {
						code := res.ErrorCode
						if code == "" {
							code = job.ErrorCode
						}
						last = fmt.Sprintf(`{"state":"%s","detail":{"error":"no result line","code":%q}}`, job.State, code)
					}
					return last, job.State, nil
				}
			}
		}
		time.Sleep(10 * time.Second)
	}
	return "", "", fmt.Errorf("job %s did not finish within %s; check later with: ominullctl maint status", id, limit)
}

func (c *APIClient) maintStatus(endpoint string) error {
	raw, err := c.doRequest(http.MethodGet, "/api/v1/maintenance?endpoint_id="+url.QueryEscape(endpoint), nil)
	if err != nil {
		return err
	}
	if c.cfg.JSONOutput {
		fmt.Println(string(raw))
		return nil
	}
	var out struct {
		Packages []struct {
			Name    string `json:"name"`
			Risk    string `json:"risk"`
			Version int    `json:"latest_version"`
			Last    *struct {
				State       string     `json:"state"`
				Mode        string     `json:"mode"`
				Reason      string     `json:"reason"`
				Reboot      bool       `json:"reboot"`
				Changed     []string   `json:"changed"`
				Version     int        `json:"version"`
				RequestedAt time.Time  `json:"requested_at"`
				CompletedAt *time.Time `json:"completed_at"`
			} `json:"last"`
		} `json:"packages"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return fmt.Errorf("unreadable answer: %s", strings.TrimSpace(string(raw)))
	}
	if len(out.Packages) == 0 {
		fmt.Println("No maintenance packages fit this host.")
		return nil
	}
	for _, p := range out.Packages {
		if p.Last == nil {
			fmt.Printf("%-20s v%-3d never run\n", p.Name, p.Version)
			continue
		}
		l := p.Last
		at := l.RequestedAt
		if l.CompletedAt != nil {
			at = *l.CompletedAt
		}
		extra := ""
		if l.Reason != "" {
			extra += " - " + l.Reason
		}
		if len(l.Changed) > 0 {
			extra += fmt.Sprintf(" (%d changed)", len(l.Changed))
		}
		if l.Reboot {
			extra += " (reboot needed)"
		}
		fmt.Printf("%-20s v%-3d %-9s %-8s %s%s\n", p.Name, l.Version, l.State, l.Mode, at.Local().Format("2006-01-02 15:04"), extra)
	}
	return nil
}

func (c *APIClient) maintSchedule(args []string) error {
	pos, flags, err := splitMaintArgs(args)
	if err != nil {
		return err
	}
	if len(pos) != 2 || flags["every"] == "" {
		return fmt.Errorf("usage: ominullctl maint schedule ENDPOINT[,ENDPOINT...] PKG --every hourly|daily|weekly [--mode audit|enforce]")
	}
	raw, err := c.doRequest(http.MethodGet, "/api/v1/maintenance?endpoint_id="+url.QueryEscape(strings.Split(pos[0], ",")[0]), nil)
	if err != nil {
		return err
	}
	var st struct {
		Packages []struct {
			ScriptID string `json:"script_id"`
			Name     string `json:"name"`
			Timeout  int    `json:"timeout"`
			Version  int    `json:"latest_version"`
		} `json:"packages"`
	}
	if err := json.Unmarshal(raw, &st); err != nil {
		return err
	}
	for _, p := range st.Packages {
		if p.Name != pos[1] {
			continue
		}
		// Same timeout and output bound as `maint run`, so a run the owner's
		// package rule covers is the run this schedule asks for.
		body := map[string]interface{}{
			"script_id": p.ScriptID, "version": p.Version, "target_endpoints": strings.Split(pos[0], ","),
			"parameters": map[string]string{"mode": flags["mode"]}, "recurrence": flags["every"],
			"timeout_seconds": p.Timeout, "max_output_bytes": 1 << 20,
		}
		out, err := c.doRequest(http.MethodPost, "/api/v1/scripts/schedules", body)
		if err == nil {
			fmt.Println(string(out))
			fmt.Fprintln(os.Stderr, "[*] Scheduled runs happen only while the owner's approve-all rule covers this exact package run; make one by answering \"Approve all like this\" on a `maint run` ask.")
		}
		return err
	}
	return fmt.Errorf("no package called %q fits %s", pos[1], pos[0])
}
