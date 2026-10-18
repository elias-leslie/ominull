package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

// Exit codes of ominullctl maint wait (and maint run, maint script without
// --no-wait), so an agent running it as a background task can branch on them.
const (
	exitWaitOK        = 0
	exitWaitFailed    = 3 // a run ended without doing its job (failed, cancelled, not run)
	exitWaitAttention = 4 // a run needs attention (stalled, waiting on a window, no result)
	exitWaitTimeout   = 5 // --timeout passed with nothing to report
)

// exitCodeError ends ominullctl with a given exit code.
type exitCodeError struct {
	code int
	msg  string
}

func (e *exitCodeError) Error() string { return e.msg }

func exitCodeOf(err error) (int, string) {
	var ec *exitCodeError
	if errors.As(err, &ec) {
		return ec.code, ec.msg
	}
	return 1, err.Error()
}

type waitEntry struct {
	ID         string `json:"id"`
	JobID      string `json:"job_id"`
	EndpointID string `json:"endpoint_id"`
	Host       string `json:"host"`
	Package    string `json:"package"`
	Step       string `json:"step"`
	State      string `json:"state"`
	Final      bool   `json:"final"`
	Attention  bool   `json:"attention"`
	Failed     bool   `json:"failed"`
	Reason     string `json:"reason"`
	Line       string `json:"line"`
	Progress   *struct {
		Pct     int    `json:"pct"`
		Message string `json:"message"`
	} `json:"progress"`
	Window *struct {
		Title   string `json:"title"`
		Process string `json:"process"`
		Session int    `json:"session"`
	} `json:"window"`
}

type waitView struct {
	Entries   []waitEntry `json:"entries"`
	Unknown   []string    `json:"unknown"`
	AnyFinal  bool        `json:"any_final"`
	AllFinal  bool        `json:"all_final"`
	Attention bool        `json:"attention"`
	Failed    bool        `json:"failed"`
}

// waitLine is one line per run: who, what, state, and what it says.
func waitLine(e waitEntry) string {
	who := e.EndpointID
	if e.Host != "" && !strings.EqualFold(e.Host, e.EndpointID) {
		who = e.EndpointID + " (" + e.Host + ")"
	}
	what := e.Package
	if e.Step != "" {
		what += " step " + e.Step
	}
	parts := []string{who, what, e.State}
	if e.JobID != "" {
		parts = append(parts, "job "+e.JobID)
	}
	if e.Reason != "" {
		parts = append(parts, "- "+e.Reason)
	} else if e.Progress != nil && e.Progress.Message != "" && !e.Final {
		parts = append(parts, "- "+e.Progress.Message)
	}
	if e.Final && e.Line != "" {
		parts = append(parts, e.Line)
	}
	return strings.Join(parts, " ")
}

// waitPollSeconds is how long the hub may hold one wait request.
var waitPollSeconds = 25

// waitRuns long-polls the hub until any run (all with all) ends or one needs
// attention, prints one line per run and returns the exit code. The hub
// holds each request open and answers on the event; nothing here polls.
func (c *APIClient) waitRuns(ids []string, all bool, timeout time.Duration) error {
	var deadline time.Time
	if timeout > 0 {
		deadline = time.Now().Add(timeout)
	}
	// The hub holds each request up to waitPollSeconds; the ordinary 15 s
	// client timeout would cut every quiet poll short and give up after a
	// few minutes of nothing happening, so the wait gets its own client.
	if c.httpClient.Timeout > 0 && c.httpClient.Timeout < time.Duration(waitPollSeconds+15)*time.Second {
		hc := *c.httpClient
		hc.Timeout = time.Duration(waitPollSeconds+15) * time.Second
		c = &APIClient{cfg: c.cfg, httpClient: &hc}
	}
	q := url.Values{"ids": {strings.Join(ids, ",")}, "wait": {strconv.Itoa(waitPollSeconds)}}
	if all {
		q.Set("all", "1")
	}
	failures := 0
	for {
		raw, status, err := c.doRequestWith(http.MethodGet, "/api/v1/maintenance/wait?"+q.Encode(), nil, nil)
		if err != nil || status != http.StatusOK {
			// A hub restart or a network blip: try again shortly, a few times.
			if failures++; failures > 20 {
				if err == nil {
					err = fmt.Errorf("hub answered %d: %s", status, strings.TrimSpace(string(raw)))
				}
				return err
			}
			time.Sleep(3 * time.Second)
			continue
		}
		failures = 0
		var v waitView
		if err := json.Unmarshal(raw, &v); err != nil {
			return fmt.Errorf("unreadable answer: %v", err)
		}
		if len(v.Unknown) > 0 && len(v.Entries) == 0 {
			return &exitCodeError{2, "no such job, run or playbook run: " + strings.Join(v.Unknown, ", ")}
		}
		done := v.Attention || (all && v.AllFinal) || (!all && v.AnyFinal)
		if !done && (deadline.IsZero() || time.Now().Before(deadline)) {
			continue
		}
		if c.cfg.JSONOutput {
			fmt.Println(string(raw))
		} else {
			for _, e := range v.Entries {
				fmt.Println(waitLine(e))
			}
			for _, id := range v.Unknown {
				fmt.Fprintf(os.Stderr, "[!] unknown id %s\n", id)
			}
		}
		switch {
		case v.Attention:
			return &exitCodeError{exitWaitAttention, "a run needs attention"}
		case v.Failed:
			return &exitCodeError{exitWaitFailed, "a run did not succeed"}
		case !done:
			return &exitCodeError{exitWaitTimeout, "nothing to report within " + timeout.String()}
		}
		return nil
	}
}

func (c *APIClient) maintWait(args []string) error {
	var ids []string
	all := false
	var timeout time.Duration
	for i := 0; i < len(args); i++ {
		switch a := args[i]; {
		case a == "--all":
			all = true
		case a == "--timeout" && i+1 < len(args):
			d, err := time.ParseDuration(args[i+1])
			if err != nil || d <= 0 {
				return fmt.Errorf("--timeout takes a duration such as 30m")
			}
			timeout = d
			i++
		case strings.HasPrefix(a, "--"):
			return fmt.Errorf("unknown flag %s", a)
		default:
			for _, id := range strings.Split(a, ",") {
				if id = strings.TrimSpace(id); id != "" {
					ids = append(ids, id)
				}
			}
		}
	}
	if len(ids) == 0 {
		return &exitCodeError{2, "usage: ominullctl maint wait ID... [--all] [--timeout 30m]  (job, run or playbook run ids)"}
	}
	return c.waitRuns(ids, all, timeout)
}

// printRunIDs prints a run's ids on stdout, one per line, for scripts.
func printRunIDs(runID string, jobs []runJob) {
	if runID != "" {
		fmt.Printf("run %s\n", runID)
	}
	for _, j := range jobs {
		fmt.Printf("job %s %s %s\n", j.JobID, j.EndpointID, j.Package)
	}
}

type runJob struct {
	JobID      string `json:"job_id"`
	EndpointID string `json:"endpoint_id"`
	Package    string `json:"package"`
}

// maintScript runs a one-off script: one owner tap, then the same runner,
// supervision, result and audit as a package.
func (c *APIClient) maintScript(args []string) error {
	usage := "usage: ominullctl maint script ENDPOINT[,ENDPOINT...] --file F --reason TEXT [--name N] [--shell powershell|bash|sh] [--timeout 10m] [--no-wait]"
	var pos []string
	flags := map[string]string{}
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch a {
		case "--no-wait":
			flags["no-wait"] = "1"
		case "--file", "--reason", "--name", "--shell", "--timeout":
			if i+1 >= len(args) {
				return fmt.Errorf("%s needs a value", a)
			}
			flags[a[2:]] = args[i+1]
			i++
		default:
			if strings.HasPrefix(a, "--") {
				return fmt.Errorf("unknown flag %s", a)
			}
			pos = append(pos, a)
		}
	}
	if len(pos) != 1 || flags["file"] == "" || flags["reason"] == "" {
		return fmt.Errorf("%s", usage)
	}
	src, err := os.ReadFile(flags["file"])
	if err != nil {
		return err
	}
	shell := flags["shell"]
	if shell == "" {
		switch {
		case strings.HasSuffix(flags["file"], ".ps1"):
			shell = "powershell"
		case strings.HasSuffix(flags["file"], ".sh"):
			shell = "sh"
			if strings.HasPrefix(string(src), "#!/bin/bash") || strings.HasPrefix(string(src), "#!/usr/bin/env bash") {
				shell = "bash"
			}
		default:
			return fmt.Errorf("say --shell powershell, bash or sh")
		}
	}
	name := flags["name"]
	if name == "" {
		name = strings.TrimSuffix(strings.TrimSuffix(baseName(flags["file"]), ".ps1"), ".sh")
	}
	body := map[string]interface{}{"endpoint_ids": strings.Split(pos[0], ","), "name": name, "shell": shell,
		"source": string(src), "reason": flags["reason"]}
	if t := flags["timeout"]; t != "" {
		d, err := time.ParseDuration(t)
		if err != nil {
			return fmt.Errorf("--timeout takes a duration such as 10m")
		}
		body["timeout_seconds"] = int(d / time.Second)
	}
	raw, err := c.ownerApproved(http.MethodPost, "/api/v1/maintenance/script", body)
	if err != nil {
		return err
	}
	return c.afterRun(raw, flags["no-wait"] != "")
}

// afterRun prints a started run's ids and, unless noWait, waits for every
// run to end (or one to need attention).
func (c *APIClient) afterRun(raw []byte, noWait bool) error {
	var out struct {
		RunID string   `json:"run_id"`
		Jobs  []runJob `json:"jobs"`
	}
	if json.Unmarshal(raw, &out) != nil || len(out.Jobs) == 0 {
		return fmt.Errorf("the hub created no jobs: %s", strings.TrimSpace(string(raw)))
	}
	printRunIDs(out.RunID, out.Jobs)
	if noWait {
		return nil
	}
	ids := []string{out.RunID}
	if out.RunID == "" {
		ids = ids[:0]
		for _, j := range out.Jobs {
			ids = append(ids, j.JobID)
		}
	}
	return c.waitRuns(ids, true, 0)
}

func baseName(p string) string {
	if i := strings.LastIndexAny(p, `/\`); i >= 0 {
		return p[i+1:]
	}
	return p
}

// maintPromote turns a script into a library package (it needs a package
// header): a one-off run's job id, or --file.
func (c *APIClient) maintPromote(args []string) error {
	body := map[string]string{}
	switch {
	case len(args) == 2 && args[0] == "--file":
		src, err := os.ReadFile(args[1])
		if err != nil {
			return err
		}
		body["source"] = string(src)
	case len(args) == 1 && !strings.HasPrefix(args[0], "--"):
		body["job_id"] = args[0]
	default:
		return fmt.Errorf("usage: ominullctl maint promote JOB_ID | --file F")
	}
	raw, err := c.doRequest(http.MethodPost, "/api/v1/maintenance/script/promote", body)
	if err != nil {
		return err
	}
	var out struct {
		Package string `json:"package"`
		Version int    `json:"version"`
		Digest  string `json:"digest"`
	}
	_ = json.Unmarshal(raw, &out)
	c.printOutput(out, func() {
		fmt.Printf("[+] %s v%d is in the library (digest %s). It is not a released package, so every run asks the owner until a hub release ships it.\n", out.Package, out.Version, out.Digest)
	})
	return nil
}

// maintCancel asks a run's job to stop: the agent kills the run and its
// children at its next heartbeat and reports it cancelled.
func (c *APIClient) maintCancel(args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("usage: ominullctl maint cancel JOB_ID")
	}
	raw, err := c.doRequest(http.MethodPost, "/api/v1/response/jobs/cancel", map[string]string{"job_id": args[0]})
	if err == nil {
		fmt.Println(strings.TrimSpace(string(raw)))
	}
	return err
}
