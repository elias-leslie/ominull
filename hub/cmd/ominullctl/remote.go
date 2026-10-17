package main

// Remote commands for agents (and people) at a terminal of their own: run a
// command on an enrolled endpoint and get its stdout, stderr and exit code
// back, keep one approved session open for a run of commands, and copy small
// files. Everything rides the hub's existing terminal session: the owner
// approves each session with one passkey tap (POST /api/v1/terminal/sessions
// answers 202 until they do), the session is recorded like any console shell,
// and it ends at the hub's session limits. No new listener on the endpoint.
//
// A terminal is a pty, made for people. To give a caller clean output the
// command travels base64-encoded, runs in a child process with stdout and
// stderr captured to files, and comes back base64-encoded between marker
// lines with its exit code and byte counts; prompts, echo and escape
// sequences around it are ignored. Linux runs /bin/sh, Windows PowerShell.

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/gorilla/websocket"
)

const (
	remoteChunk       = 512              // base64 characters per typed line (well under a tty's 4095-byte line)
	remoteMaxPut      = 2 << 20          // bytes a put sends
	remoteMaxOutput   = 8 << 20          // bytes of stdout+stderr one command may return
	remoteReadyWait   = 90 * time.Second // agent connect + shell start
	remoteReadyRetry  = 10 * time.Second
	remoteDefaultTTL  = 45 * time.Minute
	remoteMaxTTL      = 60 * time.Minute // the hub ends every session at 60 minutes
	remoteFrameStdin  = "stdin"
	remoteFrameResize = "resize"
	remoteFrameClose  = "close"
)

// remoteShellKind is the remote shell dialect, chosen from the program.
type remoteShellKind int

const (
	shellPOSIX remoteShellKind = iota
	shellPowerShell
)

func shellKindFor(program string) remoteShellKind {
	if strings.Contains(strings.ToLower(program), "powershell") || strings.Contains(strings.ToLower(program), "pwsh") {
		return shellPowerShell
	}
	return shellPOSIX
}

// remoteJob is one unit of work: run a command, write a file, read a file.
type remoteJob struct {
	Op      string `json:"op"` // exec | put | get
	Command string `json:"command,omitempty"`
	Path    string `json:"path,omitempty"`
	Data    []byte `json:"data,omitempty"`
	Timeout int    `json:"timeout_s,omitempty"`
}

// remoteResult is what came back.
type remoteResult struct {
	Stdout []byte `json:"stdout"`
	Stderr []byte `json:"stderr"`
	Exit   int    `json:"exit"`
	Error  string `json:"error,omitempty"`
}

func newNonce() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func psQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }
func shQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }
func chunks(s string) []string { // remoteChunk-sized pieces of s
	var out []string
	for len(s) > remoteChunk {
		out = append(out, s[:remoteChunk])
		s = s[remoteChunk:]
	}
	if s != "" {
		out = append(out, s)
	}
	return out
}

// readyScript turns the interactive shell quiet (no prompt, no echo where
// the shell allows it) and prints the ready marker, all on one line: text
// typed ahead while PowerShell is still loading PSReadLine is lost when the
// module is removed, so nothing may follow on a second line. The typed text
// never contains the marker itself.
func readyScript(kind remoteShellKind, nonce string) string {
	if kind == shellPowerShell {
		return "Remove-Module PSReadLine -ErrorAction SilentlyContinue; function prompt {' '}; $ProgressPreference='SilentlyContinue'; Write-Output ('OMNX'+'" + nonce + ":R')\r"
	}
	return "stty -echo 2>/dev/null; PS1=''; PS2=''; export TERM=dumb; printf '%s%s\\n' OMNX '" + nonce + ":R'\n"
}

// psEnvPrefix gives the command the environment a logged-in shell has: the
// agent starts the terminal with a minimal one (PATH, SYSTEMROOT, COMSPEC),
// so PATHEXT is PowerShell's bare ".CPL" and `hostname` is not found.
const psEnvPrefix = "$env:PATHEXT='.COM;.EXE;.BAT;.CMD;.VBS;.VBE;.JS;.JSE;.WSF;.WSH;.MSC;.CPL'\r\n" +
	"if(-not $env:windir){$env:windir=$env:SystemRoot}\r\n" +
	"if(-not $env:TEMP){$env:TEMP=[IO.Path]::GetTempPath().TrimEnd('\\'); $env:TMP=$env:TEMP}\r\n" +
	"if(-not $env:ProgramData){$env:ProgramData='C:\\ProgramData'}\r\n" +
	"if(-not $env:COMPUTERNAME){$env:COMPUTERNAME=[Environment]::MachineName}\r\n"

// jobScript is the text typed into the shell for one job.
func jobScript(kind remoteShellKind, job remoteJob, nonce string) (string, error) {
	var payload []byte
	switch job.Op {
	case "exec":
		if kind == shellPowerShell {
			// The child reads the file as UTF-8 (BOM) and exits with the
			// command's own code: exit N, else a failed native command's
			// code, else 1 if the last statement failed.
			payload = append([]byte("\xef\xbb\xbf"+psEnvPrefix+"$ErrorActionPreference='Continue'\r\n[Console]::OutputEncoding=[Text.Encoding]::UTF8\r\n$global:LASTEXITCODE=0\r\n"), job.Command...)
			payload = append(payload, "\r\nif(-not $?){if($LASTEXITCODE){exit $LASTEXITCODE}; exit 1}; exit $LASTEXITCODE\r\n"...)
		} else {
			payload = []byte(job.Command + "\n")
		}
	case "put":
		payload = job.Data
	case "get":
	default:
		return "", fmt.Errorf("unknown remote operation %q", job.Op)
	}
	if (job.Op == "put" || job.Op == "get") && strings.TrimSpace(job.Path) == "" {
		return "", errors.New("a remote path is required")
	}
	enc := base64.StdEncoding.EncodeToString(payload)
	var b strings.Builder
	if kind == shellPowerShell {
		nl := "\r"
		b.WriteString("$__d=Join-Path ([IO.Path]::GetTempPath()) ('omn'+[guid]::NewGuid().ToString('N')); $null=New-Item -ItemType Directory -Path $__d; $__i=New-Object Text.StringBuilder" + nl)
		for _, c := range chunks(enc) {
			b.WriteString("$null=$__i.Append('" + c + "')" + nl)
		}
		b.WriteString("[IO.File]::WriteAllBytes(\"$__d\\s\",[Convert]::FromBase64String($__i.ToString())); $null=New-Item -ItemType File -Force -Path \"$__d\\o\",\"$__d\\e\",\"$__d\\n\"" + nl)
		switch job.Op {
		case "exec":
			b.WriteString("Copy-Item \"$__d\\s\" \"$__d\\s.ps1\"; $__p=Start-Process -FilePath powershell.exe -ArgumentList @('-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File',('\"'+$__d+'\\s.ps1\"')) -RedirectStandardInput \"$__d\\n\" -RedirectStandardOutput \"$__d\\o\" -RedirectStandardError \"$__d\\e\" -NoNewWindow -Wait -PassThru; $__c=$__p.ExitCode" + nl)
		case "put":
			b.WriteString("try { [IO.File]::Copy(\"$__d\\s\"," + psQuote(job.Path) + ",$true); $__c=0 } catch { [IO.File]::WriteAllText(\"$__d\\e\",$_.Exception.Message); $__c=1 }" + nl)
		case "get":
			b.WriteString("try { [IO.File]::Copy(" + psQuote(job.Path) + ",\"$__d\\o\",$true); $__c=0 } catch { [IO.File]::WriteAllText(\"$__d\\e\",$_.Exception.Message); $__c=1 }" + nl)
		}
		b.WriteString("Write-Output ('OMNX'+'" + nonce + ":O'); $__b=[IO.File]::ReadAllBytes(\"$__d\\o\"); if($__b.Length){[Convert]::ToBase64String($__b,'InsertLineBreaks')}; " +
			"Write-Output ('OMNX'+'" + nonce + ":E'); $__f=[IO.File]::ReadAllBytes(\"$__d\\e\"); if($__f.Length){[Convert]::ToBase64String($__f,'InsertLineBreaks')}; " +
			"Write-Output ('OMNX'+'" + nonce + ":Z:'+$__c+':'+$__b.Length+':'+$__f.Length); Remove-Item -Recurse -Force $__d" + nl)
		return b.String(), nil
	}
	b.WriteString("__d=$(mktemp -d) && : >\"$__d/i\" && : >\"$__d/o\" && : >\"$__d/e\"\n")
	for _, c := range chunks(enc) {
		b.WriteString("printf %s '" + c + "' >>\"$__d/i\"\n")
	}
	b.WriteString("base64 -d \"$__d/i\" >\"$__d/s\"\n")
	switch job.Op {
	case "exec":
		b.WriteString("sh \"$__d/s\" >\"$__d/o\" 2>\"$__d/e\" </dev/null; __c=$?\n")
	case "put":
		b.WriteString("cat \"$__d/s\" >" + shQuote(job.Path) + " 2>\"$__d/e\"; __c=$?\n")
	case "get":
		b.WriteString("cat -- " + shQuote(job.Path) + " >\"$__d/o\" 2>\"$__d/e\"; __c=$?\n")
	}
	b.WriteString("printf '%s%s\\n' OMNX '" + nonce + ":O'; base64 \"$__d/o\"; printf '%s%s\\n' OMNX '" + nonce + ":E'; base64 \"$__d/e\"; " +
		"printf '%s%s:%s:%s:%s\\n' OMNX '" + nonce + ":Z' \"$__c\" \"$(wc -c <\"$__d/o\" | tr -d ' ')\" \"$(wc -c <\"$__d/e\" | tr -d ' ')\"; rm -rf \"$__d\"\n")
	return b.String(), nil
}

var ansiRE = regexp.MustCompile(`\x1b\][^\x07\x1b]*(\x07|\x1b\\)|\x1b\[[0-?]*[ -/]*[@-~]|\x1b[@-Z\\-_]`)

// cleanLines strips terminal escape sequences and splits output into trimmed
// lines. A cursor move is a line break: ConPTY repaints with them.
func cleanLines(raw []byte) []string {
	s := ansiRE.ReplaceAllStringFunc(string(raw), func(m string) string {
		if strings.HasPrefix(m, "\x1b[") && strings.ContainsAny(m[len(m)-1:], "HfEFd") {
			return "\n"
		}
		return ""
	})
	s = strings.ReplaceAll(s, "\r", "\n")
	out := strings.Split(s, "\n")
	for i := range out {
		out[i] = strings.TrimSpace(out[i])
	}
	return out
}

// parseResult finds one job's result in the shell's output. done is false
// until the end marker has arrived.
func parseResult(raw []byte, nonce string) (res remoteResult, done bool, err error) {
	lines := cleanLines(raw)
	o, e, z := "OMNX"+nonce+":O", "OMNX"+nonce+":E", "OMNX"+nonce+":Z:"
	state := 0
	var out, errb strings.Builder
	for _, l := range lines {
		// A prompt the shell printed may share the marker's line.
		if i := strings.Index(l, "OMNX"+nonce+":"); i > 0 {
			l = l[i:]
		}
		switch {
		case l == o:
			state, out, errb = 1, strings.Builder{}, strings.Builder{}
		case l == e && state == 1:
			state = 2
		case strings.HasPrefix(l, z) && state == 2:
			f := strings.Split(strings.TrimPrefix(l, z), ":")
			if len(f) != 3 {
				return res, true, fmt.Errorf("garbled end marker %q", l)
			}
			code, err1 := strconv.Atoi(f[0])
			olen, err2 := strconv.Atoi(f[1])
			elen, err3 := strconv.Atoi(f[2])
			if err1 != nil || err2 != nil || err3 != nil {
				return res, true, fmt.Errorf("garbled end marker %q", l)
			}
			if res.Stdout, err = base64.StdEncoding.DecodeString(out.String()); err != nil {
				return res, true, fmt.Errorf("stdout garbled in transit: %w", err)
			}
			if res.Stderr, err = base64.StdEncoding.DecodeString(errb.String()); err != nil {
				return res, true, fmt.Errorf("stderr garbled in transit: %w", err)
			}
			if len(res.Stdout) != olen || len(res.Stderr) != elen {
				return res, true, fmt.Errorf("output garbled in transit (%d/%d stdout, %d/%d stderr bytes)", len(res.Stdout), olen, len(res.Stderr), elen)
			}
			res.Exit = code
			return res, true, nil
		case state == 1:
			out.WriteString(l)
		case state == 2:
			errb.WriteString(l)
		}
	}
	return res, false, nil
}

// wsFrame is the hub's terminal frame (hub/pkg/terminal.TerminalFrame).
type wsFrame struct {
	Type string `json:"type"`
	Data []byte `json:"data,omitempty"`
	Rows uint16 `json:"rows,omitempty"`
	Cols uint16 `json:"cols,omitempty"`
}

// remoteShell is one attached session.
type remoteShell struct {
	conn  *websocket.Conn
	kind  remoteShellKind
	mu    sync.Mutex // one job at a time
	wmu   sync.Mutex
	bmu   sync.Mutex
	buf   []byte
	more  chan struct{}
	ended chan struct{}
	why   string
}

func newRemoteShell(conn *websocket.Conn, kind remoteShellKind) *remoteShell {
	rs := &remoteShell{conn: conn, kind: kind, more: make(chan struct{}, 1), ended: make(chan struct{})}
	go rs.readLoop()
	return rs
}

func (rs *remoteShell) readLoop() {
	defer close(rs.ended)
	for {
		_, msg, err := rs.conn.ReadMessage()
		if err != nil {
			var ce *websocket.CloseError
			if errors.As(err, &ce) {
				rs.why = ce.Text
			} else {
				rs.why = err.Error()
			}
			return
		}
		var f wsFrame
		if json.Unmarshal(msg, &f) != nil {
			continue
		}
		if f.Type == remoteFrameClose {
			rs.why = "the remote shell ended"
			return
		}
		rs.bmu.Lock()
		if len(rs.buf) < remoteMaxOutput*2 {
			rs.buf = append(rs.buf, f.Data...)
		}
		rs.bmu.Unlock()
		select {
		case rs.more <- struct{}{}:
		default:
		}
	}
}

func (rs *remoteShell) send(f wsFrame) error {
	rs.wmu.Lock()
	defer rs.wmu.Unlock()
	b, _ := json.Marshal(f)
	_ = rs.conn.SetWriteDeadline(time.Now().Add(30 * time.Second))
	return rs.conn.WriteMessage(websocket.TextMessage, b)
}

func (rs *remoteShell) type_(text string) error {
	data := []byte(text)
	for len(data) > 0 {
		n := min(len(data), 64*1024)
		if err := rs.send(wsFrame{Type: remoteFrameStdin, Data: data[:n]}); err != nil {
			return err
		}
		data = data[n:]
	}
	return nil
}

// waitFor waits until check accepts the output gathered since the last reset.
func (rs *remoteShell) waitFor(timeout time.Duration, check func([]byte) (bool, error)) error {
	deadline := time.NewTimer(timeout)
	defer deadline.Stop()
	for {
		rs.bmu.Lock()
		snapshot := append([]byte(nil), rs.buf...)
		rs.bmu.Unlock()
		if ok, err := check(snapshot); ok || err != nil {
			return err
		}
		select {
		case <-rs.more:
		case <-rs.ended:
			rs.bmu.Lock()
			snapshot = append([]byte(nil), rs.buf...)
			rs.bmu.Unlock()
			if ok, err := check(snapshot); ok || err != nil {
				return err
			}
			return fmt.Errorf("session ended: %s", rs.why)
		case <-deadline.C:
			return fmt.Errorf("no answer from the endpoint within %s", timeout)
		}
	}
}

func (rs *remoteShell) reset() {
	rs.bmu.Lock()
	rs.buf = rs.buf[:0]
	rs.bmu.Unlock()
}

// start quiets the shell and waits until it answers.
func (rs *remoteShell) start() error {
	if err := rs.send(wsFrame{Type: remoteFrameResize, Rows: 50, Cols: 250}); err != nil {
		return err
	}
	nonce := newNonce()
	marker := "OMNX" + nonce + ":R"
	// sh may still be starting; say it again until it answers. PowerShell
	// gets the line once: a second line typed ahead while PSReadLine is
	// being removed wedges its console (reproduced on Windows 11, PS 5.1).
	deadline := time.Now().Add(remoteReadyWait)
	retry := remoteReadyRetry
	if rs.kind == shellPowerShell {
		retry = remoteReadyWait
	}
	for {
		if err := rs.type_(readyScript(rs.kind, nonce)); err != nil {
			return err
		}
		err := rs.waitFor(retry, func(b []byte) (bool, error) {
			for _, l := range cleanLines(b) {
				if strings.HasSuffix(l, marker) {
					return true, nil
				}
			}
			return false, nil
		})
		if err == nil || !strings.Contains(err.Error(), "no answer") || time.Now().After(deadline) {
			return err
		}
	}
}

func (rs *remoteShell) run(job remoteJob) (remoteResult, error) {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	nonce := newNonce()
	script, err := jobScript(rs.kind, job, nonce)
	if err != nil {
		return remoteResult{}, err
	}
	rs.reset()
	if err := rs.type_(script); err != nil {
		return remoteResult{}, err
	}
	timeout := time.Duration(job.Timeout) * time.Second
	if timeout <= 0 {
		timeout = 10 * time.Minute
	}
	var res remoteResult
	err = rs.waitFor(timeout, func(b []byte) (bool, error) {
		r, done, perr := parseResult(b, nonce)
		if done {
			res = r
		}
		return done, perr
	})
	return res, err
}

func (rs *remoteShell) close() {
	_ = rs.send(wsFrame{Type: remoteFrameClose})
	_ = rs.conn.Close()
}

// ---- hub side ----------------------------------------------------------

// hubSafe refuses to send the admin key over plain HTTP off this host, as
// scripts/owner-approval.sh does.
func hubSafe(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return err
	}
	host := u.Hostname()
	if u.Scheme == "https" || host == "127.0.0.1" || host == "localhost" || host == "::1" {
		return nil
	}
	return fmt.Errorf("refusing to send the hub key to %s over plain HTTP; use https://HUB:9443 with --ca or OMINULL_HUB_CA", raw)
}

func (c *APIClient) tlsConfig() (*tls.Config, error) {
	if c.cfg.CAFile == "" {
		return nil, nil
	}
	pem, err := os.ReadFile(c.cfg.CAFile)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("%s holds no PEM certificate", c.cfg.CAFile)
	}
	return &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}, nil
}

type openedSession struct {
	SessionID string `json:"session_id"`
	Token     string `json:"connect_token"`
	Program   string `json:"program"`
	Endpoint  string `json:"endpoint_id"`
}

// openSession asks the hub for a terminal on endpoint, waiting for the
// owner's tap, and returns the session and its one-use operator token.
func (c *APIClient) openSession(endpoint string) (*openedSession, error) {
	if err := hubSafe(c.cfg.HubURL); err != nil {
		return nil, err
	}
	program := ""
	raw, err := c.doRequest(http.MethodGet, "/api/v1/endpoints", nil)
	if err != nil {
		return nil, err
	}
	var eps []struct {
		ID     string `json:"id"`
		OS     string `json:"os"`
		Status string `json:"status"`
		Caps   string `json:"response_capabilities"`
	}
	if err := json.Unmarshal(raw, &eps); err != nil {
		return nil, fmt.Errorf("endpoint list unreadable: %w", err)
	}
	found := false
	for _, ep := range eps {
		if ep.ID != endpoint {
			continue
		}
		found = true
		if ep.Status != "online" {
			return nil, fmt.Errorf("%s is %s; a session needs the agent online", endpoint, ep.Status)
		}
		var caps struct {
			Terminal struct {
				Programs []string `json:"programs"`
			} `json:"terminal"`
		}
		_ = json.Unmarshal([]byte(ep.Caps), &caps)
		for _, p := range caps.Terminal.Programs {
			if p == "/bin/sh" || strings.EqualFold(p, "powershell.exe") {
				program = p
				break
			}
		}
		if program == "" {
			return nil, fmt.Errorf("%s offers no /bin/sh or powershell.exe terminal (programs %v)", endpoint, caps.Terminal.Programs)
		}
	}
	if !found {
		return nil, fmt.Errorf("no endpoint %q on this hub (ominullctl endpoints lists them)", endpoint)
	}
	body := map[string]string{"endpoint_id": endpoint, "program": program}
	out, err := c.ownerApproved(http.MethodPost, "/api/v1/terminal/sessions", body)
	if err != nil {
		return nil, err
	}
	var s openedSession
	if err := json.Unmarshal(out, &s); err != nil || s.SessionID == "" || s.Token == "" {
		return nil, fmt.Errorf("the hub opened no session it would hand this caller: %s", string(out))
	}
	if s.Endpoint == "" {
		s.Endpoint = endpoint
	}
	return &s, nil
}

func wsURL(hub, sessionID string) (string, error) {
	u, err := url.Parse(strings.TrimRight(hub, "/") + "/api/v1/terminal/ws/operator")
	if err != nil {
		return "", err
	}
	switch u.Scheme {
	case "https":
		u.Scheme = "wss"
	case "http":
		u.Scheme = "ws"
	}
	u.RawQuery = "session_id=" + url.QueryEscape(sessionID)
	return u.String(), nil
}

func attachSession(hub string, tlsCfg *tls.Config, s *openedSession) (*remoteShell, error) {
	return attachSessionKeep(hub, tlsCfg, s, false)
}

// attachSessionKeep with keep returns the attached session even when the
// shell does not answer, so `shell open --debug` can look at what it prints.
func attachSessionKeep(hub string, tlsCfg *tls.Config, s *openedSession, keep bool) (*remoteShell, error) {
	target, err := wsURL(hub, s.SessionID)
	if err != nil {
		return nil, err
	}
	dialer := websocket.Dialer{TLSClientConfig: tlsCfg, HandshakeTimeout: 20 * time.Second, Proxy: nil}
	hdr := http.Header{}
	hdr.Set("X-Terminal-Token", s.Token)
	conn, resp, err := dialer.Dial(target, hdr)
	if err != nil {
		if resp != nil {
			b, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
			return nil, fmt.Errorf("attach refused (%d): %s", resp.StatusCode, strings.TrimSpace(string(b)))
		}
		return nil, err
	}
	conn.SetReadLimit(4 << 20)
	rs := newRemoteShell(conn, shellKindFor(s.Program))
	if err := rs.start(); err != nil {
		if keep {
			return rs, fmt.Errorf("the endpoint's shell did not come up: %w", err)
		}
		rs.close()
		return nil, fmt.Errorf("the endpoint's shell did not come up: %w", err)
	}
	return rs, nil
}

// raw types text as is and returns everything the terminal printed within
// wait: a look at the raw stream for `shell raw` (debugging a shell dialect).
func (rs *remoteShell) raw(text string, wait time.Duration) []byte {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	rs.reset()
	_ = rs.type_(text)
	select {
	case <-time.After(wait):
	case <-rs.ended:
	}
	rs.bmu.Lock()
	defer rs.bmu.Unlock()
	return append([]byte(nil), rs.buf...)
}

// ---- held sessions -----------------------------------------------------

func heldDir() string {
	base := os.Getenv("XDG_RUNTIME_DIR")
	if base == "" {
		base = filepath.Join(os.TempDir(), fmt.Sprintf("ominull-%d", os.Getuid()))
	}
	return filepath.Join(base, "ominull")
}

var unsafeName = regexp.MustCompile(`[^A-Za-z0-9._-]`)

func heldSocket(endpoint string) string {
	return filepath.Join(heldDir(), unsafeName.ReplaceAllString(endpoint, "_")+".sock")
}

// heldEndedMarker records why a held session ended without shell end.
func heldEndedMarker(endpoint string) string {
	return heldSocket(endpoint) + ".ended"
}

// heldCall sends one job to a held session; ok is false when none is held.
func heldCall(endpoint string, job remoteJob) (remoteResult, bool, error) {
	conn, err := net.Dial("unix", heldSocket(endpoint))
	if err != nil {
		// A held session that ended on its own must not turn the next exec
		// into a fresh owner tap the owner did not expect.
		if why, rerr := os.ReadFile(heldEndedMarker(endpoint)); rerr == nil {
			_ = os.Remove(heldEndedMarker(endpoint))
			return remoteResult{}, true, fmt.Errorf("the held session to %s ended (%s); open a new one with ominullctl shell open %s", endpoint, strings.TrimSpace(string(why)), endpoint)
		}
		return remoteResult{}, false, nil
	}
	defer conn.Close()
	if err := json.NewEncoder(conn).Encode(job); err != nil {
		return remoteResult{}, true, err
	}
	var res remoteResult
	if err := json.NewDecoder(bufio.NewReader(conn)).Decode(&res); err != nil {
		return res, true, fmt.Errorf("the held session went away: %w", err)
	}
	if res.Error != "" {
		return res, true, errors.New(res.Error)
	}
	return res, true, nil
}

type holdSpec struct {
	Hub     string        `json:"hub"`
	CAFile  string        `json:"ca_file"`
	Session openedSession `json:"session"`
	TTL     time.Duration `json:"ttl"`
	Debug   bool          `json:"debug,omitempty"`
}

// runHolder is the background process behind `shell open`: it keeps the
// session attached and serves jobs on a private socket until the TTL, the
// hub's own limits or `shell end`.
func runHolder() int {
	ready := os.NewFile(3, "ready")
	report := func(msg string) {
		if ready != nil {
			fmt.Fprintln(ready, msg)
			ready.Close()
			ready = nil
		}
	}
	var spec holdSpec
	if err := json.NewDecoder(os.Stdin).Decode(&spec); err != nil {
		report("error: " + err.Error())
		return 1
	}
	c := newAPIClient(CLIConfig{HubURL: spec.Hub, CAFile: spec.CAFile})
	tlsCfg, err := c.tlsConfig()
	if err != nil {
		report("error: " + err.Error())
		return 1
	}
	rs, err := attachSessionKeep(spec.Hub, tlsCfg, &spec.Session, spec.Debug)
	unready := ""
	if err != nil && (rs == nil || !spec.Debug) {
		report("error: " + err.Error())
		return 1
	} else if err != nil {
		unready = " (debug: " + err.Error() + ")"
	}
	defer rs.close()
	sock := heldSocket(spec.Session.Endpoint)
	_ = os.Remove(sock)
	old := syscall.Umask(0o077)
	ln, err := net.Listen("unix", sock)
	syscall.Umask(old)
	if err != nil {
		report("error: " + err.Error())
		return 1
	}
	defer os.Remove(sock)
	marker := heldEndedMarker(spec.Session.Endpoint)
	_ = os.Remove(marker)
	stop := make(chan struct{})
	var once sync.Once
	end := func() { once.Do(func() { close(stop); ln.Close() }) }
	endFor := func(why string) {
		_ = os.WriteFile(marker, []byte(why+"\n"), 0o600)
		end()
	}
	go func() {
		select {
		case <-time.After(spec.TTL):
			endFor("its time limit passed")
		case <-rs.ended:
			endFor("the hub closed it")
		case <-stop:
		}
		end()
	}()
	report("ok " + spec.Session.SessionID + unready)
	for {
		conn, err := ln.Accept()
		if err != nil {
			return 0
		}
		func() {
			defer conn.Close()
			var job remoteJob
			if json.NewDecoder(conn).Decode(&job) != nil {
				return
			}
			if job.Op == "raw" {
				_ = json.NewEncoder(conn).Encode(remoteResult{Stdout: rs.raw(job.Command, time.Duration(job.Timeout)*time.Second)})
				return
			}
			if job.Op == "ready" {
				res := remoteResult{}
				if err := rs.start(); err != nil {
					res.Error = err.Error()
				}
				_ = json.NewEncoder(conn).Encode(res)
				return
			}
			if job.Op == "end" {
				_ = json.NewEncoder(conn).Encode(remoteResult{})
				end()
				return
			}
			res, err := rs.run(job)
			if err != nil {
				res.Error = err.Error()
			}
			_ = json.NewEncoder(conn).Encode(res)
			if err != nil && strings.Contains(err.Error(), "within") {
				endFor("a command did not finish in time and left the shell busy")
			}
		}()
	}
}

// ---- commands ----------------------------------------------------------

func remoteFlags(name string, args []string) (*flag.FlagSet, *int, []string, error) {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	timeout := fs.Int("timeout", 600, "seconds to wait for the command")
	if err := fs.Parse(args); err != nil {
		return nil, nil, nil, err
	}
	return fs, timeout, fs.Args(), nil
}

// runJob uses a held session for the endpoint when there is one, otherwise
// opens a one-shot session (one owner tap) and ends it afterwards.
func (c *APIClient) runJob(endpoint string, job remoteJob) (remoteResult, error) {
	if res, held, err := heldCall(endpoint, job); held {
		return res, err
	}
	s, err := c.openSession(endpoint)
	if err != nil {
		return remoteResult{}, err
	}
	tlsCfg, err := c.tlsConfig()
	if err != nil {
		return remoteResult{}, err
	}
	rs, err := attachSession(c.cfg.HubURL, tlsCfg, s)
	if err != nil {
		return remoteResult{}, err
	}
	defer rs.close()
	return rs.run(job)
}

// cmdExec: ominullctl exec [--timeout S] ENDPOINT -- COMMAND...
func (c *APIClient) cmdExec(args []string) (int, error) {
	_, timeout, rest, err := remoteFlags("exec", args)
	if err != nil {
		return 2, err
	}
	if len(rest) > 0 && rest[0] == "--" {
		rest = rest[1:]
	}
	if len(rest) < 2 {
		return 2, errors.New("usage: ominullctl exec [--timeout S] ENDPOINT -- COMMAND... (COMMAND - reads it from stdin)")
	}
	endpoint, cmd := rest[0], rest[1:]
	if cmd[0] == "--" {
		cmd = cmd[1:]
	}
	command := strings.Join(cmd, " ")
	if command == "-" {
		b, err := io.ReadAll(io.LimitReader(os.Stdin, remoteMaxPut+1))
		if err != nil || len(b) > remoteMaxPut {
			return 2, errors.New("the command on stdin is unreadable or over 2 MiB")
		}
		command = string(b)
	}
	res, err := c.runJob(endpoint, remoteJob{Op: "exec", Command: command, Timeout: *timeout})
	if err != nil {
		return 1, err
	}
	if c.cfg.JSONOutput {
		_ = json.NewEncoder(os.Stdout).Encode(map[string]interface{}{"stdout": string(res.Stdout), "stderr": string(res.Stderr), "exit": res.Exit})
		return 0, nil
	}
	os.Stdout.Write(res.Stdout)
	os.Stderr.Write(res.Stderr)
	return res.Exit, nil
}

// cmdPut: ominullctl put ENDPOINT LOCAL REMOTE
func (c *APIClient) cmdPut(args []string) error {
	_, timeout, rest, err := remoteFlags("put", args)
	if err != nil {
		return err
	}
	if len(rest) != 3 {
		return errors.New("usage: ominullctl put ENDPOINT LOCAL_FILE REMOTE_PATH")
	}
	data, err := os.ReadFile(rest[1])
	if err != nil {
		return err
	}
	if len(data) > remoteMaxPut {
		return fmt.Errorf("%s is over 2 MiB; the terminal channel is for small files", rest[1])
	}
	res, err := c.runJob(rest[0], remoteJob{Op: "put", Path: rest[2], Data: data, Timeout: *timeout})
	if err != nil {
		return err
	}
	if res.Exit != 0 {
		return fmt.Errorf("writing %s failed: %s", rest[2], strings.TrimSpace(string(res.Stderr)))
	}
	fmt.Fprintf(os.Stderr, "[+] wrote %d bytes to %s:%s\n", len(data), rest[0], rest[2])
	return nil
}

// cmdGet: ominullctl get ENDPOINT REMOTE LOCAL (LOCAL - is stdout)
func (c *APIClient) cmdGet(args []string) error {
	_, timeout, rest, err := remoteFlags("get", args)
	if err != nil {
		return err
	}
	if len(rest) != 3 {
		return errors.New("usage: ominullctl get ENDPOINT REMOTE_PATH LOCAL_FILE (- for stdout)")
	}
	res, err := c.runJob(rest[0], remoteJob{Op: "get", Path: rest[1], Timeout: *timeout})
	if err != nil {
		return err
	}
	if res.Exit != 0 {
		return fmt.Errorf("reading %s failed: %s", rest[1], strings.TrimSpace(string(res.Stderr)))
	}
	if rest[2] == "-" {
		_, err = os.Stdout.Write(res.Stdout)
		return err
	}
	return os.WriteFile(rest[2], res.Stdout, 0o600)
}

// shellOpen: one owner tap, then commands on this endpoint reuse the session.
func (c *APIClient) shellOpen(args []string) error {
	fs := flag.NewFlagSet("shell open", flag.ContinueOnError)
	ttl := fs.Duration("ttl", remoteDefaultTTL, "how long to keep the session (at most 60m; the hub also ends it after 15 idle minutes)")
	debug := fs.Bool("debug", false, "keep the session even if the shell does not answer (for shell raw)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("usage: ominullctl shell open [--ttl 45m] ENDPOINT")
	}
	endpoint := fs.Arg(0)
	if *ttl <= 0 || *ttl > remoteMaxTTL {
		*ttl = remoteMaxTTL
	}
	_ = os.Remove(heldEndedMarker(endpoint)) // opening a new session is the answer to an ended one
	if _, held, _ := heldCall(endpoint, remoteJob{Op: "exec", Command: "true", Timeout: 30}); held {
		fmt.Fprintf(os.Stderr, "[+] A session to %s is already open; ominullctl exec %s -- ... uses it.\n", endpoint, endpoint)
		return nil
	}
	if err := os.MkdirAll(heldDir(), 0o700); err != nil {
		return err
	}
	s, err := c.openSession(endpoint)
	if err != nil {
		return err
	}
	spec, _ := json.Marshal(holdSpec{Hub: c.cfg.HubURL, CAFile: c.cfg.CAFile, Session: *s, TTL: *ttl, Debug: *debug})
	self, err := os.Executable()
	if err != nil {
		return err
	}
	logf, err := os.OpenFile(filepath.Join(heldDir(), unsafeName.ReplaceAllString(endpoint, "_")+".log"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	defer logf.Close()
	pr, pw, err := os.Pipe()
	if err != nil {
		return err
	}
	cmd := exec.Command(self, "__hold")
	cmd.Stdin = bytes.NewReader(spec)
	cmd.Stdout, cmd.Stderr = logf, logf
	cmd.ExtraFiles = []*os.File{pw}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		return err
	}
	pw.Close()
	line, _ := bufio.NewReader(pr).ReadString('\n')
	pr.Close()
	_ = cmd.Process.Release()
	line = strings.TrimSpace(line)
	if !strings.HasPrefix(line, "ok") {
		return fmt.Errorf("the session did not stay open: %s", strings.TrimPrefix(line, "error: "))
	}
	if i := strings.Index(line, " (debug: "); i >= 0 {
		fmt.Fprintln(os.Stderr, "[!] "+strings.TrimSuffix(line[i+2:], ")"))
	}
	fmt.Fprintf(os.Stderr, "[+] Session %s to %s is open for %s. Run: ominullctl exec %s -- COMMAND; end it with ominullctl shell end %s\n",
		s.SessionID, endpoint, ttl.String(), endpoint, endpoint)
	return nil
}

func shellEnd(args []string) error {
	if len(args) != 1 {
		return errors.New("usage: ominullctl shell end ENDPOINT")
	}
	if _, held, err := heldCall(args[0], remoteJob{Op: "end"}); !held {
		return fmt.Errorf("no session to %s is open here", args[0])
	} else if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "[+] Session to %s ended.\n", args[0])
	return nil
}

// cmdEnrol: LAN self-enrolment windows. Opening one waits for the owner's
// tap; listing and closing do not.
func (c *APIClient) cmdEnrol(args []string) error {
	action := "list"
	if len(args) > 0 {
		action, args = args[0], args[1:]
	}
	switch action {
	case "list":
		raw, err := c.doRequest(http.MethodGet, "/api/v1/enrolment/windows", nil)
		if err != nil {
			return err
		}
		var res struct {
			Windows   []map[string]interface{} `json:"windows"`
			PortalURL string                   `json:"portal_url"`
		}
		_ = json.Unmarshal(raw, &res)
		c.printOutput(res, func() {
			for _, w := range res.Windows {
				fmt.Printf("[%v] %v %v cidrs=%v used=%v/%v expires=%v label=%q\n", w["id"], w["state"], w["role"], w["cidrs"], w["used"], w["max_uses"], w["expires_at"], w["label"])
			}
			if len(res.Windows) == 0 {
				fmt.Println("No enrolment windows.")
			}
			fmt.Println("Portal:", res.PortalURL)
		})
		return nil
	case "open":
		fs := flag.NewFlagSet("enrol open", flag.ContinueOnError)
		label := fs.String("label", "", "what the window is for")
		cidrs := fs.String("cidr", "", "comma-separated networks allowed to install (required)")
		hours := fs.Float64("hours", 2, "hours the window stays open (at most 168)")
		maxUses := fs.Int("max-uses", 1, "installs allowed (0: no limit)")
		role := fs.String("role", "", "role for enrolled machines (default workstation)")
		tenant := fs.String("tenant-id", "", "tenant for enrolled machines")
		location := fs.String("location", "", "location for enrolled machines")
		passFile := fs.String("passcode-file", "", "file whose first line is a passcode the installer must type (kept off the command line)")
		if err := fs.Parse(args); err != nil {
			return err
		}
		var nets []string
		for _, n := range strings.Split(*cidrs, ",") {
			if n = strings.TrimSpace(n); n != "" {
				nets = append(nets, n)
			}
		}
		if len(nets) == 0 {
			return errors.New("usage: ominullctl enrol open --cidr 192.0.2.0/24 [--label L] [--hours 2] [--max-uses 1] [--passcode-file F]")
		}
		body := map[string]interface{}{"label": *label, "cidrs": nets, "hours": *hours, "max_uses": *maxUses,
			"role": *role, "tenant_id": *tenant, "location_id": *location}
		if *passFile != "" {
			b, err := os.ReadFile(*passFile)
			if err != nil {
				return err
			}
			body["passcode"] = strings.TrimSpace(strings.SplitN(string(b), "\n", 2)[0])
		}
		raw, err := c.ownerApproved(http.MethodPost, "/api/v1/enrolment/windows", body)
		if err != nil {
			return err
		}
		var res struct {
			Window    map[string]interface{} `json:"window"`
			PortalURL string                 `json:"portal_url"`
		}
		_ = json.Unmarshal(raw, &res)
		c.printOutput(res, func() {
			fmt.Printf("[+] Enrolment window %v open until %v. Installers: %s\n", res.Window["id"], res.Window["expires_at"], res.PortalURL)
		})
		return nil
	case "close", "revoke":
		if len(args) != 1 {
			return errors.New("usage: ominullctl enrol close WINDOW_ID")
		}
		if _, err := c.doRequest(http.MethodDelete, "/api/v1/enrolment/windows?id="+url.QueryEscape(args[0]), nil); err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "[+] Enrolment window %s closed.\n", args[0])
		return nil
	}
	return errors.New("usage: ominullctl enrol list | open --cidr NETS [...] | close WINDOW_ID")
}

// shellRaw: ominullctl shell raw ENDPOINT TEXT [WAIT_S] types TEXT (\n and
// \r escapes honoured) into the held session and prints the raw output,
// quoted. shell ready ENDPOINT re-runs the quiet-shell setup.
func shellRaw(args []string) error {
	if len(args) < 2 {
		return errors.New("usage: ominullctl shell raw ENDPOINT TEXT [WAIT_SECONDS]")
	}
	wait := 3
	if len(args) > 2 {
		wait, _ = strconv.Atoi(args[2])
	}
	text := strings.NewReplacer(`\r`, "\r", `\n`, "\n", `\x03`, "\x03").Replace(args[1])
	res, held, err := heldCall(args[0], remoteJob{Op: "raw", Command: text, Timeout: wait})
	if !held {
		return fmt.Errorf("no session to %s is open here", args[0])
	}
	if err != nil {
		return err
	}
	fmt.Printf("%q\n", res.Stdout)
	return nil
}

func shellReady(args []string) error {
	if len(args) != 1 {
		return errors.New("usage: ominullctl shell ready ENDPOINT")
	}
	_, held, err := heldCall(args[0], remoteJob{Op: "ready"})
	if !held {
		return fmt.Errorf("no session to %s is open here", args[0])
	}
	return err
}
