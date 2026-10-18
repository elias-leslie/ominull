package main

// ominullctl screen: remote screen sessions (docs/REMOTE_SCREEN.md section 8).
//
// screen open asks for a session on an enrolled endpoint (one passkey tap on
// the owner's phone; POST /api/v1/screen/sessions answers 202 until then),
// then starts the native viewer and hands it the session. screen hold asks
// once and keeps the session for an agent's info/shot/click/... commands,
// each of which rotates the one-use operator token (/attach) and runs
// `ominull-screen ctl <action>` for one attach-act-detach. screen watch
// opens a view-only attachment for the owner to watch along.
//
// Every operator or watch token goes to ominull-screen as one JSON line on
// its stdin, never in argv or the environment (both are readable by other
// processes), is never written to disk and is never printed.

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// screenViewerName is the native viewer binary ominullctl starts (its ctl
// subcommand is the headless agent mode).
const screenViewerName = "ominull-screen"

// defaultScreenMaxEdge is the long edge, in pixels, screenshots are scaled
// down to unless --max-edge or $OMINULL_SCREEN_MAX_EDGE says otherwise.
const defaultScreenMaxEdge = 1280

// screenHandshake is the one line the viewer reads on stdin.
type screenHandshake struct {
	HubURL    string `json:"hub_url"`
	CAPEM     string `json:"ca_pem"`
	SessionID string `json:"session_id"`
	Token     string `json:"token"`
	Mode      string `json:"mode"`
	Host      string `json:"host"`
	// Text is screen type's text: ctl reads it here, never from argv.
	Text string `json:"text,omitempty"`
}

// maxScreenTypeText bounds the text screen type sends (the viewer's stdin
// line has a 256 KiB cap that also carries the CA bundle).
const maxScreenTypeText = 64 * 1024

// screenStdin is where screen type reads its text with "-" or no text
// argument. Tests replace it.
var screenStdin io.Reader = os.Stdin

// screenAgentLabel is --agent, else $OMINULL_AGENT: a short name for the
// agent asking, which the hub shows in the owner's approval and the audit
// (X-Ominull-Agent). Empty means none.
func screenAgentLabel(flagVal string) (string, error) {
	v := strings.TrimSpace(flagVal)
	if v == "" {
		v = strings.TrimSpace(os.Getenv("OMINULL_AGENT"))
	}
	if len(v) > 64 {
		return "", errors.New("--agent (or $OMINULL_AGENT) is at most 64 characters")
	}
	for i := 0; i < len(v); i++ {
		if v[i] < 0x20 || v[i] > 0x7e {
			return "", errors.New("--agent (or $OMINULL_AGENT) takes printable ASCII only")
		}
		if v[i] == '"' || v[i] == '\\' {
			return "", errors.New("--agent (or $OMINULL_AGENT) cannot contain quotes or backslashes")
		}
	}
	return v, nil
}

// agentHeader adds X-Ominull-Agent to every request it carries.
type agentHeader struct {
	base  http.RoundTripper
	label string
}

func (t agentHeader) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Set("X-Ominull-Agent", t.label)
	return t.base.RoundTrip(r)
}

// withAgent is c sending X-Ominull-Agent: label on every request (c itself
// when label is empty).
func (c *APIClient) withAgent(label string) *APIClient {
	if label == "" {
		return c
	}
	hc := *c.httpClient
	base := hc.Transport
	if base == nil {
		base = http.DefaultTransport
	}
	hc.Transport = agentHeader{base: base, label: label}
	cp := *c
	cp.httpClient = &hc
	return &cp
}

func (c *APIClient) cmdScreen(args []string) error {
	if len(args) == 0 {
		return errors.New(screenUsageShort)
	}
	switch args[0] {
	case "open":
		return c.screenOpen(args[1:], os.Stdout)
	case "hold":
		return c.screenHold(args[1:], os.Stdout)
	case "watch":
		return c.screenWatch(args[1:], os.Stdout)
	case "end":
		return c.screenEnd(args[1:], os.Stdout)
	case "settings":
		return c.screenSettings(args[1:], os.Stdout)
	case "info", "shot", "click", "move", "drag", "scroll", "type", "key":
		return c.screenAction(args[0], args[1:], os.Stdout)
	case "help", "--help", "-h":
		fmt.Print(screenHelp)
		return nil
	}
	return fmt.Errorf("unknown screen command %q\n%s", args[0], screenUsageShort)
}

const screenUsageShort = `usage: ominullctl screen open|hold|info|shot|click|move|drag|scroll|type|key|watch|end|settings ...
(ominullctl help screen explains them)`

// screenHelp is `ominullctl help screen`: the usage an agent reads.
const screenHelp = `Remote screen (Windows endpoints that report the screen capability)

Owner viewing:
  ominullctl screen open [--view] [--ttl 90m] [--viewer PATH] [--agent LABEL] ENDPOINT
      One owner tap, then the screen viewer (ominull-screen) shows ENDPOINT's
      screen. --view: watch only. The session ends when the viewer closes.

Agent control (a held session):
  ominullctl screen hold [--view] [--ttl 90m] [--agent LABEL] ENDPOINT
      One owner tap; the owner's phone says an agent with the admin key asks.
      --agent (default $OMINULL_AGENT) names the agent in that ask and in the
      audit: up to 64 printable ASCII characters.
      Every command below then reuses that session until it ends - no more
      taps. Prints the screen info (monitors and sizes).
  ominullctl screen info  ENDPOINT
      Monitors (id, size, primary), the active monitor and the desktop
      (user, secure or lock screen).
  ominullctl screen shot  ENDPOINT -o FILE.png [--monitor N] [--max-edge E]
      One full frame of a monitor (default: the primary), cursor drawn in,
      scaled down so its long edge is at most E pixels. Prints
      {"path","width","height","scale","monitor","monitor_width","monitor_height"}.
  ominullctl screen click ENDPOINT X Y [--button left|right|middle] [--double] [--monitor N] [--max-edge E]
  ominullctl screen move  ENDPOINT X Y [--monitor N] [--max-edge E]
  ominullctl screen drag  ENDPOINT X1 Y1 X2 Y2 [--monitor N] [--max-edge E]
  ominullctl screen scroll ENDPOINT X Y DY [--monitor N] [--max-edge E]
      DY is wheel notches, 1..10, up positive and down negative.
  ominullctl screen type  ENDPOINT ["text" | -]
      Types the text as Unicode characters (the audit records only its length).
      With - or no text, reads it from stdin (one trailing newline dropped),
      which keeps a password off the command line. Either way the text goes
      to ominull-screen on its stdin, never in its arguments.
  ominullctl screen key   ENDPOINT COMBO
      A key or combination: enter, esc, tab, win+r, ctrl+c, alt+f4,
      ctrl+alt+del (the secure attention sequence), ...
  ominullctl screen watch ENDPOINT
      Opens the screen viewer view-only beside the held session, so the owner
      can watch what the agent does.
  ominullctl screen end   ENDPOINT
      Ends the held session.

Settings:
  ominullctl screen settings [ENDPOINT] [--ask-first on|off|fleet]
      Shows or changes whether a screen session first asks the person at the
      keyboard to allow it: for ENDPOINT, or the fleet default for machines
      without their own setting (off unless set). on applies at once; off
      (and fleet, when it means off) waits for the owner's tap. fleet drops
      ENDPOINT's own setting, or with no ENDPOINT forgets the fleet default.

Coordinates: X and Y are pixels in the last screenshot taken with the same
--max-edge and --monitor, not the monitor's own pixels. Take a shot, read
the position off it, act with the same flags. --max-edge defaults to 1280
(or $OMINULL_SCREEN_MAX_EDGE).

One tap per held session: hold asks the owner once; the other commands never
ask. When the session ends (its time limit, the hub ending an idle session,
the person at the keyboard declining or ending it, screen end), the next
command fails with "open a new one with ominullctl screen hold ENDPOINT"
instead of asking the owner again; run screen hold for a new tap.

Each command attaches, acts and detaches; the endpoint stops capturing while
nothing is attached. Tokens go to ominull-screen on its stdin, never on a
command line, and are never printed.
`

// findScreenViewer is --viewer, else the viewer next to this executable,
// else the one on PATH.
func findScreenViewer(flagPath string) (string, error) {
	if flagPath != "" {
		if st, err := os.Stat(flagPath); err != nil || st.IsDir() {
			return "", fmt.Errorf("no screen viewer at %s", flagPath)
		}
		return flagPath, nil
	}
	if self, err := os.Executable(); err == nil {
		p := filepath.Join(filepath.Dir(self), screenViewerName)
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			return p, nil
		}
	}
	if p, err := exec.LookPath(screenViewerName); err == nil {
		return p, nil
	}
	return "", fmt.Errorf("the screen viewer (%s) isn't installed next to ominullctl or on PATH; install it or pass --viewer PATH", screenViewerName)
}

func (c *APIClient) screenOpen(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("screen open", flag.ContinueOnError)
	view := fs.Bool("view", false, "watch only: no mouse or keyboard")
	agentFlag := fs.String("agent", "", "name of the agent asking, shown to the owner and in the audit (default $OMINULL_AGENT)")
	ttl := fs.Duration("ttl", 0, "how long the session may run, e.g. 90m (default and most: the hub's session limit; the hub also ends an idle session)")
	viewerFlag := fs.String("viewer", "", "the screen viewer to start (default: "+screenViewerName+" next to ominullctl, else on PATH)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("usage: ominullctl screen open [--view] [--ttl 90m] [--viewer PATH] [--agent LABEL] ENDPOINT")
	}
	agent, err := screenAgentLabel(*agentFlag)
	if err != nil {
		return err
	}
	c = c.withAgent(agent)
	if err := hubSafe(c.cfg.HubURL); err != nil {
		return err
	}
	// Find the viewer before asking the owner: a tap for a session nothing
	// can show is a wasted ask.
	viewer, err := findScreenViewer(*viewerFlag)
	if err != nil {
		return err
	}
	var caPEM []byte
	if c.cfg.CAFile != "" {
		if caPEM, err = os.ReadFile(c.cfg.CAFile); err != nil {
			return err
		}
	}
	endpoint := fs.Arg(0)
	mode := "control"
	if *view {
		mode = "view"
	}
	body := map[string]interface{}{"endpoint_id": endpoint, "mode": mode}
	if *ttl > 0 {
		body["max_duration_seconds"] = int64((*ttl + time.Second - 1) / time.Second)
	}
	raw, err := c.ownerApproved(http.MethodPost, "/api/v1/screen/sessions", body)
	if err != nil {
		return err
	}
	var s struct {
		SessionID string `json:"session_id"`
		Mode      string `json:"mode"`
		Token     string `json:"connect_token"`
	}
	if err := json.Unmarshal(raw, &s); err != nil || s.SessionID == "" || s.Token == "" {
		return fmt.Errorf("the hub opened no screen session it would hand this caller: %s", screenRedact(raw))
	}
	if s.Mode == "" {
		s.Mode = mode
	}
	// The session holds the endpoint's one screen slot until it ends; end
	// it whenever this command is done with it.
	end := func() {
		_, _, _ = c.doRequestWith(http.MethodDelete, "/api/v1/screen/sessions?id="+url.QueryEscape(s.SessionID), nil, nil)
	}
	hs, _ := json.Marshal(screenHandshake{
		HubURL: strings.TrimRight(c.cfg.HubURL, "/"), CAPEM: string(caPEM), SessionID: s.SessionID,
		Token: s.Token, Mode: s.Mode, Host: c.endpointLabel(endpoint),
	})
	cmd := exec.Command(viewer)
	cmd.Stdout, cmd.Stderr = os.Stderr, os.Stderr
	stdin, err := cmd.StdinPipe()
	if err != nil {
		end()
		return err
	}
	if err := cmd.Start(); err != nil {
		end()
		return fmt.Errorf("the screen viewer %s would not start (%v); the session was ended", viewer, err)
	}
	_, werr := stdin.Write(append(hs, '\n'))
	_ = stdin.Close()
	runErr := cmd.Wait()
	end()
	what := "Control"
	if s.Mode == "view" {
		what = "Watch-only"
	}
	switch {
	case werr != nil && runErr == nil:
		runErr = fmt.Errorf("the viewer did not take the session: %w", werr)
		fallthrough
	case runErr != nil:
		fmt.Fprintf(out, "%s screen session on %s ended: the viewer failed (%v)\n", what, endpoint, runErr)
		return runErr
	}
	fmt.Fprintf(out, "%s screen session on %s ended.\n", what, endpoint)
	return nil
}

// endpointLabel is the endpoint's hostname as the hub knows it, or its id.
func (c *APIClient) endpointLabel(id string) string {
	raw, err := c.doRequest(http.MethodGet, "/api/v1/endpoints", nil)
	if err != nil {
		return id
	}
	var eps []struct {
		ID       string `json:"id"`
		Hostname string `json:"hostname"`
	}
	if json.Unmarshal(raw, &eps) != nil {
		return id
	}
	for _, ep := range eps {
		if ep.ID == id && ep.Hostname != "" {
			return ep.Hostname
		}
	}
	return id
}

// screenRedact keeps a connect token out of an error message.
func screenRedact(raw []byte) string {
	var m map[string]interface{}
	if json.Unmarshal(raw, &m) != nil {
		return strings.TrimSpace(string(raw))
	}
	if _, ok := m["connect_token"]; ok {
		m["connect_token"] = "(hidden)"
	}
	b, _ := json.Marshal(m)
	return string(b)
}

// ---- held screen sessions ----------------------------------------------

// heldScreen is what ominullctl keeps between an agent's screen commands. No
// token: each command rotates a fresh one through /attach.
type heldScreen struct {
	Hub       string    `json:"hub"`
	SessionID string    `json:"session_id"`
	Endpoint  string    `json:"endpoint"`
	Mode      string    `json:"mode"`
	Host      string    `json:"host"`
	ExpiresAt time.Time `json:"expires_at"`
	// Agent is the --agent label hold was given; later commands send it too.
	Agent string `json:"agent,omitempty"`
}

func heldScreenFile(endpoint string) string {
	return filepath.Join(heldDir(), unsafeName.ReplaceAllString(endpoint, "_")+".screen.json")
}

// heldScreenEnded marks a held screen session that ended without screen
// end, with the reason, like shell open's marker.
func heldScreenEnded(endpoint string) string {
	return heldScreenFile(endpoint) + ".ended"
}

func loadHeldScreen(endpoint string) (*heldScreen, error) {
	raw, err := os.ReadFile(heldScreenFile(endpoint))
	if err != nil {
		if why, rerr := os.ReadFile(heldScreenEnded(endpoint)); rerr == nil {
			return nil, screenEndedError(endpoint, strings.TrimSpace(string(why)))
		}
		return nil, fmt.Errorf("no screen session to %s is held here; run ominullctl screen hold %s (one owner tap)", endpoint, endpoint)
	}
	var h heldScreen
	if err := json.Unmarshal(raw, &h); err != nil || h.SessionID == "" {
		_ = os.Remove(heldScreenFile(endpoint))
		return nil, fmt.Errorf("the held screen state for %s is unreadable; run ominullctl screen hold %s", endpoint, endpoint)
	}
	return &h, nil
}

func screenEndedError(endpoint, why string) error {
	return fmt.Errorf("the held screen session to %s ended (%s); open a new one with ominullctl screen hold %s", endpoint, why, endpoint)
}

// markScreenEnded drops the held state and leaves the ended marker, so every
// later command says the session ended instead of looking for another one.
func markScreenEnded(endpoint, why string) error {
	_ = os.Remove(heldScreenFile(endpoint))
	_ = os.WriteFile(heldScreenEnded(endpoint), []byte(why+"\n"), 0o600)
	return screenEndedError(endpoint, why)
}

// screenMaxEdge is --max-edge's default: $OMINULL_SCREEN_MAX_EDGE, else 1280.
func screenMaxEdge() int {
	if v, err := strconv.Atoi(strings.TrimSpace(os.Getenv("OMINULL_SCREEN_MAX_EDGE"))); err == nil && v >= 16 && v <= 16384 {
		return v
	}
	return defaultScreenMaxEdge
}

// screenHandshakeLine is the one stdin line ominull-screen reads.
func (c *APIClient) screenHandshakeLine(sessionID, token, mode, host, text string) ([]byte, error) {
	var caPEM []byte
	if c.cfg.CAFile != "" {
		var err error
		if caPEM, err = os.ReadFile(c.cfg.CAFile); err != nil {
			return nil, err
		}
	}
	hs, err := json.Marshal(screenHandshake{
		HubURL: strings.TrimRight(c.cfg.HubURL, "/"), CAPEM: string(caPEM), SessionID: sessionID,
		Token: token, Mode: mode, Host: host, Text: text,
	})
	return append(hs, '\n'), err
}

// screenCtlRunner runs `ominull-screen ctl ARGS...` with the handshake on
// stdin and returns its stdout (one JSON object). Tests replace it.
var screenCtlRunner = func(tool string, args []string, stdin []byte) ([]byte, error) {
	cmd := exec.Command(tool, append([]string{"ctl"}, args...)...)
	cmd.Stdin = bytes.NewReader(stdin)
	cmd.Stderr = os.Stderr
	out, err := cmd.Output()
	if err != nil {
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			return out, fmt.Errorf("ominull-screen ctl %s failed: %s", args[0], ctlError(out, exit))
		}
		return out, fmt.Errorf("ominull-screen would not start: %w", err)
	}
	return out, nil
}

// ctlError is the error ctl printed ({"error": ...}), else its exit status.
func ctlError(out []byte, exit *exec.ExitError) string {
	var res struct {
		Error string `json:"error"`
	}
	if json.Unmarshal(bytes.TrimSpace(out), &res) == nil && res.Error != "" {
		return res.Error
	}
	return exit.Error()
}

// screenAttach rotates the held session's operator token. A session the hub
// no longer has live leaves the ended marker.
func (c *APIClient) screenAttach(h *heldScreen) (string, error) {
	if !h.ExpiresAt.IsZero() && time.Now().After(h.ExpiresAt) {
		return "", markScreenEnded(h.Endpoint, "it reached its time limit")
	}
	raw, status, err := c.doRequestWith(http.MethodPost, "/api/v1/screen/sessions/attach", map[string]string{"session_id": h.SessionID}, nil)
	if err != nil {
		switch status {
		case http.StatusNotFound, http.StatusConflict, http.StatusGone:
			return "", markScreenEnded(h.Endpoint, "the hub says it is no longer live")
		}
		return "", err
	}
	var s struct {
		Token string `json:"connect_token"`
	}
	if json.Unmarshal(raw, &s) != nil || s.Token == "" {
		return "", fmt.Errorf("the hub gave no screen token: %s", screenRedact(raw))
	}
	return s.Token, nil
}

// screenCtl runs one ctl action on the held session and returns its JSON.
// text (screen type) rides the stdin line, never argv.
func (c *APIClient) screenCtl(h *heldScreen, tool string, args []string, text string) ([]byte, error) {
	c = c.withAgent(h.Agent)
	token, err := c.screenAttach(h)
	if err != nil {
		return nil, err
	}
	line, err := c.screenHandshakeLine(h.SessionID, token, h.Mode, h.Host, text)
	if err != nil {
		return nil, err
	}
	out, err := screenCtlRunner(tool, args, line)
	if err != nil {
		// ctl says "the session ended: WHY. Open a new one."
		if i := strings.Index(err.Error(), "the session ended: "); i >= 0 {
			why := strings.TrimSpace(err.Error()[i+len("the session ended: "):])
			why = strings.TrimSuffix(strings.TrimSuffix(why, "Open a new one."), " ")
			return nil, markScreenEnded(h.Endpoint, strings.TrimSuffix(why, "."))
		}
		return nil, err
	}
	return out, nil
}

// screenHold: one owner tap for a session an agent then drives with the
// other screen commands.
func (c *APIClient) screenHold(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("screen hold", flag.ContinueOnError)
	view := fs.Bool("view", false, "watch only: info and shot work, input does not")
	ttl := fs.Duration("ttl", 0, "how long to keep the session, e.g. 90m (default and most: the hub's session limit; the hub also ends an idle session)")
	viewerFlag := fs.String("viewer", "", "ominull-screen to run (default: next to ominullctl, else on PATH)")
	agentFlag := fs.String("agent", "", "name of the agent asking, shown to the owner and in the audit (default $OMINULL_AGENT)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("usage: ominullctl screen hold [--view] [--ttl 90m] [--agent LABEL] ENDPOINT")
	}
	agent, err := screenAgentLabel(*agentFlag)
	if err != nil {
		return err
	}
	c = c.withAgent(agent)
	endpoint := fs.Arg(0)
	if err := hubSafe(c.cfg.HubURL); err != nil {
		return err
	}
	tool, err := findScreenViewer(*viewerFlag)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(heldDir(), 0o700); err != nil {
		return err
	}
	// Already held and still live: reuse it, no new tap.
	if h, err := loadHeldScreen(endpoint); err == nil {
		if res, err := c.screenCtl(h, tool, []string{"info"}, ""); err == nil {
			fmt.Fprintf(os.Stderr, "[+] A screen session to %s is already held; the screen commands use it.\n", endpoint)
			_, err = out.Write(res)
			return err
		}
	}
	_ = os.Remove(heldScreenEnded(endpoint)) // a new session is the answer to an ended one
	_ = os.Remove(heldScreenFile(endpoint))

	mode := "control"
	if *view {
		mode = "view"
	}
	body := map[string]interface{}{"endpoint_id": endpoint, "mode": mode}
	if *ttl > 0 {
		body["max_duration_seconds"] = int64((*ttl + time.Second - 1) / time.Second)
	}
	raw, err := c.ownerApproved(http.MethodPost, "/api/v1/screen/sessions", body)
	if err != nil {
		return err
	}
	var s struct {
		SessionID string    `json:"session_id"`
		Mode      string    `json:"mode"`
		Token     string    `json:"connect_token"`
		ExpiresAt time.Time `json:"expires_at"`
	}
	if err := json.Unmarshal(raw, &s); err != nil || s.SessionID == "" || s.Token == "" {
		return fmt.Errorf("the hub opened no screen session it would hand this caller: %s", screenRedact(raw))
	}
	if s.Mode == "" {
		s.Mode = mode
	}
	if s.ExpiresAt.IsZero() && *ttl > 0 {
		s.ExpiresAt = time.Now().Add(*ttl)
	}
	h := &heldScreen{Hub: strings.TrimRight(c.cfg.HubURL, "/"), SessionID: s.SessionID, Endpoint: endpoint, Mode: s.Mode, Host: c.endpointLabel(endpoint), ExpiresAt: s.ExpiresAt, Agent: agent}
	end := func() {
		_, _, _ = c.doRequestWith(http.MethodDelete, "/api/v1/screen/sessions?id="+url.QueryEscape(s.SessionID), nil, nil)
	}
	// Attach once now, with the token the open returned: the endpoint must
	// connect within the hub's connect timeout, and this is also the check
	// that the screen is really there.
	line, err := c.screenHandshakeLine(s.SessionID, s.Token, s.Mode, h.Host, "")
	if err != nil {
		end()
		return err
	}
	res, err := screenCtlRunner(tool, []string{"info"}, line)
	if err != nil {
		end()
		return fmt.Errorf("%v; the session was ended", err)
	}
	state, _ := json.Marshal(h)
	if err := os.WriteFile(heldScreenFile(endpoint), state, 0o600); err != nil {
		end()
		return err
	}
	left := "until the hub's session limit"
	if !s.ExpiresAt.IsZero() {
		left = "for " + time.Until(s.ExpiresAt).Round(time.Minute).String()
	}
	what := "Control"
	if s.Mode == "view" {
		what = "View-only"
	}
	fmt.Fprintf(os.Stderr, "[+] %s screen session to %s is held %s. Use ominullctl screen shot|click|type|... %s; end it with ominullctl screen end %s\n",
		what, endpoint, left, endpoint, endpoint)
	_, err = out.Write(res)
	return err
}

// screenAction runs one agent command (info, shot, click, ...) on the held
// session and prints ctl's JSON result unchanged.
func (c *APIClient) screenAction(action string, args []string, out io.Writer) error {
	fs := flag.NewFlagSet("screen "+action, flag.ContinueOnError)
	monitor := fs.Int("monitor", -1, "monitor id (default: the primary)")
	maxEdge := fs.Int("max-edge", screenMaxEdge(), "long edge of the screenshot space in pixels")
	output := fs.String("o", "", "PNG file to write (shot)")
	button := fs.String("button", "left", "left, right or middle (click)")
	double := fs.Bool("double", false, "double click (click)")
	viewerFlag := fs.String("viewer", "", "ominull-screen to run (default: next to ominullctl, else on PATH)")
	// Flags may come before or after the positional arguments; a negative
	// number (scroll DY) is an argument, and everything after "--" is.
	var pos []string
	rest := args
	for len(rest) > 0 {
		if rest[0] == "--" {
			pos = append(pos, rest[1:]...)
			break
		}
		if _, err := strconv.ParseFloat(rest[0], 64); err == nil {
			pos, rest = append(pos, rest[0]), rest[1:]
			continue
		}
		if err := fs.Parse(rest); err != nil {
			return err
		}
		left := fs.Args()
		if consumed := rest[:len(rest)-len(left)]; len(consumed) > 0 && consumed[len(consumed)-1] == "--" {
			pos = append(pos, left...)
			break
		}
		rest = left
		if len(rest) > 0 { // Parse stopped at an argument
			pos, rest = append(pos, rest[0]), rest[1:]
		}
	}
	want := map[string]int{"info": 0, "shot": 0, "click": 2, "move": 2, "drag": 4, "scroll": 3, "type": 1, "key": 1}[action]
	if action == "type" && len(pos) == 1 {
		pos = append(pos, "-") // no text argument: read it from stdin
	}
	if len(pos) != want+1 {
		return fmt.Errorf("usage: ominullctl screen %s ENDPOINT%s (ominullctl help screen)", action,
			map[string]string{"info": "", "shot": " -o FILE.png [--monitor N] [--max-edge E]", "click": " X Y [--button B] [--double] [--monitor N]",
				"move": " X Y [--monitor N]", "drag": " X1 Y1 X2 Y2 [--monitor N]", "scroll": " X Y DY [--monitor N]", "type": ` ["text" | -]`, "key": " COMBO"}[action])
	}
	endpoint, vals := pos[0], pos[1:]
	if *maxEdge < 16 || *maxEdge > 16384 {
		return errors.New("--max-edge must be between 16 and 16384")
	}
	ctl := []string{action, "--max-edge", strconv.Itoa(*maxEdge)}
	switch action {
	case "shot", "click", "move", "drag", "scroll":
		if *monitor >= 0 {
			ctl = append(ctl, "--monitor", strconv.Itoa(*monitor))
		}
		for _, v := range vals {
			if _, err := strconv.ParseFloat(v, 64); err != nil {
				return fmt.Errorf("%q is not a number", v)
			}
		}
	}
	switch action {
	case "shot":
		if *output == "" {
			return errors.New("screen shot needs -o FILE.png")
		}
		abs, err := filepath.Abs(*output)
		if err != nil {
			return err
		}
		ctl = append(ctl, "-o", abs)
	case "click":
		switch *button {
		case "left", "right", "middle":
		default:
			return errors.New("--button is left, right or middle")
		}
		ctl = append(ctl, "--button", *button)
		if *double {
			ctl = append(ctl, "--double")
		}
	}
	// The text goes on ctl's stdin line, never in its argv (the process list).
	text := ""
	if action == "type" {
		var err error
		if text, err = screenTypeText(vals[0]); err != nil {
			return err
		}
		vals = nil
	}
	// Positionals after "--", so a negative DY is never read as a flag.
	ctl = append(append(ctl, "--"), vals...)

	h, err := loadHeldScreen(endpoint)
	if err != nil {
		return err
	}
	tool, err := findScreenViewer(*viewerFlag)
	if err != nil {
		return err
	}
	res, err := c.screenCtl(h, tool, ctl, text)
	if err != nil {
		return err
	}
	_, err = out.Write(res)
	return err
}

// screenTypeText is screen type's text: the argument, or with "-" stdin
// minus one trailing newline (so echo and here-strings type no Enter).
func screenTypeText(arg string) (string, error) {
	text := arg
	if arg == "-" {
		raw, err := io.ReadAll(io.LimitReader(screenStdin, maxScreenTypeText+3))
		if err != nil {
			return "", fmt.Errorf("could not read the text from stdin: %w", err)
		}
		text = strings.TrimSuffix(strings.TrimSuffix(string(raw), "\n"), "\r")
	}
	switch {
	case text == "":
		return "", errors.New("screen type needs some text")
	case len(text) > maxScreenTypeText:
		return "", fmt.Errorf("screen type takes at most %d bytes of text", maxScreenTypeText)
	case !utf8.ValidString(text):
		return "", errors.New("screen type's text is not UTF-8")
	}
	return text, nil
}

// screenWatch opens the GUI viewer view-only beside the held session, for
// the owner to watch what an agent does. It does not end the session.
func (c *APIClient) screenWatch(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("screen watch", flag.ContinueOnError)
	viewerFlag := fs.String("viewer", "", "the screen viewer to start (default: "+screenViewerName+" next to ominullctl, else on PATH)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("usage: ominullctl screen watch ENDPOINT")
	}
	endpoint := fs.Arg(0)
	h, err := loadHeldScreen(endpoint)
	if err != nil {
		return err
	}
	c = c.withAgent(h.Agent)
	viewer, err := findScreenViewer(*viewerFlag)
	if err != nil {
		return err
	}
	raw, status, err := c.doRequestWith(http.MethodPost, "/api/v1/screen/sessions/watch", map[string]string{"session_id": h.SessionID}, nil)
	if err != nil {
		if status == http.StatusNotFound || status == http.StatusGone || (status == http.StatusConflict && strings.Contains(err.Error(), "no longer live")) {
			return markScreenEnded(endpoint, "the hub says it is no longer live")
		}
		return err
	}
	var wt struct {
		Token string `json:"token"`
		Mode  string `json:"mode"`
		Host  string `json:"host"`
	}
	if json.Unmarshal(raw, &wt) != nil || wt.Token == "" {
		return errors.New("the hub gave no watch token (watch tokens are for the admin key; the console gets a launch link instead)")
	}
	host := wt.Host
	if host == "" {
		host = h.Host
	}
	line, err := c.screenHandshakeLine(h.SessionID, wt.Token, "view", host, "")
	if err != nil {
		return err
	}
	cmd := exec.Command(viewer)
	cmd.Stdin = bytes.NewReader(line)
	cmd.Stdout, cmd.Stderr = os.Stderr, os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("the screen viewer failed: %w", err)
	}
	fmt.Fprintf(out, "Stopped watching %s; the held session is still open.\n", endpoint)
	return nil
}

// screenEnd ends the held session.
func (c *APIClient) screenEnd(args []string, out io.Writer) error {
	if len(args) != 1 {
		return errors.New("usage: ominullctl screen end ENDPOINT")
	}
	endpoint := args[0]
	if _, err := os.Stat(heldScreenFile(endpoint)); err != nil {
		if rerr := os.Remove(heldScreenEnded(endpoint)); rerr == nil {
			fmt.Fprintf(out, "The screen session to %s had already ended.\n", endpoint)
			return nil
		}
	}
	h, err := loadHeldScreen(endpoint)
	if err != nil {
		return err
	}
	_, status, err := c.withAgent(h.Agent).doRequestWith(http.MethodDelete, "/api/v1/screen/sessions?id="+url.QueryEscape(h.SessionID), nil, nil)
	_ = os.Remove(heldScreenFile(endpoint))
	_ = os.Remove(heldScreenEnded(endpoint))
	if err != nil && status != http.StatusNotFound {
		return err
	}
	fmt.Fprintf(out, "Screen session to %s ended.\n", endpoint)
	return nil
}

// screenSettings shows or changes screen.ask_first (GET/PUT
// /api/v1/screen/settings). Turning it off waits for the owner's tap.
func (c *APIClient) screenSettings(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("screen settings", flag.ContinueOnError)
	ask := fs.String("ask-first", "", "on, off, or fleet (follow the fleet default / forget it)")
	var pos []string
	rest := args
	for len(rest) > 0 {
		if err := fs.Parse(rest); err != nil {
			return err
		}
		if rest = fs.Args(); len(rest) > 0 {
			pos, rest = append(pos, rest[0]), rest[1:]
		}
	}
	if len(pos) > 1 {
		return errors.New("usage: ominullctl screen settings [ENDPOINT] [--ask-first on|off|fleet]")
	}
	path := "/api/v1/screen/settings"
	endpoint := ""
	if len(pos) == 1 {
		endpoint = pos[0]
		path += "?endpoint_id=" + url.QueryEscape(endpoint)
	}
	var raw []byte
	var err error
	switch *ask {
	case "":
		raw, err = c.doRequest(http.MethodGet, path, nil)
	case "on", "off":
		raw, err = c.ownerApproved(http.MethodPut, path, map[string]bool{"ask_first": *ask == "on"})
	case "fleet":
		raw, err = c.ownerApproved(http.MethodPut, path, map[string]bool{"reset": true})
	default:
		return errors.New("--ask-first is on, off or fleet")
	}
	if err != nil {
		return err
	}
	var v struct {
		AskFirst  bool            `json:"ask_first"`
		Source    string          `json:"source"`
		Fleet     bool            `json:"fleet_ask_first"`
		Endpoints map[string]bool `json:"endpoints"`
		Changed   *bool           `json:"changed"`
	}
	if err := json.Unmarshal(raw, &v); err != nil {
		return fmt.Errorf("unreadable screen settings: %s", strings.TrimSpace(string(raw)))
	}
	if c.cfg.JSONOutput {
		_, err = out.Write(append(raw, '\n'))
		return err
	}
	onOff := map[bool]string{true: "on", false: "off"}
	if endpoint != "" {
		src := map[string]string{"endpoint": "its own setting", "fleet": "the fleet default", "default": "not set anywhere"}[v.Source]
		fmt.Fprintf(out, "Ask the person at the keyboard first on %s: %s (%s; fleet default %s)\n", endpoint, onOff[v.AskFirst], src, onOff[v.Fleet])
	} else {
		fmt.Fprintf(out, "Ask the person at the keyboard first, fleet default: %s\n", onOff[v.AskFirst])
		ids := make([]string, 0, len(v.Endpoints))
		for id := range v.Endpoints {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		for _, id := range ids {
			fmt.Fprintf(out, "  %s: %s\n", id, onOff[v.Endpoints[id]])
		}
	}
	if v.Changed != nil && !*v.Changed {
		fmt.Fprintln(out, "(already set that way; nothing changed)")
	}
	return nil
}
