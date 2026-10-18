package screen

import (
	"encoding/json"
	"fmt"
	"sync"
	"time"
	"unicode/utf8"
)

// Agent action audit (REMOTE_SCREEN.md section 7): while an agent (the hub
// admin key, via ominullctl) holds a session's control attachment, every
// input it sends is audited by kind and coordinates - mouse button down/up,
// wheel, key, sas - with typed text by length only, never content, and plain
// mouse moves not logged one by one. Writes are rate limited per session;
// what the limit holds back is counted into the next line written.

// InputAuditFunc writes one audit line for a session's input.
type InputAuditFunc func(line string)

const (
	auditBurst  = 30              // lines a session may write at once
	auditRefill = 5 * time.Second // ... and one more line per this
)

type inputAuditor struct {
	write    InputAuditFunc
	tokens   float64
	last     time.Time
	held     int
	heldMove int
}

var (
	auditMu  sync.Mutex
	auditors = map[string]*inputAuditor{}
)

// SetInputAudit audits a session's control input through fn; the hub sets
// it while an agent holds control. The returned func stops it, unless a
// later SetInputAudit for the session (a superseding attachment) replaced it.
func SetInputAudit(sessionID string, fn InputAuditFunc) (clear func()) {
	a := &inputAuditor{write: fn, tokens: auditBurst, last: time.Now()}
	auditMu.Lock()
	auditors[sessionID] = a
	auditMu.Unlock()
	return func() {
		auditMu.Lock()
		defer auditMu.Unlock()
		if auditors[sessionID] == a {
			delete(auditors, sessionID)
		}
	}
}

type inputFrame struct {
	Ev      string          `json:"ev"`
	X       *float64        `json:"x"`
	Y       *float64        `json:"y"`
	DX      float64         `json:"dx"`
	DY      float64         `json:"dy"`
	Monitor int             `json:"monitor"`
	Buttons map[string]bool `json:"buttons"`
	Code    int             `json:"code"`
	Down    bool            `json:"down"`
	Ext     bool            `json:"ext"`
	Ch      string          `json:"ch"`
}

// auditInput describes one control input frame for the audit, if the session
// is being audited.
func (p *policy) auditInput(data []byte) {
	auditMu.Lock()
	a := auditors[p.sessionID]
	auditMu.Unlock()
	if a == nil {
		return
	}
	var f inputFrame
	if json.Unmarshal(data, &f) != nil {
		return
	}
	at := func() string {
		if f.X == nil || f.Y == nil {
			return fmt.Sprintf("on monitor %d", f.Monitor)
		}
		return fmt.Sprintf("at %d,%d on monitor %d (0..65535)", int(*f.X), int(*f.Y), f.Monitor)
	}
	var line string
	switch f.Ev {
	case "mouse":
		var changes []string
		for _, b := range []string{"l", "r", "m"} {
			if f.Buttons[b] != p.buttons[b] {
				state := "up"
				if f.Buttons[b] {
					state = "down"
				}
				changes = append(changes, map[string]string{"l": "left", "r": "right", "m": "middle"}[b]+" button "+state)
				p.buttons[b] = f.Buttons[b]
			}
		}
		if len(changes) == 0 {
			a.note("", true)
			return
		}
		line = "mouse " + joinWords(changes) + " " + at()
	case "wheel":
		line = fmt.Sprintf("wheel dx=%d dy=%d %s", int(f.DX), int(f.DY), at())
	case "key":
		state := "up"
		if f.Down {
			state = "down"
		}
		line = fmt.Sprintf("key scancode %d%s %s", f.Code, map[bool]string{true: " (extended)"}[f.Ext], state)
	case "text":
		line = fmt.Sprintf("typed text, %d characters", utf8.RuneCountInString(f.Ch))
	case "sas":
		line = "Ctrl+Alt+Del (secure attention) requested"
	default:
		line = "input of an unknown kind"
	}
	a.note("Agent screen input: "+line, false)
}

func joinWords(w []string) string {
	out := ""
	for i, s := range w {
		if i > 0 {
			out += ", "
		}
		out += s
	}
	return out
}

// note writes a line within the session's rate limit, or counts it.
func (a *inputAuditor) note(line string, move bool) {
	auditMu.Lock()
	now := time.Now()
	a.tokens += now.Sub(a.last).Seconds() / auditRefill.Seconds()
	if a.tokens > auditBurst {
		a.tokens = auditBurst
	}
	a.last = now
	if move {
		a.heldMove++
		auditMu.Unlock()
		return
	}
	if a.tokens < 1 {
		a.held++
		auditMu.Unlock()
		return
	}
	a.tokens--
	if a.held > 0 || a.heldMove > 0 {
		line += fmt.Sprintf(" (since the last line: %d more inputs not logged one by one, %d mouse moves)", a.held, a.heldMove)
		a.held, a.heldMove = 0, 0
	}
	write := a.write
	auditMu.Unlock()
	write(line)
}
