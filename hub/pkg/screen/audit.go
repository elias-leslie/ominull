package screen

import (
	"fmt"
	"sync"
	"time"
	"unicode/utf8"
)

// Agent action audit (REMOTE_SCREEN.md section 7): while an agent (the hub
// admin key, via ominullctl) holds a session's control attachment, every
// input it sends is audited by kind and coordinates - mouse button down/up,
// wheel, sas - with typed text by length only, never content. Plain mouse
// moves and key events are counted, not logged one by one (a scancode
// stream is a keylog). Writes are rate limited per session; what the limit
// holds back is counted into the next line written, and whatever is still
// counted when auditing stops (the agent detaches or the session ends) is
// written then, so no input goes unaccounted.

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
	heldKey  int
}

var (
	auditMu  sync.Mutex
	auditors = map[string]*inputAuditor{}
)

// SetInputAudit audits a session's control input through fn; the hub sets
// it while an agent holds control. The returned func stops it, writing a
// last line for anything still counted, unless a later SetInputAudit for the
// session (a superseding attachment) replaced it; the replaced auditor's
// counts are written when it is replaced.
func SetInputAudit(sessionID string, fn InputAuditFunc) (clear func()) {
	a := &inputAuditor{write: fn, tokens: auditBurst, last: time.Now()}
	auditMu.Lock()
	prev := auditors[sessionID]
	auditors[sessionID] = a
	prevLine, prevWrite := prev.takeCountsLocked()
	auditMu.Unlock()
	if prevLine != "" {
		prevWrite(prevLine)
	}
	return func() {
		auditMu.Lock()
		if auditors[sessionID] == a {
			delete(auditors, sessionID)
		}
		line, write := a.takeCountsLocked()
		auditMu.Unlock()
		if line != "" {
			write(line)
		}
	}
}

// takeCountsLocked returns a line for the counts held so far (and clears
// them), or "" when nothing is held. auditMu must be held.
func (a *inputAuditor) takeCountsLocked() (string, InputAuditFunc) {
	if a == nil || (a.held == 0 && a.heldMove == 0 && a.heldKey == 0) {
		return "", nil
	}
	line := "Agent screen input: " + a.countsLocked() + " since the last line"
	return line, a.write
}

// countsLocked describes and clears the held counts.
func (a *inputAuditor) countsLocked() string {
	s := fmt.Sprintf("%d more inputs not logged one by one, %d mouse moves, %d key events", a.held, a.heldMove, a.heldKey)
	a.held, a.heldMove, a.heldKey = 0, 0, 0
	return s
}

// auditInput describes one control input frame for the audit, if the session
// is being audited. f is the same parse the hub forwards.
func (p *policy) auditInput(f *wireInput) {
	auditMu.Lock()
	a := auditors[p.sessionID]
	auditMu.Unlock()
	if a == nil || f == nil {
		return
	}
	monitor := int64(0)
	if f.Monitor != nil {
		monitor = *f.Monitor
	}
	at := func() string {
		if f.X == nil || f.Y == nil {
			return fmt.Sprintf("on monitor %d", monitor)
		}
		return fmt.Sprintf("at %d,%d on monitor %d (0..65535)", *f.X, *f.Y, monitor)
	}
	var line string
	switch f.Ev {
	case "mouse":
		var b wireButtons
		if f.Buttons != nil {
			b = *f.Buttons
		}
		now := map[string]bool{"l": b.L, "r": b.R, "m": b.M}
		var changes []string
		for _, k := range []string{"l", "r", "m"} {
			if now[k] != p.buttons[k] {
				state := "up"
				if now[k] {
					state = "down"
				}
				changes = append(changes, map[string]string{"l": "left", "r": "right", "m": "middle"}[k]+" button "+state)
				p.buttons[k] = now[k]
			}
		}
		if len(changes) == 0 {
			a.count(countMove)
			return
		}
		line = "mouse " + joinWords(changes) + " " + at()
	case "wheel":
		var dx, dy int64
		if f.DX != nil {
			dx = *f.DX
		}
		if f.DY != nil {
			dy = *f.DY
		}
		line = fmt.Sprintf("wheel dx=%d dy=%d %s", dx, dy, at())
	case "key":
		a.count(countKey)
		return
	case "text":
		n := 0
		if f.Ch != nil {
			n = utf8.RuneCountInString(*f.Ch)
		}
		line = fmt.Sprintf("typed text, %d characters", n)
	case "sas":
		line = "Ctrl+Alt+Del (secure attention) requested"
	default:
		line = "input of an unknown kind"
	}
	a.note("Agent screen input: " + line)
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

const (
	countMove = iota
	countKey
)

// count records an input that is counted, never logged on its own.
func (a *inputAuditor) count(kind int) {
	auditMu.Lock()
	defer auditMu.Unlock()
	if kind == countKey {
		a.heldKey++
	} else {
		a.heldMove++
	}
}

// note writes a line within the session's rate limit, or counts it.
func (a *inputAuditor) note(line string) {
	auditMu.Lock()
	now := time.Now()
	a.tokens += now.Sub(a.last).Seconds() / auditRefill.Seconds()
	if a.tokens > auditBurst {
		a.tokens = auditBurst
	}
	a.last = now
	if a.tokens < 1 {
		a.held++
		auditMu.Unlock()
		return
	}
	a.tokens--
	if a.held > 0 || a.heldMove > 0 || a.heldKey > 0 {
		line += " (since the last line: " + a.countsLocked() + ")"
	}
	write := a.write
	auditMu.Unlock()
	write(line)
}
