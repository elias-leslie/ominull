package screen

import (
	"encoding/json"
	"errors"
	"math"
	"strings"
	"sync"

	"github.com/gorilla/websocket"
	"ominull/hub/pkg/response"
	"ominull/hub/pkg/terminal"
)

// The hub parses only the JSON control frames it polices (REMOTE_SCREEN.md
// 4.4). Every binary agent message (a tile, a cursor shape: fixed binary
// header + bytes) is opaque and passes through as binary, unread. Operator
// and watcher frames are parsed strictly and forwarded only as the hub's own
// canonical re-encoding (frame.go); the helper still validates every bound.

// Operator -> agent frame types.
const (
	opAck        = "ack"
	opInput      = "input"
	opSetMonitor = "set_monitor"
	opQuality    = "quality"
	opClose      = "close"
)

// Agent -> operator JSON frame types.
const (
	agHello          = "hello"
	agDesktop        = "desktop"
	agFrameEnd       = "frame_end"
	agCursorPos      = "cursor_pos"
	agResized        = "resized"
	agSASUnavailable = "sas_unavailable"
	agBye            = "bye"
)

type policy struct {
	sessionID string
	control   bool
	// replayMu guards hello and desktop: the latest monitor list (as a
	// hello) and desktop message from the agent, which the helper sends only
	// at start and on a change. Each new attachment gets them first
	// (terminal.ReplayPolicy), or a second ominullctl command would wait
	// forever for a monitor list.
	replayMu sync.Mutex
	hello    []byte
	desktop  []byte
	// lastFrame is the agent's latest frame_end (monitor, frame), guarded by
	// replayMu; haveFrame says one was seen.
	lastMonitor, lastFrame int64
	haveFrame              bool
	// buttons is the control attachment's last mouse button state, for the
	// input audit (read pump goroutine only).
	buttons map[string]bool
}

func newPolicy(program, sessionID string) terminal.FramePolicy {
	mode, _ := ModeOf(program)
	// Anything but an explicit control session is view-only.
	return &policy{sessionID: sessionID, control: mode == response.ScreenModeControl, buttons: map[string]bool{}}
}

// Watcher polices a watch attachment: its canonical ack reaches the agent
// (re-encoded) while it paces; its close detaches it alone; input and stream
// changes are not a watcher's to make and are dropped. Anything that does not
// parse strictly detaches the watcher.
func (p *policy) Watcher(msgType int, data []byte) terminal.FrameDecision {
	if msgType != websocket.TextMessage {
		return closeWith("forbidden_watcher_frame_type")
	}
	f, err := parseOperatorFrame(data)
	if errors.Is(err, errForbiddenType) {
		return closeWith("forbidden_watcher_frame_type")
	}
	if err != nil {
		return closeWith("malformed_watcher_frame")
	}
	switch f.Type {
	case opAck:
		return terminal.FrameDecision{Data: f.encode()}
	case opClose:
		return closeWith("watcher_left")
	}
	return terminal.FrameDecision{Action: terminal.FrameDrop}
}

func closeWith(reason string) terminal.FrameDecision {
	return terminal.FrameDecision{Action: terminal.FrameCloseSession, Reason: reason}
}

// controlFrame is the agent -> operator subset the hub reads.
type controlFrame struct {
	Type   string `json:"type"`
	Reason string `json:"reason"`
}

// Operator polices the control attachment. Every forwarded frame is the
// hub's own re-encoding of a strict parse (frame.go); pause and resume are
// the hub's to send and end the session if an operator sends them.
func (p *policy) Operator(msgType int, data []byte) terminal.FrameDecision {
	if msgType != websocket.TextMessage {
		return closeWith("forbidden_operator_frame_type")
	}
	f, err := parseOperatorFrame(data)
	if errors.Is(err, errForbiddenType) {
		return closeWith("forbidden_operator_frame_type")
	}
	if err != nil {
		return closeWith("malformed_operator_frame")
	}
	switch f.Type {
	case opAck:
		// The viewer acks every frame by itself; that is not a person.
		return terminal.FrameDecision{Data: f.encode()}
	case opInput:
		if !p.control {
			// The owner approved watching only. The helper ignores input in
			// a view session too; this is the hub's half.
			return terminal.FrameDecision{Action: terminal.FrameDrop}
		}
		p.auditInput(f.Input)
		return terminal.FrameDecision{Data: f.encode(), Activity: true}
	case opSetMonitor, opQuality:
		return terminal.FrameDecision{Data: f.encode(), Activity: true}
	case opClose:
		return closeWith("operator_requested_close")
	}
	return closeWith("forbidden_operator_frame_type")
}

func (p *policy) Agent(msgType int, data []byte) terminal.FrameDecision {
	switch msgType {
	case websocket.BinaryMessage:
		return terminal.FrameDecision{}
	case websocket.TextMessage:
	default:
		return closeWith("forbidden_agent_frame_type")
	}
	var f controlFrame
	if err := json.Unmarshal(data, &f); err != nil {
		return closeWith("malformed_agent_frame")
	}
	switch f.Type {
	case agHello, agResized:
		p.remember(f.Type, data)
		return terminal.FrameDecision{}
	case agDesktop:
		p.remember(f.Type, data)
		return terminal.FrameDecision{}
	case agFrameEnd:
		var fe struct {
			Monitor int64 `json:"monitor"`
			Frame   int64 `json:"frame"`
		}
		if json.Unmarshal(data, &fe) == nil && fe.Frame >= 0 && fe.Monitor >= 0 {
			p.replayMu.Lock()
			p.lastMonitor, p.lastFrame, p.haveFrame = fe.Monitor, fe.Frame, true
			p.replayMu.Unlock()
		}
		return terminal.FrameDecision{}
	case agCursorPos, agSASUnavailable:
		return terminal.FrameDecision{}
	case agBye:
		reason := "agent_bye"
		if r := cleanReason(f.Reason); r != "" {
			reason += ": " + r
		}
		return closeWith(reason)
	}
	return closeWith("forbidden_agent_frame_type")
}

// remember keeps the state a later attachment needs. A resized carries the
// same monitors and active fields as hello, so it is kept as a hello.
func (p *policy) remember(typ string, data []byte) {
	var keep []byte
	switch typ {
	case agHello, agResized:
		var m struct {
			Monitors json.RawMessage `json:"monitors"`
			Active   json.RawMessage `json:"active"`
		}
		if json.Unmarshal(data, &m) != nil || len(m.Monitors) == 0 {
			return
		}
		if len(m.Active) == 0 {
			m.Active = json.RawMessage("0")
		}
		keep, _ = json.Marshal(struct {
			Type     string          `json:"type"`
			Monitors json.RawMessage `json:"monitors"`
			Active   json.RawMessage `json:"active"`
		}{agHello, m.Monitors, m.Active})
	case agDesktop:
		keep = append([]byte(nil), data...)
	}
	if keep == nil {
		return
	}
	p.replayMu.Lock()
	defer p.replayMu.Unlock()
	if typ == agDesktop {
		p.desktop = keep
	} else {
		p.hello = keep
	}
}

// Replay is what each new attachment gets first: the monitor list, then the
// current desktop (terminal.ReplayPolicy).
func (p *policy) Replay() [][]byte {
	p.replayMu.Lock()
	defer p.replayMu.Unlock()
	var out [][]byte
	if p.hello != nil {
		out = append(out, p.hello)
	}
	if p.desktop != nil {
		out = append(out, p.desktop)
	}
	return out
}

// ResumeMessages acks the latest frame twice when a viewer comes back after a
// pause (terminal.ResumePolicy). Frames that reached the hub while nobody was
// attached were dropped unacked, and the helper sends nothing while two are
// unacked (REMOTE_SCREEN.md 4.3), so without this a second ominullctl command
// got its monitor list and then never a picture. The helper counts an ack
// only for a frame inside its window, so a spare ack opens nothing it should
// not. MaxUnacked acks open a full window.
func (p *policy) ResumeMessages() [][]byte {
	p.replayMu.Lock()
	defer p.replayMu.Unlock()
	if !p.haveFrame {
		return nil
	}
	ack, _ := json.Marshal(struct {
		Type    string `json:"type"`
		Monitor int64  `json:"monitor"`
		Frame   int64  `json:"frame"`
	}{opAck, p.lastMonitor, p.lastFrame})
	out := make([][]byte, maxUnacked)
	for i := range out {
		out[i] = ack
	}
	return out
}

// maxUnacked is the helper's flow-control window (screen/helper MAX_UNACKED).
const maxUnacked = 2

func clampInt(v *float64, lo, hi, def int) int {
	if v == nil || math.IsNaN(*v) || math.IsInf(*v, 0) {
		return def
	}
	n := int(math.Round(*v))
	if n < lo {
		return lo
	}
	if n > hi {
		return hi
	}
	return n
}

// cleanReason keeps a bye reason short and plain: it ends up in the session's
// close reason and the WebSocket close frame (at most 123 bytes).
func cleanReason(s string) string {
	var b strings.Builder
	for _, c := range s {
		if b.Len() >= 64 {
			break
		}
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == ' ', c == '_', c == '-', c == '.':
			b.WriteRune(c)
		}
	}
	return strings.TrimSpace(b.String())
}
