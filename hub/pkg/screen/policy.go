package screen

import (
	"encoding/json"
	"math"
	"strings"

	"github.com/gorilla/websocket"
	"ominull/hub/pkg/response"
	"ominull/hub/pkg/terminal"
)

// The hub parses only the JSON control frames it polices (REMOTE_SCREEN.md
// 4.4): the frame type, a quality request and a bye's reason. Every binary
// agent message (a tile, a cursor shape: fixed binary header + bytes) is
// opaque and passes through as binary, unread. Input events pass through
// unread too; the helper validates them.

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
	agFrameEnd       = "frame_end"
	agCursorPos      = "cursor_pos"
	agResized        = "resized"
	agSASUnavailable = "sas_unavailable"
	agBye            = "bye"
)

type policy struct {
	sessionID string
	control   bool
	// buttons is the control attachment's last mouse button state, for the
	// input audit (read pump goroutine only).
	buttons map[string]bool
}

func newPolicy(program, sessionID string) terminal.FramePolicy {
	mode, _ := ModeOf(program)
	// Anything but an explicit control session is view-only.
	return &policy{sessionID: sessionID, control: mode == response.ScreenModeControl, buttons: map[string]bool{}}
}

// Watcher polices a watch attachment: its acks reach the agent while it
// paces; its close detaches it alone; input and stream changes are not a
// watcher's to make.
func (p *policy) Watcher(msgType int, data []byte) terminal.FrameDecision {
	if msgType != websocket.TextMessage {
		return closeWith("forbidden_watcher_frame_type")
	}
	var f controlFrame
	if err := json.Unmarshal(data, &f); err != nil {
		return closeWith("malformed_watcher_frame")
	}
	switch f.Type {
	case opAck:
		return terminal.FrameDecision{}
	case opClose:
		return closeWith("watcher_left")
	}
	return terminal.FrameDecision{Action: terminal.FrameDrop}
}

func closeWith(reason string) terminal.FrameDecision {
	return terminal.FrameDecision{Action: terminal.FrameCloseSession, Reason: reason}
}

type controlFrame struct {
	Type   string   `json:"type"`
	FPS    *float64 `json:"fps"`
	JPEGQ  *float64 `json:"jpeg_q"`
	Reason string   `json:"reason"`
}

func (p *policy) Operator(msgType int, data []byte) terminal.FrameDecision {
	if msgType != websocket.TextMessage {
		return closeWith("forbidden_operator_frame_type")
	}
	var f controlFrame
	if err := json.Unmarshal(data, &f); err != nil {
		return closeWith("malformed_operator_frame")
	}
	switch f.Type {
	case opAck:
		// The viewer acks every frame by itself; that is not a person.
		return terminal.FrameDecision{}
	case opInput:
		if !p.control {
			// The owner approved watching only. The helper ignores input in
			// a view session too; this is the hub's half.
			return terminal.FrameDecision{Action: terminal.FrameDrop}
		}
		p.auditInput(data)
		return terminal.FrameDecision{Activity: true}
	case opSetMonitor:
		return terminal.FrameDecision{Activity: true}
	case opQuality:
		fps := clampInt(f.FPS, 1, MaxFPS, MaxFPS)
		q := clampInt(f.JPEGQ, MinJPEGQuality, MaxJPEGQuality, DefaultJPEGQuality)
		out, _ := json.Marshal(struct {
			Type  string `json:"type"`
			FPS   int    `json:"fps"`
			JPEGQ int    `json:"jpeg_q"`
		}{opQuality, fps, q})
		return terminal.FrameDecision{Data: out, Activity: true}
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
	case agHello, agFrameEnd, agCursorPos, agResized, agSASUnavailable:
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
