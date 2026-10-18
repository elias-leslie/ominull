package terminal

import (
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// Session kinds other than a shell ride the same relay, manager, caps and
// sweeper (the remote screen, hub/pkg/screen). A kind is chosen by the
// session's program: a program starting with a registered prefix belongs to
// that kind and the relay polices its frames with the kind's FramePolicy
// instead of the shell's {stdin,resize,close}/{stdout,close} rule. A shell
// session (no registered prefix) behaves exactly as before.

// FrameAction is what the relay does with one WebSocket message.
type FrameAction int

const (
	// FrameForward passes the message on to the other side.
	FrameForward FrameAction = iota
	// FrameDrop discards the message and keeps the session.
	FrameDrop
	// FrameCloseSession ends the session (a protocol violation, or a side
	// asking to end it).
	FrameCloseSession
)

// FrameDecision is a policy's verdict on one message.
type FrameDecision struct {
	Action FrameAction
	// Reason is the close reason when Action is FrameCloseSession.
	Reason string
	// Data, when set, replaces the message payload (sent as a text message):
	// a policy that clamps a field re-encodes the frame.
	Data []byte
	// Activity marks operator activity: it pushes the idle deadline.
	Activity bool
}

// FramePolicy polices one session's frames. The relay calls Operator from the
// operator's read pump and Agent from the agent's, so a policy keeps any
// per-direction state apart.
type FramePolicy interface {
	Operator(msgType int, data []byte) FrameDecision
	Agent(msgType int, data []byte) FrameDecision
}

// WatchPolicy is implemented by the policy of a kind that takes watch
// (view-only) attachments beside the one control attachment. The relay calls
// Watcher from each watcher's read pump: FrameForward sends the message to
// the agent only while that watcher paces the stream (no control attachment,
// and it is the oldest watcher); FrameDrop discards it; FrameCloseSession
// detaches that watcher alone - a watcher never ends the session.
type WatchPolicy interface {
	Watcher(msgType int, data []byte) FrameDecision
}

// ReplayPolicy is implemented by the policy of a kind whose agent sends some
// state only once (screen: the monitor list and the current desktop) that
// every attachment needs before anything else. The relay writes Replay's text
// messages to each new control or watch attachment first, before its write
// pump starts, so they always arrive ahead of the live stream.
type ReplayPolicy interface {
	Replay() [][]byte
}

// ResumePolicy is implemented by the policy of a kind that must tell the agent
// more than ResumeMessage when the first attachment comes back after a pause
// (screen: acks for frames the departed viewer never acked, so the agent's
// flow-control window is open again). The relay sends them right after the
// resume, to the agent.
type ResumePolicy interface {
	ResumeMessages() [][]byte
}

// writeReplay sends a ReplayPolicy's messages to a just-upgraded attachment.
func writeReplay(conn *websocket.Conn, p FramePolicy) error {
	rp, ok := p.(ReplayPolicy)
	if !ok {
		return nil
	}
	for _, msg := range rp.Replay() {
		_ = conn.SetWriteDeadline(time.Now().Add(WriteWait))
		if err := conn.WriteMessage(websocket.TextMessage, msg); err != nil {
			return err
		}
	}
	return nil
}

// SessionKind is a non-shell session kind.
type SessionKind struct {
	// Prefix selects the kind from the session's program, e.g. "screen:".
	Prefix string
	// Name is the kind in people's words, for refusals ("screen").
	Name string
	// NewPolicy makes the policy for one session's relay.
	NewPolicy func(program, sessionID string) FramePolicy
	// MaxWatchers is how many watch attachments a session may have at once
	// beside its control attachment (0: none; the policy must then not need
	// to be a WatchPolicy).
	MaxWatchers int
	// MaxPerEndpoint caps live sessions of this kind on one endpoint, on
	// top of the shared caps (which they also count against). 0: no own cap.
	MaxPerEndpoint int
	// NoRecording: the session is not recorded and gets no evidence bundle.
	NoRecording bool
	// AttachedIsActivity: an attached operator (answering the relay's pings)
	// counts as activity, so a session being watched is not idled out.
	AttachedIsActivity bool
	// PauseMessage is sent to the agent as text when the last attachment
	// (control or watch) leaves; ResumeMessage when the first one comes back
	// after a pause (nil sends nothing).
	PauseMessage, ResumeMessage []byte
}

var (
	kindsMu sync.RWMutex
	kinds   []SessionKind
)

// RegisterKind adds a session kind. Registering a prefix twice replaces it.
func RegisterKind(k SessionKind) {
	if k.Prefix == "" || k.NewPolicy == nil {
		panic("terminal: a session kind needs a prefix and a policy")
	}
	kindsMu.Lock()
	defer kindsMu.Unlock()
	for i := range kinds {
		if kinds[i].Prefix == k.Prefix {
			kinds[i] = k
			return
		}
	}
	kinds = append(kinds, k)
}

// KindFor returns the session kind a program belongs to, or nil for a shell.
func KindFor(program string) *SessionKind {
	kindsMu.RLock()
	defer kindsMu.RUnlock()
	for i := range kinds {
		if strings.HasPrefix(program, kinds[i].Prefix) {
			k := kinds[i]
			return &k
		}
	}
	return nil
}

// countLiveKind counts live sessions of one kind on an endpoint.
func (m *Manager) countLiveKind(endpointID, prefix string, now time.Time) (int, error) {
	var n int
	err := m.db.QueryRow(`
		SELECT COUNT(*) FROM terminal_sessions
		WHERE endpoint_id = ? AND substr(program, 1, ?) = ?
		  AND state IN ('waiting', 'connecting', 'active', 'detached') AND expires_at > ?;
	`, endpointID, len(prefix), prefix, now).Scan(&n)
	return n, err
}

// touchActivity pushes a session's idle deadline without recording a frame.
func (pr *PairedRelay) touchActivity() {
	now := time.Now().UTC()
	pr.sess.mu.Lock()
	pr.sess.IdleExpiresAt = now.Add(pr.mgr.idle())
	pr.sess.dirty = true
	pr.sess.mu.Unlock()
}
