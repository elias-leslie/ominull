package terminal

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"
)

const (
	// MaxMessageSize is the maximum frame size in bytes (64 KiB).
	MaxMessageSize = 64 * 1024

	// MaxQueueBytes is the maximum buffered queue per direction (1 MiB).
	MaxQueueBytes = 1024 * 1024

	// WriteWait is the maximum time to wait for a frame write.
	WriteWait = 5 * time.Second

	// PongWait is the maximum time to wait for the next pong from peer.
	PongWait = 60 * time.Second

	// PingPeriod is the interval between heartbeats (must be < PongWait).
	PingPeriod = 25 * time.Second
)

var upgrader = websocket.Upgrader{
	ReadBufferSize:  32 * 1024,
	WriteBufferSize: 32 * 1024,
	CheckOrigin: func(r *http.Request) bool {
		return true // Origin enforcement is handled at the HTTP layer
	},
}

// PairedRelay coordinates full-duplex bidirectional frame streaming between
// the operator's browser and the remote endpoint agent.
type PairedRelay struct {
	mu           sync.Mutex
	sess         *TerminalSession
	mgr          *Manager
	opConn       *websocket.Conn
	agentConn    *websocket.Conn
	opToAgent    chan TerminalFrame
	agentToOp    chan TerminalFrame
	opQueueBytes atomic.Int64
	agQueueBytes atomic.Int64
	done         chan struct{}
	closeOnce    sync.Once
	ctx          context.Context
	cancel       context.CancelFunc

	// detached is read by agentReadPump on every frame. While it is set the
	// pump records to the session recording and does not enqueue: with no
	// operatorWritePump draining agentToOp, a chatty process would otherwise
	// push agQueueBytes past MaxQueueBytes and the pump would close the
	// session it was supposed to be keeping alive. A detached `yes` reaches
	// 1 MiB in well under a second.
	detached atomic.Bool

	// opStop belongs to the current operator attachment, not to the relay.
	// Closing pr.done would tear down the agent side too, so a detach needs
	// its own signal - and without one the previous operatorWritePump would
	// stay parked on agentToOp and steal frames from the next attachment.
	opStop chan struct{}
}

// newPairedRelay initializes pairing state for a terminal session.
func newPairedRelay(sess *TerminalSession, mgr *Manager) *PairedRelay {
	ctx, cancel := context.WithCancel(context.Background())
	return &PairedRelay{
		sess:      sess,
		mgr:       mgr,
		opToAgent: make(chan TerminalFrame, 64),
		agentToOp: make(chan TerminalFrame, 64),
		done:      make(chan struct{}),
		ctx:       ctx,
		cancel:    cancel,
	}
}

// Close gracefully closes both WebSocket connections and transitions session state.
func (pr *PairedRelay) Close(reason string) {
	pr.closeOnce.Do(func() {
		pr.cancel()
		close(pr.done)

		now := time.Now().UTC()
		pr.sess.mu.Lock()
		pr.sess.State = StateClosed
		pr.sess.ClosedAt = &now
		if pr.sess.CloseReason == "" {
			pr.sess.CloseReason = reason
		}
		startedAt := pr.sess.StartedAt
		opConn := pr.sess.OperatorConnected
		agConn := pr.sess.AgentConnected
		pr.sess.mu.Unlock()

		_ = pr.mgr.updateDurableState(pr.sess.SessionID, StateClosed, startedAt, &now, reason, opConn, agConn)

		pr.mu.Lock()
		opWS := pr.opConn
		agWS := pr.agentConn
		pr.opConn = nil
		pr.agentConn = nil
		pr.mu.Unlock()

		// Send close frame and close operator connection
		if opWS != nil {
			_ = opWS.WriteControl(
				websocket.CloseMessage,
				websocket.FormatCloseMessage(websocket.CloseNormalClosure, reason),
				time.Now().Add(WriteWait),
			)
			_ = opWS.Close()
		}

		// Send close frame and close agent connection
		if agWS != nil {
			_ = agWS.WriteControl(
				websocket.CloseMessage,
				websocket.FormatCloseMessage(websocket.CloseNormalClosure, reason),
				time.Now().Add(WriteWait),
			)
			_ = agWS.Close()
		}

		// Seal session recording into evidence store
		_ = pr.mgr.SealSessionRecording(pr.sess.SessionID)
	})
}

// isClosed reports whether the whole relay has already been torn down.
func (pr *PairedRelay) isClosed() bool {
	select {
	case <-pr.done:
		return true
	default:
		return false
	}
}

// DetachOperator drops the operator's socket and leaves everything else alone:
// the agent connection, its ping ticker, the context, the frame log and the
// evidence bundle all survive. The session moves active -> detached and the
// remote process tree keeps running.
//
// It is deliberately not Close's twin. Close is once-only and terminal; detach
// happens once per attachment and a session may cycle through it many times.
// It is a no-op on an already-closed relay, which is what lets the read pump
// call it from a defer that also runs after a protocol violation has called
// Close.
func (pr *PairedRelay) DetachOperator(reason string) {
	if pr.isClosed() {
		return
	}

	pr.mu.Lock()
	opWS := pr.opConn
	stop := pr.opStop
	pr.opConn = nil
	pr.opStop = nil
	pr.mu.Unlock()

	if opWS == nil && stop == nil {
		return // already detached
	}

	// Stop this attachment's write pump before anything else, so it cannot
	// take a frame off agentToOp that the next operator should have replayed.
	if stop != nil {
		close(stop)
	}

	pr.detached.Store(true)

	// Discard whatever was queued for the operator who just left. It has
	// already been recorded, and the reattaching operator replays the
	// recording from the beginning - handing them these frames as well would
	// print the same output twice. Draining is also what makes the byte
	// counter's reset honest.
	for {
		select {
		case <-pr.agentToOp:
			continue
		default:
		}
		break
	}
	pr.agQueueBytes.Store(0)

	now := time.Now().UTC()
	pr.sess.mu.Lock()
	pr.sess.OperatorConnected = false
	// Only a live session detaches. One that is closing, failed or expired
	// keeps the state it already reached.
	if pr.sess.State == StateActive || pr.sess.State == StateConnecting {
		pr.sess.State = StateDetached
	}
	st := pr.sess.State
	startedAt := pr.sess.StartedAt
	closedAt := pr.sess.ClosedAt
	closeReason := pr.sess.CloseReason
	agConn := pr.sess.AgentConnected
	pr.sess.mu.Unlock()

	_ = pr.mgr.updateDurableState(pr.sess.SessionID, st, startedAt, closedAt, closeReason, false, agConn)

	if opWS != nil {
		_ = opWS.WriteControl(
			websocket.CloseMessage,
			websocket.FormatCloseMessage(websocket.CloseNormalClosure, reason),
			time.Now().Add(WriteWait),
		)
		_ = opWS.Close()
	}

	// The agent is untouched on purpose: no close frame, no cancel, no seal.
	// Sending it a close frame is exactly what killed the process tree.
	_ = now
}

// AttachOperator upgrades the operator HTTP connection to WSS and starts relay loops.
func (m *Manager) AttachOperator(w http.ResponseWriter, r *http.Request, sessionID, rawToken string) error {
	sess, err := m.GetSession(sessionID)
	if err != nil {
		return errors.New("terminal session not found")
	}

	if !sess.ValidateOperatorToken(rawToken) {
		return errors.New("invalid or expired terminal connect token")
	}

	sess.mu.Lock()
	// StateDetached is attachable - that is the whole point of it. The
	// terminal states stay refused, and so does a second concurrent operator:
	// two browsers writing into one pty interleave keystrokes and the
	// recording stops being a record of what one person did.
	if sess.State == StateClosed || sess.State == StateFailed || sess.State == StateExpired {
		sess.mu.Unlock()
		return fmt.Errorf("session is in terminal state: %s", sess.State)
	}
	if sess.OperatorConnected {
		sess.mu.Unlock()
		return errors.New("operator already connected to session")
	}

	if sess.relay == nil {
		sess.relay = newPairedRelay(sess, m)
	}
	relay := sess.relay
	sess.OperatorConnected = true
	now := time.Now().UTC()
	if sess.AgentConnected {
		sess.State = StateActive
		// StartedAt is when the shell started, not when this viewer arrived.
		// Resetting it on every attach made a reattached session read as
		// brand new and hid how long a root shell had been open.
		if sess.StartedAt == nil {
			sess.StartedAt = &now
		}
	} else {
		sess.State = StateConnecting
	}
	// Attaching is operator activity. Without this a session detached for
	// fourteen minutes would be swept moments after somebody came back to it.
	sess.IdleExpiresAt = now.Add(m.idleTimeout)
	idleAt := sess.IdleExpiresAt
	st := sess.State
	startedAt := sess.StartedAt
	closedAt := sess.ClosedAt
	reason := sess.CloseReason
	opConn := sess.OperatorConnected
	agConn := sess.AgentConnected
	sess.mu.Unlock()

	_ = m.updateDurableState(sess.SessionID, st, startedAt, closedAt, reason, opConn, agConn)
	_ = m.updateDurableIdle(sess.SessionID, idleAt)

	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		sess.mu.Lock()
		sess.OperatorConnected = false
		sess.mu.Unlock()
		return fmt.Errorf("websocket upgrade failed: %w", err)
	}

	stop := make(chan struct{})
	relay.mu.Lock()
	relay.opConn = conn
	relay.opStop = stop
	relay.mu.Unlock()
	// Resume enqueueing to the operator. Ordering matters: the flag clears
	// only once this attachment owns opConn, so no frame is enqueued into a
	// channel with nothing draining it.
	relay.detached.Store(false)

	// Launch operator read/write pumps
	go relay.operatorWritePump(conn, stop)
	relay.operatorReadPump(conn, stop)

	return nil
}

// AttachAgent upgrades the agent HTTP connection to WSS and starts relay loops.
func (m *Manager) AttachAgent(w http.ResponseWriter, r *http.Request, sessionID, endpointID, rawToken string) error {
	sess, err := m.GetSession(sessionID)
	if err != nil {
		return errors.New("terminal session not found")
	}

	if sess.EndpointID != endpointID {
		return errors.New("endpoint ID mismatch for session")
	}

	if !sess.ValidateToken(rawToken) {
		return errors.New("invalid or expired terminal connect token")
	}

	sess.mu.Lock()
	if sess.State == StateClosed || sess.State == StateFailed || sess.State == StateExpired {
		sess.mu.Unlock()
		return fmt.Errorf("session is in terminal state: %s", sess.State)
	}
	if sess.AgentConnected {
		sess.mu.Unlock()
		return errors.New("agent already connected to session")
	}

	if sess.relay == nil {
		sess.relay = newPairedRelay(sess, m)
	}
	relay := sess.relay
	sess.AgentConnected = true
	now := time.Now().UTC()
	if sess.OperatorConnected {
		sess.State = StateActive
		sess.StartedAt = &now
	} else {
		sess.State = StateConnecting
	}
	st := sess.State
	startedAt := sess.StartedAt
	closedAt := sess.ClosedAt
	reason := sess.CloseReason
	opConn := sess.OperatorConnected
	agConn := sess.AgentConnected
	sess.mu.Unlock()

	_ = m.updateDurableState(sess.SessionID, st, startedAt, closedAt, reason, opConn, agConn)

	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		sess.mu.Lock()
		sess.AgentConnected = false
		sess.mu.Unlock()
		return fmt.Errorf("websocket upgrade failed: %w", err)
	}

	relay.mu.Lock()
	relay.agentConn = conn
	relay.mu.Unlock()

	// Launch agent read/write pumps
	go relay.agentWritePump(conn)
	relay.agentReadPump(conn)

	return nil
}

// operatorReadPump reads frames from the operator browser and forwards to agent.
func (pr *PairedRelay) operatorReadPump(conn *websocket.Conn, stop chan struct{}) {
	// An operator socket going away is a detach, not a teardown. This was
	// `pr.Close("operator_disconnected")`, and Close sends the agent a
	// WebSocket close frame, which the agent answers by SIGTERM/SIGKILL of
	// the whole process group. Closing the browser tab killed the shell.
	//
	// Protocol violations below still call Close before returning, and
	// DetachOperator is a no-op once the relay is closed, so this defer does
	// not undo them.
	defer pr.DetachOperator("operator_disconnected")

	conn.SetReadLimit(MaxMessageSize)
	_ = conn.SetReadDeadline(time.Now().Add(PongWait))
	conn.SetPongHandler(func(string) error {
		_ = conn.SetReadDeadline(time.Now().Add(PongWait))
		return nil
	})

	for {
		_, message, err := conn.ReadMessage()
		if err != nil {
			break
		}

		var frame TerminalFrame
		if err := json.Unmarshal(message, &frame); err != nil {
			// Malformed frame is a protocol violation; abort
			pr.Close("malformed_operator_frame")
			break
		}

		// Operator is only permitted to send stdin, resize, or close
		switch frame.Type {
		case FrameStdin, FrameResize, FrameClose:
			// Valid frame type
		default:
			pr.Close("forbidden_operator_frame_type")
			return
		}

		if frame.Type == FrameClose {
			frame.Timestamp = time.Now().UTC()
			_ = pr.mgr.RecordFrame(pr.sess.SessionID, frame)
			pr.Close("operator_requested_close")
			return
		}

		frame.Timestamp = time.Now().UTC()

		// Audit record operator frame (stdin, resize)
		_ = pr.mgr.RecordFrame(pr.sess.SessionID, frame)

		// Enforce bounded queue (1 MiB cap)
		frameSize := int64(len(frame.Data) + 64)
		if pr.opQueueBytes.Add(frameSize) > MaxQueueBytes {
			pr.Close("operator_queue_overflow")
			return
		}

		select {
		case pr.opToAgent <- frame:
		case <-pr.done:
			return
		}
	}
}

// agentReadPump reads stdout/close frames from the endpoint agent and forwards to operator.
func (pr *PairedRelay) agentReadPump(conn *websocket.Conn) {
	defer pr.Close("agent_disconnected")

	conn.SetReadLimit(MaxMessageSize)
	_ = conn.SetReadDeadline(time.Now().Add(PongWait))
	conn.SetPongHandler(func(string) error {
		_ = conn.SetReadDeadline(time.Now().Add(PongWait))
		return nil
	})

	for {
		_, message, err := conn.ReadMessage()
		if err != nil {
			break
		}

		var frame TerminalFrame
		if err := json.Unmarshal(message, &frame); err != nil {
			pr.Close("malformed_agent_frame")
			break
		}

		// Agent is only permitted to send stdout or close
		switch frame.Type {
		case FrameStdout, FrameClose:
			// Valid frame type
		default:
			pr.Close("forbidden_agent_frame_type")
			return
		}

		if frame.Type == FrameClose {
			frame.Timestamp = time.Now().UTC()
			_ = pr.mgr.RecordFrame(pr.sess.SessionID, frame)
			pr.Close("agent_process_terminated")
			return
		}

		frame.Timestamp = time.Now().UTC()

		// Audit record frame in session memory
		_ = pr.mgr.RecordFrame(pr.sess.SessionID, frame)

		// Detached: recorded above, and that is the whole delivery. Nothing
		// is draining agentToOp with no operator attached, so enqueueing here
		// would push agQueueBytes past MaxQueueBytes within a second of any
		// chatty process and close the session - the queue would kill exactly
		// the sessions detaching exists to keep alive. The operator gets this
		// output back from the recording when they reattach.
		if pr.detached.Load() {
			continue
		}

		// Enforce bounded queue (1 MiB cap)
		frameSize := int64(len(frame.Data) + 64)
		if pr.agQueueBytes.Add(frameSize) > MaxQueueBytes {
			pr.Close("agent_queue_overflow")
			return
		}

		select {
		case pr.agentToOp <- frame:
		case <-pr.done:
			return
		}
	}
}

// operatorWritePump forwards stdout frames received from agent to operator browser.
func (pr *PairedRelay) operatorWritePump(conn *websocket.Conn, stop chan struct{}) {
	ticker := time.NewTicker(PingPeriod)
	defer func() {
		ticker.Stop()
		// Same hazard as the read pump: this write pump failing is one
		// operator's socket failing, not a reason to kill their shell.
		pr.DetachOperator("operator_write_pump_exit")
	}()

	for {
		select {
		case <-pr.done:
			return
		case <-stop:
			// This attachment has been detached. Return without touching
			// the session: a later pump owns the relay now.
			return
		case frame, ok := <-pr.agentToOp:
			_ = conn.SetWriteDeadline(time.Now().Add(WriteWait))
			if !ok {
				_ = conn.WriteMessage(websocket.CloseMessage, []byte{})
				return
			}
			pr.agQueueBytes.Add(-int64(len(frame.Data) + 64))

			data, err := json.Marshal(frame)
			if err != nil {
				return
			}
			if err := conn.WriteMessage(websocket.TextMessage, data); err != nil {
				return
			}

		case <-ticker.C:
			_ = conn.SetWriteDeadline(time.Now().Add(WriteWait))
			if err := conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				return
			}
		}
	}
}

// agentWritePump forwards stdin/resize frames received from operator to agent.
func (pr *PairedRelay) agentWritePump(conn *websocket.Conn) {
	ticker := time.NewTicker(PingPeriod)
	defer func() {
		ticker.Stop()
		pr.Close("agent_write_pump_exit")
	}()

	for {
		select {
		case <-pr.done:
			return
		case frame, ok := <-pr.opToAgent:
			_ = conn.SetWriteDeadline(time.Now().Add(WriteWait))
			if !ok {
				_ = conn.WriteMessage(websocket.CloseMessage, []byte{})
				return
			}
			pr.opQueueBytes.Add(-int64(len(frame.Data) + 64))

			data, err := json.Marshal(frame)
			if err != nil {
				return
			}
			if err := conn.WriteMessage(websocket.TextMessage, data); err != nil {
				return
			}

		case <-ticker.C:
			_ = conn.SetWriteDeadline(time.Now().Add(WriteWait))
			if err := conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				return
			}
		}
	}
}

// ValidateToken checks a plaintext token against the stored SHA-256 hash using constant-time comparison.
func (s *TerminalSession) ValidateToken(raw string) bool {
	if raw == "" || s.TokenHash == "" {
		return false
	}
	h := sha256.Sum256([]byte(raw))
	expected := hex.EncodeToString(h[:])
	return subtle.ConstantTimeCompare([]byte(expected), []byte(s.TokenHash)) == 1
}

// ValidateOperatorToken checks the operator's half of the connect credential.
// Until the first rotation there is no operator-specific hash and the session's
// original token answers for both sides, which is what keeps a session created
// by an older hub attachable across the upgrade.
func (s *TerminalSession) ValidateOperatorToken(raw string) bool {
	s.mu.RLock()
	opHash := s.OperatorTokenHash
	s.mu.RUnlock()
	if opHash == "" {
		return s.ValidateToken(raw)
	}
	if raw == "" {
		return false
	}
	h := sha256.Sum256([]byte(raw))
	expected := hex.EncodeToString(h[:])
	return subtle.ConstantTimeCompare([]byte(expected), []byte(opHash)) == 1
}

// HashToken computes the SHA-256 hex string of a plaintext token.
func HashToken(raw string) string {
	h := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(h[:])
}
