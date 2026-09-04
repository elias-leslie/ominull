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

		pr.mu.Lock()
		defer pr.mu.Unlock()

		now := time.Now().UTC()
		pr.sess.mu.Lock()
		pr.sess.State = StateClosed
		pr.sess.ClosedAt = &now
		if pr.sess.CloseReason == "" {
			pr.sess.CloseReason = reason
		}
		pr.sess.mu.Unlock()

		// Send close frame and close operator connection
		if pr.opConn != nil {
			_ = pr.opConn.WriteControl(
				websocket.CloseMessage,
				websocket.FormatCloseMessage(websocket.CloseNormalClosure, reason),
				time.Now().Add(WriteWait),
			)
			_ = pr.opConn.Close()
		}

		// Send close frame and close agent connection
		if pr.agentConn != nil {
			_ = pr.agentConn.WriteControl(
				websocket.CloseMessage,
				websocket.FormatCloseMessage(websocket.CloseNormalClosure, reason),
				time.Now().Add(WriteWait),
			)
			_ = pr.agentConn.Close()
		}
	})
}

// AttachOperator upgrades the operator HTTP connection to WSS and starts relay loops.
func (m *Manager) AttachOperator(w http.ResponseWriter, r *http.Request, sessionID, rawToken string) error {
	sess, err := m.GetSession(sessionID)
	if err != nil {
		return errors.New("terminal session not found")
	}

	if !sess.ValidateToken(rawToken) {
		return errors.New("invalid or expired terminal connect token")
	}

	sess.mu.Lock()
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
		sess.StartedAt = &now
	} else {
		sess.State = StateConnecting
	}
	sess.mu.Unlock()

	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		sess.mu.Lock()
		sess.OperatorConnected = false
		sess.mu.Unlock()
		return fmt.Errorf("websocket upgrade failed: %w", err)
	}

	relay.mu.Lock()
	relay.opConn = conn
	relay.mu.Unlock()

	// Launch operator read/write pumps
	go relay.operatorWritePump(conn)
	relay.operatorReadPump(conn)

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
	sess.mu.Unlock()

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
func (pr *PairedRelay) operatorReadPump(conn *websocket.Conn) {
	defer pr.Close("operator_disconnected")

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
			pr.Close("operator_requested_close")
			return
		}

		frame.Timestamp = time.Now().UTC()

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
			pr.Close("agent_process_terminated")
			return
		}

		frame.Timestamp = time.Now().UTC()

		// Audit record frame in session memory
		_ = pr.mgr.RecordFrame(pr.sess.SessionID, frame)

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
func (pr *PairedRelay) operatorWritePump(conn *websocket.Conn) {
	ticker := time.NewTicker(PingPeriod)
	defer func() {
		ticker.Stop()
		pr.Close("operator_write_pump_exit")
	}()

	for {
		select {
		case <-pr.done:
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

// HashToken computes the SHA-256 hex string of a plaintext token.
func HashToken(raw string) string {
	h := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(h[:])
}
