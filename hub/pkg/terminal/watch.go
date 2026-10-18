package terminal

import (
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// Watch attachments: a session kind with MaxWatchers > 0 (the screen) takes
// view-only attachments beside its one control attachment, so the owner can
// watch an agent drive. Each watcher has its own queue and write pump; a
// slow one drops what it cannot take instead of holding up the agent, the
// control attachment or the other watchers. A shell has no watchers: none of
// this runs for one.

// watcherQueue is how many messages one watcher may have waiting.
const watcherQueue = 64

type watcher struct {
	conn     *websocket.Conn
	out      chan relayMsg
	stop     chan struct{}
	stopOnce func()
}

func (w *watcher) end(reason string) {
	w.stopOnce()
	_ = w.conn.WriteControl(websocket.CloseMessage,
		websocket.FormatCloseMessage(websocket.CloseNormalClosure, reason), time.Now().Add(WriteWait))
	_ = w.conn.Close()
}

// controlAttached reports whether the control attachment is connected.
func (pr *PairedRelay) controlAttached() bool {
	pr.mu.Lock()
	defer pr.mu.Unlock()
	return pr.opConn != nil
}

// WatcherCount is how many watch attachments a session has now.
func (m *Manager) WatcherCount(sessionID string) int {
	sess, err := m.GetSession(sessionID)
	if err != nil {
		return 0
	}
	sess.mu.RLock()
	relay := sess.relay
	sess.mu.RUnlock()
	if relay == nil {
		return 0
	}
	relay.mu.Lock()
	defer relay.mu.Unlock()
	return len(relay.watchers)
}

// pauseIfUnwatched tells the agent to pause once no attachment remains.
// paused is set only once the pause is queued for the agent, so it never
// claims a pause the agent did not get. pauseMu orders pause and resume.
func (pr *PairedRelay) pauseIfUnwatched() {
	if pr.kind == nil {
		return
	}
	pr.pauseMu.Lock()
	defer pr.pauseMu.Unlock()
	pr.mu.Lock()
	send := pr.opConn == nil && len(pr.watchers) == 0 && !pr.paused
	pr.mu.Unlock()
	if send && pr.sendAgentControl(pr.kind.PauseMessage) {
		pr.mu.Lock()
		pr.paused = true
		pr.mu.Unlock()
	}
}

// resumeIfPaused tells a paused agent to resume (the first attachment back).
// A resume that could not be queued leaves the relay paused, so the next
// attachment tries again.
func (pr *PairedRelay) resumeIfPaused() {
	if pr.kind == nil {
		return
	}
	pr.pauseMu.Lock()
	defer pr.pauseMu.Unlock()
	pr.mu.Lock()
	send := pr.paused
	pr.mu.Unlock()
	if send && pr.sendAgentControl(pr.kind.ResumeMessage) {
		pr.mu.Lock()
		pr.paused = false
		pr.mu.Unlock()
	}
}

// fanOut hands one agent message to every watcher. A full watcher queue
// drops an image at once (the next keyframe repaints it) and gives a text
// frame a moment, so a watcher pacing the stream still sees its frame_end.
func (pr *PairedRelay) fanOut(msg relayMsg) {
	pr.mu.Lock()
	if len(pr.watchers) == 0 {
		pr.mu.Unlock()
		return
	}
	ws := append([]*watcher(nil), pr.watchers...)
	pr.mu.Unlock()
	for _, w := range ws {
		select {
		case w.out <- msg:
			continue
		case <-w.stop:
			continue
		default:
		}
		if msg.typ != websocket.TextMessage {
			continue
		}
		t := time.NewTimer(time.Second)
		select {
		case w.out <- msg:
		case <-w.stop:
		case <-t.C:
		}
		t.Stop()
	}
}

// isPacer reports whether w's acks reach the agent: nobody controls and w is
// the oldest watcher.
func (pr *PairedRelay) isPacer(w *watcher) bool {
	pr.mu.Lock()
	defer pr.mu.Unlock()
	return pr.opConn == nil && len(pr.watchers) > 0 && pr.watchers[0] == w
}

func (pr *PairedRelay) removeWatcher(w *watcher, reason string) {
	pr.mu.Lock()
	found := false
	for i, x := range pr.watchers {
		if x == w {
			pr.watchers = append(pr.watchers[:i:i], pr.watchers[i+1:]...)
			found = true
			break
		}
	}
	pr.mu.Unlock()
	if !found {
		return
	}
	w.end(reason)
	pr.pauseIfUnwatched()
}

// AttachWatcher upgrades a watch (view-only) attachment and relays to it
// until it leaves; the caller has already checked the watch credential. It
// refuses a kind without watchers, a session that is over, and one at its
// watcher cap.
func (m *Manager) AttachWatcher(w http.ResponseWriter, r *http.Request, sessionID string) error {
	sess, err := m.GetSession(sessionID)
	if err != nil {
		return errors.New("session not found")
	}
	kind := KindFor(sess.Program)
	if kind == nil || kind.MaxWatchers <= 0 {
		return errors.New("this session takes no watchers")
	}
	sess.mu.Lock()
	if sess.State == StateClosed || sess.State == StateFailed || sess.State == StateExpired {
		sess.mu.Unlock()
		return fmt.Errorf("session is in terminal state: %s", sess.State)
	}
	if sess.relay == nil {
		sess.relay = newPairedRelay(sess, m)
	}
	relay := sess.relay
	sess.IdleExpiresAt = time.Now().UTC().Add(m.idle())
	sess.dirty = true
	sess.mu.Unlock()
	wp, ok := relay.policy.(WatchPolicy)
	if !ok {
		return errors.New("this session takes no watchers")
	}

	relay.mu.Lock()
	full := len(relay.watchers) >= kind.MaxWatchers
	relay.mu.Unlock()
	if full {
		return fmt.Errorf("this session already has %d watchers", kind.MaxWatchers)
	}
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return fmt.Errorf("websocket upgrade failed: %w", err)
	}
	stop := make(chan struct{})
	var stopOnce sync.Once
	wt := &watcher{conn: conn, out: make(chan relayMsg, watcherQueue), stop: stop,
		stopOnce: func() { stopOnce.Do(func() { close(stop) }) }}
	relay.mu.Lock()
	if relay.isClosed() || len(relay.watchers) >= kind.MaxWatchers {
		relay.mu.Unlock()
		wt.end("session_unavailable")
		return errors.New("session closed or watcher cap reached")
	}
	relay.watchers = append(relay.watchers, wt)
	relay.mu.Unlock()
	relay.resumeIfPaused()

	go relay.watcherWritePump(wt)
	relay.watcherReadPump(wt, wp)
	return nil
}

func (pr *PairedRelay) watcherWritePump(w *watcher) {
	ticker := time.NewTicker(PingPeriod)
	defer func() {
		ticker.Stop()
		pr.removeWatcher(w, "watcher_write_pump_exit")
	}()
	for {
		select {
		case <-pr.done:
			return
		case <-w.stop:
			return
		case msg := <-w.out:
			_ = w.conn.SetWriteDeadline(time.Now().Add(WriteWait))
			w.conn.EnableWriteCompression(msg.typ == websocket.TextMessage && len(msg.data) > 512)
			if err := w.conn.WriteMessage(msg.typ, msg.data); err != nil {
				return
			}
		case <-ticker.C:
			_ = w.conn.SetWriteDeadline(time.Now().Add(WriteWait))
			if err := w.conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				return
			}
		}
	}
}

func (pr *PairedRelay) watcherReadPump(w *watcher, wp WatchPolicy) {
	defer pr.removeWatcher(w, "watcher_disconnected")
	w.conn.SetReadLimit(MaxOperatorMessageSize)
	_ = w.conn.SetReadDeadline(time.Now().Add(PongWait))
	watched := pr.kind != nil && pr.kind.AttachedIsActivity
	w.conn.SetPongHandler(func(string) error {
		_ = w.conn.SetReadDeadline(time.Now().Add(PongWait))
		if watched {
			pr.touchActivity()
		}
		return nil
	})
	for {
		typ, message, err := w.conn.ReadMessage()
		if err != nil {
			return
		}
		d := wp.Watcher(typ, message)
		switch d.Action {
		case FrameCloseSession:
			return
		case FrameDrop:
			continue
		}
		if !pr.isPacer(w) {
			continue
		}
		// Only the policy's own re-encoding reaches the agent, never the
		// watcher's bytes.
		msg, d := reencoded(d)
		if d.Action != FrameForward {
			continue
		}
		if !pr.opQueue.acquire(msg.cost, pr.done, w.stop, nil) {
			return
		}
		select {
		case pr.opToAgent <- msg:
		case <-pr.done:
			pr.opQueue.release(msg.cost)
			return
		case <-w.stop:
			pr.opQueue.release(msg.cost)
			return
		}
	}
}
