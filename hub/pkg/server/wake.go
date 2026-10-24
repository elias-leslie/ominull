package server

import (
	"fmt"
	"sync"
	"time"
)

// wakeNotifier wakes long-polls when something they wait for changes.
type wakeNotifier struct {
	mu sync.Mutex
	ch chan struct{}
}

func (n *wakeNotifier) wait() <-chan struct{} {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.ch == nil {
		n.ch = make(chan struct{})
	}
	return n.ch
}

func (n *wakeNotifier) notify() {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.ch != nil {
		close(n.ch)
	}
	n.ch = make(chan struct{})
}

// parseWait reads a long-poll wait in seconds, capped at 25.
func parseWait(s string) time.Duration {
	var n int
	if _, err := fmt.Sscanf(s, "%d", &n); err != nil || n < 0 {
		return 0
	}
	if n > 25 {
		n = 25
	}
	return time.Duration(n) * time.Second
}
