package detector

import (
	"fmt"
	"log"
	"strings"
	"time"

	"ominull/hub/pkg/storage"
)

// Learning observations: the cheap record kept while a window is open.
//
// This is deliberately not the flow table. What a proposal needs to argue for
// itself is "which program talked to which network, how often, on how many
// machines, at what hours" - a few hundred counted keys, not millions of rows.
// Writing one row per flow would make learning mode the most expensive thing
// the hub does and would tell an operator nothing the events table cannot
// already answer.
//
// So the detector counts in memory and flushes on a timer. Losing a partial
// buffer to a restart costs a few counts out of thousands and changes no
// proposal's argument; holding a database transaction open on the event path
// would cost every endpoint's telemetry.

const (
	// learnFlushInterval is how often counts reach the database.
	learnFlushInterval = 30 * time.Second
	// learnBufferCap bounds the buffer for the case where nothing is flushing
	// it - a test calling Evaluate directly, or a hub whose flush goroutine has
	// not started. Reaching it flushes inline rather than growing without end.
	learnBufferCap = 20000
)

type learnKey struct {
	windowID   string
	endpointID string
	kind       string
	key        string
}

type learnCount struct {
	count int64
	first time.Time
	last  time.Time
}

// observeForLearning folds one flow into the open window's record, if there is
// one. It returns whether the endpoint is learning, so the caller does not have
// to ask twice.
func (e *Engine) observeForLearning(ev storage.Event, ep storage.Endpoint, org, tenancy string, localHour int, now time.Time) bool {
	window, learning := e.store.LearningWindowFor(ep)
	if !learning {
		return false
	}
	if ev.Direction != "OUTBOUND" {
		// Inbound conversations are not what a quiet pair vouches for, and an
		// estate's active hours are better read from what it initiates.
		return true
	}

	proc := processBase(ev.ProcessPath)
	owner := strings.ToLower(strings.TrimSpace(org))

	facts := []struct{ kind, key string }{
		{storage.LearnHour, fmt.Sprintf("%d", localHour)},
	}
	if proc != "" && proc != "unknown" {
		facts = append(facts, struct{ kind, key string }{storage.LearnProcess, proc})
	}
	if !isPrivateIP(ev.DstIP) {
		if ev.DstPort > 0 {
			facts = append(facts, struct{ kind, key string }{storage.LearnPort, fmt.Sprintf("%d", ev.DstPort)})
		}
		// Two destinations never become a pair. One nobody can name, because a
		// proposal has to say who it would vouch for. And rented compute,
		// because anyone can buy space inside a cloud range: the tuning refuses
		// to enforce such a pair, so offering one in a proposal list would be
		// offering a change that does nothing but look like protection.
		if owner != "" && tenancy != storage.TenancyHosting {
			facts = append(facts, struct{ kind, key string }{storage.LearnOwner, owner})
			if proc != "" && proc != "unknown" {
				facts = append(facts, struct{ kind, key string }{storage.LearnPair, proc + "@" + owner})
			}
		}
	}

	e.learnMu.Lock()
	if e.learnBuf == nil {
		e.learnBuf = map[learnKey]*learnCount{}
	}
	for _, f := range facts {
		k := learnKey{windowID: window.ID, endpointID: ep.ID, kind: f.kind, key: f.key}
		c, ok := e.learnBuf[k]
		if !ok {
			c = &learnCount{first: now}
			e.learnBuf[k] = c
		}
		c.count++
		if now.After(c.last) {
			c.last = now
		}
	}
	over := len(e.learnBuf) >= learnBufferCap
	e.learnMu.Unlock()

	if over {
		e.flushLearning()
	}
	return true
}

// flushLearning writes what has been counted and empties the buffer.
func (e *Engine) flushLearning() {
	e.learnMu.Lock()
	buf := e.learnBuf
	e.learnBuf = map[learnKey]*learnCount{}
	e.learnMu.Unlock()

	if len(buf) == 0 {
		return
	}
	obs := make([]storage.LearningObservation, 0, len(buf))
	for k, c := range buf {
		obs = append(obs, storage.LearningObservation{
			WindowID:   k.windowID,
			EndpointID: k.endpointID,
			Kind:       k.kind,
			Key:        k.key,
			Count:      c.count,
			FirstSeen:  c.first,
			LastSeen:   c.last,
		})
	}
	if err := e.store.RecordLearningObservations(obs); err != nil {
		log.Printf("[-] learning observations were not written: %v", err)
	}
}

// startLearningFlush drains the buffer on a timer for as long as the engine
// runs, and once more on the way out so a window closed straight after a
// restart still carries its last half-minute.
func (e *Engine) startLearningFlush(done <-chan struct{}) {
	go func() {
		ticker := time.NewTicker(learnFlushInterval)
		defer ticker.Stop()
		for {
			select {
			case <-done:
				e.flushLearning()
				return
			case <-ticker.C:
				e.flushLearning()
				if n, err := e.store.CloseExpiredLearningWindows(); err != nil {
					log.Printf("[-] expired learning windows were not closed: %v", err)
				} else if n > 0 {
					log.Printf("[*] %d learning window(s) reached their end and were closed", n)
				}
			}
		}
	}()
}

// processBase is the program's name without its path, lower-cased, which is the
// form both quiet lists match on.
func processBase(path string) string {
	clean := strings.ReplaceAll(path, "\\", "/")
	if i := strings.LastIndex(clean, "/"); i >= 0 {
		clean = clean[i+1:]
	}
	return strings.ToLower(strings.TrimSpace(clean))
}
