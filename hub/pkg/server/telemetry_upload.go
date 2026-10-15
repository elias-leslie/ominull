package server

import (
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Agent upload transport: gzip bodies and replayed batches.
//
// An agent compresses its batch only after a heartbeat reply has said this hub
// takes gzip ("accept_encoding"), because an older hub reads a compressed body
// as neither a batch nor a legacy array and answers it as a GET - a 200 that
// stores nothing. A batch the hub could not take (unreachable, 5xx) is kept by
// the agent and sent again later with X-Ominull-Replay: those carry stale
// header fields (collector counters, readiness), so only their events count.

// maxTelemetryDecoded bounds what a gzip body may expand to. Agents send at
// most 64 events per batch, about a megabyte of JSON.
const maxTelemetryDecoded = 8 << 20

const telemetryReplayHeader = "X-Ominull-Replay"

var (
	errUnsupportedEncoding = errors.New("unsupported content encoding")
	errBodyTooLarge        = errors.New("decoded body exceeds the telemetry limit")
)

// readTelemetryBody returns the decoded request body, the number of bytes
// that arrived on the wire and whether it was gzip.
func readTelemetryBody(r *http.Request) ([]byte, int64, bool, error) {
	wire, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, 0, false, err
	}
	switch enc := strings.ToLower(strings.TrimSpace(r.Header.Get("Content-Encoding"))); enc {
	case "", "identity":
		return wire, int64(len(wire)), false, nil
	case "gzip":
		zr, err := gzip.NewReader(bytes.NewReader(wire))
		if err != nil {
			return nil, 0, false, fmt.Errorf("gzip body: %w", err)
		}
		defer zr.Close()
		body, err := io.ReadAll(io.LimitReader(zr, maxTelemetryDecoded+1))
		if err != nil {
			return nil, 0, false, fmt.Errorf("gzip body: %w", err)
		}
		if len(body) > maxTelemetryDecoded {
			return nil, 0, false, errBodyTooLarge
		}
		return body, int64(len(wire)), true, nil
	default:
		return nil, 0, false, fmt.Errorf("%w %q", errUnsupportedEncoding, enc)
	}
}

func telemetryBodyStatus(err error) int {
	var tooLarge *http.MaxBytesError
	switch {
	case errors.Is(err, errUnsupportedEncoding):
		return http.StatusUnsupportedMediaType
	case errors.Is(err, errBodyTooLarge), errors.As(err, &tooLarge):
		return http.StatusRequestEntityTooLarge
	default:
		return http.StatusBadRequest
	}
}

func isTelemetryReplay(r *http.Request) bool {
	return r.Header.Get(telemetryReplayHeader) == "1"
}

// batchLedger remembers the batch ids this hub has stored or is storing, so a
// replay of a batch whose reply the agent lost (a slow write under a held
// lock outlasting the agent's timeout) is not stored twice. In memory and
// bounded: a hub restart forgets it, which leaves only the narrow case of a
// write that committed just before the restart.
type batchLedger struct {
	mu   sync.Mutex
	seen map[string]batchEntry
}

type batchEntry struct {
	done bool
	at   time.Time
}

type batchState int

const (
	batchNew batchState = iota
	batchInFlight
	batchDone
)

const (
	batchLedgerMax = 50000
	batchLedgerTTL = 2 * time.Hour
)

// begin claims a batch id for storing, or says it is stored or being stored.
// A batch without an id (older agents) is always new.
func (l *batchLedger) begin(endpointID, batchID string) batchState {
	if batchID == "" || len(batchID) > 64 {
		return batchNew
	}
	key := endpointID + "\x00" + batchID
	now := time.Now()
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.seen == nil {
		l.seen = map[string]batchEntry{}
	}
	if e, ok := l.seen[key]; ok && now.Sub(e.at) < batchLedgerTTL {
		if e.done {
			return batchDone
		}
		return batchInFlight
	}
	if len(l.seen) >= batchLedgerMax {
		for k, e := range l.seen {
			if now.Sub(e.at) >= batchLedgerTTL {
				delete(l.seen, k)
			}
		}
		// Still full of fresh ids: drop arbitrary ones rather than grow.
		for k := range l.seen {
			if len(l.seen) < batchLedgerMax {
				break
			}
			delete(l.seen, k)
		}
	}
	l.seen[key] = batchEntry{at: now}
	return batchNew
}

// finish records the outcome: a stored batch is remembered as done, a failed
// one is forgotten so its replay is taken.
func (l *batchLedger) finish(endpointID, batchID string, stored bool) {
	if batchID == "" || len(batchID) > 64 {
		return
	}
	key := endpointID + "\x00" + batchID
	l.mu.Lock()
	defer l.mu.Unlock()
	if stored {
		l.seen[key] = batchEntry{done: true, at: time.Now()}
	} else {
		delete(l.seen, key)
	}
}
