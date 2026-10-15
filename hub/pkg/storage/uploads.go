package storage

import (
	"fmt"
	"sort"
	"sync"
	"time"
)

// Upload accounting: what each agent sends the hub per day, on the wire and
// decoded. This is the agent egress half of the data budget (the stored half
// is the data size report), and the number the upload budget is measured by:
// gzip shows up as wire bytes below decoded bytes, replayed batches (sent
// again after the hub was unreachable) are counted on their own.
//
// Counted in memory and written at most once a minute, so a heartbeat costs
// no extra write. A hub stop loses at most the last minute of counts.

const uploadFlushEvery = time.Minute

type uploadKey struct {
	endpoint string
	day      string
}

type uploadCounts struct {
	batches, wire, raw, gzipBatches, replays int64
}

type uploadLedger struct {
	mu      sync.Mutex
	pending map[uploadKey]*uploadCounts
	flushed time.Time
}

func (s *Store) initUploadSchema() error {
	_, err := s.db.Exec(`
	CREATE TABLE IF NOT EXISTS ingest_uploads_daily (
		day TEXT NOT NULL,
		endpoint_id TEXT NOT NULL,
		batches INTEGER NOT NULL DEFAULT 0,
		wire_bytes INTEGER NOT NULL DEFAULT 0,
		raw_bytes INTEGER NOT NULL DEFAULT 0,
		gzip_batches INTEGER NOT NULL DEFAULT 0,
		replayed_batches INTEGER NOT NULL DEFAULT 0,
		PRIMARY KEY (day, endpoint_id)
	) WITHOUT ROWID;`)
	return err
}

// RecordUpload counts one accepted telemetry request from endpointID: wire is
// the request body as received, raw the decoded JSON.
func (s *Store) RecordUpload(endpointID string, wire, raw int64, gzipped, replay bool) {
	now := time.Now().UTC()
	l := &s.uploads
	l.mu.Lock()
	if l.pending == nil {
		l.pending = map[uploadKey]*uploadCounts{}
		l.flushed = now
	}
	k := uploadKey{endpointID, now.Format("2006-01-02")}
	c := l.pending[k]
	if c == nil {
		c = &uploadCounts{}
		l.pending[k] = c
	}
	c.batches++
	c.wire += wire
	c.raw += raw
	if gzipped {
		c.gzipBatches++
	}
	if replay {
		c.replays++
	}
	var due map[uploadKey]*uploadCounts
	if now.Sub(l.flushed) >= uploadFlushEvery {
		due, l.pending, l.flushed = l.pending, map[uploadKey]*uploadCounts{}, now
	}
	l.mu.Unlock()
	if due != nil {
		if err := s.writeUploads(due); err != nil {
			l.restore(due)
		}
	}
}

// restore puts counts back after a failed write: the next flush tries again.
func (l *uploadLedger) restore(due map[uploadKey]*uploadCounts) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for k, v := range due {
		c := l.pending[k]
		if c == nil {
			l.pending[k] = v
			continue
		}
		c.batches += v.batches
		c.wire += v.wire
		c.raw += v.raw
		c.gzipBatches += v.gzipBatches
		c.replays += v.replays
	}
}

// FlushUploads writes the pending counts now (tests, reports).
func (s *Store) FlushUploads() error {
	l := &s.uploads
	l.mu.Lock()
	due := l.pending
	l.pending, l.flushed = map[uploadKey]*uploadCounts{}, time.Now().UTC()
	l.mu.Unlock()
	if len(due) == 0 {
		return nil
	}
	if err := s.writeUploads(due); err != nil {
		l.restore(due)
		return err
	}
	return nil
}

func (s *Store) writeUploads(due map[uploadKey]*uploadCounts) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	st, err := tx.Prepare(`INSERT INTO ingest_uploads_daily (day, endpoint_id, batches, wire_bytes, raw_bytes, gzip_batches, replayed_batches)
		VALUES (?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT (day, endpoint_id) DO UPDATE SET
			batches = batches + excluded.batches, wire_bytes = wire_bytes + excluded.wire_bytes,
			raw_bytes = raw_bytes + excluded.raw_bytes, gzip_batches = gzip_batches + excluded.gzip_batches,
			replayed_batches = replayed_batches + excluded.replayed_batches`)
	if err != nil {
		return err
	}
	defer st.Close()
	for k, c := range due {
		if _, err := st.Exec(k.day, k.endpoint, c.batches, c.wire, c.raw, c.gzipBatches, c.replays); err != nil {
			return fmt.Errorf("record uploads: %w", err)
		}
	}
	return tx.Commit()
}

// EndpointUpload is one endpoint's uploads on one UTC day.
type EndpointUpload struct {
	Day             string  `json:"day"`
	EndpointID      string  `json:"endpoint_id"`
	Batches         int64   `json:"batches"`
	WireBytes       int64   `json:"wire_bytes"`
	RawBytes        int64   `json:"raw_bytes"`
	GzipBatches     int64   `json:"gzip_batches"`
	ReplayedBatches int64   `json:"replayed_batches"`
	WireMB          float64 `json:"wire_mb"`
	Ratio           float64 `json:"ratio"` // raw / wire
}

// UploadsSince lists per-endpoint daily uploads from the given UTC day on,
// newest day first, pending counts included.
func (s *Store) UploadsSince(day string) ([]EndpointUpload, error) {
	if err := s.FlushUploads(); err != nil {
		return nil, err
	}
	rows, err := s.db.Query(`SELECT day, endpoint_id, batches, wire_bytes, raw_bytes, gzip_batches, replayed_batches
		FROM ingest_uploads_daily WHERE day >= ?`, day)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []EndpointUpload
	for rows.Next() {
		var u EndpointUpload
		if err := rows.Scan(&u.Day, &u.EndpointID, &u.Batches, &u.WireBytes, &u.RawBytes, &u.GzipBatches, &u.ReplayedBatches); err != nil {
			return nil, err
		}
		u.WireMB = round2(float64(u.WireBytes) / 1e6)
		if u.WireBytes > 0 {
			u.Ratio = round2(float64(u.RawBytes) / float64(u.WireBytes))
		}
		out = append(out, u)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Day != out[j].Day {
			return out[i].Day > out[j].Day
		}
		return out[i].WireBytes > out[j].WireBytes
	})
	return out, rows.Err()
}
