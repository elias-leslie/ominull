package storage

import (
	"bufio"
	"compress/gzip"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// Cold segments.
//
// Past the raw window, flows live on as one gzip NDJSON file per UTC day,
// written once the day is over and before its raw rows are pruned:
//
//	{"type":"flow_hour", ...}   per endpoint, hour, executable image, direction,
//	                            action, protocol, destination, port, name, country
//	{"type":"local_hour", ...}  loopback counters per process instance and port
//	{"type":"process", ...}     every process instance active that day, with
//	                            its first and last seen time
//
// Standard library gzip only; `zcat file | jq` reads them. The files are
// rollups, not evidence: flows near held evidence stay raw in the database.

// coldSegmentGrace is how long after midnight UTC a day is still open to late
// batches before it is exported.
const coldSegmentGrace = 30 * time.Minute

func (s *Store) initColdSchema() error {
	_, err := s.db.Exec(`
	CREATE TABLE IF NOT EXISTS flow_cold_segments (
		day TEXT PRIMARY KEY,
		path TEXT NOT NULL,
		bytes INTEGER NOT NULL,
		records INTEGER NOT NULL,
		endpoints INTEGER NOT NULL,
		raw_rows INTEGER NOT NULL DEFAULT 0,
		created_at DATETIME NOT NULL
	);`)
	return err
}

// ColdSegment describes one written day.
type ColdSegment struct {
	Day string `json:"day"`
	// Path is the file on the hub; not served (the file name is the day).
	Path      string    `json:"-"`
	Bytes     int64     `json:"bytes"`
	Records   int64     `json:"records"`
	Endpoints int64     `json:"endpoints"`
	RawRows   int64     `json:"raw_rows"`
	CreatedAt time.Time `json:"created_at"`
}

// coldDirectory is where segments go: the policy's directory, else "cold"
// beside the database file. An in-memory database has none.
func (s *Store) coldDirectory() string {
	if s.coldDir != "" {
		return s.coldDir
	}
	var seq int
	var name, file string
	if err := s.db.QueryRow("PRAGMA database_list").Scan(&seq, &name, &file); err != nil || file == "" {
		return ""
	}
	return filepath.Join(filepath.Dir(file), "cold")
}

// ColdSegments lists the written days, newest first.
func (s *Store) ColdSegments() ([]ColdSegment, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	rows, err := s.db.Query("SELECT day, path, bytes, records, endpoints, raw_rows, created_at FROM flow_cold_segments ORDER BY day DESC")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ColdSegment
	for rows.Next() {
		var c ColdSegment
		if err := rows.Scan(&c.Day, &c.Path, &c.Bytes, &c.Records, &c.Endpoints, &c.RawRows, &c.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// exportColdSegments writes every finished day that has raw rows and no
// segment yet, oldest first.
func (s *Store) exportColdSegments(policy RetentionPolicy, now time.Time) error {
	dir := s.coldDirectory()
	if dir == "" || policy.FlowRollups <= 0 || s.legacyEventsPresent() {
		return nil
	}
	oldest, err := s.oldestFlowTime()
	if err != nil || !oldest.Valid {
		return err
	}
	first := scanTime(oldest.String)
	if first.IsZero() {
		return nil
	}
	day := time.Date(first.Year(), first.Month(), first.Day(), 0, 0, 0, 0, time.UTC)
	if keep := now.Add(-policy.FlowRollups); day.Before(keep) {
		day = time.Date(keep.Year(), keep.Month(), keep.Day(), 0, 0, 0, 0, time.UTC)
	}
	for ; !now.Before(day.Add(24*time.Hour + coldSegmentGrace)); day = day.Add(24 * time.Hour) {
		name := day.Format("2006-01-02")
		have, err := s.coldSegmentWritten(name)
		if err != nil {
			return err
		}
		if have {
			continue
		}
		if err := s.exportColdDay(dir, day); err != nil {
			return fmt.Errorf("cold segment %s: %w", name, err)
		}
	}
	return nil
}

func (s *Store) oldestFlowTime() (sql.NullString, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var oldest sql.NullString
	err := s.db.QueryRow("SELECT MIN(timestamp) FROM flows").Scan(&oldest)
	return oldest, err
}

func (s *Store) coldSegmentWritten(day string) (bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var have int
	err := s.db.QueryRow("SELECT COUNT(*) FROM flow_cold_segments WHERE day = ?", day).Scan(&have)
	return have > 0, err
}

type coldWriter struct {
	enc     *json.Encoder
	records int64
}

func (w *coldWriter) write(v interface{}) error {
	w.records++
	return w.enc.Encode(v)
}

// exportColdDay writes one day's rollups. Reads run under the read lock, so
// ingest is never blocked behind the export.
func (s *Store) exportColdDay(dir string, day time.Time) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	name := day.Format("2006-01-02")
	final := filepath.Join(dir, "flows-"+name+".ndjson.gz")
	tmp, err := os.CreateTemp(dir, ".flows-"+name+"-*.tmp")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	buf := bufio.NewWriterSize(tmp, 1<<16)
	gz, err := gzip.NewWriterLevel(buf, gzip.BestCompression)
	if err != nil {
		tmp.Close()
		return err
	}
	w := &coldWriter{enc: json.NewEncoder(gz)}
	from, to := day, day.Add(24*time.Hour)

	s.mu.RLock()
	endpoints, rawRows, err := s.writeColdDay(w, from, to)
	s.mu.RUnlock()
	if err == nil {
		err = gz.Close()
	}
	if err == nil {
		err = buf.Flush()
	}
	if err == nil {
		err = tmp.Sync()
	}
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	if err := os.Rename(tmp.Name(), final); err != nil {
		return err
	}
	info, err := os.Stat(final)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err = s.db.Exec(`INSERT INTO flow_cold_segments (day, path, bytes, records, endpoints, raw_rows, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(day) DO UPDATE SET path = excluded.path, bytes = excluded.bytes, records = excluded.records,
		endpoints = excluded.endpoints, raw_rows = excluded.raw_rows, created_at = excluded.created_at`,
		name, final, info.Size(), w.records, endpoints, rawRows, time.Now().UTC())
	return err
}

func (s *Store) writeColdDay(w *coldWriter, from, to time.Time) (int64, int64, error) {
	endpoints := map[string]struct{}{}
	var rawRows int64

	rows, err := s.db.Query(`
		SELECT e.endpoint_id, substr(f.timestamp, 1, 13), i.path, i.sha256, i.signer, s.direction, s.action,
			f.protocol, f.dst_ip, f.dst_port, d.name, g.country,
			COUNT(*), SUM(f.samples), SUM(f.obs_count), SUM(f.bytes_in), SUM(f.bytes_out), MIN(f.timestamp), MAX(f.timestamp)
		FROM flows f
		JOIN flow_endpoints e ON e.id = f.endpoint_ref
		JOIN flow_shapes s ON s.id = f.shape_ref
		JOIN flow_geo g ON g.id = f.geo_ref
		JOIN flow_processes p ON p.id = f.process_ref
		JOIN flow_images i ON i.id = p.image_ref
		JOIN flow_names d ON d.id = CASE WHEN f.sni_ref != 0 THEN f.sni_ref ELSE f.domain_ref END
		WHERE f.timestamp >= ? AND f.timestamp < ?
		GROUP BY 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12`, flowTime(from), flowTime(to))
	if err != nil {
		return 0, 0, err
	}
	for rows.Next() {
		var r struct {
			Type       string `json:"type"`
			EndpointID string `json:"endpoint_id"`
			Hour       string `json:"hour"`
			Path       string `json:"process_path"`
			SHA256     string `json:"executable_sha256,omitempty"`
			Signer     string `json:"executable_signer,omitempty"`
			Direction  string `json:"direction"`
			Action     string `json:"action"`
			Protocol   int    `json:"protocol"`
			DstIP      string `json:"dst_ip"`
			DstPort    int    `json:"dst_port"`
			Name       string `json:"name,omitempty"`
			Country    string `json:"country,omitempty"`
			Rows       int64  `json:"rows"`
			Samples    int64  `json:"samples"`
			Obs        int64  `json:"observations"`
			BytesIn    int64  `json:"bytes_in"`
			BytesOut   int64  `json:"bytes_out"`
			First      string `json:"first_seen"`
			Last       string `json:"last_seen"`
		}
		var first, last interface{}
		if err := rows.Scan(&r.EndpointID, &r.Hour, &r.Path, &r.SHA256, &r.Signer, &r.Direction, &r.Action,
			&r.Protocol, &r.DstIP, &r.DstPort, &r.Name, &r.Country,
			&r.Rows, &r.Samples, &r.Obs, &r.BytesIn, &r.BytesOut, &first, &last); err != nil {
			rows.Close()
			return 0, 0, err
		}
		r.Type = "flow_hour"
		r.Hour = r.Hour + ":00:00Z"
		if len(r.Hour) > 10 {
			r.Hour = r.Hour[:10] + "T" + r.Hour[11:]
		}
		r.First = scanTime(first).Format(time.RFC3339Nano)
		r.Last = scanTime(last).Format(time.RFC3339Nano)
		endpoints[r.EndpointID] = struct{}{}
		rawRows += r.Rows
		if err := w.write(&r); err != nil {
			rows.Close()
			return 0, 0, err
		}
	}
	if err := rows.Close(); err != nil {
		return 0, 0, err
	}

	rows, err = s.db.Query(`
		SELECT e.endpoint_id, l.hour, i.path, i.sha256, p.instance_id, p.pid, s.direction, l.protocol, l.service_port,
			l.samples, l.obs_count, l.bytes_in, l.bytes_out, l.first_at, l.last_at
		FROM flow_local_hourly l
		JOIN flow_endpoints e ON e.id = l.endpoint_ref
		JOIN flow_shapes s ON s.id = l.shape_ref
		JOIN flow_processes p ON p.id = l.process_ref
		JOIN flow_images i ON i.id = p.image_ref
		WHERE l.hour >= ? AND l.hour < ?`, from.Unix()/flowHour, to.Unix()/flowHour)
	if err != nil {
		return 0, 0, err
	}
	for rows.Next() {
		var r struct {
			Type        string `json:"type"`
			EndpointID  string `json:"endpoint_id"`
			Hour        string `json:"hour"`
			Path        string `json:"process_path"`
			SHA256      string `json:"executable_sha256,omitempty"`
			Instance    string `json:"process_instance_id,omitempty"`
			PID         int64  `json:"process_id"`
			Direction   string `json:"direction"`
			Protocol    int    `json:"protocol"`
			ServicePort int    `json:"service_port"`
			Samples     int64  `json:"samples"`
			Obs         int64  `json:"observations"`
			BytesIn     int64  `json:"bytes_in"`
			BytesOut    int64  `json:"bytes_out"`
			First       string `json:"first_seen"`
			Last        string `json:"last_seen"`
		}
		var hour, firstNs, lastNs int64
		if err := rows.Scan(&r.EndpointID, &hour, &r.Path, &r.SHA256, &r.Instance, &r.PID, &r.Direction, &r.Protocol,
			&r.ServicePort, &r.Samples, &r.Obs, &r.BytesIn, &r.BytesOut, &firstNs, &lastNs); err != nil {
			rows.Close()
			return 0, 0, err
		}
		r.Type = "local_hour"
		r.Hour = time.Unix(hour*flowHour, 0).UTC().Format(time.RFC3339)
		r.First = time.Unix(0, firstNs).UTC().Format(time.RFC3339Nano)
		r.Last = time.Unix(0, lastNs).UTC().Format(time.RFC3339Nano)
		endpoints[r.EndpointID] = struct{}{}
		rawRows++
		if err := w.write(&r); err != nil {
			rows.Close()
			return 0, 0, err
		}
	}
	if err := rows.Close(); err != nil {
		return 0, 0, err
	}

	rows, err = s.db.Query(`
		SELECT e.endpoint_id, p.instance_id, p.pid, p.parent_pid, p.parent_instance_id, i.path, i.sha256, i.signer,
			c.command_line, p.user_identity, p.first_seen, p.last_seen
		FROM flow_processes p
		JOIN flow_endpoints e ON e.id = p.endpoint_ref
		JOIN flow_images i ON i.id = p.image_ref
		JOIN flow_commands c ON c.id = p.command_ref
		WHERE p.id IN (
			SELECT process_ref FROM flows WHERE timestamp >= ? AND timestamp < ?
			UNION SELECT process_ref FROM flow_local_hourly WHERE hour >= ? AND hour < ?)`,
		flowTime(from), flowTime(to), from.Unix()/flowHour, to.Unix()/flowHour)
	if err != nil {
		return 0, 0, err
	}
	defer rows.Close()
	for rows.Next() {
		var r struct {
			Type        string `json:"type"`
			EndpointID  string `json:"endpoint_id"`
			Instance    string `json:"process_instance_id,omitempty"`
			PID         int64  `json:"process_id"`
			ParentPID   int64  `json:"parent_pid,omitempty"`
			ParentInst  string `json:"parent_process_instance_id,omitempty"`
			Path        string `json:"process_path"`
			SHA256      string `json:"executable_sha256,omitempty"`
			Signer      string `json:"executable_signer,omitempty"`
			CommandLine string `json:"command_line,omitempty"`
			User        string `json:"user_identity,omitempty"`
			First       string `json:"first_seen"`
			Last        string `json:"last_seen"`
		}
		var first, last interface{}
		if err := rows.Scan(&r.EndpointID, &r.Instance, &r.PID, &r.ParentPID, &r.ParentInst, &r.Path, &r.SHA256, &r.Signer,
			&r.CommandLine, &r.User, &first, &last); err != nil {
			return 0, 0, err
		}
		r.Type = "process"
		r.First = scanTime(first).Format(time.RFC3339Nano)
		r.Last = scanTime(last).Format(time.RFC3339Nano)
		if err := w.write(&r); err != nil {
			return 0, 0, err
		}
	}
	return int64(len(endpoints)), rawRows, rows.Err()
}

// pruneColdSegments deletes day files older than cutoff.
func (s *Store) pruneColdSegments(cutoff time.Time) (int64, error) {
	segments, err := s.ColdSegments()
	if err != nil {
		return 0, err
	}
	limit := cutoff.Format("2006-01-02")
	var n int64
	for _, seg := range segments {
		if seg.Day >= limit {
			continue
		}
		if err := os.Remove(seg.Path); err != nil && !os.IsNotExist(err) {
			return n, err
		}
		s.mu.Lock()
		_, err := s.db.Exec("DELETE FROM flow_cold_segments WHERE day = ?", seg.Day)
		s.mu.Unlock()
		if err != nil {
			return n, err
		}
		n++
	}
	return n, nil
}
