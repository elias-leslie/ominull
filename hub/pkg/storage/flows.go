package storage

import (
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"fmt"
	"time"

	"ominull/hub/pkg/netaddr"
)

// Flow storage.
//
// Endpoint flows were 98% of the database: every socket sample was its own
// 1.7 KB row, repeating the command line, executable path and hash, two process
// instance ids and a JSON blob, under ten indexes. A busy workstation wrote
// about 2.4 GB a day. The same evidence now lives in:
//
//   - flows: one row per process instance, direction, protocol, source address,
//     destination, port and name per minute. Repeat samples of the same flow in
//     that minute add to its counters (samples, observation count, bytes,
//     first/last observed). The source port of the first sample is kept.
//   - flow_local_hourly: loopback traffic as hourly counters per process
//     instance and service port. It is a host talking to itself; the counters
//     keep which process did it, how often and how much, without a row per
//     ephemeral port.
//   - dictionaries for what repeats: endpoints, executable images (path, hash,
//     signer), process instances (pid, parent, command line, user, first and
//     last seen), observation shapes (layer, action, direction, attribution,
//     collector source/timing/byte basis), geography and names (domain, SNI).
//
// The schema is platform neutral: an image is a path, a hash and a signer on
// every OS; a process instance id is an opaque string the agent chooses (the
// Linux agent derives it from boot id, pid and start time, Windows from its
// own process key), never parsed by the hub. OS-specific collector names are
// values in the shape dictionary, not columns.
//
// The events view keeps every existing reader working: it presents the old
// column set over the new tables, so analytics, traffic and topology queries
// did not change. Writers go through flowWriter.

const (
	flowMinute = int64(60)
	flowHour   = int64(3600)
	// flowOpenWindow is how many minutes back an open aggregate may still be
	// merged into. Late batches older than that start a new row.
	flowOpenWindow = int64(3)
	// flowCacheLimit bounds each dictionary cache; a full cache is cleared and
	// refilled from the database on demand.
	flowCacheLimit = 50000
)

func (s *Store) initFlowSchema() error {
	schema := `
	CREATE TABLE IF NOT EXISTS flow_endpoints (
		id INTEGER PRIMARY KEY,
		tenant_id TEXT NOT NULL,
		endpoint_id TEXT NOT NULL,
		UNIQUE (endpoint_id, tenant_id)
	);
	CREATE TABLE IF NOT EXISTS flow_images (
		id INTEGER PRIMARY KEY,
		path TEXT NOT NULL,
		sha256 TEXT NOT NULL DEFAULT '',
		signer TEXT NOT NULL DEFAULT '',
		first_seen DATETIME NOT NULL,
		UNIQUE (path, sha256, signer)
	);
	CREATE TABLE IF NOT EXISTS flow_commands (
		id INTEGER PRIMARY KEY,
		command_line TEXT NOT NULL UNIQUE
	);
	INSERT OR IGNORE INTO flow_commands (id, command_line) VALUES (0, '');
	-- key_hash is the first 8 bytes of a SHA-256 over every identity column
	-- (processIdentityHash); one integer index instead of a copy of the
	-- instance ids and command line. Rows written by the events view trigger
	-- carry no hash and are found by their columns.
	CREATE TABLE IF NOT EXISTS flow_processes (
		id INTEGER PRIMARY KEY,
		endpoint_ref INTEGER NOT NULL,
		key_hash INTEGER UNIQUE,
		instance_id TEXT NOT NULL DEFAULT '',
		pid INTEGER NOT NULL DEFAULT 0,
		parent_pid INTEGER NOT NULL DEFAULT 0,
		parent_instance_id TEXT NOT NULL DEFAULT '',
		image_ref INTEGER NOT NULL,
		command_ref INTEGER NOT NULL DEFAULT 0,
		user_identity TEXT NOT NULL DEFAULT '',
		first_seen DATETIME NOT NULL,
		last_seen DATETIME NOT NULL
	);
	CREATE TABLE IF NOT EXISTS flow_shapes (
		id INTEGER PRIMARY KEY,
		layer TEXT NOT NULL DEFAULT '',
		action TEXT NOT NULL DEFAULT '',
		direction TEXT NOT NULL DEFAULT '',
		attribution_status TEXT NOT NULL DEFAULT '',
		obs_source TEXT NOT NULL DEFAULT '',
		obs_timing TEXT NOT NULL DEFAULT '',
		obs_byte_basis TEXT NOT NULL DEFAULT '',
		UNIQUE (layer, action, direction, attribution_status, obs_source, obs_timing, obs_byte_basis)
	);
	CREATE TABLE IF NOT EXISTS flow_geo (
		id INTEGER PRIMARY KEY,
		country TEXT NOT NULL DEFAULT '',
		city TEXT NOT NULL DEFAULT '',
		asn TEXT NOT NULL DEFAULT '',
		org TEXT NOT NULL DEFAULT '',
		UNIQUE (country, city, asn, org)
	);
	CREATE TABLE IF NOT EXISTS flow_names (
		id INTEGER PRIMARY KEY,
		name TEXT NOT NULL UNIQUE
	);
	INSERT OR IGNORE INTO flow_names (id, name) VALUES (0, '');

	CREATE TABLE IF NOT EXISTS flows (
		id INTEGER PRIMARY KEY,
		endpoint_ref INTEGER NOT NULL,
		timestamp DATETIME NOT NULL,
		shape_ref INTEGER NOT NULL,
		protocol INTEGER NOT NULL,
		src_ip TEXT NOT NULL,
		dst_ip TEXT NOT NULL,
		src_port INTEGER NOT NULL,
		dst_port INTEGER NOT NULL,
		bytes_in INTEGER NOT NULL DEFAULT 0,
		bytes_out INTEGER NOT NULL DEFAULT 0,
		geo_ref INTEGER NOT NULL,
		process_ref INTEGER NOT NULL,
		domain_ref INTEGER NOT NULL DEFAULT 0,
		sni_ref INTEGER NOT NULL DEFAULT 0,
		duration_ms INTEGER NOT NULL DEFAULT 0,
		observed_at DATETIME,
		obs_count INTEGER NOT NULL DEFAULT 0,
		first_at INTEGER,
		last_at INTEGER,
		lost INTEGER NOT NULL DEFAULT 0,
		incomplete INTEGER NOT NULL DEFAULT 0,
		samples INTEGER NOT NULL DEFAULT 1,
		-- samples that carried a byte count (an aggregate's bytes may come
		-- from some of its samples only)
		measured INTEGER NOT NULL DEFAULT 0
	);
	-- Three indexes: time (every window query and the prune), endpoint and
	-- time (per-endpoint views), process (what did this process talk to).
	CREATE INDEX IF NOT EXISTS idx_flows_time ON flows(timestamp);
	CREATE INDEX IF NOT EXISTS idx_flows_endpoint_time ON flows(endpoint_ref, timestamp);
	CREATE INDEX IF NOT EXISTS idx_flows_process ON flows(process_ref);

	CREATE TABLE IF NOT EXISTS flow_local_hourly (
		endpoint_ref INTEGER NOT NULL,
		hour INTEGER NOT NULL,
		process_ref INTEGER NOT NULL,
		shape_ref INTEGER NOT NULL,
		protocol INTEGER NOT NULL,
		service_port INTEGER NOT NULL,
		samples INTEGER NOT NULL DEFAULT 0,
		obs_count INTEGER NOT NULL DEFAULT 0,
		bytes_in INTEGER NOT NULL DEFAULT 0,
		bytes_out INTEGER NOT NULL DEFAULT 0,
		first_at INTEGER NOT NULL,
		last_at INTEGER NOT NULL,
		PRIMARY KEY (endpoint_ref, hour, process_ref, shape_ref, protocol, service_port)
	) WITHOUT ROWID;
	CREATE INDEX IF NOT EXISTS idx_flow_local_hour ON flow_local_hourly(hour);
	`
	if _, err := s.db.Exec(schema); err != nil {
		return fmt.Errorf("flow schema: %w", err)
	}

	var kind string
	err := s.db.QueryRow("SELECT type FROM sqlite_master WHERE name = 'events'").Scan(&kind)
	switch {
	case err == sql.ErrNoRows:
	case err != nil:
		return err
	case kind == "table":
		// The old row-per-sample table. Bring old shapes up to its last
		// column set (cheap: metadata only), then rename it out of the way;
		// the migration worker moves its rows into flows and drops it when
		// done. The rollup trigger goes with it: the flow writer does rollups.
		for _, stmt := range legacyEventColumns {
			if err := runAdditiveMigration(s.db, stmt); err != nil {
				return err
			}
		}
		for _, stmt := range []string{
			"DROP TRIGGER IF EXISTS trg_events_rollups",
			"ALTER TABLE events RENAME TO events_legacy",
		} {
			if _, err := s.db.Exec(stmt); err != nil {
				return fmt.Errorf("retire legacy events table: %w", err)
			}
		}
	}
	// Topology cube: written on every insert, read by nothing.
	if _, err := s.db.Exec("DROP TRIGGER IF EXISTS trg_events_rollups; DROP TABLE IF EXISTS topology_edges_cube"); err != nil {
		return fmt.Errorf("retire topology cube: %w", err)
	}
	if _, err := s.db.Exec(eventsViewSQL); err != nil {
		return fmt.Errorf("events view: %w", err)
	}
	if _, err := s.db.Exec(eventsViewProcessSQL); err != nil {
		return fmt.Errorf("events view process lookup: %w", err)
	}
	if _, err := s.db.Exec(eventsInsertTriggerSQL); err != nil {
		return fmt.Errorf("events view insert trigger: %w", err)
	}
	if err := s.initAnomalyCountsSchema(); err != nil {
		return err
	}
	if err := s.initUploadSchema(); err != nil {
		return err
	}
	if err := s.initColdSchema(); err != nil {
		return err
	}
	s.flowWriter = newFlowWriter()
	// A small legacy table (a test, a lab hub) is moved at once; a large one
	// in the background (StartRetention).
	if s.legacyEventsPresent() {
		var span int64
		if err := s.db.QueryRow("SELECT COALESCE(MAX(rowid) - MIN(rowid), 0) FROM events_legacy").Scan(&span); err != nil {
			return err
		}
		if span < legacySyncRows {
			if _, err := s.copyLegacyEvents(RetentionPolicy{}, nil); err != nil {
				return fmt.Errorf("migrate legacy events: %w", err)
			}
			if err := s.dropLegacyEvents(); err != nil {
				return err
			}
		}
	}
	return nil
}

// legacySyncRows is the largest legacy table migrated during startup.
const legacySyncRows = 200000

// legacyEventColumns are the columns the old events table gained over time.
var legacyEventColumns = []string{
	"ALTER TABLE events ADD COLUMN bytes_in INTEGER NOT NULL DEFAULT 0",
	"ALTER TABLE events ADD COLUMN bytes_out INTEGER NOT NULL DEFAULT 0",
	"ALTER TABLE events ADD COLUMN country TEXT NOT NULL DEFAULT 'US'",
	"ALTER TABLE events ADD COLUMN city TEXT NOT NULL DEFAULT ''",
	"ALTER TABLE events ADD COLUMN asn TEXT NOT NULL DEFAULT ''",
	"ALTER TABLE events ADD COLUMN org TEXT NOT NULL DEFAULT ''",
	"ALTER TABLE events ADD COLUMN duration_ms INTEGER NOT NULL DEFAULT 0",
	"ALTER TABLE events ADD COLUMN domain TEXT DEFAULT ''",
	"ALTER TABLE events ADD COLUMN sni TEXT DEFAULT ''",
	"ALTER TABLE events ADD COLUMN process_instance_id TEXT DEFAULT ''",
	"ALTER TABLE events ADD COLUMN parent_pid INTEGER NOT NULL DEFAULT 0",
	"ALTER TABLE events ADD COLUMN parent_process_instance_id TEXT DEFAULT ''",
	"ALTER TABLE events ADD COLUMN command_line TEXT DEFAULT ''",
	"ALTER TABLE events ADD COLUMN user_identity TEXT DEFAULT ''",
	"ALTER TABLE events ADD COLUMN executable_sha256 TEXT DEFAULT ''",
	"ALTER TABLE events ADD COLUMN attribution_status TEXT DEFAULT ''",
	"ALTER TABLE events ADD COLUMN observed_at DATETIME",
	"ALTER TABLE events ADD COLUMN observation_json TEXT DEFAULT '{}'",
}

// eventsViewSQL presents flows with the column set of the old events table.
// observation_json is rebuilt from typed columns with nanosecond times.
const eventsViewSQL = `
CREATE VIEW IF NOT EXISTS events AS
SELECT f.id AS id, e.tenant_id AS tenant_id, e.endpoint_id AS endpoint_id, f.timestamp AS timestamp,
	s.layer AS layer, s.action AS action, s.direction AS direction, f.protocol AS protocol,
	f.src_ip AS src_ip, f.dst_ip AS dst_ip, f.src_port AS src_port, f.dst_port AS dst_port,
	f.bytes_in AS bytes_in, f.bytes_out AS bytes_out, g.country AS country,
	i.path AS process_path, p.pid AS process_id, g.city AS city, g.asn AS asn, g.org AS org,
	f.duration_ms AS duration_ms, d.name AS domain, n.name AS sni,
	p.instance_id AS process_instance_id, p.parent_pid AS parent_pid,
	p.parent_instance_id AS parent_process_instance_id, c.command_line AS command_line,
	p.user_identity AS user_identity, i.sha256 AS executable_sha256, i.signer AS executable_signer,
	s.attribution_status AS attribution_status, f.observed_at AS observed_at,
	json_object(
		'incomplete', json(CASE WHEN f.incomplete != 0 THEN 'true' ELSE 'false' END),
		'timing', NULLIF(s.obs_timing, ''), 'source', NULLIF(s.obs_source, ''),
		'byte_basis', NULLIF(s.obs_byte_basis, ''), 'count', f.obs_count,
		'first_at', CASE WHEN f.first_at IS NULL THEN NULL ELSE
			strftime('%Y-%m-%dT%H:%M:%S', f.first_at / 1000000000, 'unixepoch') || printf('.%09dZ', f.first_at % 1000000000) END,
		'last_at', CASE WHEN f.last_at IS NULL THEN NULL ELSE
			strftime('%Y-%m-%dT%H:%M:%S', f.last_at / 1000000000, 'unixepoch') || printf('.%09dZ', f.last_at % 1000000000) END,
		'lost', f.lost) AS observation_json,
	f.samples AS samples, f.measured AS measured_samples, f.endpoint_ref AS endpoint_ref, f.process_ref AS process_ref
FROM flows f
JOIN flow_endpoints e ON e.id = f.endpoint_ref
JOIN flow_shapes s ON s.id = f.shape_ref
JOIN flow_geo g ON g.id = f.geo_ref
JOIN flow_processes p ON p.id = f.process_ref
JOIN flow_images i ON i.id = p.image_ref
JOIN flow_commands c ON c.id = p.command_ref
JOIN flow_names d ON d.id = f.domain_ref
JOIN flow_names n ON n.id = f.sni_ref;
`

// eventsViewProcessSQL resolves a process row by its identity columns (the
// events view insert trigger; not a hot path).
const eventsViewProcessSQL = `
CREATE VIEW IF NOT EXISTS events_view_process AS
SELECT p.id AS id, e.endpoint_id AS endpoint_id, e.tenant_id AS tenant_id, p.instance_id AS instance_id, p.pid AS pid,
	p.parent_pid AS parent_pid, p.parent_instance_id AS parent_instance_id, i.path AS path, i.sha256 AS sha256,
	i.signer AS signer, c.command_line AS command_line, p.user_identity AS user_identity
FROM flow_processes p
JOIN flow_endpoints e ON e.id = p.endpoint_ref
JOIN flow_images i ON i.id = p.image_ref
JOIN flow_commands c ON c.id = p.command_ref;
`

// eventsInsertTriggerSQL keeps a plain INSERT INTO events working (tools and
// tests that write rows directly). It stores the row as given, one sample per
// row, without minute aggregation; the hub's own writers use flowWriter.
const eventsInsertTriggerSQL = `
CREATE TRIGGER IF NOT EXISTS trg_events_view_insert INSTEAD OF INSERT ON events
BEGIN
	INSERT OR IGNORE INTO flow_endpoints (tenant_id, endpoint_id) VALUES (COALESCE(NEW.tenant_id, 'default'), NEW.endpoint_id);
	INSERT OR IGNORE INTO flow_images (path, sha256, signer, first_seen) VALUES (COALESCE(NEW.process_path, ''), COALESCE(NEW.executable_sha256, ''), COALESCE(NEW.executable_signer, ''), NEW.timestamp);
	INSERT OR IGNORE INTO flow_commands (command_line) VALUES (COALESCE(NEW.command_line, ''));
	INSERT INTO flow_processes (endpoint_ref, instance_id, pid, parent_pid, parent_instance_id, image_ref, command_ref, user_identity, first_seen, last_seen)
	SELECT
		(SELECT id FROM flow_endpoints WHERE endpoint_id = NEW.endpoint_id AND tenant_id = COALESCE(NEW.tenant_id, 'default')),
		COALESCE(NEW.process_instance_id, ''), COALESCE(NEW.process_id, 0), COALESCE(NEW.parent_pid, 0), COALESCE(NEW.parent_process_instance_id, ''),
		(SELECT id FROM flow_images WHERE path = COALESCE(NEW.process_path, '') AND sha256 = COALESCE(NEW.executable_sha256, '') AND signer = COALESCE(NEW.executable_signer, '')),
		(SELECT id FROM flow_commands WHERE command_line = COALESCE(NEW.command_line, '')),
		COALESCE(NEW.user_identity, ''), NEW.timestamp, NEW.timestamp
	WHERE NOT EXISTS (SELECT 1 FROM events_view_process WHERE endpoint_id = NEW.endpoint_id AND tenant_id = COALESCE(NEW.tenant_id, 'default')
		AND instance_id = COALESCE(NEW.process_instance_id, '') AND pid = COALESCE(NEW.process_id, 0)
		AND parent_pid = COALESCE(NEW.parent_pid, 0) AND parent_instance_id = COALESCE(NEW.parent_process_instance_id, '')
		AND path = COALESCE(NEW.process_path, '') AND sha256 = COALESCE(NEW.executable_sha256, '') AND signer = COALESCE(NEW.executable_signer, '')
		AND command_line = COALESCE(NEW.command_line, '') AND user_identity = COALESCE(NEW.user_identity, ''));
	INSERT OR IGNORE INTO flow_shapes (layer, action, direction, attribution_status, obs_source, obs_timing, obs_byte_basis)
	VALUES (COALESCE(NEW.layer, ''), COALESCE(NEW.action, ''), COALESCE(NEW.direction, ''), COALESCE(NEW.attribution_status, ''),
		COALESCE(json_extract(NEW.observation_json, '$.source'), ''), COALESCE(json_extract(NEW.observation_json, '$.timing'), ''),
		COALESCE(json_extract(NEW.observation_json, '$.byte_basis'), ''));
	INSERT OR IGNORE INTO flow_geo (country, city, asn, org) VALUES (COALESCE(NEW.country, 'US'), COALESCE(NEW.city, ''), COALESCE(NEW.asn, ''), COALESCE(NEW.org, ''));
	INSERT OR IGNORE INTO flow_names (name) VALUES (COALESCE(NEW.domain, ''));
	INSERT OR IGNORE INTO flow_names (name) VALUES (COALESCE(NEW.sni, ''));
	INSERT INTO flows (endpoint_ref, timestamp, shape_ref, protocol, src_ip, dst_ip, src_port, dst_port, bytes_in, bytes_out, geo_ref, process_ref, domain_ref, sni_ref, duration_ms, observed_at, obs_count, lost, incomplete, samples, measured)
	VALUES (
		(SELECT id FROM flow_endpoints WHERE endpoint_id = NEW.endpoint_id AND tenant_id = COALESCE(NEW.tenant_id, 'default')),
		NEW.timestamp,
		(SELECT id FROM flow_shapes WHERE layer = COALESCE(NEW.layer, '') AND action = COALESCE(NEW.action, '') AND direction = COALESCE(NEW.direction, '')
			AND attribution_status = COALESCE(NEW.attribution_status, '')
			AND obs_source = COALESCE(json_extract(NEW.observation_json, '$.source'), '')
			AND obs_timing = COALESCE(json_extract(NEW.observation_json, '$.timing'), '')
			AND obs_byte_basis = COALESCE(json_extract(NEW.observation_json, '$.byte_basis'), '')),
		NEW.protocol, NEW.src_ip, NEW.dst_ip, NEW.src_port, NEW.dst_port, COALESCE(NEW.bytes_in, 0), COALESCE(NEW.bytes_out, 0),
		(SELECT id FROM flow_geo WHERE country = COALESCE(NEW.country, 'US') AND city = COALESCE(NEW.city, '') AND asn = COALESCE(NEW.asn, '') AND org = COALESCE(NEW.org, '')),
		(SELECT id FROM events_view_process WHERE endpoint_id = NEW.endpoint_id AND tenant_id = COALESCE(NEW.tenant_id, 'default')
			AND instance_id = COALESCE(NEW.process_instance_id, '') AND pid = COALESCE(NEW.process_id, 0)
			AND parent_pid = COALESCE(NEW.parent_pid, 0) AND parent_instance_id = COALESCE(NEW.parent_process_instance_id, '')
			AND path = COALESCE(NEW.process_path, '') AND sha256 = COALESCE(NEW.executable_sha256, '') AND signer = COALESCE(NEW.executable_signer, '')
			AND command_line = COALESCE(NEW.command_line, '') AND user_identity = COALESCE(NEW.user_identity, '') ORDER BY id LIMIT 1),
		(SELECT id FROM flow_names WHERE name = COALESCE(NEW.domain, '')),
		(SELECT id FROM flow_names WHERE name = COALESCE(NEW.sni, '')),
		COALESCE(NEW.duration_ms, 0), NEW.observed_at,
		COALESCE(json_extract(NEW.observation_json, '$.count'), 0),
		COALESCE(json_extract(NEW.observation_json, '$.lost'), 0),
		COALESCE(json_extract(NEW.observation_json, '$.incomplete'), 0),
		1, CASE WHEN COALESCE(NEW.bytes_in, 0) + COALESCE(NEW.bytes_out, 0) > 0 THEN 1 ELSE 0 END);
	INSERT INTO bandwidth_buckets (tenant_id, hour_bucket, country, direction, bytes_in, bytes_out, flow_count, block_count, measured_count)
	VALUES (
		COALESCE(NEW.tenant_id, 'default'),
		strftime('%Y-%m-%dT%H:00:00Z', substr(NEW.timestamp, 1, 19) || 'Z'),
		CASE WHEN COALESCE(NEW.country, 'US') = '' THEN 'UNKNOWN' ELSE COALESCE(NEW.country, 'US') END,
		CASE WHEN COALESCE(NEW.direction, '') = '' THEN 'OUTBOUND' ELSE NEW.direction END,
		COALESCE(NEW.bytes_in, 0), COALESCE(NEW.bytes_out, 0), 1,
		CASE WHEN NEW.action = 'BLOCK' THEN 1 ELSE 0 END,
		CASE WHEN COALESCE(NEW.bytes_in, 0) + COALESCE(NEW.bytes_out, 0) > 0 THEN 1 ELSE 0 END)
	ON CONFLICT (tenant_id, hour_bucket, country, direction) DO UPDATE SET
		bytes_in = bandwidth_buckets.bytes_in + excluded.bytes_in,
		bytes_out = bandwidth_buckets.bytes_out + excluded.bytes_out,
		flow_count = bandwidth_buckets.flow_count + 1,
		block_count = bandwidth_buckets.block_count + excluded.block_count,
		measured_count = bandwidth_buckets.measured_count + excluded.measured_count;
END;
`

type imageKey struct{ path, sha, signer string }

type processKey struct {
	endpoint               int64
	instance, parentInst   string
	pid, ppid              uint32
	image                  int64
	commandLine, userIdent string
}

type shapeKey struct {
	layer, action, direction, attribution string
	source, timing, byteBasis             string
}

type geoKey struct{ country, city, asn, org string }

type endpointKey struct{ tenant, endpoint string }

// openFlowKey identifies a minute aggregate. The source port is not part of
// it: repeat samples of a client talking to the same service in one minute
// are one row, carrying the first source port seen.
type openFlowKey struct {
	endpoint, minute, process, shape, geo, domain, sni int64
	protocol                                           uint8
	dstPort                                            uint16
	srcIP, dstIP                                       string
}

type processEntry struct {
	id       int64
	lastSeen time.Time
}

// flowWriter holds the dictionary caches and the open minute aggregates. It
// is guarded by Store.mu (writers hold the write lock). Entries created inside
// a transaction are staged and only become visible once it commits, so a
// rolled-back batch never leaves a cached id that does not exist.
type flowWriter struct {
	endpoints map[endpointKey]int64
	images    map[imageKey]int64
	processes map[processKey]processEntry
	shapes    map[shapeKey]int64
	geo       map[geoKey]int64
	names     map[string]int64
	commands  map[string]int64
	open      map[openFlowKey]int64
	maxMinute int64
	// lastGC is when unreferenced dictionary rows were last collected.
	lastGC time.Time
	// dns holds the open minute rows of dns_events (dns.go).
	dns       map[dnsKey]int64
	dnsMinute int64
}

func newFlowWriter() *flowWriter {
	w := &flowWriter{}
	w.reset()
	return w
}

func (w *flowWriter) reset() {
	w.endpoints = map[endpointKey]int64{}
	w.images = map[imageKey]int64{}
	w.processes = map[processKey]processEntry{}
	w.shapes = map[shapeKey]int64{}
	w.geo = map[geoKey]int64{}
	w.names = map[string]int64{"": 0}
	w.commands = map[string]int64{"": 0}
	w.open = map[openFlowKey]int64{}
	w.dns = map[dnsKey]int64{}
}

// flowBatch is one transaction's view of the writer.
type flowBatch struct {
	w  *flowWriter
	tx *sql.Tx

	endpoints map[endpointKey]int64
	images    map[imageKey]int64
	processes map[processKey]processEntry
	shapes    map[shapeKey]int64
	geo       map[geoKey]int64
	names     map[string]int64
	commands  map[string]int64
	open      map[openFlowKey]int64

	stmts map[string]*sql.Stmt
	// rollups=false is the legacy migration: its rows were already counted
	// into bandwidth_buckets by the old trigger.
	rollups   bool
	bandwidth map[bandwidthKey]*bandwidthDelta
}

type bandwidthKey struct{ tenant, hour, country, direction string }
type bandwidthDelta struct{ in, out, flows, blocks, measured int64 }

var flowStatements = map[string]string{
	"endpoint": `INSERT INTO flow_endpoints (tenant_id, endpoint_id) VALUES (?, ?)
		ON CONFLICT (endpoint_id, tenant_id) DO UPDATE SET tenant_id = excluded.tenant_id RETURNING id`,
	"image": `INSERT INTO flow_images (path, sha256, signer, first_seen) VALUES (?, ?, ?, ?)
		ON CONFLICT (path, sha256, signer) DO UPDATE SET path = excluded.path RETURNING id`,
	"command": `INSERT INTO flow_commands (command_line) VALUES (?) ON CONFLICT (command_line) DO UPDATE SET command_line = excluded.command_line RETURNING id`,
	"process": `INSERT INTO flow_processes (endpoint_ref, key_hash, instance_id, pid, parent_pid, parent_instance_id, image_ref, command_ref, user_identity, first_seen, last_seen)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT (key_hash)
		DO UPDATE SET last_seen = MAX(last_seen, excluded.last_seen), first_seen = MIN(first_seen, excluded.first_seen) RETURNING id`,
	"shape": `INSERT INTO flow_shapes (layer, action, direction, attribution_status, obs_source, obs_timing, obs_byte_basis) VALUES (?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT (layer, action, direction, attribution_status, obs_source, obs_timing, obs_byte_basis) DO UPDATE SET layer = excluded.layer RETURNING id`,
	"geo": `INSERT INTO flow_geo (country, city, asn, org) VALUES (?, ?, ?, ?)
		ON CONFLICT (country, city, asn, org) DO UPDATE SET country = excluded.country RETURNING id`,
	"name": `INSERT INTO flow_names (name) VALUES (?) ON CONFLICT (name) DO UPDATE SET name = excluded.name RETURNING id`,
	"insert": `INSERT INTO flows (endpoint_ref, timestamp, shape_ref, protocol, src_ip, dst_ip, src_port, dst_port, bytes_in, bytes_out, geo_ref, process_ref, domain_ref, sni_ref, duration_ms, observed_at, obs_count, first_at, last_at, lost, incomplete, samples, measured)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?)`,
	"merge": `UPDATE flows SET bytes_in = bytes_in + ?, bytes_out = bytes_out + ?, obs_count = obs_count + ?, lost = lost + ?,
		samples = samples + 1, measured = measured + ?, incomplete = MAX(incomplete, ?), duration_ms = MAX(duration_ms, ?),
		first_at = CASE WHEN first_at IS NULL OR (? IS NOT NULL AND ? < first_at) THEN COALESCE(?, first_at) ELSE first_at END,
		last_at = CASE WHEN last_at IS NULL OR (? IS NOT NULL AND ? > last_at) THEN COALESCE(?, last_at) ELSE last_at END,
		observed_at = COALESCE(?, observed_at)
		WHERE id = ?`,
	"local": `INSERT INTO flow_local_hourly (endpoint_ref, hour, process_ref, shape_ref, protocol, service_port, samples, obs_count, bytes_in, bytes_out, first_at, last_at)
		VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?, ?, ?, ?)
		ON CONFLICT (endpoint_ref, hour, process_ref, shape_ref, protocol, service_port) DO UPDATE SET
			samples = samples + 1, obs_count = obs_count + excluded.obs_count,
			bytes_in = bytes_in + excluded.bytes_in, bytes_out = bytes_out + excluded.bytes_out,
			first_at = MIN(first_at, excluded.first_at), last_at = MAX(last_at, excluded.last_at)`,
	"bandwidth": `INSERT INTO bandwidth_buckets (tenant_id, hour_bucket, country, direction, bytes_in, bytes_out, flow_count, block_count, measured_count)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT (tenant_id, hour_bucket, country, direction) DO UPDATE SET
			bytes_in = bandwidth_buckets.bytes_in + excluded.bytes_in,
			bytes_out = bandwidth_buckets.bytes_out + excluded.bytes_out,
			flow_count = bandwidth_buckets.flow_count + excluded.flow_count,
			block_count = bandwidth_buckets.block_count + excluded.block_count,
			measured_count = bandwidth_buckets.measured_count + excluded.measured_count`,
}

func (w *flowWriter) begin(tx *sql.Tx, rollups bool) *flowBatch {
	return &flowBatch{
		w: w, tx: tx, rollups: rollups,
		endpoints: map[endpointKey]int64{}, images: map[imageKey]int64{},
		processes: map[processKey]processEntry{}, shapes: map[shapeKey]int64{},
		geo: map[geoKey]int64{}, names: map[string]int64{}, commands: map[string]int64{}, open: map[openFlowKey]int64{},
		stmts: map[string]*sql.Stmt{}, bandwidth: map[bandwidthKey]*bandwidthDelta{},
	}
}

func (b *flowBatch) stmt(name string) (*sql.Stmt, error) {
	if st, ok := b.stmts[name]; ok {
		return st, nil
	}
	st, err := b.tx.Prepare(flowStatements[name])
	if err != nil {
		return nil, fmt.Errorf("prepare flow %s: %w", name, err)
	}
	b.stmts[name] = st
	return st, nil
}

func (b *flowBatch) close() {
	for _, st := range b.stmts {
		st.Close()
	}
}

// commit publishes the staged cache entries after the transaction committed.
func (b *flowBatch) commit() {
	w := b.w
	if len(w.endpoints)+len(w.images)+len(w.processes)+len(w.names)+len(w.commands) > 4*flowCacheLimit {
		w.reset()
	}
	for k, v := range b.endpoints {
		w.endpoints[k] = v
	}
	for k, v := range b.images {
		w.images[k] = v
	}
	for k, v := range b.processes {
		w.processes[k] = v
	}
	for k, v := range b.shapes {
		w.shapes[k] = v
	}
	for k, v := range b.geo {
		w.geo[k] = v
	}
	for k, v := range b.names {
		w.names[k] = v
	}
	for k, v := range b.commands {
		w.commands[k] = v
	}
	for k, v := range b.open {
		w.open[k] = v
		if k.minute > w.maxMinute {
			w.maxMinute = k.minute
		}
	}
	if len(w.open) > flowCacheLimit/5 || len(b.open) > 0 {
		for k := range w.open {
			if k.minute < w.maxMinute-flowOpenWindow {
				delete(w.open, k)
			}
		}
	}
}

func (b *flowBatch) returningID(name string, args ...interface{}) (int64, error) {
	st, err := b.stmt(name)
	if err != nil {
		return 0, err
	}
	var id int64
	if err := st.QueryRow(args...).Scan(&id); err != nil {
		return 0, fmt.Errorf("flow %s dictionary: %w", name, err)
	}
	return id, nil
}

func (b *flowBatch) endpointRef(tenant, endpoint string) (int64, error) {
	k := endpointKey{tenant, endpoint}
	if id, ok := b.endpoints[k]; ok {
		return id, nil
	}
	if id, ok := b.w.endpoints[k]; ok {
		return id, nil
	}
	id, err := b.returningID("endpoint", tenant, endpoint)
	if err == nil {
		b.endpoints[k] = id
	}
	return id, err
}

func (b *flowBatch) imageRef(path, sha, signer string, seen time.Time) (int64, error) {
	k := imageKey{path, sha, signer}
	if id, ok := b.images[k]; ok {
		return id, nil
	}
	if id, ok := b.w.images[k]; ok {
		return id, nil
	}
	id, err := b.returningID("image", path, sha, signer, flowTime(seen))
	if err == nil {
		b.images[k] = id
	}
	return id, err
}

// processRefreshAfter is how stale a cached process's last_seen may get
// before the dictionary row is touched again.
const processRefreshAfter = 10 * time.Minute

func (b *flowBatch) processRef(k processKey, seen time.Time) (int64, error) {
	if e, ok := b.processes[k]; ok && seen.Sub(e.lastSeen) < processRefreshAfter {
		return e.id, nil
	}
	if e, ok := b.w.processes[k]; ok && seen.Sub(e.lastSeen) < processRefreshAfter {
		return e.id, nil
	}
	commandRef, err := b.commandRef(k.commandLine)
	if err != nil {
		return 0, err
	}
	at := flowTime(seen)
	id, err := b.returningID("process", k.endpoint, processIdentityHash(k), k.instance, k.pid, k.ppid, k.parentInst, k.image, commandRef, k.userIdent, at, at)
	if err == nil {
		b.processes[k] = processEntry{id: id, lastSeen: seen}
	}
	return id, err
}

// processIdentityHash is the dictionary key of a process row: the first 8
// bytes of a SHA-256 over its identity fields, each length prefixed.
func processIdentityHash(k processKey) int64 {
	h := sha256.New()
	var n [8]byte
	field := func(v string) {
		binary.BigEndian.PutUint64(n[:], uint64(len(v)))
		h.Write(n[:])
		h.Write([]byte(v))
	}
	num := func(v int64) {
		binary.BigEndian.PutUint64(n[:], uint64(v))
		h.Write(n[:])
	}
	num(k.endpoint)
	num(k.image)
	num(int64(k.pid))
	num(int64(k.ppid))
	field(k.instance)
	field(k.parentInst)
	field(k.commandLine)
	field(k.userIdent)
	sum := h.Sum(nil)
	return int64(binary.BigEndian.Uint64(sum[:8]))
}

func (b *flowBatch) commandRef(cmd string) (int64, error) {
	if cmd == "" {
		return 0, nil
	}
	if id, ok := b.commands[cmd]; ok {
		return id, nil
	}
	if id, ok := b.w.commands[cmd]; ok {
		return id, nil
	}
	id, err := b.returningID("command", cmd)
	if err == nil {
		b.commands[cmd] = id
	}
	return id, err
}

// flowTimeLayout is how flow times are stored: whole seconds, UTC. Sub-second
// observation times are kept in first_at/last_at (nanoseconds).
const flowTimeLayout = "2006-01-02 15:04:05"

func flowTime(t time.Time) string { return t.UTC().Format(flowTimeLayout) }

func (b *flowBatch) shapeRef(k shapeKey) (int64, error) {
	if id, ok := b.shapes[k]; ok {
		return id, nil
	}
	if id, ok := b.w.shapes[k]; ok {
		return id, nil
	}
	id, err := b.returningID("shape", k.layer, k.action, k.direction, k.attribution, k.source, k.timing, k.byteBasis)
	if err == nil {
		b.shapes[k] = id
	}
	return id, err
}

func (b *flowBatch) geoRef(k geoKey) (int64, error) {
	if id, ok := b.geo[k]; ok {
		return id, nil
	}
	if id, ok := b.w.geo[k]; ok {
		return id, nil
	}
	id, err := b.returningID("geo", k.country, k.city, k.asn, k.org)
	if err == nil {
		b.geo[k] = id
	}
	return id, err
}

func (b *flowBatch) nameRef(name string) (int64, error) {
	if name == "" {
		return 0, nil
	}
	if id, ok := b.names[name]; ok {
		return id, nil
	}
	if id, ok := b.w.names[name]; ok {
		return id, nil
	}
	id, err := b.returningID("name", name)
	if err == nil {
		b.names[name] = id
	}
	return id, err
}

func nanosOrNil(t *time.Time) interface{} {
	if t == nil || t.IsZero() {
		return nil
	}
	return t.UTC().UnixNano()
}

// IsLocalFlow reports whether a flow stays on the host (loopback on either
// end). Those are stored as hourly counters instead of minute rows.
func IsLocalFlow(ev Event) bool {
	return netaddr.IsLoopback(ev.DstIP) || netaddr.IsLoopback(ev.SrcIP)
}

// servicePort is the lower non-zero port of a local flow: the listening side
// of a loopback conversation, whichever socket reported it.
func servicePort(a, b uint16) uint16 {
	switch {
	case a == 0:
		return b
	case b == 0:
		return a
	case a < b:
		return a
	default:
		return b
	}
}

// add records one normalized event (addresses canonical, time UTC, country
// filled in).
func (b *flowBatch) add(ev Event) error {
	tenant := ev.TenantID
	if tenant == "" {
		tenant = "default"
	}
	endpointRef, err := b.endpointRef(tenant, ev.EndpointID)
	if err != nil {
		return err
	}
	imageRef, err := b.imageRef(ev.ProcessPath, ev.ExecutableSHA256, "", ev.Timestamp)
	if err != nil {
		return err
	}
	processRef, err := b.processRef(processKey{
		endpoint: endpointRef, instance: ev.ProcessInstanceID, parentInst: ev.ParentProcessInstanceID,
		pid: ev.ProcessID, ppid: ev.ParentPID, image: imageRef,
		commandLine: ev.CommandLine, userIdent: ev.UserIdentity,
	}, ev.Timestamp)
	if err != nil {
		return err
	}
	obs := ev.Observation
	shapeRef, err := b.shapeRef(shapeKey{
		layer: ev.Layer, action: ev.Action, direction: ev.Direction, attribution: ev.AttributionStatus,
		source: obs.Source, timing: obs.Timing, byteBasis: obs.ByteBasis,
	})
	if err != nil {
		return err
	}
	first, last := nanosOrNil(obs.FirstAt), nanosOrNil(obs.LastAt)
	if b.rollups {
		b.addBandwidth(tenant, ev)
	}

	if IsLocalFlow(ev) {
		firstAt, lastAt := ev.Timestamp.UnixNano(), ev.Timestamp.UnixNano()
		if v, ok := first.(int64); ok {
			firstAt = v
		}
		if v, ok := last.(int64); ok {
			lastAt = v
		}
		st, err := b.stmt("local")
		if err != nil {
			return err
		}
		_, err = st.Exec(endpointRef, ev.Timestamp.Unix()/flowHour, processRef, shapeRef, ev.Protocol,
			servicePort(ev.SrcPort, ev.DstPort), obs.Count, ev.BytesIn, ev.BytesOut, firstAt, lastAt)
		if err != nil {
			return fmt.Errorf("record local flow counters: %w", err)
		}
		return nil
	}

	geoRef, err := b.geoRef(geoKey{ev.Country, "", "", ""})
	if err != nil {
		return err
	}
	domainRef, err := b.nameRef(ev.Domain)
	if err != nil {
		return err
	}
	sniRef, err := b.nameRef(ev.SNI)
	if err != nil {
		return err
	}
	var observedAt interface{}
	if ev.ObservedAt != nil && !ev.ObservedAt.IsZero() {
		observedAt = ev.ObservedAt.UTC().Format(time.RFC3339Nano)
	}
	incomplete := 0
	if obs.Incomplete {
		incomplete = 1
	}
	measured := 0
	if ev.BytesIn+ev.BytesOut > 0 {
		measured = 1
	}

	key := openFlowKey{
		endpoint: endpointRef, minute: ev.Timestamp.Unix() / flowMinute, process: processRef, shape: shapeRef,
		geo: geoRef, domain: domainRef, sni: sniRef, protocol: ev.Protocol, dstPort: ev.DstPort,
		srcIP: ev.SrcIP, dstIP: ev.DstIP,
	}
	rowID, open := b.open[key]
	if !open {
		rowID, open = b.w.open[key]
	}
	if open {
		st, err := b.stmt("merge")
		if err != nil {
			return err
		}
		res, err := st.Exec(ev.BytesIn, ev.BytesOut, obs.Count, obs.Lost, measured, incomplete, 0,
			first, first, first, last, last, last, observedAt, rowID)
		if err != nil {
			return fmt.Errorf("merge flow: %w", err)
		}
		if n, _ := res.RowsAffected(); n == 1 {
			return nil
		}
		// The row was pruned or the cache is stale: insert afresh.
	}
	st, err := b.stmt("insert")
	if err != nil {
		return err
	}
	res, err := st.Exec(endpointRef, flowTime(ev.Timestamp), shapeRef, ev.Protocol, ev.SrcIP, ev.DstIP, ev.SrcPort, ev.DstPort,
		ev.BytesIn, ev.BytesOut, geoRef, processRef, domainRef, sniRef, 0, observedAt, obs.Count, first, last,
		obs.Lost, incomplete, measured)
	if err != nil {
		return fmt.Errorf("insert flow: %w", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return err
	}
	b.open[key] = id
	return nil
}

func (b *flowBatch) addBandwidth(tenant string, ev Event) {
	country := ev.Country
	if country == "" {
		country = CountryUnknown
	}
	direction := ev.Direction
	if direction == "" {
		direction = "OUTBOUND"
	}
	k := bandwidthKey{tenant, ev.Timestamp.UTC().Format("2006-01-02T15:00:00Z"), country, direction}
	d := b.bandwidth[k]
	if d == nil {
		d = &bandwidthDelta{}
		b.bandwidth[k] = d
	}
	d.in += ev.BytesIn
	d.out += ev.BytesOut
	d.flows++
	if ev.Action == "BLOCK" {
		d.blocks++
	}
	if ev.BytesIn+ev.BytesOut > 0 {
		d.measured++
	}
}

// finish writes the batch's rollups; call before the transaction commits.
func (b *flowBatch) finish() error {
	if len(b.bandwidth) == 0 {
		return nil
	}
	st, err := b.stmt("bandwidth")
	if err != nil {
		return err
	}
	for k, d := range b.bandwidth {
		if _, err := st.Exec(k.tenant, k.hour, k.country, k.direction, d.in, d.out, d.flows, d.blocks, d.measured); err != nil {
			return fmt.Errorf("bandwidth rollup: %w", err)
		}
	}
	return nil
}

// normalizeFlowEvent applies the storage normalization every writer shares.
func normalizeFlowEvent(ev Event) Event {
	ev.SrcIP, ev.DstIP = canonicalAddress(ev.SrcIP), canonicalAddress(ev.DstIP)
	ev.Timestamp = ev.Timestamp.UTC()
	if ev.TenantID == "" {
		ev.TenantID = "default"
	}
	if ev.Country == "" {
		ev.Country = CountryUnknown
	}
	return ev
}

// writeFlows stores events inside an open transaction. The caller holds
// s.mu for writing and must call the returned batch's commit after a
// successful tx.Commit.
func (s *Store) writeFlows(tx *sql.Tx, events []Event, rollups bool) (*flowBatch, error) {
	b := s.flowWriter.begin(tx, rollups)
	for _, ev := range events {
		if err := b.add(normalizeFlowEvent(ev)); err != nil {
			b.close()
			return nil, err
		}
	}
	if err := b.finish(); err != nil {
		b.close()
		return nil, err
	}
	b.close()
	return b, nil
}

// insertFlows is the whole write for callers without their own transaction.
func (s *Store) insertFlows(events []Event) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	b, err := s.writeFlows(tx, events, true)
	if err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit flows: %w", err)
	}
	b.commit()
	return nil
}

// deleteEndpointFlows removes an endpoint's flow rows, counters and process
// dictionary entries inside the caller's transaction.
func deleteEndpointFlows(tx *sql.Tx, endpointID string) error {
	for _, q := range []string{
		"DELETE FROM flows WHERE endpoint_ref IN (SELECT id FROM flow_endpoints WHERE endpoint_id = ?)",
		"DELETE FROM flow_local_hourly WHERE endpoint_ref IN (SELECT id FROM flow_endpoints WHERE endpoint_id = ?)",
		"DELETE FROM flow_processes WHERE endpoint_ref IN (SELECT id FROM flow_endpoints WHERE endpoint_id = ?)",
	} {
		if _, err := tx.Exec(q, endpointID); err != nil {
			return err
		}
	}
	return nil
}

// resetFlowCaches drops cached ids after rows were deleted outside the writer.
func (s *Store) resetFlowCaches() {
	if s.flowWriter != nil {
		s.flowWriter.reset()
	}
}
