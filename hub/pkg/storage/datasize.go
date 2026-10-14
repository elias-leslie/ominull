package storage

import (
	"bufio"
	"database/sql"
	"fmt"
	"math"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Data size report: the measuring stick for retention.
//
// The hub states, per data type, how many bytes it holds and what that is per
// endpoint-day (endpoint data) or per router-client-day (router data), hot
// (raw window in SQLite) versus retained (rollups past it), with projections
// for more endpoints and days, against fixed budgets. The console and the
// Nightshift feed read the cached report; it is rebuilt by the retention
// sweep (dbstat reads every page, so not per request).

// DataBudgets are the goal posts the report is measured against.
type DataBudgets struct {
	HotBusyMBPerDay      float64 `json:"hot_busy_mb_per_day"`
	HotTypicalMBPerDay   float64 `json:"hot_typical_mb_per_day"`
	RetainedMBPerEPDay   float64 `json:"retained_mb_per_endpoint_day"`
	RetainedStretchMB    float64 `json:"retained_stretch_mb_per_endpoint_day"`
	RouterMBPerClientDay float64 `json:"router_mb_per_client_day"`
	HubRSSMB             float64 `json:"hub_rss_mb"`
	DBMaxMB              float64 `json:"db_max_mb"`
	DBGrowthMBPerDay     float64 `json:"db_growth_mb_per_day"`
}

// DefaultDataBudgets: hot raw ≤15 MB/day for a busy host and ≤3 for a typical
// one, retained ≤0.5 MB per endpoint-day (stretch 0.2), router ≤0.3 MB per
// client-day; hub RSS well under its 1 GiB container; the database bounded.
func DefaultDataBudgets() DataBudgets {
	return DataBudgets{
		HotBusyMBPerDay: 15, HotTypicalMBPerDay: 3, RetainedMBPerEPDay: 0.5, RetainedStretchMB: 0.2,
		RouterMBPerClientDay: 0.3, HubRSSMB: 256, DBMaxMB: 2048, DBGrowthMBPerDay: 64,
	}
}

// DataTypeSize is one data type's footprint.
type DataTypeSize struct {
	Type       string   `json:"type"`
	Label      string   `json:"label"`
	Tier       string   `json:"tier"`  // hot | retained
	Scope      string   `json:"scope"` // endpoint | router | hub
	Tables     []string `json:"tables,omitempty"`
	Bytes      int64    `json:"bytes"`
	IndexBytes int64    `json:"index_bytes"`
	Rows       int64    `json:"rows"`
	MBPerDay   float64  `json:"mb_per_day"`
	MBPerUnit  float64  `json:"mb_per_unit_day"` // per endpoint-day or router-client-day
	UnitDays   float64  `json:"unit_days"`
	WindowDays float64  `json:"window_days"`
}

// EndpointDataRate is one endpoint's hot flow data per day.
type EndpointDataRate struct {
	EndpointID string  `json:"endpoint_id"`
	Days       int     `json:"days"`
	RowsPerDay float64 `json:"rows_per_day"`
	MBPerDay   float64 `json:"mb_per_day"`
}

// DataProjection is the projected size for a fleet and period.
type DataProjection struct {
	Endpoints int     `json:"endpoints"`
	Days      int     `json:"days"`
	GB        float64 `json:"gb"`
}

// DataReport is the full report.
type DataReport struct {
	GeneratedAt        time.Time           `json:"generated_at"`
	DurationMS         int64               `json:"duration_ms"`
	DBBytes            int64               `json:"db_bytes"`
	WALBytes           int64               `json:"wal_bytes"`
	FreeBytes          int64               `json:"free_bytes"`
	FlowIndexes        int                 `json:"flow_indexes"`
	HubRSSBytes        int64               `json:"hub_rss_bytes"`
	HubCPUPercent      float64             `json:"hub_cpu_percent"`
	IngestEvents       int64               `json:"ingest_events"`
	IngestMicrosPerEvt float64             `json:"ingest_us_per_event"`
	QueryMS            map[string]float64  `json:"query_ms"`
	Types              []DataTypeSize      `json:"types"`
	Endpoints          []EndpointDataRate  `json:"endpoints"`
	HotBusyMBPerDay    float64             `json:"hot_busy_mb_per_day"`
	HotTypicalMBPerDay float64             `json:"hot_typical_mb_per_day"`
	HotMBPerEPDay      float64             `json:"hot_mb_per_endpoint_day"`
	RetainedMBPerEPDay float64             `json:"retained_mb_per_endpoint_day"`
	RouterMBPerClient  float64             `json:"router_mb_per_client_day"`
	RouterClients      float64             `json:"router_clients_per_day"`
	DBGrowthMBPerDay   float64             `json:"db_growth_mb_per_day"`
	Projections        []DataProjection    `json:"projections"`
	Budgets            DataBudgets         `json:"budgets"`
	OverBudget         []string            `json:"over_budget"`
	ColdSegments       int                 `json:"cold_segments"`
	ColdBytes          int64               `json:"cold_bytes"`
	Migration          FlowMigrationStatus `json:"migration"`
	Estimated          bool                `json:"estimated,omitempty"`
	Error              string              `json:"error,omitempty"`
}

type dataReportCache struct {
	mu      sync.Mutex
	report  *DataReport
	lastCPU float64
	lastAt  time.Time
}

// ingest counters for the report (µs per event).
var ingestNanos, ingestEvents atomic.Int64

func recordIngest(started time.Time, events int) {
	ingestNanos.Add(int64(time.Since(started)))
	ingestEvents.Add(int64(events))
}

// DataReport returns the last computed report (nil before the first sweep).
func (s *Store) DataReport() *DataReport {
	s.dataReport.mu.Lock()
	defer s.dataReport.mu.Unlock()
	return s.dataReport.report
}

// dataTypes maps tables to report types. Tables not listed fall into "other".
var dataTypes = []struct {
	typ, label, tier, scope string
	tables                  []string
	prefix                  []string
}{
	{"flows", "Endpoint flows + process attribution", "hot", "endpoint",
		[]string{"flows", "flow_endpoints", "flow_images", "flow_processes", "flow_commands", "flow_shapes", "flow_geo", "flow_names", "events_legacy"}, nil},
	{"local_counters", "Loopback counters (hourly)", "hot", "endpoint", []string{"flow_local_hourly"}, nil},
	{"comm_profiles", "Communication profiles", "hot", "endpoint", []string{"comm_profiles"}, nil},
	{"bandwidth", "Bandwidth rollup", "hot", "endpoint", []string{"bandwidth_buckets"}, nil},
	{"dns_events", "Router DNS", "hot", "router", []string{"dns_events", "dns_resolutions"}, nil},
	{"router_flows", "Router flows (5-min)", "hot", "router", []string{"router_flows", "router_client_counters"}, nil},
	{"anomalies", "Anomalies + resolutions", "hot", "hub", []string{"anomaly_alerts", "anomaly_resolutions"}, nil},
	{"inventory", "Inventory / posture", "hot", "endpoint", []string{"software_inventory", "vulnerabilities", "vulnerability_matches"}, []string{"data_"}},
	{"baselines", "Baselines + learning", "hot", "endpoint", nil, []string{"agent_egress_", "learning_", "baseline_"}},
	{"dns_daily", "Router DNS per client×domain daily", "retained", "router", []string{"dns_domain_daily"}, nil},
	{"router_daily", "Router per-device daily", "retained", "router", []string{"router_client_daily"}, nil},
	{"anomaly_counts", "Anomaly counts per signature", "retained", "hub", []string{"anomaly_signature_daily"}, nil},
}

func dataTypeFor(table string) int {
	for i, t := range dataTypes {
		for _, n := range t.tables {
			if n == table {
				return i
			}
		}
		for _, p := range t.prefix {
			if strings.HasPrefix(table, p) {
				return i
			}
		}
	}
	return -1
}

// RefreshDataReport rebuilds the cached report.
func (s *Store) RefreshDataReport(policy RetentionPolicy) error {
	started := time.Now()
	r := &DataReport{GeneratedAt: started.UTC(), Budgets: DefaultDataBudgets(), QueryMS: map[string]float64{}}
	r.Migration = s.flowMigrationStatus()
	err := s.buildDataReport(r, policy)
	if err != nil {
		r.Error = err.Error()
	}
	r.DurationMS = time.Since(started).Milliseconds()
	s.dataReport.mu.Lock()
	cpu := processCPUSeconds()
	if !s.dataReport.lastAt.IsZero() && cpu > 0 {
		if wall := started.Sub(s.dataReport.lastAt).Seconds(); wall > 0 {
			r.HubCPUPercent = round2(100 * (cpu - s.dataReport.lastCPU) / wall)
		}
	}
	s.dataReport.lastCPU, s.dataReport.lastAt = cpu, started
	s.dataReport.report = r
	s.dataReport.mu.Unlock()
	return err
}

func round2(v float64) float64 { return math.Round(v*100) / 100 }
func round4(v float64) float64 { return math.Round(v*10000) / 10000 }

const mb = 1 << 20

func (s *Store) buildDataReport(r *DataReport, policy RetentionPolicy) error {
	r.HubRSSBytes = processRSSBytes()
	if n := ingestEvents.Load(); n > 0 {
		r.IngestEvents = n
		r.IngestMicrosPerEvt = round2(float64(ingestNanos.Load()) / float64(n) / 1000)
	}
	var pageSize, pageCount, freePages int64
	_ = s.db.QueryRow("PRAGMA page_size").Scan(&pageSize)
	_ = s.db.QueryRow("PRAGMA page_count").Scan(&pageCount)
	_ = s.db.QueryRow("PRAGMA freelist_count").Scan(&freePages)
	r.DBBytes, r.FreeBytes = pageSize*pageCount, pageSize*freePages
	if p := dbFilePath(s); p != "" {
		if info, err := os.Stat(p + "-wal"); err == nil {
			r.WALBytes = info.Size()
		}
	}
	_ = s.db.QueryRow("SELECT COUNT(*) FROM sqlite_master WHERE type = 'index' AND tbl_name = 'flows'").Scan(&r.FlowIndexes)

	// Bytes per object. dbstat reads every page: skipped while the legacy
	// table is still there (tens of GB); the page total stands in.
	tableBytes, indexBytes := map[string]int64{}, map[string]int64{}
	if !r.Migration.Pending {
		if err := s.objectSizes(tableBytes, indexBytes); err != nil {
			r.Estimated = true
		}
	} else {
		r.Estimated = true
	}

	now := time.Now().UTC()
	today := now.Truncate(24 * time.Hour)
	types := make([]DataTypeSize, len(dataTypes))
	for i, t := range dataTypes {
		types[i] = DataTypeSize{Type: t.typ, Label: t.label, Tier: t.tier, Scope: t.scope}
	}
	other := DataTypeSize{Type: "other", Label: "Settings, keys, audit, other", Tier: "hot", Scope: "hub"}
	for table, b := range tableBytes {
		i := dataTypeFor(table)
		if i < 0 {
			other.Bytes += b
			other.IndexBytes += indexBytes[table]
			continue
		}
		types[i].Bytes += b
		types[i].IndexBytes += indexBytes[table]
		types[i].Tables = append(types[i].Tables, table)
	}
	for i := range types {
		sort.Strings(types[i].Tables)
	}

	// Endpoint-days over complete days in the raw window.
	rates, epDays, rowsComplete, rowsTotal, err := s.endpointFlowRates(today)
	if err != nil {
		return err
	}
	clientDays, routerDays, err := s.routerClientDays(today)
	if err != nil {
		return err
	}
	windowDays := policy.Events.Hours() / 24
	for i := range types {
		t := &types[i]
		total := float64(t.Bytes + t.IndexBytes)
		switch {
		case t.Type == "flows" || t.Type == "local_counters":
			if rowsTotal > 0 && epDays > 0 {
				share := float64(rowsComplete) / float64(rowsTotal)
				days := float64(distinctDays(rates))
				t.UnitDays = float64(epDays)
				t.MBPerUnit = round4(total * share / float64(epDays) / mb)
				if days > 0 {
					t.MBPerDay = round4(total * share / days / mb)
					t.WindowDays = days
				}
			}
		case t.Tier == "hot" && t.Scope == "endpoint" && epDays > 0:
			days := math.Max(1, math.Min(windowDays, float64(distinctDays(rates))))
			t.UnitDays = float64(epDays)
			t.MBPerUnit = round4(total / float64(epDays) / mb)
			t.MBPerDay = round4(total / days / mb)
			t.WindowDays = days
		case t.Scope == "router" && clientDays > 0:
			t.UnitDays = clientDays
			t.MBPerUnit = round4(total / clientDays / mb)
			if routerDays > 0 {
				t.MBPerDay = round4(total / routerDays / mb)
				t.WindowDays = routerDays
			}
		}
	}

	// Per-endpoint rates: rows per day × the average bytes of a flow row
	// (table, indexes and dictionaries) plus loopback counters likewise.
	flowsT, localT := types[0], types[1]
	var flowRowBytes float64
	if rowsTotal > 0 {
		flowRowBytes = float64(flowsT.Bytes+flowsT.IndexBytes+localT.Bytes+localT.IndexBytes) / float64(rowsTotal)
	}
	var perEP []float64
	for i := range rates {
		rates[i].MBPerDay = round4(rates[i].RowsPerDay * flowRowBytes / mb)
		perEP = append(perEP, rates[i].MBPerDay)
	}
	sort.Slice(rates, func(i, j int) bool { return rates[i].MBPerDay > rates[j].MBPerDay })
	r.Endpoints = rates
	if len(perEP) > 0 {
		sort.Float64s(perEP)
		r.HotBusyMBPerDay = perEP[len(perEP)-1]
		r.HotTypicalMBPerDay = round4(median(perEP))
	}

	// Hot per endpoint-day: every endpoint-scoped hot type.
	var hotPerEP, growth float64
	for _, t := range types {
		if t.Tier == "hot" && t.Scope == "endpoint" {
			hotPerEP += t.MBPerUnit
		}
		if t.Tier == "hot" {
			growth += t.MBPerDay
		}
	}
	r.HotMBPerEPDay = round4(hotPerEP)

	// Retained: cold segment bytes per endpoint-day they cover.
	segments, err := s.ColdSegments()
	if err != nil {
		return err
	}
	var coldEPDays int64
	cold := DataTypeSize{Type: "flow_rollups", Label: "Flow rollups (hourly, daily gzip cold files)", Tier: "retained", Scope: "endpoint"}
	for _, seg := range segments {
		cold.Bytes += seg.Bytes
		cold.Rows += seg.Records
		coldEPDays += seg.Endpoints
	}
	r.ColdSegments, r.ColdBytes = len(segments), cold.Bytes
	if coldEPDays > 0 {
		cold.UnitDays = float64(coldEPDays)
		cold.MBPerUnit = round4(float64(cold.Bytes) / float64(coldEPDays) / mb)
		cold.MBPerDay = round4(float64(cold.Bytes) / float64(len(segments)) / mb)
		cold.WindowDays = float64(len(segments))
	}
	r.RetainedMBPerEPDay = cold.MBPerUnit
	types = append(types, cold, other)
	for i := range types {
		types[i].Rows = s.tableRows(types[i].Tables)
	}
	r.Types = types

	var routerPerClient float64
	for _, t := range types {
		if t.Scope == "router" && t.Tier == "hot" {
			routerPerClient += t.MBPerUnit
		}
	}
	r.RouterMBPerClient = round4(routerPerClient)
	if routerDays > 0 {
		r.RouterClients = round2(clientDays / routerDays)
	}
	r.DBGrowthMBPerDay = round2(growth)

	// Projections: N endpoints × D days, hot for the raw window then retained.
	for _, n := range []int{5, 25, 100, 500} {
		for _, d := range []int{7, 30, 90} {
			hotDays := math.Min(float64(d), windowDays)
			retDays := math.Max(0, float64(d)-windowDays)
			gb := float64(n) * (hotDays*r.HotMBPerEPDay + retDays*r.RetainedMBPerEPDay) / 1024
			r.Projections = append(r.Projections, DataProjection{Endpoints: n, Days: d, GB: round2(gb)})
		}
	}

	s.timeQueries(r)
	r.OverBudget = overBudget(r)
	return nil
}

func dbFilePath(s *Store) string {
	var seq int
	var name, file string
	if err := s.db.QueryRow("PRAGMA database_list").Scan(&seq, &name, &file); err != nil {
		return ""
	}
	return file
}

func overBudget(r *DataReport) []string {
	b := r.Budgets
	out := []string{}
	check := func(name, unit string, v, limit float64) {
		if limit > 0 && v > limit {
			out = append(out, fmt.Sprintf("%s %s %s (budget %s)", name, strconv.FormatFloat(v, 'g', 3, 64), unit, strconv.FormatFloat(limit, 'g', -1, 64)))
		}
	}
	check("busiest endpoint", "MB/day hot", r.HotBusyMBPerDay, b.HotBusyMBPerDay)
	check("typical endpoint", "MB/day hot", r.HotTypicalMBPerDay, b.HotTypicalMBPerDay)
	check("retained", "MB per endpoint-day", r.RetainedMBPerEPDay, b.RetainedMBPerEPDay)
	check("router", "MB per client-day", r.RouterMBPerClient, b.RouterMBPerClientDay)
	check("hub memory", "MB", float64(r.HubRSSBytes)/mb, b.HubRSSMB)
	check("database", "MB", float64(r.DBBytes-r.FreeBytes)/mb, b.DBMaxMB)
	check("database growth", "MB/day", r.DBGrowthMBPerDay, b.DBGrowthMBPerDay)
	return out
}

func median(sorted []float64) float64 {
	n := len(sorted)
	if n == 0 {
		return 0
	}
	if n%2 == 1 {
		return sorted[n/2]
	}
	return (sorted[n/2-1] + sorted[n/2]) / 2
}

func distinctDays(rates []EndpointDataRate) int {
	max := 0
	for _, r := range rates {
		if r.Days > max {
			max = r.Days
		}
	}
	return max
}

// objectSizes fills bytes per table and per table's indexes from dbstat.
func (s *Store) objectSizes(tables, indexes map[string]int64) error {
	owner := map[string]string{}
	kind := map[string]string{}
	rows, err := s.db.Query("SELECT name, tbl_name, type FROM sqlite_master WHERE type IN ('table', 'index')")
	if err != nil {
		return err
	}
	for rows.Next() {
		var name, tbl, typ string
		if err := rows.Scan(&name, &tbl, &typ); err != nil {
			rows.Close()
			return err
		}
		owner[name], kind[name] = tbl, typ
	}
	rows.Close()
	rows, err = s.db.Query("SELECT name, SUM(pgsize) FROM dbstat GROUP BY name")
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var name string
		var size int64
		if err := rows.Scan(&name, &size); err != nil {
			return err
		}
		tbl := owner[name]
		if tbl == "" {
			tbl = name
		}
		if kind[name] == "index" {
			indexes[tbl] += size
		} else {
			tables[tbl] += size
		}
	}
	return rows.Err()
}

func (s *Store) tableRows(tables []string) int64 {
	var total int64
	for _, t := range tables {
		var n int64
		if t == "events_legacy" {
			continue // counting it is a full scan of tens of GB
		}
		if err := s.db.QueryRow(`SELECT COUNT(*) FROM "` + t + `"`).Scan(&n); err == nil {
			total += n
		}
	}
	return total
}

// endpointFlowRates counts flow rows per endpoint per complete day (minute
// rows plus loopback counter rows).
func (s *Store) endpointFlowRates(today time.Time) ([]EndpointDataRate, int64, int64, int64, error) {
	type agg struct {
		days map[string]struct{}
		rows int64
	}
	per := map[string]*agg{}
	var complete, total int64
	limit := today.Format("2006-01-02")
	add := func(ep, day string, n int64) {
		total += n
		if day >= limit {
			return
		}
		complete += n
		a := per[ep]
		if a == nil {
			a = &agg{days: map[string]struct{}{}}
			per[ep] = a
		}
		a.days[day] = struct{}{}
		a.rows += n
	}
	rows, err := s.db.Query(`SELECT e.endpoint_id, d.day, d.n FROM (
		SELECT endpoint_ref, substr(timestamp, 1, 10) AS day, COUNT(*) AS n FROM flows GROUP BY 1, 2) d
		JOIN flow_endpoints e ON e.id = d.endpoint_ref`)
	if err != nil {
		return nil, 0, 0, 0, err
	}
	for rows.Next() {
		var ep, day string
		var n int64
		if err := rows.Scan(&ep, &day, &n); err != nil {
			rows.Close()
			return nil, 0, 0, 0, err
		}
		add(ep, day, n)
	}
	rows.Close()
	rows, err = s.db.Query(`SELECT e.endpoint_id, d.day, d.n FROM (
		SELECT endpoint_ref, strftime('%Y-%m-%d', hour * 3600, 'unixepoch') AS day, COUNT(*) AS n FROM flow_local_hourly GROUP BY 1, 2) d
		JOIN flow_endpoints e ON e.id = d.endpoint_ref`)
	if err != nil {
		return nil, 0, 0, 0, err
	}
	for rows.Next() {
		var ep, day string
		var n int64
		if err := rows.Scan(&ep, &day, &n); err != nil {
			rows.Close()
			return nil, 0, 0, 0, err
		}
		add(ep, day, n)
	}
	rows.Close()
	var out []EndpointDataRate
	var epDays int64
	for ep, a := range per {
		d := len(a.days)
		epDays += int64(d)
		out = append(out, EndpointDataRate{EndpointID: ep, Days: d, RowsPerDay: round2(float64(a.rows) / float64(d))})
	}
	return out, epDays, complete, total, nil
}

// routerClientDays counts distinct DNS clients per complete day.
func (s *Store) routerClientDays(today time.Time) (float64, float64, error) {
	var clientDays, days sql.NullFloat64
	err := s.db.QueryRow(`SELECT COUNT(*), COUNT(DISTINCT day) FROM (
		SELECT DISTINCT substr(timestamp, 1, 10) AS day, client_ip FROM dns_events WHERE timestamp < ?)`, flowTime(today)).Scan(&clientDays, &days)
	if err != nil {
		return 0, 0, err
	}
	return clientDays.Float64, days.Float64, nil
}

// timeQueries measures the console's main reads and the feed's queries.
func (s *Store) timeQueries(r *DataReport) {
	measure := func(name string, f func() error) {
		started := time.Now()
		if err := f(); err != nil {
			r.QueryMS[name] = -1
			return
		}
		r.QueryMS[name] = round2(float64(time.Since(started).Microseconds()) / 1000)
	}
	measure("recent_flows_200", func() error { _, err := s.QueryEvents("", "", 200); return err })
	measure("topology_1h", func() error { _, err := s.GetTopologyGraph(time.Hour); return err })
	measure("analytics_summary", func() error { _, err := s.analyticsSummaryUncached(""); return err })
	measure("nightshift_feed_anomalies", func() error {
		_, err := s.SummariseOpenAnomalies(time.Now().Add(-24 * time.Hour))
		return err
	})
	measure("nightshift_feed_outcomes", func() error {
		_, _, err := s.ListAnomalyOutcomeDays(time.Now().Add(-14*24*time.Hour), 200)
		return err
	})
}

func processRSSBytes() int64 {
	f, err := os.Open("/proc/self/status")
	if err != nil {
		return 0
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "VmRSS:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				kb, _ := strconv.ParseInt(fields[1], 10, 64)
				return kb * 1024
			}
		}
	}
	return 0
}

// processCPUSeconds is user+system CPU time of this process.
func processCPUSeconds() float64 {
	raw, err := os.ReadFile("/proc/self/stat")
	if err != nil {
		return 0
	}
	s := string(raw)
	if i := strings.LastIndexByte(s, ')'); i >= 0 {
		s = s[i+2:]
	}
	f := strings.Fields(s)
	if len(f) < 13 {
		return 0
	}
	utime, _ := strconv.ParseFloat(f[11], 64)
	stime, _ := strconv.ParseFloat(f[12], 64)
	return (utime + stime) / 100 // USER_HZ
}
