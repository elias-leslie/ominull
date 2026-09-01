package storage

import (
	"database/sql"
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"
)

type TrafficFilter struct {
	TenantID     string
	Range        string
	From         time.Time
	To           time.Time
	EndpointID   string
	SrcIP        string
	DstIP        string
	Process      string
	Domain       string
	Country      string
	Protocol     int
	Port         int
	Direction    string
	Action       string
	MeasuredOnly bool
	Cursor       string
	Limit        int
}

type TrafficOverview struct {
	AsOf                 time.Time              `json:"as_of"`
	WindowStart          time.Time              `json:"window_start"`
	WindowEnd            time.Time              `json:"window_end"`
	BucketSize           string                 `json:"bucket_size"`
	TotalFlows           int64                  `json:"total_flows"`
	MeasuredFlows        int64                  `json:"measured_flows"`
	MeasuredFlowCoverage float64                `json:"measured_flow_coverage"`
	Totals               TrafficTotals          `json:"totals"`
	Trends               []TrafficTrendBucket   `json:"trends"`
	Distributions        TrafficDistributions   `json:"distributions"`
	Rankings             TrafficRankings        `json:"rankings"`
	Heatmap              []TrafficHeatmapCell   `json:"heatmap,omitempty"`
	ActiveFilters        map[string]interface{} `json:"active_filters"`
}

type TrafficTotals struct {
	BytesIn      int64 `json:"bytes_in"`
	BytesOut     int64 `json:"bytes_out"`
	TotalBytes   int64 `json:"total_bytes"`
	FlowCount    int64 `json:"flow_count"`
	BlockCount   int64 `json:"block_count"`
	AnomalyCount int64 `json:"anomaly_count"`
}

type TrafficTrendBucket struct {
	Timestamp time.Time `json:"timestamp"`
	BytesIn   int64     `json:"bytes_in"`
	BytesOut  int64     `json:"bytes_out"`
	Flows     int64     `json:"flows"`
	Blocks    int64     `json:"blocks"`
	Anomalies int64     `json:"anomalies"`
}

type TrafficDistributions struct {
	Protocols  []DistributionSlice `json:"protocols"`
	Actions    []DistributionSlice `json:"actions"`
	Directions []DistributionSlice `json:"directions"`
}

type DistributionSlice struct {
	Label      string  `json:"label"`
	Count      int64   `json:"count"`
	TotalBytes int64   `json:"total_bytes"`
	Percentage float64 `json:"percentage"`
}

type TrafficRankings struct {
	TopEndpoints    []RankingItem `json:"top_endpoints"`
	TopProcesses    []RankingItem `json:"top_processes"`
	TopDestinations []RankingItem `json:"top_destinations"`
	TopDomains      []RankingItem `json:"top_domains"`
	TopCountries    []RankingItem `json:"top_countries"`
	TopPorts        []RankingItem `json:"top_ports"`
}

type RankingItem struct {
	Key        string  `json:"key"`
	Label      string  `json:"label"`
	FlowCount  int64   `json:"flow_count"`
	BytesIn    int64   `json:"bytes_in"`
	BytesOut   int64   `json:"bytes_out"`
	TotalBytes int64   `json:"total_bytes"`
	Country    string  `json:"country,omitempty"`
	Service    string  `json:"service,omitempty"`
	Sparkline  []int64 `json:"sparkline,omitempty"`
}

type TrafficHeatmapCell struct {
	DayOfWeek  int   `json:"day_of_week"` // 0 = Sunday, 6 = Saturday
	HourOfDay  int   `json:"hour_of_day"` // 0..23
	Flows      int64 `json:"flows"`
	TotalBytes int64 `json:"total_bytes"`
}

type TrafficFlowItem struct {
	ID          string    `json:"id"`
	TenantID    string    `json:"tenant_id"`
	Timestamp   time.Time `json:"timestamp"`
	EndpointID  string    `json:"endpoint_id"`
	Hostname    string    `json:"hostname"`
	Layer       string    `json:"layer"`
	Action      string    `json:"action"`
	Direction   string    `json:"direction"`
	Protocol    int       `json:"protocol"`
	ProtoName   string    `json:"proto_name"`
	SrcIP       string    `json:"src_ip"`
	DstIP       string    `json:"dst_ip"`
	SrcPort     int       `json:"src_port"`
	DstPort     int       `json:"dst_port"`
	ProcessPath string    `json:"process_path"`
	ProcessName string    `json:"process_name"`
	Domain      string    `json:"domain"`
	Country     string    `json:"country"`
	BytesIn     int64     `json:"bytes_in"`
	BytesOut    int64     `json:"bytes_out"`
	IsAnomalous bool      `json:"is_anomalous"`
	AnomalyType string    `json:"anomaly_type,omitempty"`
}

type TrafficFlowsResult struct {
	Flows         []TrafficFlowItem      `json:"flows"`
	NextCursor    string                 `json:"next_cursor"`
	Total         int64                  `json:"total"`
	ActiveFilters map[string]interface{} `json:"active_filters"`
}

// ResolveTrafficWindow calculates start and end times and bucket sizes based on filter.
func ResolveTrafficWindow(filter TrafficFilter) (time.Time, time.Time, string, time.Duration) {
	now := time.Now().UTC()
	start := now.Add(-1 * time.Hour)
	end := now
	bucketStr := "1m"
	bucketDur := 1 * time.Minute

	if !filter.From.IsZero() && !filter.To.IsZero() && filter.To.After(filter.From) {
		start = filter.From
		end = filter.To
	} else {
		switch strings.ToLower(filter.Range) {
		case "15m":
			start = now.Add(-15 * time.Minute)
			bucketStr = "30s"
			bucketDur = 30 * time.Second
		case "1h", "":
			start = now.Add(-1 * time.Hour)
			bucketStr = "1m"
			bucketDur = 1 * time.Minute
		case "6h":
			start = now.Add(-6 * time.Hour)
			bucketStr = "5m"
			bucketDur = 5 * time.Minute
		case "24h":
			start = now.Add(-24 * time.Hour)
			bucketStr = "15m"
			bucketDur = 15 * time.Minute
		case "7d":
			start = now.Add(-7 * 24 * time.Hour)
			bucketStr = "2h"
			bucketDur = 2 * time.Hour
		case "all", "history":
			start = now.Add(-30 * 24 * time.Hour)
			bucketStr = "1d"
			bucketDur = 24 * time.Hour
		default:
			start = now.Add(-1 * time.Hour)
		}
	}

	diff := end.Sub(start)
	if diff <= 30*time.Minute {
		bucketStr = "30s"
		bucketDur = 30 * time.Second
	} else if diff <= 3*time.Hour {
		bucketStr = "1m"
		bucketDur = 1 * time.Minute
	} else if diff <= 12*time.Hour {
		bucketStr = "5m"
		bucketDur = 5 * time.Minute
	} else if diff <= 48*time.Hour {
		bucketStr = "15m"
		bucketDur = 15 * time.Minute
	} else if diff <= 14*24*time.Hour {
		bucketStr = "2h"
		bucketDur = 2 * time.Hour
	} else {
		bucketStr = "1d"
		bucketDur = 24 * time.Hour
	}

	return start, end, bucketStr, bucketDur
}

func buildTrafficWhere(filter TrafficFilter, start, end time.Time) (string, []interface{}, map[string]interface{}) {
	var where []string
	var args []interface{}
	active := make(map[string]interface{})

	where = append(where, "timestamp >= ? AND timestamp <= ?")
	args = append(args, start, end)
	active["window_start"] = start
	active["window_end"] = end

	if filter.TenantID != "" {
		where = append(where, "tenant_id = ?")
		args = append(args, filter.TenantID)
		active["tenant_id"] = filter.TenantID
	}
	if filter.EndpointID != "" {
		where = append(where, "endpoint_id = ?")
		args = append(args, filter.EndpointID)
		active["endpoint_id"] = filter.EndpointID
	}
	if filter.SrcIP != "" {
		where = append(where, "src_ip = ?")
		args = append(args, filter.SrcIP)
		active["src_ip"] = filter.SrcIP
	}
	if filter.DstIP != "" {
		where = append(where, "dst_ip = ?")
		args = append(args, filter.DstIP)
		active["dst_ip"] = filter.DstIP
	}
	if filter.Process != "" {
		where = append(where, "(process_path LIKE ? OR process_path = ?)")
		args = append(args, "%/"+filter.Process, filter.Process)
		active["process"] = filter.Process
	}
	if filter.Domain != "" {
		where = append(where, "domain LIKE ?")
		args = append(args, "%"+strings.ToLower(filter.Domain)+"%")
		active["domain"] = filter.Domain
	}
	if filter.Country != "" {
		where = append(where, "country = ?")
		args = append(args, strings.ToUpper(filter.Country))
		active["country"] = filter.Country
	}
	if filter.Protocol != 0 {
		where = append(where, "protocol = ?")
		args = append(args, filter.Protocol)
		active["protocol"] = filter.Protocol
	}
	if filter.Port != 0 {
		where = append(where, "(dst_port = ? OR src_port = ?)")
		args = append(args, filter.Port, filter.Port)
		active["port"] = filter.Port
	}
	if filter.Direction != "" {
		where = append(where, "direction = ?")
		args = append(args, strings.ToUpper(filter.Direction))
		active["direction"] = filter.Direction
	}
	if filter.Action != "" {
		where = append(where, "action = ?")
		args = append(args, strings.ToUpper(filter.Action))
		active["action"] = filter.Action
	}
	if filter.MeasuredOnly {
		where = append(where, "(bytes_in + bytes_out > 0)")
		active["measured_only"] = true
	}

	whereClause := " WHERE " + strings.Join(where, " AND ")
	return whereClause, args, active
}

const trafficCacheTTL = 15 * time.Second

type trafficCache struct {
	mu      sync.Mutex
	entries map[string]trafficCacheEntry
}

type trafficCacheEntry struct {
	overview *TrafficOverview
	computed time.Time
}

func (c *trafficCache) get(key string, now time.Time) *TrafficOverview {
	c.mu.Lock()
	defer c.mu.Unlock()
	entry, ok := c.entries[key]
	if !ok || now.Sub(entry.computed) > trafficCacheTTL {
		return nil
	}
	return entry.overview
}

func (c *trafficCache) put(key string, overview *TrafficOverview, now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.entries == nil {
		c.entries = make(map[string]trafficCacheEntry)
	}
	c.entries[key] = trafficCacheEntry{overview: overview, computed: now}
}

func (f TrafficFilter) CacheKey() string {
	return fmt.Sprintf("%s|%s|%s|%s|%s|%s|%s|%s|%d|%d|%s|%s|%t|%s|%s",
		f.TenantID, f.Range, f.EndpointID, f.SrcIP, f.DstIP, f.Process, f.Domain,
		f.Country, f.Protocol, f.Port, f.Direction, f.Action, f.MeasuredOnly,
		f.From.Format(time.RFC3339), f.To.Format(time.RFC3339))
}

func (s *Store) QueryTrafficOverview(filter TrafficFilter) (*TrafficOverview, error) {
	now := time.Now().UTC()
	cacheKey := filter.CacheKey()
	if cached := s.traffic.get(cacheKey, now); cached != nil {
		return cached, nil
	}

	start, end, bucketSize, bucketDur := ResolveTrafficWindow(filter)
	whereClause, args, activeFilters := buildTrafficWhere(filter, start, end)

	s.mu.RLock()
	defer s.mu.RUnlock()

	overview := &TrafficOverview{
		AsOf:          now,
		WindowStart:   start,
		WindowEnd:     end,
		BucketSize:    bucketSize,
		ActiveFilters: activeFilters,
	}

	isUnfiltered := filter.EndpointID == "" && filter.SrcIP == "" && filter.DstIP == "" &&
		filter.Process == "" && filter.Domain == "" && filter.Country == "" &&
		filter.Protocol == 0 && filter.Port == 0 && filter.Direction == "" &&
		filter.Action == "" && !filter.MeasuredOnly

	// 1. Totals & Coverage Query
	if isUnfiltered && end.Sub(start) >= 6*time.Hour {
		// FAST PATH: Read from bandwidth_buckets cube
		startBucket := start.Format("2006-01-02T15:00:00Z")
		endBucket := end.Format("2006-01-02T15:00:00Z")
		totQuery := `
			SELECT
				COALESCE(SUM(flow_count), 0),
				COALESCE(SUM(measured_count), 0),
				COALESCE(SUM(bytes_in), 0),
				COALESCE(SUM(bytes_out), 0),
				COALESCE(SUM(block_count), 0)
			FROM bandwidth_buckets
			WHERE hour_bucket >= ? AND hour_bucket <= ?
		`
		totArgs := []interface{}{startBucket, endBucket}
		if filter.TenantID != "" {
			totQuery += " AND tenant_id = ?"
			totArgs = append(totArgs, filter.TenantID)
		}
		var totalFlows, measuredFlows, bytesIn, bytesOut, blockCount int64
		_ = s.db.QueryRow(totQuery, totArgs...).Scan(&totalFlows, &measuredFlows, &bytesIn, &bytesOut, &blockCount)
		overview.TotalFlows = totalFlows
		overview.MeasuredFlows = measuredFlows
		if totalFlows > 0 {
			overview.MeasuredFlowCoverage = float64(measuredFlows) / float64(totalFlows)
		}
		overview.Totals = TrafficTotals{
			BytesIn:    bytesIn,
			BytesOut:   bytesOut,
			TotalBytes: bytesIn + bytesOut,
			FlowCount:  totalFlows,
			BlockCount: blockCount,
		}
	} else {
		totalsQuery := fmt.Sprintf(`
			SELECT
				COUNT(*),
				COALESCE(SUM(CASE WHEN bytes_in + bytes_out > 0 THEN 1 ELSE 0 END), 0),
				COALESCE(SUM(bytes_in), 0),
				COALESCE(SUM(bytes_out), 0),
				COALESCE(SUM(CASE WHEN action = 'BLOCK' THEN 1 ELSE 0 END), 0)
			FROM events
			%s
		`, whereClause)

		var (
			totalFlows    int64
			measuredFlows int64
			bytesIn       int64
			bytesOut      int64
			blockCount    int64
		)
		if err := s.db.QueryRow(totalsQuery, args...).Scan(&totalFlows, &measuredFlows, &bytesIn, &bytesOut, &blockCount); err != nil {
			return nil, fmt.Errorf("query totals: %w", err)
		}

		overview.TotalFlows = totalFlows
		overview.MeasuredFlows = measuredFlows
		if totalFlows > 0 {
			overview.MeasuredFlowCoverage = float64(measuredFlows) / float64(totalFlows)
		}
		overview.Totals = TrafficTotals{
			BytesIn:    bytesIn,
			BytesOut:   bytesOut,
			TotalBytes: bytesIn + bytesOut,
			FlowCount:  totalFlows,
			BlockCount: blockCount,
		}
	}

	// Count Anomalies in same window
	var anomalyCount int64
	anomQuery := "SELECT COUNT(*) FROM anomaly_alerts WHERE timestamp >= ? AND timestamp <= ?"
	anomArgs := []interface{}{start, end}
	if filter.TenantID != "" {
		anomQuery += " AND tenant_id = ?"
		anomArgs = append(anomArgs, filter.TenantID)
	}
	_ = s.db.QueryRow(anomQuery, anomArgs...).Scan(&anomalyCount)
	overview.Totals.AnomalyCount = anomalyCount

	// 2. Trendline Buckets
	overview.Trends = s.buildTrendBuckets(whereClause, args, start, end, bucketDur, isUnfiltered, filter.TenantID)

	// 3. Distributions (Protocols, Actions, Directions)
	overview.Distributions = s.queryDistributions(whereClause, args, overview.TotalFlows, overview.Totals.TotalBytes, isUnfiltered, start, end, filter.TenantID)

	// 4. Rankings (Top Endpoints, Processes, Destinations, Domains, Countries, Ports)
	overview.Rankings = s.queryRankings(whereClause, args, start, end, filter, isUnfiltered)

	// 5. Heatmap (for ranges >= 24 hours)
	if end.Sub(start) >= 24*time.Hour {
		overview.Heatmap = s.queryHeatmap(whereClause, args, isUnfiltered, start, end, filter.TenantID)
	}

	s.traffic.put(cacheKey, overview, now)
	return overview, nil
}

func (s *Store) buildTrendBuckets(whereClause string, args []interface{}, start, end time.Time, bucketDur time.Duration, isUnfiltered bool, tenantID string) []TrafficTrendBucket {
	// Initialize empty slots across the window
	var buckets []TrafficTrendBucket
	bucketMap := make(map[int64]*TrafficTrendBucket)

	stepSec := int64(bucketDur.Seconds())
	if stepSec <= 0 {
		stepSec = 60
	}
	startUnix := start.Unix()
	endUnix := end.Unix()

	for t := startUnix; t <= endUnix; t += stepSec {
		bTime := time.Unix(t, 0).UTC()
		b := TrafficTrendBucket{Timestamp: bTime}
		buckets = append(buckets, b)
		bucketMap[t/stepSec] = &buckets[len(buckets)-1]
	}

	// FAST PATH: If unfiltered and window >= 6h, read from bandwidth_buckets
	if isUnfiltered && end.Sub(start) >= 6*time.Hour {
		startBucket := start.Format("2006-01-02T15:00:00Z")
		endBucket := end.Format("2006-01-02T15:00:00Z")
		cubeQuery := `
			SELECT hour_bucket, COALESCE(SUM(bytes_in), 0), COALESCE(SUM(bytes_out), 0), COALESCE(SUM(flow_count), 0), COALESCE(SUM(block_count), 0)
			FROM bandwidth_buckets
			WHERE hour_bucket >= ? AND hour_bucket <= ?
		`
		cubeArgs := []interface{}{startBucket, endBucket}
		if tenantID != "" {
			cubeQuery += " AND tenant_id = ?"
			cubeArgs = append(cubeArgs, tenantID)
		}
		cubeQuery += " GROUP BY hour_bucket ORDER BY hour_bucket ASC"

		rows, err := s.db.Query(cubeQuery, cubeArgs...)
		if err == nil {
			defer rows.Close()
			for rows.Next() {
				var (
					hStr                     string
					bin, bout, flows, blocks int64
				)
				if err := rows.Scan(&hStr, &bin, &bout, &flows, &blocks); err == nil {
					if t, err := time.Parse(time.RFC3339, hStr); err == nil {
						key := t.Unix() / stepSec
						if slot, ok := bucketMap[key]; ok {
							slot.BytesIn += bin
							slot.BytesOut += bout
							slot.Flows += flows
							slot.Blocks += blocks
						}
					}
				}
			}
			return buckets
		}
	}

	trendQuery := fmt.Sprintf(`
		SELECT
			CAST(strftime('%%s', substr(timestamp, 1, 19) || 'Z') AS INTEGER) / %d * %d as bucket_sec,
			COALESCE(SUM(bytes_in), 0),
			COALESCE(SUM(bytes_out), 0),
			COUNT(*),
			COALESCE(SUM(CASE WHEN action = 'BLOCK' THEN 1 ELSE 0 END), 0)
		FROM events
		%s
		GROUP BY bucket_sec
		ORDER BY bucket_sec ASC
	`, stepSec, stepSec, whereClause)

	rows, err := s.db.Query(trendQuery, args...)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var (
				bucketSec int64
				bin       int64
				bout      int64
				flows     int64
				blocks    int64
			)
			if err := rows.Scan(&bucketSec, &bin, &bout, &flows, &blocks); err == nil {
				key := bucketSec / stepSec
				if slot, ok := bucketMap[key]; ok {
					slot.BytesIn = bin
					slot.BytesOut = bout
					slot.Flows = flows
					slot.Blocks = blocks
				}
			}
		}
	}

	return buckets
}

func (s *Store) queryDistributions(whereClause string, args []interface{}, totalFlows, totalBytes int64, isUnfiltered bool, start, end time.Time, tenantID string) TrafficDistributions {
	dist := TrafficDistributions{
		Protocols:  []DistributionSlice{},
		Actions:    []DistributionSlice{},
		Directions: []DistributionSlice{},
	}

	if isUnfiltered && end.Sub(start) >= 6*time.Hour {
		startBucket := start.Format("2006-01-02T15:00:00Z")
		endBucket := end.Format("2006-01-02T15:00:00Z")

		// Directions from bandwidth_buckets
		dirQuery := `SELECT direction, COALESCE(SUM(flow_count), 0), COALESCE(SUM(bytes_in + bytes_out), 0)
			FROM bandwidth_buckets WHERE hour_bucket >= ? AND hour_bucket <= ?`
		dirArgs := []interface{}{startBucket, endBucket}
		if tenantID != "" {
			dirQuery += " AND tenant_id = ?"
			dirArgs = append(dirArgs, tenantID)
		}
		dirQuery += " GROUP BY direction ORDER BY SUM(flow_count) DESC"
		if rows, err := s.db.Query(dirQuery, dirArgs...); err == nil {
			defer rows.Close()
			for rows.Next() {
				var label string
				var count, bytesVal int64
				if err := rows.Scan(&label, &count, &bytesVal); err == nil {
					pct := 0.0
					if totalFlows > 0 {
						pct = float64(count) / float64(totalFlows)
					}
					dist.Directions = append(dist.Directions, DistributionSlice{
						Label:      label,
						Count:      count,
						TotalBytes: bytesVal,
						Percentage: pct,
					})
				}
			}
		}

		// Actions from bandwidth_buckets
		actQuery := `SELECT 'PERMIT', COALESCE(SUM(flow_count - block_count), 0), COALESCE(SUM(bytes_in + bytes_out), 0)
			FROM bandwidth_buckets WHERE hour_bucket >= ? AND hour_bucket <= ?`
		actArgs := []interface{}{startBucket, endBucket}
		if tenantID != "" {
			actQuery += " AND tenant_id = ?"
			actArgs = append(actArgs, tenantID)
		}
		if rows, err := s.db.Query(actQuery, actArgs...); err == nil {
			defer rows.Close()
			for rows.Next() {
				var label string
				var count, bytesVal int64
				if err := rows.Scan(&label, &count, &bytesVal); err == nil && count > 0 {
					pct := 0.0
					if totalFlows > 0 {
						pct = float64(count) / float64(totalFlows)
					}
					dist.Actions = append(dist.Actions, DistributionSlice{
						Label:      label,
						Count:      count,
						TotalBytes: bytesVal,
						Percentage: pct,
					})
				}
			}
		}

		// Protocols from comm_profiles
		protoQuery := `SELECT UPPER(protocol), SUM(event_count), SUM(total_bytes_in + total_bytes_out)
			FROM comm_profiles WHERE last_seen >= ?`
		protoArgs := []interface{}{start}
		if tenantID != "" {
			protoQuery += " AND tenant_id = ?"
			protoArgs = append(protoArgs, tenantID)
		}
		protoQuery += " GROUP BY protocol ORDER BY SUM(event_count) DESC LIMIT 6"
		if rows, err := s.db.Query(protoQuery, protoArgs...); err == nil {
			defer rows.Close()
			for rows.Next() {
				var label string
				var count, bytesVal int64
				if err := rows.Scan(&label, &count, &bytesVal); err == nil {
					pct := 0.0
					if totalFlows > 0 {
						pct = float64(count) / float64(totalFlows)
					}
					dist.Protocols = append(dist.Protocols, DistributionSlice{
						Label:      label,
						Count:      count,
						TotalBytes: bytesVal,
						Percentage: pct,
					})
				}
			}
		}
		return dist
	}

	// Standard path
	protoQuery := fmt.Sprintf(`
		SELECT
			CASE WHEN protocol = 6 THEN 'TCP' WHEN protocol = 17 THEN 'UDP' WHEN protocol = 1 THEN 'ICMP' ELSE 'OTHER (' || protocol || ')' END as proto_name,
			COUNT(*),
			COALESCE(SUM(bytes_in + bytes_out), 0)
		FROM events
		%s
		GROUP BY proto_name
		ORDER BY COUNT(*) DESC
		LIMIT 6
	`, whereClause)

	rows, err := s.db.Query(protoQuery, args...)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var label string
			var count, bytesVal int64
			if err := rows.Scan(&label, &count, &bytesVal); err == nil {
				pct := 0.0
				if totalFlows > 0 {
					pct = float64(count) / float64(totalFlows)
				}
				dist.Protocols = append(dist.Protocols, DistributionSlice{
					Label:      label,
					Count:      count,
					TotalBytes: bytesVal,
					Percentage: pct,
				})
			}
		}
	}

	// B. Actions
	actionQuery := fmt.Sprintf(`
		SELECT
			CASE WHEN action = '' THEN 'PERMIT' ELSE action END as act_name,
			COUNT(*),
			COALESCE(SUM(bytes_in + bytes_out), 0)
		FROM events
		%s
		GROUP BY act_name
		ORDER BY COUNT(*) DESC
	`, whereClause)

	rowsAct, err := s.db.Query(actionQuery, args...)
	if err == nil {
		defer rowsAct.Close()
		for rowsAct.Next() {
			var label string
			var count, bytesVal int64
			if err := rowsAct.Scan(&label, &count, &bytesVal); err == nil {
				pct := 0.0
				if totalFlows > 0 {
					pct = float64(count) / float64(totalFlows)
				}
				dist.Actions = append(dist.Actions, DistributionSlice{
					Label:      label,
					Count:      count,
					TotalBytes: bytesVal,
					Percentage: pct,
				})
			}
		}
	}

	// C. Directions
	dirQuery := fmt.Sprintf(`
		SELECT
			CASE WHEN direction = '' THEN 'OUTBOUND' ELSE direction END as dir_name,
			COUNT(*),
			COALESCE(SUM(bytes_in + bytes_out), 0)
		FROM events
		%s
		GROUP BY dir_name
		ORDER BY COUNT(*) DESC
	`, whereClause)

	rowsDir, err := s.db.Query(dirQuery, args...)
	if err == nil {
		defer rowsDir.Close()
		for rowsDir.Next() {
			var label string
			var count, bytesVal int64
			if err := rowsDir.Scan(&label, &count, &bytesVal); err == nil {
				pct := 0.0
				if totalFlows > 0 {
					pct = float64(count) / float64(totalFlows)
				}
				dist.Directions = append(dist.Directions, DistributionSlice{
					Label:      label,
					Count:      count,
					TotalBytes: bytesVal,
					Percentage: pct,
				})
			}
		}
	}

	return dist
}

func (s *Store) queryRankings(whereClause string, args []interface{}, start, end time.Time, filter TrafficFilter, isUnfiltered bool) TrafficRankings {
	rankings := TrafficRankings{
		TopEndpoints:    []RankingItem{},
		TopProcesses:    []RankingItem{},
		TopDestinations: []RankingItem{},
		TopDomains:      []RankingItem{},
		TopCountries:    []RankingItem{},
		TopPorts:        []RankingItem{},
	}

	if isUnfiltered && end.Sub(start) >= 6*time.Hour {
		startBucket := start.Format("2006-01-02T15:00:00Z")
		endBucket := end.Format("2006-01-02T15:00:00Z")

		// 1. Top Endpoints from comm_profiles
		epQ := "SELECT endpoint_id, endpoint_id, SUM(event_count), SUM(total_bytes_in), SUM(total_bytes_out), SUM(total_bytes_in + total_bytes_out) FROM comm_profiles WHERE last_seen >= ?"
		epArgs := []interface{}{start}
		if filter.TenantID != "" {
			epQ += " AND tenant_id = ?"
			epArgs = append(epArgs, filter.TenantID)
		}
		epQ += " GROUP BY endpoint_id ORDER BY SUM(total_bytes_in + total_bytes_out) DESC LIMIT 8"
		rankings.TopEndpoints = s.scanRankings(epQ, epArgs)

		// 2. Top Processes from comm_profiles
		procQ := "SELECT process_name, process_name, SUM(event_count), SUM(total_bytes_in), SUM(total_bytes_out), SUM(total_bytes_in + total_bytes_out) FROM comm_profiles WHERE last_seen >= ?"
		procArgs := []interface{}{start}
		if filter.TenantID != "" {
			procQ += " AND tenant_id = ?"
			procArgs = append(procArgs, filter.TenantID)
		}
		procQ += " GROUP BY process_name ORDER BY SUM(total_bytes_in + total_bytes_out) DESC LIMIT 8"
		rankings.TopProcesses = s.scanRankings(procQ, procArgs)

		// 3. Top Destinations from comm_profiles
		dstQ := "SELECT dst_ip, dst_ip, SUM(event_count), SUM(total_bytes_in), SUM(total_bytes_out), SUM(total_bytes_in + total_bytes_out) FROM comm_profiles WHERE last_seen >= ?"
		dstArgs := []interface{}{start}
		if filter.TenantID != "" {
			dstQ += " AND tenant_id = ?"
			dstArgs = append(dstArgs, filter.TenantID)
		}
		dstQ += " GROUP BY dst_ip ORDER BY SUM(total_bytes_in + total_bytes_out) DESC LIMIT 8"
		rankings.TopDestinations = s.scanRankings(dstQ, dstArgs)

		// 4. Top Domains from dns_events
		domQ := "SELECT domain, domain, COUNT(*), 0, 0, 0 FROM dns_events WHERE timestamp >= ? AND timestamp <= ? AND domain != ''"
		domArgs := []interface{}{start, end}
		if filter.TenantID != "" {
			domQ += " AND tenant_id = ?"
			domArgs = append(domArgs, filter.TenantID)
		}
		domQ += " GROUP BY domain ORDER BY COUNT(*) DESC LIMIT 8"
		rankings.TopDomains = s.scanRankings(domQ, domArgs)

		// 5. Top Countries from bandwidth_buckets
		ctryQ := "SELECT country, country, SUM(flow_count), SUM(bytes_in), SUM(bytes_out), SUM(bytes_in + bytes_out) FROM bandwidth_buckets WHERE hour_bucket >= ? AND hour_bucket <= ? AND country != ''"
		ctryArgs := []interface{}{startBucket, endBucket}
		if filter.TenantID != "" {
			ctryQ += " AND tenant_id = ?"
			ctryArgs = append(ctryArgs, filter.TenantID)
		}
		ctryQ += " GROUP BY country ORDER BY SUM(flow_count) DESC LIMIT 8"
		rankings.TopCountries = s.scanRankings(ctryQ, ctryArgs)

		// 6. Top Ports from comm_profiles
		portQ := "SELECT CAST(dst_port AS TEXT), CAST(dst_port AS TEXT), SUM(event_count), SUM(total_bytes_in), SUM(total_bytes_out), SUM(total_bytes_in + total_bytes_out) FROM comm_profiles WHERE last_seen >= ? AND dst_port > 0"
		portArgs := []interface{}{start}
		if filter.TenantID != "" {
			portQ += " AND tenant_id = ?"
			portArgs = append(portArgs, filter.TenantID)
		}
		portQ += " GROUP BY dst_port ORDER BY SUM(event_count) DESC LIMIT 8"
		rankings.TopPorts = s.scanRankings(portQ, portArgs)

		return rankings
	}

	// Standard path
	// 1. Top Endpoints
	epQuery := fmt.Sprintf(`
		SELECT
			endpoint_id,
			endpoint_id as label,
			COUNT(*),
			COALESCE(SUM(bytes_in), 0),
			COALESCE(SUM(bytes_out), 0),
			COALESCE(SUM(bytes_in + bytes_out), 0)
		FROM events
		%s
		GROUP BY endpoint_id
		ORDER BY COALESCE(SUM(bytes_in + bytes_out), 0) DESC, COUNT(*) DESC
		LIMIT 8
	`, whereClause)
	rankings.TopEndpoints = s.scanRankings(epQuery, args)

	// 2. Top Processes
	procQuery := fmt.Sprintf(`
		SELECT
			process_path,
			CASE
				WHEN process_path = '' OR process_path = '.' OR process_path = '/' THEN 'kernel/system'
				ELSE replace(replace(process_path, '\', '/'), rtrim(replace(process_path, '\', '/'), replace(replace(process_path, '\', '/'), '/', '')), '')
			END as proc_name,
			COUNT(*),
			COALESCE(SUM(bytes_in), 0),
			COALESCE(SUM(bytes_out), 0),
			COALESCE(SUM(bytes_in + bytes_out), 0)
		FROM events
		%s
		GROUP BY proc_name
		ORDER BY COALESCE(SUM(bytes_in + bytes_out), 0) DESC, COUNT(*) DESC
		LIMIT 8
	`, whereClause)
	rankings.TopProcesses = s.scanRankings(procQuery, args)

	// 3. Top Destinations
	dstQuery := fmt.Sprintf(`
		SELECT
			dst_ip,
			dst_ip,
			COUNT(*),
			COALESCE(SUM(bytes_in), 0),
			COALESCE(SUM(bytes_out), 0),
			COALESCE(SUM(bytes_in + bytes_out), 0)
		FROM events
		%s
		GROUP BY dst_ip
		ORDER BY COALESCE(SUM(bytes_in + bytes_out), 0) DESC, COUNT(*) DESC
		LIMIT 8
	`, whereClause)
	rankings.TopDestinations = s.scanRankings(dstQuery, args)

	// 4. Top Domains: Query from dns_events for rich domain name intelligence
	domQuery := `
		SELECT
			domain,
			domain,
			COUNT(*),
			0,
			0,
			0
		FROM dns_events
		WHERE timestamp >= ? AND timestamp <= ? AND domain != ''
	`
	domArgs := []interface{}{start, end}
	if filter.TenantID != "" {
		domQuery += " AND tenant_id = ?"
		domArgs = append(domArgs, filter.TenantID)
	}
	domQuery += " GROUP BY domain ORDER BY COUNT(*) DESC LIMIT 8"
	rankings.TopDomains = s.scanRankings(domQuery, domArgs)
	if len(rankings.TopDomains) == 0 {
		fallbackDomQuery := fmt.Sprintf(`
			SELECT domain, domain, COUNT(*), COALESCE(SUM(bytes_in), 0), COALESCE(SUM(bytes_out), 0), COALESCE(SUM(bytes_in + bytes_out), 0)
			FROM events %s AND domain != '' GROUP BY domain ORDER BY COUNT(*) DESC LIMIT 8
		`, whereClause)
		rankings.TopDomains = s.scanRankings(fallbackDomQuery, args)
	}

	// 5. Top Countries
	ctryQuery := fmt.Sprintf(`
		SELECT
			country,
			country,
			COUNT(*),
			COALESCE(SUM(bytes_in), 0),
			COALESCE(SUM(bytes_out), 0),
			COALESCE(SUM(bytes_in + bytes_out), 0)
		FROM events
		%s AND country != ''
		GROUP BY country
		ORDER BY COUNT(*) DESC, COALESCE(SUM(bytes_in + bytes_out), 0) DESC
		LIMIT 8
	`, whereClause)
	rankings.TopCountries = s.scanRankings(ctryQuery, args)

	// 6. Top Ports
	portQuery := fmt.Sprintf(`
		SELECT
			CAST(dst_port AS TEXT),
			CAST(dst_port AS TEXT),
			COUNT(*),
			COALESCE(SUM(bytes_in), 0),
			COALESCE(SUM(bytes_out), 0),
			COALESCE(SUM(bytes_in + bytes_out), 0)
		FROM events
		%s AND dst_port > 0
		GROUP BY dst_port
		ORDER BY COUNT(*) DESC, COALESCE(SUM(bytes_in + bytes_out), 0) DESC
		LIMIT 8
	`, whereClause)
	rankings.TopPorts = s.scanRankings(portQuery, args)

	return rankings
}

func (s *Store) scanRankings(query string, args []interface{}) []RankingItem {
	var items []RankingItem
	rows, err := s.db.Query(query, args...)
	if err != nil {
		return items
	}
	defer rows.Close()

	for rows.Next() {
		var key, label string
		var count, bin, bout, total int64
		if err := rows.Scan(&key, &label, &count, &bin, &bout, &total); err == nil {
			if label == "" {
				label = "—"
			}
			items = append(items, RankingItem{
				Key:        key,
				Label:      label,
				FlowCount:  count,
				BytesIn:    bin,
				BytesOut:   bout,
				TotalBytes: total,
			})
		}
	}
	return items
}

func (s *Store) queryHeatmap(whereClause string, args []interface{}, isUnfiltered bool, start, end time.Time, tenantID string) []TrafficHeatmapCell {
	var cells []TrafficHeatmapCell

	if isUnfiltered && end.Sub(start) >= 6*time.Hour {
		startBucket := start.Format("2006-01-02T15:00:00Z")
		endBucket := end.Format("2006-01-02T15:00:00Z")
		query := `
			SELECT
				CAST(strftime('%w', hour_bucket) AS INTEGER) as dow,
				CAST(strftime('%H', hour_bucket) AS INTEGER) as hod,
				COALESCE(SUM(flow_count), 0),
				COALESCE(SUM(bytes_in + bytes_out), 0)
			FROM bandwidth_buckets
			WHERE hour_bucket >= ? AND hour_bucket <= ?
		`
		hArgs := []interface{}{startBucket, endBucket}
		if tenantID != "" {
			query += " AND tenant_id = ?"
			hArgs = append(hArgs, tenantID)
		}
		query += " GROUP BY dow, hod ORDER BY dow ASC, hod ASC"

		if rows, err := s.db.Query(query, hArgs...); err == nil {
			defer rows.Close()
			for rows.Next() {
				var dow, hod int
				var flows, totalBytes int64
				if err := rows.Scan(&dow, &hod, &flows, &totalBytes); err == nil {
					cells = append(cells, TrafficHeatmapCell{
						DayOfWeek:  dow,
						HourOfDay:  hod,
						Flows:      flows,
						TotalBytes: totalBytes,
					})
				}
			}
			return cells
		}
	}

	query := fmt.Sprintf(`
		SELECT
			CAST(strftime('%%w', substr(timestamp, 1, 19) || 'Z') AS INTEGER) as dow,
			CAST(strftime('%%H', substr(timestamp, 1, 19) || 'Z') AS INTEGER) as hod,
			COUNT(*),
			COALESCE(SUM(bytes_in + bytes_out), 0)
		FROM events
		%s
		GROUP BY dow, hod
		ORDER BY dow ASC, hod ASC
	`, whereClause)

	rows, err := s.db.Query(query, args...)
	if err != nil {
		return cells
	}
	defer rows.Close()

	for rows.Next() {
		var dow, hod int
		var flows, totalBytes int64
		if err := rows.Scan(&dow, &hod, &flows, &totalBytes); err == nil {
			cells = append(cells, TrafficHeatmapCell{
				DayOfWeek:  dow,
				HourOfDay:  hod,
				Flows:      flows,
				TotalBytes: totalBytes,
			})
		}
	}
	return cells
}

func (s *Store) QueryTrafficFlows(filter TrafficFilter) (*TrafficFlowsResult, error) {
	start, end, _, _ := ResolveTrafficWindow(filter)
	whereClause, args, activeFilters := buildTrafficWhere(filter, start, end)

	limit := filter.Limit
	if limit <= 0 || limit > 200 {
		limit = 50
	}

	offset := 0
	if filter.Cursor != "" {
		if raw, err := base64.StdEncoding.DecodeString(filter.Cursor); err == nil {
			if off, err := strconv.Atoi(string(raw)); err == nil && off >= 0 {
				offset = off
			}
		}
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	// 1. Total count
	countQuery := "SELECT COUNT(*) FROM events" + whereClause
	var total int64
	if err := s.db.QueryRow(countQuery, args...).Scan(&total); err != nil {
		return nil, fmt.Errorf("count traffic flows: %w", err)
	}

	// 2. Fetch page (limit + 1 to check next page)
	query := fmt.Sprintf(`
		SELECT
			rowid,
			tenant_id,
			timestamp,
			endpoint_id,
			layer,
			action,
			direction,
			protocol,
			src_ip,
			dst_ip,
			src_port,
			dst_port,
			process_path,
			domain,
			country,
			bytes_in,
			bytes_out
		FROM events
		%s
		ORDER BY timestamp DESC, rowid DESC
		LIMIT ? OFFSET ?
	`, whereClause)

	pageArgs := append(args, limit+1, offset)
	rows, err := s.db.Query(query, pageArgs...)
	if err != nil {
		return nil, fmt.Errorf("query traffic flows: %w", err)
	}
	defer rows.Close()

	var flows []TrafficFlowItem
	hasNext := false

	for rows.Next() {
		if len(flows) >= limit {
			hasNext = true
			break
		}
		var (
			rowID       int64
			tenantID    string
			timestamp   time.Time
			endpointID  string
			layer       string
			action      string
			direction   string
			protocol    int
			srcIP       string
			dstIP       string
			srcPort     int
			dstPort     int
			processPath string
			domain      string
			country     string
			bytesIn     int64
			bytesOut    int64
		)
		if err := rows.Scan(&rowID, &tenantID, &timestamp, &endpointID, &layer, &action, &direction,
			&protocol, &srcIP, &dstIP, &srcPort, &dstPort, &processPath, &domain, &country, &bytesIn, &bytesOut); err != nil {
			return nil, err
		}

		protoName := "TCP"
		if protocol == 17 {
			protoName = "UDP"
		} else if protocol == 1 {
			protoName = "ICMP"
		}

		cleanPath := strings.ReplaceAll(processPath, "\\", "/")
		parts := strings.Split(cleanPath, "/")
		procName := parts[len(parts)-1]
		if procName == "" || procName == "." {
			procName = "kernel/system"
		}

		flows = append(flows, TrafficFlowItem{
			ID:          strconv.FormatInt(rowID, 10),
			TenantID:    tenantID,
			Timestamp:   timestamp,
			EndpointID:  endpointID,
			Layer:       layer,
			Action:      action,
			Direction:   direction,
			Protocol:    protocol,
			ProtoName:   protoName,
			SrcIP:       srcIP,
			DstIP:       dstIP,
			SrcPort:     srcPort,
			DstPort:     dstPort,
			ProcessPath: processPath,
			ProcessName: procName,
			Domain:      domain,
			Country:     country,
			BytesIn:     bytesIn,
			BytesOut:    bytesOut,
		})
	}

	nextCursor := ""
	if hasNext {
		nextCursor = base64.StdEncoding.EncodeToString([]byte(strconv.Itoa(offset + limit)))
	}

	if flows == nil {
		flows = []TrafficFlowItem{}
	}

	res := TrafficFlowResultWithAnomalies(s, flows, nextCursor, total, activeFilters)
	return &res, nil
}

func TrafficFlowResultWithAnomalies(s *Store, flows []TrafficFlowItem, nextCursor string, total int64, activeFilters map[string]interface{}) TrafficFlowsResult {
	// Enrich with anomaly tag if any
	return TrafficFlowsResult{
		Flows:         flows,
		NextCursor:    nextCursor,
		Total:         total,
		ActiveFilters: activeFilters,
	}
}

func (s *Store) GetTrafficFlowByID(flowID string, tenantID string) (*TrafficFlowItem, error) {
	rowID, err := strconv.ParseInt(flowID, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("invalid flow id: %s", flowID)
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	query := `
		SELECT
			rowid,
			tenant_id,
			timestamp,
			endpoint_id,
			layer,
			action,
			direction,
			protocol,
			src_ip,
			dst_ip,
			src_port,
			dst_port,
			process_path,
			domain,
			country,
			bytes_in,
			bytes_out
		FROM events
		WHERE rowid = ?
	`
	var (
		tID         string
		timestamp   time.Time
		endpointID  string
		layer       string
		action      string
		direction   string
		protocol    int
		srcIP       string
		dstIP       string
		srcPort     int
		dstPort     int
		processPath string
		domain      string
		country     string
		bytesIn     int64
		bytesOut    int64
	)

	err = s.db.QueryRow(query, rowID).Scan(&rowID, &tID, &timestamp, &endpointID, &layer, &action, &direction,
		&protocol, &srcIP, &dstIP, &srcPort, &dstPort, &processPath, &domain, &country, &bytesIn, &bytesOut)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}

	if tenantID != "" && tID != tenantID {
		return nil, nil
	}

	protoName := "TCP"
	if protocol == 17 {
		protoName = "UDP"
	} else if protocol == 1 {
		protoName = "ICMP"
	}
	cleanPath := strings.ReplaceAll(processPath, "\\", "/")
	parts := strings.Split(cleanPath, "/")
	procName := parts[len(parts)-1]
	if procName == "" || procName == "." {
		procName = "kernel/system"
	}

	return &TrafficFlowItem{
		ID:          strconv.FormatInt(rowID, 10),
		TenantID:    tID,
		Timestamp:   timestamp,
		EndpointID:  endpointID,
		Layer:       layer,
		Action:      action,
		Direction:   direction,
		Protocol:    protocol,
		ProtoName:   protoName,
		SrcIP:       srcIP,
		DstIP:       dstIP,
		SrcPort:     srcPort,
		DstPort:     dstPort,
		ProcessPath: processPath,
		ProcessName: procName,
		Domain:      domain,
		Country:     country,
		BytesIn:     bytesIn,
		BytesOut:    bytesOut,
	}, nil
}
