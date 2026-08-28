package storage

import (
	"strconv"
	"strings"
	"time"
)

/*
Flow profiles: what the events table already knows about an address that
nothing has ever probed or installed an agent on.

Fan-in is identity. A host that many agented endpoints open sessions to, on a
narrow set of service ports, from a recognisable set of processes, and which
opens nothing outward itself, is infrastructure — and which infrastructure it
is follows from the ports. That is enough to name a domain controller that
answers no scan and runs no agent.
*/

// FlowPortStat is one destination port's share of the traffic to an address.
type FlowPortStat struct {
	Port    int    `json:"port"`
	Flows   int64  `json:"flows"`
	Bytes   int64  `json:"bytes"`
	Sources int    `json:"sources"`
	Proto   string `json:"proto"`
}

// FlowProfile is the shape of the traffic arriving at one internal address.
type FlowProfile struct {
	IP              string         `json:"ip"`
	Subnet          string         `json:"subnet"`
	Flows           int64          `json:"flows"`
	Bytes           int64          `json:"bytes"`
	SourceEndpoints int            `json:"source_endpoints"`
	SourceLocations int            `json:"source_locations"`
	Processes       []string       `json:"processes"`
	Ports           []FlowPortStat `json:"ports"`
	FanOutFlows     int64          `json:"fan_out_flows"`
	FanOutTargets   int            `json:"fan_out_targets"`
	FirstSeen       time.Time      `json:"first_seen"`
	LastSeen        time.Time      `json:"last_seen"`
}

// HasPort reports whether the profile saw traffic to a port.
func (p FlowProfile) HasPort(port int) bool {
	for _, s := range p.Ports {
		if s.Port == port {
			return true
		}
	}
	return false
}

// PortList renders the ports busiest-first, for a rationale an operator reads.
func (p FlowProfile) PortList(limit int) string {
	parts := make([]string, 0, limit)
	for i, s := range p.Ports {
		if i >= limit {
			break
		}
		parts = append(parts, strconv.Itoa(s.Port))
	}
	return strings.Join(parts, "/")
}

// IsPrivateIPv4 reports whether an address is in RFC1918 space. Inference is
// about naming internal infrastructure; a public address that many hosts talk
// to is a SaaS endpoint, not a file server.
func IsPrivateIPv4(ip string) bool {
	parts := strings.Split(ip, ".")
	if len(parts) != 4 {
		return false
	}
	nums := make([]int, 4)
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 || n > 255 {
			return false
		}
		nums[i] = n
	}
	switch {
	case nums[0] == 10:
		return true
	case nums[0] == 172 && nums[1] >= 16 && nums[1] <= 31:
		return true
	case nums[0] == 192 && nums[1] == 168:
		return true
	}
	return false
}

// FlowProfiles aggregates the events table into one profile per internal
// destination address inside the window.
//
// This is deliberately a batch read: it runs on the inference schedule, not
// on a console request, because it walks the whole window.
func (s *Store) FlowProfiles(window time.Duration) ([]FlowProfile, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	cutoff := time.Now().UTC().Add(-window)
	profiles := make(map[string]*FlowProfile)

	get := func(ip string) *FlowProfile {
		if p, ok := profiles[ip]; ok {
			return p
		}
		p := &FlowProfile{IP: ip, Subnet: SubnetOf(ip)}
		profiles[ip] = p
		return p
	}

	// Per destination port: who reached it, how often, how much.
	portRows, err := s.db.Query(`
		SELECT e.dst_ip, e.dst_port, e.protocol,
		       COUNT(*), SUM(e.bytes_in + e.bytes_out), COUNT(DISTINCT e.endpoint_id)
		FROM events e
		WHERE e.timestamp >= ? AND e.action != 'BLOCK'
		GROUP BY e.dst_ip, e.dst_port, e.protocol`, cutoff)
	if err != nil {
		return nil, err
	}
	for portRows.Next() {
		var ip string
		var port, proto int
		var flows, bytes int64
		var sources int
		if err := portRows.Scan(&ip, &port, &proto, &flows, &bytes, &sources); err != nil {
			continue
		}
		if !IsPrivateIPv4(ip) {
			continue
		}
		p := get(ip)
		p.Ports = append(p.Ports, FlowPortStat{
			Port: port, Flows: flows, Bytes: bytes, Sources: sources, Proto: protoName(proto),
		})
	}
	portRows.Close()

	// Per destination: breadth of the fan-in, in endpoints and in locations.
	fanRows, err := s.db.Query(`
		SELECT e.dst_ip, COUNT(*), SUM(e.bytes_in + e.bytes_out),
		       COUNT(DISTINCT e.endpoint_id), COUNT(DISTINCT ep.location_id),
		       MIN(e.timestamp), MAX(e.timestamp)
		FROM events e
		LEFT JOIN endpoints ep ON ep.id = e.endpoint_id
		WHERE e.timestamp >= ? AND e.action != 'BLOCK'
		GROUP BY e.dst_ip`, cutoff)
	if err != nil {
		return nil, err
	}
	for fanRows.Next() {
		var ip string
		var flows, bytes int64
		var endpoints, locations int
		var first, last interface{}
		if err := fanRows.Scan(&ip, &flows, &bytes, &endpoints, &locations, &first, &last); err != nil {
			continue
		}
		if !IsPrivateIPv4(ip) {
			continue
		}
		p := get(ip)
		p.Flows = flows
		p.Bytes = bytes
		p.SourceEndpoints = endpoints
		p.SourceLocations = locations
		p.FirstSeen = scanTime(first)
		p.LastSeen = scanTime(last)
	}
	fanRows.Close()

	// Which processes originate the sessions. lsass.exe and svchost.exe
	// hitting 389 and 88 is the difference between a directory server and a
	// web host that happens to be busy.
	procRows, err := s.db.Query(`
		SELECT dst_ip, process_path, COUNT(*) AS n
		FROM events
		WHERE timestamp >= ? AND action != 'BLOCK' AND process_path != ''
		GROUP BY dst_ip, process_path
		ORDER BY n DESC`, cutoff)
	if err != nil {
		return nil, err
	}
	for procRows.Next() {
		var ip, proc string
		var n int64
		if err := procRows.Scan(&ip, &proc, &n); err != nil {
			continue
		}
		p, ok := profiles[ip]
		if !ok {
			continue
		}
		if len(p.Processes) < 6 {
			p.Processes = append(p.Processes, proc)
		}
	}
	procRows.Close()

	// Fan-out: the same address seen as a source. Infrastructure answers;
	// it does not go looking. A host with heavy fan-in and heavy fan-out is
	// a busy workstation or a pivot, not a directory server.
	outRows, err := s.db.Query(`
		SELECT src_ip, COUNT(*), COUNT(DISTINCT dst_ip)
		FROM events
		WHERE timestamp >= ?
		GROUP BY src_ip`, cutoff)
	if err != nil {
		return nil, err
	}
	for outRows.Next() {
		var ip string
		var flows int64
		var targets int
		if err := outRows.Scan(&ip, &flows, &targets); err != nil {
			continue
		}
		if p, ok := profiles[ip]; ok {
			p.FanOutFlows = flows
			p.FanOutTargets = targets
		}
	}
	outRows.Close()

	out := make([]FlowProfile, 0, len(profiles))
	for _, p := range profiles {
		sortPortStats(p.Ports)
		out = append(out, *p)
	}
	return out, nil
}

func sortPortStats(ports []FlowPortStat) {
	for i := 1; i < len(ports); i++ {
		for j := i; j > 0 && ports[j].Flows > ports[j-1].Flows; j-- {
			ports[j], ports[j-1] = ports[j-1], ports[j]
		}
	}
}

// scanTime converts what the driver hands back for an aggregate over a
// DATETIME column.
//
// SQLite has no date type. On a plain column selection the driver sees the
// declared DATETIME affinity and returns a time.Time, but MIN()/MAX() lose
// that declaration and return the stored text instead. Scanning that straight
// into a time.Time fails — and a scan error in these loops drops the row, so
// the failure is silent. That is exactly what emptied the topology graph:
// every edge row was discarded on its MAX(timestamp) column.
func scanTime(v interface{}) time.Time {
	switch t := v.(type) {
	case time.Time:
		return t.UTC()
	case string:
		return parseStoredTime(t)
	case []byte:
		return parseStoredTime(string(t))
	case int64:
		return time.Unix(t, 0).UTC()
	}
	return time.Time{}
}

func parseStoredTime(v string) time.Time {
	layouts := []string{
		"2006-01-02 15:04:05.999999999 -0700 MST", // what Go's time.Time.String writes
		time.RFC3339Nano,
		"2006-01-02 15:04:05.999999999-07:00",
		"2006-01-02 15:04:05",
	}
	for _, layout := range layouts {
		if t, err := time.Parse(layout, v); err == nil {
			return t.UTC()
		}
	}
	return time.Time{}
}

func protoName(proto int) string {
	switch proto {
	case 17:
		return "UDP"
	case 1:
		return "ICMP"
	}
	return "TCP"
}
