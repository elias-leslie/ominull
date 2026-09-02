package scanner

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"ominull/hub/pkg/storage"
)

type ScanProfile string

const (
	ProfilePassive    ScanProfile = "passive"
	ProfileStandard   ScanProfile = "standard"
	ProfileAggressive ScanProfile = "aggressive"
)

type PortInfo struct {
	Port      int     `json:"port"`
	Protocol  string  `json:"protocol"`
	Service   string  `json:"service"`
	Banner    string  `json:"banner"`
	LatencyMs float64 `json:"latency_ms"`
	RiskLevel string  `json:"risk_level"` // "CLEAN", "LOW", "MEDIUM", "HIGH", "CRITICAL"
}

type DiscoveredAsset struct {
	IP              string     `json:"ip"`
	MAC             string     `json:"mac"`
	Vendor          string     `json:"vendor"`
	Hostname        string     `json:"hostname"`
	OSGuess         string     `json:"os_guess"`
	Category        string     `json:"category"`
	Confidence      float64    `json:"confidence"`
	OpenPorts       []PortInfo `json:"open_ports"`
	IsManaged       bool       `json:"is_managed"`
	AgentEndpointID string     `json:"agent_endpoint_id"`
	RiskScore       string     `json:"risk_score"` // "CLEAN", "LOW", "MEDIUM", "HIGH", "CRITICAL"
	Weakpoints      []string   `json:"weakpoints"`
	TTL             int        `json:"ttl"`
	AppDeltaMs      float64    `json:"app_delta_ms"`
	// IdentityMethod and IdentityWhy are how the identification was reached and
	// the exact strings that reached it. The console shows them, because
	// "Ubuntu Linux" with nothing behind it was not something an operator could
	// correct - or trust.
	IdentityMethod string    `json:"identity_method"`
	IdentityWhy    []string  `json:"identity_why"`
	LastSeen       time.Time `json:"last_seen"`
}

type ScanStatus struct {
	ID         string      `json:"id"`
	Subnet     string      `json:"subnet"`
	Profile    ScanProfile `json:"profile"`
	Status     string      `json:"status"` // "running", "completed", "failed"
	Progress   int         `json:"progress"`
	FoundCount int         `json:"found_count"`
	TotalHosts int         `json:"total_hosts"`
	StartTime  time.Time   `json:"start_time"`
	EndTime    time.Time   `json:"end_time,omitempty"`
}

type CoverageSummary struct {
	TotalDiscovered int     `json:"total_discovered"`
	TotalManaged    int     `json:"total_managed"`
	TotalUnmanaged  int     `json:"total_unmanaged"`
	CoveragePercent float64 `json:"coverage_percent"`
	CriticalRisks   int     `json:"critical_risks"`
	HighRisks       int     `json:"high_risks"`
	// TTLMeasured says whether the sweep can read hop limits, and TTLNote says
	// what to do about it when it cannot. A blank TTL column with no
	// explanation is a fault report nobody can act on.
	TTLMeasured bool   `json:"ttl_measured"`
	TTLNote     string `json:"ttl_note,omitempty"`
}

type Scanner struct {
	store        *storage.Store
	customSigs   []DeviceSignature
	activeScans  map[string]*ScanStatus
	cachedAssets map[string]DiscoveredAsset
	dhcpSnooper  *DHCPSnooper
	scheduler    *Scheduler
	mu           sync.RWMutex
}

func New(store *storage.Store) *Scanner {
	s := &Scanner{
		store:        store,
		customSigs:   make([]DeviceSignature, 0),
		activeScans:  make(map[string]*ScanStatus),
		cachedAssets: make(map[string]DiscoveredAsset),
	}
	s.dhcpSnooper = NewDHCPSnooper(s)
	s.scheduler = NewScheduler(s, store, 4*time.Hour, nil)
	// Discovery used to live only in cachedAssets, so a hub restart erased
	// every host the scanner had ever found. The assets table is now the
	// record of truth and this map is a read cache over it.
	s.hydrateFromStore()
	return s
}

// StartBackground launches the passive DHCP listener and periodic sweep scheduler
func (s *Scanner) StartBackground() {
	if s.dhcpSnooper != nil {
		_ = s.dhcpSnooper.Start()
	}
	if s.scheduler != nil {
		s.scheduler.Start()
	}
}

// StopBackground stops the passive DHCP listener and sweep scheduler
func (s *Scanner) StopBackground() {
	if s.dhcpSnooper != nil {
		s.dhcpSnooper.Stop()
	}
	if s.scheduler != nil {
		s.scheduler.Stop()
	}
}

// RecordPassiveDHCP handles a passively snooped DHCP packet from the local network segment
func (s *Scanner) RecordPassiveDHCP(ip, mac, hostname, vendorClass string, params []byte) {
	if mac == "" {
		return
	}

	vendor := LookupVendor(mac)
	dhcpStr := fmt.Sprintf("dhcp:vendor=%s,host=%s", vendorClass, hostname)
	ident := identityFromDHCP(dhcpStr)

	osGuess := "Generic Network Host"
	category := "Workstation"
	confidence := 0.60
	method := "dhcp-snoop"
	evidence := []string{dhcpStr}

	if ident != nil {
		osGuess = ident.Name
		category = ident.Category
		confidence = ident.Confidence
		method = ident.Method
		evidence = ident.Evidence
	} else if vendor != "Generic / Unassigned Hardware" {
		osGuess = vendor + " Device"
	}

	asset := DiscoveredAsset{
		IP:             ip,
		MAC:            mac,
		Vendor:         vendor,
		Hostname:       hostname,
		OSGuess:        osGuess,
		Category:       category,
		Confidence:     confidence,
		RiskScore:      "LOW",
		Weakpoints:     []string{"Passively Discovered via DHCP Broadcast"},
		IdentityMethod: method,
		IdentityWhy:    evidence,
		LastSeen:       time.Now().UTC(),
	}

	s.mu.Lock()
	if ip != "" {
		s.cachedAssets[ip] = asset
	}
	s.mu.Unlock()

	s.persist(asset)
}

// hydrateFromStore refills the in-memory cache from the persisted asset
// graph. Only assets a scan actually touched come back: an asset known solely
// from an agent check-in or from flow inference is not a discovery result and
// would inflate the coverage denominator with hosts nobody probed.
func (s *Scanner) hydrateFromStore() {
	if s.store == nil {
		return
	}
	assets, err := s.store.ListAssets("")
	if err != nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, a := range assets {
		if !hasSource(a, storage.SourceScan) {
			continue
		}
		s.cachedAssets[a.IP] = assetToDiscovered(a)
	}
}

func hasSource(a storage.Asset, source string) bool {
	for _, c := range a.Claims {
		if c.Source == source {
			return true
		}
	}
	return false
}

// assetToDiscovered projects a persisted asset back onto the scanner's own
// shape. Confidence is taken from the winning identity claim so a rehydrated
// row reports the same fingerprint strength it did before the restart.
func assetToDiscovered(a storage.Asset) DiscoveredAsset {
	ports := make([]PortInfo, 0, len(a.Ports))
	for _, p := range a.Ports {
		ports = append(ports, PortInfo{
			Port:      p.Port,
			Protocol:  p.Protocol,
			Service:   p.Service,
			Banner:    p.Banner,
			LatencyMs: p.LatencyMs,
			RiskLevel: p.RiskLevel,
		})
	}
	conf := 0.0
	ttl := 64
	for _, c := range a.Claims {
		if c.Source == storage.SourceScan && c.Field == storage.FieldOS && c.Confidence > conf {
			conf = c.Confidence
		}
	}
	weakpoints, risk := evaluateWeakpoints(ports, a.HasAgent(), a.OS)
	if a.RiskScore != "" {
		risk = a.RiskScore
	}
	return DiscoveredAsset{
		IP:              a.IP,
		MAC:             a.MAC,
		Vendor:          a.Vendor,
		Hostname:        a.Hostname,
		OSGuess:         a.OS,
		Category:        a.Category,
		Confidence:      conf,
		OpenPorts:       ports,
		IsManaged:       a.HasAgent(),
		AgentEndpointID: a.AgentEndpointID,
		RiskScore:       risk,
		Weakpoints:      weakpoints,
		TTL:             ttl,
		LastSeen:        a.LastSeenAt,
	}
}

// persist writes a probe result through to the asset graph, which is what
// makes a discovery outlive the process that found it.
func (s *Scanner) persist(a DiscoveredAsset) {
	if s.store == nil {
		return
	}
	ports := make([]storage.AssetPort, 0, len(a.OpenPorts))
	for _, p := range a.OpenPorts {
		ports = append(ports, storage.AssetPort{
			Port:      p.Port,
			Protocol:  strings.ToLower(p.Protocol),
			Service:   p.Service,
			Banner:    p.Banner,
			RiskLevel: p.RiskLevel,
			LatencyMs: p.LatencyMs,
		})
	}
	_ = s.store.UpsertAssetFromScan(a.IP, a.MAC, a.Vendor, a.Hostname, a.OSGuess, a.Category,
		a.RiskScore, a.Confidence, ports, a.LastSeen)
}

// Common ports for Standard Profile (Top High Value Infra, Hypervisors, & IoT)
var standardPorts = []int{
	21, 22, 23, 25, 53, 80, 88, 110, 135, 139, 143, 389, 443, 445,
	993, 995, 1433, 1521, 1883, 3000, 3306, 3389, 5000, 5001, 5432, 5900, 5985, 6379, 6443,
	8000, 8006, 8008, 8080, 8123, 8443, 9000, 9090, 9100, 9443, 9999,
}

// Full ports for Aggressive IR Profile (Top 100)
var aggressivePorts = append(standardPorts, []int{
	69, 79, 111, 161, 162, 179, 512, 513, 514, 515, 631, 873, 902, 987,
	1080, 1194, 2049, 2375, 2376, 3128, 4899, 5060, 5555,
	5601, 5672, 6000, 7000, 7001, 8009, 8081, 8181, 8500, 8888,
	9200, 9300, 10000, 10250, 11211, 27017, 27018, 50000,
}...)

func getServiceName(port int) string {
	switch port {
	case 21:
		return "FTP"
	case 22:
		return "SSH"
	case 23:
		return "Telnet"
	case 25:
		return "SMTP"
	case 53:
		return "DNS"
	case 80, 8000, 8080, 8081:
		return "HTTP"
	case 88:
		return "Kerberos"
	case 135:
		return "MSRPC"
	case 139, 445:
		return "SMB / NetBIOS"
	case 389:
		return "LDAP"
	case 443, 8443:
		return "HTTPS / TLS"
	case 1433:
		return "MSSQL"
	case 1521:
		return "Oracle DB"
	case 1883:
		return "MQTT IoT Broker"
	case 3000:
		return "Grafana Dashboard"
	case 3306:
		return "MySQL"
	case 3389:
		return "RDP"
	case 5000, 5001:
		return "Synology DSM / UPnP"
	case 5432:
		return "PostgreSQL"
	case 5555:
		return "Android ADB"
	case 5900:
		return "VNC"
	case 5985, 5986:
		return "WinRM"
	case 6379:
		return "Redis DB"
	case 6443:
		return "Kubernetes API Server"
	case 8006:
		return "Proxmox VE Web Console"
	case 8008, 8009:
		return "Google Cast / DIAL"
	case 8123:
		return "Home Assistant HTTP"
	case 9090:
		return "Cockpit / Prometheus"
	case 9100:
		return "JetDirect Printer"
	case 9200, 9300:
		return "Elasticsearch"
	case 9443:
		return "Ominull Agent mTLS / Portainer"
	case 9999:
		return "Ominull Hub Control"
	case 10250:
		return "Kubelet API"
	case 27017:
		return "MongoDB"
	default:
		return fmt.Sprintf("TCP/%d", port)
	}
}

// targetsFor turns whatever the operator typed into the exact list of addresses
// the sweep will probe. It is resolved before the job is announced rather than
// inside the worker, because the console now shows the host count while the scan
// runs and "254" was being reported for every subnet, /30 included.
func targetsFor(subnet string) []string {
	var ips []string
	if strings.Contains(subnet, "/") {
		if _, ipNet, err := net.ParseCIDR(subnet); err == nil {
			ips = generateIPs(ipNet)
		}
	}
	if len(ips) == 0 {
		// Default to local class C /24
		base := "10.0.0."
		if strings.HasPrefix(subnet, "192.168.") || strings.HasPrefix(subnet, "10.") || strings.HasPrefix(subnet, "172.") {
			parts := strings.Split(subnet, ".")
			if len(parts) >= 3 {
				base = parts[0] + "." + parts[1] + "." + parts[2] + "."
			}
		}
		for i := 1; i <= 254; i++ {
			ips = append(ips, fmt.Sprintf("%s%d", base, i))
		}
	}
	return ips
}

// StartScan initiates an asynchronous network discovery job
func (s *Scanner) StartScan(subnet string, profile ScanProfile) (string, error) {
	ips := targetsFor(subnet)

	s.mu.Lock()
	scanID := fmt.Sprintf("scan-%d", time.Now().UnixNano()/1000000)
	status := &ScanStatus{
		ID:         scanID,
		Subnet:     subnet,
		Profile:    profile,
		Status:     "running",
		Progress:   0,
		StartTime:  time.Now().UTC(),
		TotalHosts: len(ips),
	}
	s.activeScans[scanID] = status
	s.mu.Unlock()

	go s.runScanWorker(scanID, ips, profile)
	return scanID, nil
}

func (s *Scanner) runScanWorker(scanID string, ips []string, profile ScanProfile) {

	// 1. Fetch managed endpoints from Store for immediate correlation
	endpoints := s.store.GetEndpoints()
	managedMap := make(map[string]storage.Endpoint)
	for _, ep := range endpoints {
		managedMap[ep.IP] = ep
	}

	// Parse local ARP / Neighbor Cache
	arpTable := parseLocalARPTable()

	targetPorts := standardPorts
	if profile == ProfileAggressive {
		targetPorts = aggressivePorts
	}

	var discovered []DiscoveredAsset
	var wg sync.WaitGroup
	var discMu sync.Mutex

	workerLimit := 40
	if profile == ProfileAggressive {
		workerLimit = 80
	} else if profile == ProfilePassive {
		workerLimit = 10
	}

	sem := make(chan struct{}, workerLimit)
	total := len(ips)
	// Probes finish out of order across forty workers, so progress taken from a
	// worker's own index walked backwards on screen. Count what has finished.
	var done int64

	for _, ip := range ips {
		sem <- struct{}{}
		wg.Add(1)

		go func(targetIP string) {
			defer wg.Done()
			defer func() { <-sem }()

			mac := arpTable[targetIP]
			if mac == "" {
				mac = resolveMAC(targetIP)
			}

			// If passive mode, only evaluate hosts with active ARP or known
			// traffic. It is still a probe that has been resolved, so it counts
			// towards progress: skipping the tally here stalled the bar at
			// whatever fraction of the subnet happened to answer ARP.
			if profile == ProfilePassive {
				if mac == "" {
					s.tallyProbe(scanID, &done, total, &discMu, &discovered)
					return
				}
			}

			asset, live := s.probeHost(targetIP, mac, targetPorts, profile, managedMap)
			if live {
				discMu.Lock()
				discovered = append(discovered, asset)
				discMu.Unlock()

				// cachedAssets is read under s.mu by the API handlers, so it
				// must be written under s.mu too, not under the local slice
				// mutex this loop uses for `discovered`.
				s.mu.Lock()
				s.cachedAssets[asset.IP] = asset
				s.mu.Unlock()

				s.persist(asset)
			}

			s.tallyProbe(scanID, &done, total, &discMu, &discovered)
		}(ip)
	}

	wg.Wait()

	s.mu.Lock()
	if st, ok := s.activeScans[scanID]; ok {
		st.Status = "completed"
		st.Progress = 100
		st.FoundCount = len(discovered)
		st.EndTime = time.Now().UTC()
	}
	s.mu.Unlock()
}

// tallyProbe records one finished probe against the running scan. The found
// count is read under the same mutex that guards the slice it counts.
func (s *Scanner) tallyProbe(scanID string, done *int64, total int, discMu *sync.Mutex, discovered *[]DiscoveredAsset) {
	n := atomic.AddInt64(done, 1)
	discMu.Lock()
	found := len(*discovered)
	discMu.Unlock()

	s.mu.Lock()
	if st, ok := s.activeScans[scanID]; ok && total > 0 {
		st.Progress = int((float64(n) / float64(total)) * 100)
		st.FoundCount = found
	}
	s.mu.Unlock()
}

func (s *Scanner) probeHost(ip, mac string, ports []int, profile ScanProfile, managedMap map[string]storage.Endpoint) (DiscoveredAsset, bool) {
	openPorts := make([]PortInfo, 0)
	var totalAppDelta float64
	deltaCount := 0
	// Measured, not assumed. This was `ttl := 64`, handed unchanged to a matcher
	// that awarded a fifth of its points for a TTL match - so every host on the
	// network arrived at the matcher already looking like Linux. Zero now means
	// "not measured" and scores as no evidence at all.
	ttl := measureTTL(ip)
	banners := make([]string, 0)
	extras := make([]string, 0)

	// In passive mode, skip TCP active probing unless we already know it
	if profile != ProfilePassive {
		for _, port := range ports {
			t0 := time.Now()
			// net.JoinHostPort, not "%s:%d": an IPv6 literal has to be bracketed
			// before it is a dialable address, and "fe80::1:445" is neither an
			// address nor an error - it is a host that never answers.
			addr := net.JoinHostPort(ip, strconv.Itoa(port))
			conn, err := net.DialTimeout("tcp", addr, 250*time.Millisecond)
			if err != nil {
				continue
			}

			t1 := time.Now()
			connectRTT := float64(t1.Sub(t0).Microseconds()) / 1000.0 // ms

			// Probe application banner
			banner, appLatency := probeBanner(conn, port)
			conn.Close()

			deltaMs := appLatency - connectRTT
			if deltaMs > 0 {
				totalAppDelta += deltaMs
				deltaCount++
			}

			// Probe HTTP titles, Server headers, and TLS certificates on relevant ports
			switch port {
			case 80, 8000, 8080, 8081, 8123, 9090, 3000, 5000:
				title, server, httpBanner := probeHTTPInfo(ip, port, false)
				if title != "" {
					extras = append(extras, "http-title:"+title)
				}
				if server != "" {
					banners = append(banners, "Server: "+server)
				}
				if httpBanner != "" && banner == "" {
					banner = httpBanner
				}
			case 443, 8443, 8006, 9443, 6443, 5001, 5986:
				certInfo := probeTLSCert(ip, port)
				if certInfo != "" {
					extras = append(extras, certInfo)
				}
				title, server, httpBanner := probeHTTPInfo(ip, port, true)
				if title != "" {
					extras = append(extras, "http-title:"+title)
				}
				if server != "" {
					banners = append(banners, "Server: "+server)
				}
				if httpBanner != "" && banner == "" {
					banner = httpBanner
				}
			}

			if banner != "" {
				banners = append(banners, banner)
			}

			serviceName := getServiceName(port)
			riskLevel := assessPortRisk(port, serviceName)

			openPorts = append(openPorts, PortInfo{
				Port:      port,
				Protocol:  "TCP",
				Service:   serviceName,
				Banner:    banner,
				LatencyMs: connectRTT,
				RiskLevel: riskLevel,
			})
		}
	}

	// Determine if host is live (open ports or known ARP or managed endpoint)
	_, isManaged := managedMap[ip]
	if len(openPorts) == 0 && mac == "" && !isManaged {
		return DiscoveredAsset{}, false
	}

	if mac == "" {
		if ep, ok := managedMap[ip]; ok && ep.MAC != "" {
			mac = ep.MAC
		} else {
			mac = "02:42:0a:00:00:01"
		}
	}

	// Hostname resolution
	hostname := ""
	if names, err := net.LookupAddr(ip); err == nil && len(names) > 0 {
		hostname = strings.TrimSuffix(names[0], ".")
	}
	if hostname == "" {
		if ep, ok := managedMap[ip]; ok {
			hostname = ep.Hostname
		}
	}
	if hostname != "" {
		extras = append(extras, "host:"+hostname)
	}

	// Calculate average application response delta
	avgDelta := 1.5
	if deltaCount > 0 {
		avgDelta = totalAppDelta / float64(deltaCount)
	}

	// Check managed endpoint OS & driver
	var epID string
	if ep, ok := managedMap[ip]; ok {
		isManaged = true
		epID = ep.ID
	}

	// Multi-factor OS Fingerprinting
	s.mu.RLock()
	customSigs := s.customSigs
	s.mu.RUnlock()

	var openPortInts []int
	for _, p := range openPorts {
		openPortInts = append(openPortInts, p.Port)
	}

	// Ask the host to describe itself before guessing. NetBIOS, mDNS, SSDP, and SNMP
	// are all unprivileged and all answer with the host's own words; a passive
	// sweep skips them because it is not supposed to send anything.
	if profile != ProfilePassive {
		extras = append(extras, probeExtras(ip, hostname)...)
	}

	ident := IdentifyHost(mac, ttl, openPortInts, banners, extras, avgDelta, customSigs)
	osGuess, confidence, category := ident.Name, ident.Confidence, ident.Category
	method, evidence := ident.Method, ident.Evidence
	if isManaged {
		// An installed agent reports the operating system from inside it. There
		// is nothing on the network that beats that.
		ep := managedMap[ip]
		osGuess = ep.OS
		confidence = 1.00
		category = "Workstation"
		if ep.RoleTag == "server" {
			category = "Server"
		}
		method = "agent"
		evidence = []string{"reported by the agent installed on this host"}
	}

	// Weakpoint and Risk Scoring
	weakpoints, riskScore := evaluateWeakpoints(openPorts, isManaged, osGuess)

	return DiscoveredAsset{
		IP:              ip,
		MAC:             mac,
		Vendor:          LookupVendor(mac),
		Hostname:        hostname,
		OSGuess:         osGuess,
		Category:        category,
		Confidence:      confidence,
		OpenPorts:       openPorts,
		IsManaged:       isManaged,
		AgentEndpointID: epID,
		RiskScore:       riskScore,
		Weakpoints:      weakpoints,
		TTL:             ttl,
		AppDeltaMs:      avgDelta,
		IdentityMethod:  method,
		IdentityWhy:     evidence,
		LastSeen:        time.Now().UTC(),
	}, true
}

func probeBanner(conn net.Conn, port int) (string, float64) {
	conn.SetDeadline(time.Now().Add(400 * time.Millisecond))
	t0 := time.Now()

	// Send protocol-appropriate initial byte probe
	switch port {
	case 21, 22, 25, 110, 143:
		// Service sends initial greeting upon connect (SSH, FTP, SMTP)
	case 80, 8000, 8080, 8081, 5000:
		conn.Write([]byte("GET / HTTP/1.0\r\nUser-Agent: Ominull-Scanner/1.1\r\n\r\n"))
	case 443, 8443:
		// TLS probe (ClientHello snippet)
		conn.Write([]byte("\x16\x03\x01\x00\x65\x01\x00\x00\x61\x03\x03"))
	case 445, 139:
		// SMB NetBIOS negotiate
		conn.Write([]byte("\x00\x00\x00\x2f\xff\x53\x4d\x42\x72\x00\x00\x00\x00\x18\x53\xc8"))
	default:
		conn.Write([]byte("\r\n"))
	}

	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	t1 := time.Now()
	appLatency := float64(t1.Sub(t0).Microseconds()) / 1000.0

	if err != nil || n == 0 {
		return "", appLatency
	}

	banner := strings.TrimSpace(string(buf[:n]))
	banner = strings.ReplaceAll(banner, "\r", " ")
	banner = strings.ReplaceAll(banner, "\n", " ")
	if len(banner) > 80 {
		banner = banner[:80] + "..."
	}
	return banner, appLatency
}

func assessPortRisk(port int, service string) string {
	switch port {
	case 23, 6379, 10250:
		return "CRITICAL"
	case 445, 3389, 5900, 5985:
		return "HIGH"
	case 21, 22, 80, 8080:
		return "MEDIUM"
	default:
		return "LOW"
	}
}

func evaluateWeakpoints(ports []PortInfo, isManaged bool, osGuess string) ([]string, string) {
	weakpoints := make([]string, 0)
	highestRisk := "CLEAN"

	if !isManaged {
		weakpoints = append(weakpoints, "Missing Ominull Native Agent Protection")
		highestRisk = "MEDIUM"
	}

	for _, p := range ports {
		if p.Port == 23 {
			weakpoints = append(weakpoints, "Cleartext Telnet Exposed (High-Risk Insecure Remote Access)")
			highestRisk = "CRITICAL"
		} else if p.Port == 6379 {
			weakpoints = append(weakpoints, "Unauthenticated Redis In-Memory Database Exposed")
			highestRisk = "CRITICAL"
		} else if p.Port == 445 && !isManaged {
			weakpoints = append(weakpoints, "Exposed SMBv1/v2 Service without Agent Nullification (Lateral Movement Target)")
			if highestRisk != "CRITICAL" {
				highestRisk = "HIGH"
			}
		} else if p.Port == 3389 && !isManaged {
			weakpoints = append(weakpoints, "Exposed RDP Remote Desktop Service (Brute-Force / BlueKeep Target)")
			if highestRisk != "CRITICAL" {
				highestRisk = "HIGH"
			}
		} else if p.Port == 5900 {
			weakpoints = append(weakpoints, "Cleartext VNC Remote Framebuffer Exposed")
			if highestRisk != "CRITICAL" && highestRisk != "HIGH" {
				highestRisk = "MEDIUM"
			}
		}
	}

	if len(ports) > 10 && !isManaged {
		weakpoints = append(weakpoints, "Broad Attack Surface (>10 Active Listening Ports)")
		if highestRisk != "CRITICAL" {
			highestRisk = "HIGH"
		}
	}

	if len(weakpoints) == 0 {
		weakpoints = append(weakpoints, "Verified Clean Baseline Endpoint")
	}

	return weakpoints, highestRisk
}

func parseLocalARPTable() map[string]string {
	table := make(map[string]string)
	f, err := os.Open("/proc/net/arp")
	if err == nil {
		defer f.Close()
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			fields := strings.Fields(scanner.Text())
			if len(fields) >= 4 && fields[0] != "IP" {
				ip := fields[0]
				mac := strings.ToUpper(fields[3])
				if mac != "00:00:00:00:00:00" {
					table[ip] = mac
				}
			}
		}
		return table
	}

	// macOS / BSD fallback via arp -an
	out, err := exec.Command("arp", "-an").Output()
	if err == nil {
		lines := strings.Split(string(out), "\n")
		for _, line := range lines {
			if strings.Contains(line, "(") && strings.Contains(line, ") at ") {
				parts := strings.Split(line, "(")
				if len(parts) > 1 {
					ipParts := strings.Split(parts[1], ")")
					ip := ipParts[0]
					macParts := strings.Split(line, ") at ")
					if len(macParts) > 1 {
						mac := strings.Fields(macParts[1])[0]
						table[ip] = strings.ToUpper(mac)
					}
				}
			}
		}
	}
	return table
}

func resolveMAC(ip string) string {
	// Send a quick ping to trigger ARP resolution
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	_ = exec.CommandContext(ctx, "ping", "-c", "1", "-W", "1", ip).Run()
	table := parseLocalARPTable()
	return table[ip]
}

func generateIPs(ipNet *net.IPNet) []string {
	var ips []string
	ip := ipNet.IP.Mask(ipNet.Mask)
	for ipNet.Contains(ip) {
		ips = append(ips, ip.String())
		inc(ip)
	}
	if len(ips) > 2 {
		return ips[1 : len(ips)-1] // exclude network and broadcast
	}
	return ips
}

func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

// TrainSignature allows analysts or AI subagents to teach the engine ground-truth device identities
func (s *Scanner) TrainSignature(ip, actualName, vendor, category string) (*DeviceSignature, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	asset, exists := s.cachedAssets[ip]
	if !exists {
		return nil, fmt.Errorf("asset %s not found in scanner cache", ip)
	}

	cleanMAC := strings.ToUpper(strings.ReplaceAll(strings.ReplaceAll(asset.MAC, "-", ":"), ".", ":"))
	var prefix string
	parts := strings.Split(cleanMAC, ":")
	if len(parts) >= 3 {
		prefix = parts[0] + ":" + parts[1] + ":" + parts[2]
	}

	var openPorts []int
	var bannerPats []string
	for _, p := range asset.OpenPorts {
		openPorts = append(openPorts, p.Port)
		if p.Banner != "" {
			escaped := regexp.QuoteMeta(p.Banner)
			bannerPats = append(bannerPats, "(?i)"+escaped)
		}
	}

	newSig := DeviceSignature{
		ID:             fmt.Sprintf("sig-custom-%d", time.Now().UnixNano()/1000),
		Name:           actualName,
		Vendor:         vendor,
		Category:       category,
		OUIPrefixes:    []string{prefix},
		ExpectedTTL:    []int{asset.TTL},
		ExpectedPorts:  openPorts,
		BannerPatterns: bannerPats,
		MinAppDeltaMs:  asset.AppDeltaMs * 0.5,
		MaxAppDeltaMs:  asset.AppDeltaMs * 2.0,
		ConfidenceBase: 0.98,
		IsCustom:       true,
	}

	s.customSigs = append([]DeviceSignature{newSig}, s.customSigs...)

	// Re-evaluate asset immediately with updated signature
	asset.OSGuess = actualName
	asset.Vendor = vendor
	asset.Category = category
	asset.Confidence = 0.98
	s.cachedAssets[ip] = asset

	return &newSig, nil
}

// SignatureCount reports how many operator-trained signatures are loaded.
func (s *Scanner) SignatureCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.customSigs)
}

func (s *Scanner) GetDiscoveredAssets() []DiscoveredAsset {
	s.mu.RLock()
	defer s.mu.RUnlock()

	assets := make([]DiscoveredAsset, 0, len(s.cachedAssets))
	for _, a := range s.cachedAssets {
		assets = append(assets, a)
	}
	return assets
}

func (s *Scanner) GetCoverageSummary() CoverageSummary {
	s.mu.RLock()
	defer s.mu.RUnlock()

	total := len(s.cachedAssets)
	managed := 0
	crit := 0
	high := 0

	for _, a := range s.cachedAssets {
		if a.IsManaged {
			managed++
		}
		if a.RiskScore == "CRITICAL" {
			crit++
		} else if a.RiskScore == "HIGH" {
			high++
		}
	}

	covPct := 0.0
	if total > 0 {
		covPct = (float64(managed) / float64(total)) * 100.0
	}
	ttlOK, ttlNote := TTLMeasurable()

	return CoverageSummary{
		TotalDiscovered: total,
		TotalManaged:    managed,
		TotalUnmanaged:  total - managed,
		CoveragePercent: covPct,
		CriticalRisks:   crit,
		HighRisks:       high,
		TTLMeasured:     ttlOK,
		TTLNote:         ttlNote,
	}
}

func (s *Scanner) GetScanStatus(scanID string) (*ScanStatus, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	st, ok := s.activeScans[scanID]
	if !ok {
		return nil, fmt.Errorf("scan %s not found", scanID)
	}
	return st, nil
}
