package scanner

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"sync"
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
	LastSeen        time.Time  `json:"last_seen"`
}

type ScanStatus struct {
	ID          string      `json:"id"`
	Subnet      string      `json:"subnet"`
	Profile     ScanProfile `json:"profile"`
	Status      string      `json:"status"` // "running", "completed", "failed"
	Progress    int         `json:"progress"`
	FoundCount  int         `json:"found_count"`
	TotalHosts  int         `json:"total_hosts"`
	StartTime   time.Time   `json:"start_time"`
	EndTime     time.Time   `json:"end_time,omitempty"`
}

type CoverageSummary struct {
	TotalDiscovered int     `json:"total_discovered"`
	TotalManaged    int     `json:"total_managed"`
	TotalUnmanaged  int     `json:"total_unmanaged"`
	CoveragePercent float64 `json:"coverage_percent"`
	CriticalRisks   int     `json:"critical_risks"`
	HighRisks       int     `json:"high_risks"`
}

type Scanner struct {
	store       *storage.Store
	customSigs  []DeviceSignature
	activeScans map[string]*ScanStatus
	cachedAssets map[string]DiscoveredAsset
	mu          sync.RWMutex
}

func New(store *storage.Store) *Scanner {
	s := &Scanner{
		store:        store,
		customSigs:   make([]DeviceSignature, 0),
		activeScans:  make(map[string]*ScanStatus),
		cachedAssets: make(map[string]DiscoveredAsset),
	}
	return s
}

// Common ports for Standard Profile (Top 30 High Value)
var standardPorts = []int{
	21, 22, 23, 25, 53, 80, 88, 110, 135, 139, 143, 389, 443, 445,
	993, 995, 1433, 1521, 3306, 3389, 5000, 5432, 5900, 5985, 6379,
	8000, 8008, 8080, 8443, 9000, 9100, 9999,
}

// Full ports for Aggressive IR Profile (Top 100)
var aggressivePorts = append(standardPorts, []int{
	69, 79, 111, 161, 162, 179, 512, 513, 514, 515, 631, 873, 902, 987,
	1080, 1194, 2049, 2375, 2376, 3000, 3128, 4899, 5001, 5060, 5555,
	5601, 5672, 6000, 7000, 7001, 8009, 8081, 8181, 8500, 8888, 9090,
	9200, 9300, 10000, 10250, 11211, 27017, 27018, 50000, 6443,
}...)

func getServiceName(port int) string {
	switch port {
	case 21: return "FTP"
	case 22: return "SSH"
	case 23: return "Telnet"
	case 25: return "SMTP"
	case 53: return "DNS"
	case 80, 8000, 8080, 8081: return "HTTP"
	case 88: return "Kerberos"
	case 135: return "MSRPC"
	case 139, 445: return "SMB / NetBIOS"
	case 389: return "LDAP"
	case 443, 8443: return "HTTPS / TLS"
	case 1433: return "MSSQL"
	case 1521: return "Oracle DB"
	case 3306: return "MySQL"
	case 3389: return "RDP"
	case 5000, 5001: return "Synology DSM / UPnP"
	case 5432: return "PostgreSQL"
	case 5555: return "Android ADB"
	case 5900: return "VNC"
	case 5985, 5986: return "WinRM"
	case 6379: return "Redis DB"
	case 8008, 8009: return "Google Cast / DIAL"
	case 9100: return "JetDirect Printer"
	case 9200, 9300: return "Elasticsearch"
	case 9999: return "Ominull Hub Control"
	case 10250: return "Kubelet API"
	case 27017: return "MongoDB"
	default: return fmt.Sprintf("TCP/%d", port)
	}
}

// StartScan initiates an asynchronous network discovery job
func (s *Scanner) StartScan(subnet string, profile ScanProfile) (string, error) {
	s.mu.Lock()
	scanID := fmt.Sprintf("scan-%d", time.Now().UnixNano()/1000000)
	status := &ScanStatus{
		ID:         scanID,
		Subnet:     subnet,
		Profile:    profile,
		Status:     "running",
		Progress:   0,
		StartTime:  time.Now().UTC(),
		TotalHosts: 254,
	}
	s.activeScans[scanID] = status
	s.mu.Unlock()

	go s.runScanWorker(scanID, subnet, profile)
	return scanID, nil
}

func (s *Scanner) runScanWorker(scanID string, subnet string, profile ScanProfile) {
	var ips []string
	if strings.Contains(subnet, "/") {
		_, ipNet, err := net.ParseCIDR(subnet)
		if err == nil {
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

	for idx, ip := range ips {
		sem <- struct{}{}
		wg.Add(1)

		go func(targetIP string, currentIdx int) {
			defer wg.Done()
			defer func() { <-sem }()

			mac := arpTable[targetIP]
			if mac == "" {
				mac = resolveMAC(targetIP)
			}

			// If passive mode, only evaluate hosts with active ARP or known traffic
			if profile == ProfilePassive {
				if mac == "" {
					return
				}
			}

			asset, live := s.probeHost(targetIP, mac, targetPorts, profile, managedMap)
			if live {
				discMu.Lock()
				discovered = append(discovered, asset)
				s.cachedAssets[asset.IP] = asset
				discMu.Unlock()
			}

			s.mu.Lock()
			if st, ok := s.activeScans[scanID]; ok {
				st.Progress = int((float64(currentIdx+1) / float64(total)) * 100)
				st.FoundCount = len(discovered)
			}
			s.mu.Unlock()
		}(ip, idx)
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

func (s *Scanner) probeHost(ip, mac string, ports []int, profile ScanProfile, managedMap map[string]storage.Endpoint) (DiscoveredAsset, bool) {
	openPorts := make([]PortInfo, 0)
	var totalAppDelta float64
	deltaCount := 0
	ttl := 64
	banners := make([]string, 0)

	// In passive mode, skip TCP active probing unless we already know it
	if profile != ProfilePassive {
		for _, port := range ports {
			t0 := time.Now()
			addr := fmt.Sprintf("%s:%d", ip, port)
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

	osGuess, confidence, category := MatchDeviceSignature(mac, ttl, openPortInts, banners, avgDelta, customSigs)
	if isManaged {
		ep := managedMap[ip]
		osGuess = ep.OS
		confidence = 1.00
		category = "Workstation"
		if ep.RoleTag == "server" {
			category = "Server"
		}
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
			if highestRisk != "CRITICAL" { highestRisk = "HIGH" }
		} else if p.Port == 3389 && !isManaged {
			weakpoints = append(weakpoints, "Exposed RDP Remote Desktop Service (Brute-Force / BlueKeep Target)")
			if highestRisk != "CRITICAL" { highestRisk = "HIGH" }
		} else if p.Port == 5900 {
			weakpoints = append(weakpoints, "Cleartext VNC Remote Framebuffer Exposed")
			if highestRisk != "CRITICAL" && highestRisk != "HIGH" { highestRisk = "MEDIUM" }
		}
	}

	if len(ports) > 10 && !isManaged {
		weakpoints = append(weakpoints, "Broad Attack Surface (>10 Active Listening Ports)")
		if highestRisk != "CRITICAL" { highestRisk = "HIGH" }
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
		ID:              fmt.Sprintf("sig-custom-%d", time.Now().UnixNano()/1000),
		Name:            actualName,
		Vendor:          vendor,
		Category:        category,
		OUIPrefixes:     []string{prefix},
		ExpectedTTL:     []int{asset.TTL},
		ExpectedPorts:   openPorts,
		BannerPatterns:  bannerPats,
		MinAppDeltaMs:   asset.AppDeltaMs * 0.5,
		MaxAppDeltaMs:   asset.AppDeltaMs * 2.0,
		ConfidenceBase:  0.98,
		IsCustom:        true,
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

	return CoverageSummary{
		TotalDiscovered: total,
		TotalManaged:    managed,
		TotalUnmanaged:  total - managed,
		CoveragePercent: covPct,
		CriticalRisks:   crit,
		HighRisks:       high,
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
