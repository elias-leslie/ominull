package scanner

import (
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"ominull/hub/pkg/storage"
)

// Scheduler manages autonomous recurring subnet sweeps and triggers anomaly alerts for novel assets
type Scheduler struct {
	scanner   *Scanner
	store     *storage.Store
	interval  time.Duration
	subnets   []string
	stopChan  chan struct{}
	mu        sync.Mutex
	isRunning bool
}

func NewScheduler(scanner *Scanner, store *storage.Store, interval time.Duration, subnets []string) *Scheduler {
	if interval < 10*time.Minute {
		interval = 4 * time.Hour
	}
	var cleanSubnets []string
	for _, sub := range subnets {
		sub = strings.TrimSpace(sub)
		if sub != "" {
			cleanSubnets = append(cleanSubnets, sub)
		}
	}
	return &Scheduler{
		scanner:  scanner,
		store:    store,
		interval: interval,
		subnets:  cleanSubnets,
		stopChan: make(chan struct{}),
	}
}

// SetSubnets updates the recurring discovery scope
func (s *Scheduler) SetSubnets(subnets []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var clean []string
	for _, sub := range subnets {
		sub = strings.TrimSpace(sub)
		if sub != "" {
			clean = append(clean, sub)
		}
	}
	s.subnets = clean
}

// Subnets returns a copy of configured subnets
func (s *Scheduler) Subnets() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string{}, s.subnets...)
}

// Start launches the background recurring discovery loop if explicit subnets are configured
func (s *Scheduler) Start() {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.isRunning {
		return
	}
	if len(s.subnets) == 0 {
		return
	}
	s.isRunning = true
	s.stopChan = make(chan struct{})
	log.Printf("[+] Ominull Autonomous Subnet Discovery Scheduler active (Interval: %v, Subnets: %v)", s.interval, s.subnets)

	go s.runLoop()
}

// Stop terminates the background recurring sweep loop
func (s *Scheduler) Stop() {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.isRunning {
		return
	}
	close(s.stopChan)
	s.isRunning = false
}

func (s *Scheduler) runLoop() {
	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()

	for {
		select {
		case <-s.stopChan:
			return
		case <-ticker.C:
			s.executeScheduledSweep()
		}
	}
}

func (s *Scheduler) executeScheduledSweep() {
	for _, subnet := range s.subnets {
		// Snapshot known assets before scan
		knownMap := make(map[string]bool)
		if s.store != nil {
			assets, err := s.store.ListAssets("")
			if err == nil {
				for _, a := range assets {
					if a.IP != "" {
						knownMap[a.IP] = true
					}
					if a.MAC != "" {
						knownMap[a.MAC] = true
					}
				}
			}
		}

		scanID, err := s.scanner.StartScan(subnet, ProfileStandard)
		if err != nil {
			continue
		}

		// Wait for scan completion
		for {
			time.Sleep(1 * time.Second)
			status, err := s.scanner.GetScanStatus(scanID)
			if err != nil || status == nil || status.Status == "completed" || status.Status == "failed" {
				break
			}
		}

		// Evaluate for new unmanaged device alerts
		s.evaluateNewDevices(knownMap)
	}
}

func (s *Scheduler) evaluateNewDevices(knownMap map[string]bool) {
	if s.store == nil {
		return
	}

	endpoints, err := s.store.ListEndpoints("")
	if err == nil {
		for _, ep := range endpoints {
			if ep.IP != "" {
				knownMap[ep.IP] = true
			}
			if ep.MAC != "" {
				knownMap[ep.MAC] = true
			}
		}
	}

	s.scanner.mu.RLock()
	cached := make([]DiscoveredAsset, 0, len(s.scanner.cachedAssets))
	for _, a := range s.scanner.cachedAssets {
		cached = append(cached, a)
	}
	s.scanner.mu.RUnlock()

	for _, a := range cached {
		if a.IsManaged {
			continue
		}
		// If previously unrecorded, trigger an anomaly alert
		if !knownMap[a.IP] && (a.MAC == "" || !knownMap[a.MAC]) {
			knownMap[a.IP] = true
			if a.MAC != "" {
				knownMap[a.MAC] = true
			}
			severity := "MEDIUM"
			if a.RiskScore == "HIGH" || a.RiskScore == "CRITICAL" {
				severity = "HIGH"
			}

			portsList := make([]string, 0, len(a.OpenPorts))
			for _, p := range a.OpenPorts {
				portsList = append(portsList, fmt.Sprintf("%d/%s", p.Port, p.Service))
			}
			portSummary := "None"
			if len(portsList) > 0 {
				portSummary = strings.Join(portsList, ", ")
			}

			alert := storage.AnomalyAlert{
				ID:          fmt.Sprintf("alert-disc-%d", time.Now().UnixNano()),
				TenantID:    "default",
				AnomalyType: "NOVEL_DESTINATION",
				Severity:    severity,
				Title:       fmt.Sprintf("New Unmanaged Device Discovered (%s)", a.IP),
				Description: fmt.Sprintf("Autonomous subnet sweep discovered new unmanaged device %s (%s, %s).", a.IP, a.OSGuess, a.Vendor),
				Details:     fmt.Sprintf("MAC: %s | Vendor: %s | Hostname: %s | Open Ports: %s | Method: %s", a.MAC, a.Vendor, a.Hostname, portSummary, a.IdentityMethod),
				DstIP:       a.IP,
				Timestamp:   time.Now().UTC(),
			}

			_ = s.store.CreateAnomalyAlert(alert)
		}
	}
}
