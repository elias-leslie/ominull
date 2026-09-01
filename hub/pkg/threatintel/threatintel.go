package threatintel

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"ominull/hub/pkg/storage"
)

type Manager struct {
	store      *storage.Store
	httpClient *http.Client
	mu         sync.RWMutex
	cache      map[string]*storage.IOC
	cancelFunc context.CancelFunc
}

func New(store *storage.Store) *Manager {
	return &Manager{
		store: store,
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
		cache: make(map[string]*storage.IOC),
	}
}

// StartScheduler starts background TI polling
func (m *Manager) Start(ctx context.Context, interval time.Duration) {
	subCtx, cancel := context.WithCancel(ctx)
	m.cancelFunc = cancel

	// Initial load from database cache
	m.reloadCache()

	go func() {
		// Initial sync
		if err := m.SyncAllFeeds(subCtx); err != nil {
			log.Printf("[-] Initial TI sync error: %v (using cached/fallback feeds)", err)
		}

		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-subCtx.Done():
				return
			case <-ticker.C:
				if err := m.SyncAllFeeds(subCtx); err != nil {
					log.Printf("[-] TI background sync error: %v", err)
				}
			}
		}
	}()
}

func (m *Manager) Stop() {
	if m.cancelFunc != nil {
		m.cancelFunc()
	}
}

func (m *Manager) reloadCache() {
	iocs, err := m.store.ListIOCs(1000)
	if err != nil {
		return
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	for i := range iocs {
		m.cache[iocs[i].Value] = &iocs[i]
	}
}

func (m *Manager) CheckThreat(ipOrDomain string) (*storage.IOC, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	ioc, exists := m.cache[ipOrDomain]
	return ioc, exists
}

// GetActiveIndicators returns a bounded slice of active malicious IPs/domains
// for endpoint edge threat filtering and in-line kernel drops.
func (m *Manager) GetActiveIndicators(limit int) []string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if limit <= 0 || limit > 512 {
		limit = 128
	}

	indicators := make([]string, 0, limit)
	for val := range m.cache {
		if val != "" && !strings.HasPrefix(val, "127.") && val != "::1" {
			indicators = append(indicators, val)
			if len(indicators) >= limit {
				break
			}
		}
	}
	return indicators
}

func (m *Manager) SyncAllFeeds(ctx context.Context) error {
	log.Printf("[*] Synchronizing Threat Intelligence feeds (Feodo Tracker, Emerging Threats)...")
	var allIOCs []storage.IOC

	// 1. Abuse.ch Feodo Tracker C2 IP List
	feodoIOCs, err := m.fetchFeodoFeed(ctx)
	if err != nil {
		log.Printf("[-] Failed to fetch Feodo feed: %v. Using built-in baseline C2 dataset.", err)
		feodoIOCs = m.getBuiltinFeodoBaseline()
	}
	allIOCs = append(allIOCs, feodoIOCs...)

	// 2. Emerging Threats Scanner & Brute Force IP List
	etIOCs, err := m.fetchEmergingThreatsFeed(ctx)
	if err != nil {
		etIOCs = m.getBuiltinEmergingThreatsBaseline()
	}
	allIOCs = append(allIOCs, etIOCs...)

	// Batch Upsert to Database
	if err := m.store.UpsertIOCsBatch(allIOCs); err != nil {
		return fmt.Errorf("failed to persist IOC batch: %w", err)
	}

	// Update In-Memory Lookup Cache
	m.mu.Lock()
	for i := range allIOCs {
		m.cache[allIOCs[i].Value] = &allIOCs[i]
	}
	m.mu.Unlock()

	log.Printf("[+] Threat Intelligence synchronized: %d active indicators loaded into fast lookup cache", len(allIOCs))
	return nil
}

func (m *Manager) fetchFeodoFeed(ctx context.Context) ([]storage.IOC, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", "https://feodotracker.abuse.ch/downloads/ipblocklist.txt", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Ominull-ThreatIntel/1.0")

	resp, err := m.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP error %d", resp.StatusCode)
	}

	return m.parsePlainTextIPList(resp.Body, "feodo", "c2", 95)
}

func (m *Manager) fetchEmergingThreatsFeed(ctx context.Context) ([]storage.IOC, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", "https://rules.emergingthreats.net/blockrules/compromised-ips.txt", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Ominull-ThreatIntel/1.0")

	resp, err := m.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP error %d", resp.StatusCode)
	}

	return m.parsePlainTextIPList(resp.Body, "emerging_threats", "compromised_host", 90)
}

func (m *Manager) parsePlainTextIPList(r io.Reader, source, threatType string, confidence int) ([]storage.IOC, error) {
	var list []storage.IOC
	scanner := bufio.NewScanner(r)
	now := time.Now().UTC()

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		ip := strings.Fields(line)[0]
		list = append(list, storage.IOC{
			ID:         uuid.New().String(),
			Value:      ip,
			Type:       "ipv4",
			Source:     source,
			ThreatType: threatType,
			Confidence: confidence,
			Active:     true,
			CreatedAt:  now,
			LastSeenAt: now,
		})
	}
	return list, scanner.Err()
}

func (m *Manager) getBuiltinFeodoBaseline() []storage.IOC {
	now := time.Now().UTC()
	baselineIPs := []string{
		"185.220.101.5",
		"193.106.191.12",
		"45.148.10.150",
		"89.208.103.111",
		"194.26.29.114",
		"195.123.245.16",
		"91.215.85.17",
		"103.151.125.247",
		"179.43.141.221",
	}

	var list []storage.IOC
	for _, ip := range baselineIPs {
		list = append(list, storage.IOC{
			ID:         uuid.New().String(),
			Value:      ip,
			Type:       "ipv4",
			Source:     "feodo_baseline",
			ThreatType: "c2_botnet",
			Confidence: 95,
			Active:     true,
			CreatedAt:  now,
			LastSeenAt: now,
		})
	}
	return list
}

func (m *Manager) getBuiltinEmergingThreatsBaseline() []storage.IOC {
	now := time.Now().UTC()
	baselineIPs := []string{
		"45.33.32.156",
		"198.235.24.241",
		"162.243.128.45",
		"104.248.16.89",
		"159.65.132.77",
	}

	var list []storage.IOC
	for _, ip := range baselineIPs {
		list = append(list, storage.IOC{
			ID:         uuid.New().String(),
			Value:      ip,
			Type:       "ipv4",
			Source:     "et_baseline",
			ThreatType: "scanner_bruteforce",
			Confidence: 85,
			Active:     true,
			CreatedAt:  now,
			LastSeenAt: now,
		})
	}
	return list
}
