package detector

import (
	"context"
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"ominull/hub/pkg/storage"
)

type IsolateFunc func(endpointID string, reason string) error

type Engine struct {
	store         *storage.Store
	onAutoIsolate IsolateFunc
	eventsChan    <-chan storage.Event
	mu            sync.Mutex
	portHistory   map[string][]portAccess // endpointID -> accesses
	cancel        context.CancelFunc
}

type portAccess struct {
	port uint16
	t    time.Time
}

func New(store *storage.Store, eventsChan <-chan storage.Event, onAutoIsolate IsolateFunc) *Engine {
	return &Engine{
		store:         store,
		eventsChan:    eventsChan,
		onAutoIsolate: onAutoIsolate,
		portHistory:   make(map[string][]portAccess),
	}
}

func (e *Engine) Start(ctx context.Context) {
	subCtx, cancel := context.WithCancel(ctx)
	e.cancel = cancel

	go func() {
		for {
			select {
			case <-subCtx.Done():
				return
			case ev, ok := <-e.eventsChan:
				if !ok {
					return
				}
				e.Evaluate(ev)
			}
		}
	}()
}

func (e *Engine) Stop() {
	if e.cancel != nil {
		e.cancel()
	}
}

func (e *Engine) Evaluate(ev storage.Event) {
	now := time.Now().UTC()

	// 1. Check for Rapid Port Sweeps / Reconnaissance
	if ev.Direction == "OUTBOUND" && ev.DstPort > 0 {
		e.mu.Lock()
		history := e.portHistory[ev.EndpointID]
		// Prune older than 10 seconds
		var recent []portAccess
		seenPorts := make(map[uint16]bool)
		for _, p := range history {
			if now.Sub(p.t) <= 10*time.Second {
				recent = append(recent, p)
				seenPorts[p.port] = true
			}
		}
		recent = append(recent, portAccess{port: ev.DstPort, t: now})
		seenPorts[ev.DstPort] = true
		e.portHistory[ev.EndpointID] = recent
		distinctCount := len(seenPorts)
		e.mu.Unlock()

		if distinctCount >= 15 {
			alert := storage.Alert{
				ID:          uuid.New().String(),
				TenantID:    ev.TenantID,
				EndpointID:  ev.EndpointID,
				Timestamp:   now,
				Title:       "High-Velocity Port Sweep Detected",
				Description: fmt.Sprintf("Process %s (PID %d) initiated connections to %d distinct destination ports within 10 seconds.", ev.ProcessPath, ev.ProcessID, distinctCount),
				Severity:    "HIGH",
				Mitigated:   false,
			}
			_ = e.store.CreateAlert(alert)
			log.Printf("[!] DETECTION ALERT [HIGH]: %s on endpoint %s", alert.Title, alert.EndpointID)
		}
	}

	// 2. Suspicious Shell / Script Engine External Connection
	procLower := strings.ToLower(ev.ProcessPath)
	isScriptEngine := strings.HasSuffix(procLower, "powershell.exe") ||
		strings.HasSuffix(procLower, "cmd.exe") ||
		strings.HasSuffix(procLower, "wscript.exe") ||
		strings.HasSuffix(procLower, "cscript.exe") ||
		strings.HasSuffix(procLower, "nc") ||
		strings.HasSuffix(procLower, "ncat") ||
		strings.HasSuffix(procLower, "/sh") ||
		strings.HasSuffix(procLower, "/bash")

	if isScriptEngine && ev.Direction == "OUTBOUND" && !isPrivateIP(ev.DstIP) {
		alert := storage.Alert{
			ID:          uuid.New().String(),
			TenantID:    ev.TenantID,
			EndpointID:  ev.EndpointID,
			Timestamp:   now,
			Title:       "Suspicious Interactive Shell External Egress",
			Description: fmt.Sprintf("Script interpreter %s established outbound connection to external IP %s:%d.", ev.ProcessPath, ev.DstIP, ev.DstPort),
			Severity:    "HIGH",
			Mitigated:   false,
		}
		_ = e.store.CreateAlert(alert)
		log.Printf("[!] DETECTION ALERT [HIGH]: %s on endpoint %s (%s:%d)", alert.Title, alert.EndpointID, ev.DstIP, ev.DstPort)
	}

	// 3. Automated Nullification for Blocked Threats
	if ev.Action == "BLOCK" {
		alert := storage.Alert{
			ID:          uuid.New().String(),
			TenantID:    ev.TenantID,
			EndpointID:  ev.EndpointID,
			Timestamp:   now,
			Title:       "Critical Threat Nullification Triggered",
			Description: fmt.Sprintf("Confirmed threat connection to %s blocked at ring-0. Initiating host network quarantine.", ev.DstIP),
			Severity:    "CRITICAL",
			Mitigated:   true,
		}
		_ = e.store.CreateAlert(alert)
		log.Printf("[!] DETECTION ALERT [CRITICAL]: %s on endpoint %s", alert.Title, alert.EndpointID)

		if e.onAutoIsolate != nil {
			_ = e.onAutoIsolate(ev.EndpointID, "Automated Threat Nullification: "+alert.Title)
		}
	}
}

func isPrivateIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	return ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast()
}
