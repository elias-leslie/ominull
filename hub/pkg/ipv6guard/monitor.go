package ipv6guard

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"
)

type Peer struct {
	IP  string `json:"ip"`
	MAC string `json:"mac"`
}
type Config struct {
	TenantID    string   `json:"tenant_id"`
	Enabled     bool     `json:"enabled"`
	Interface   string   `json:"interface"`
	Routers     []Peer   `json:"routers"`
	DHCPServers []Peer   `json:"dhcp_servers"`
	Prefixes    []string `json:"prefixes"`
	DNS         []string `json:"dns"`
}

func (c *Config) Validate() error {
	if c.Enabled && c.TenantID == "" {
		return fmt.Errorf("choose the tenant that owns this monitored link")
	}
	if c.Enabled && c.Interface == "" {
		return fmt.Errorf("choose a capture interface")
	}
	if len(c.Interface) > 15 || strings.ContainsAny(c.Interface, "/\x00\r\n ") {
		return fmt.Errorf("invalid interface name")
	}
	for _, peers := range [][]Peer{c.Routers, c.DHCPServers} {
		if len(peers) > 64 {
			return fmt.Errorf("at most 64 trusted peers")
		}
		for i := range peers {
			ip, err := netip.ParseAddr(peers[i].IP)
			mac, e := net.ParseMAC(peers[i].MAC)
			if err != nil || !ip.Is6() || ip.Is4In6() || ip.Zone() != "" || ip.IsMulticast() || ip.IsUnspecified() || e != nil || len(mac) != 6 || mac[0]&1 != 0 || mac.String() == "00:00:00:00:00:00" {
				return fmt.Errorf("trusted peers require an IPv6 address without zone and a unicast MAC")
			}
			peers[i].IP = ip.String()
			peers[i].MAC = mac.String()
		}
	}
	if len(c.Prefixes) > 64 || len(c.DNS) > 64 {
		return fmt.Errorf("at most 64 trusted prefixes or DNS addresses")
	}
	for i, raw := range c.Prefixes {
		p, err := netip.ParsePrefix(raw)
		if err != nil || !p.Addr().Is6() || p.Addr().Is4In6() || p.Bits() == 0 || p.Addr().IsMulticast() {
			return fmt.Errorf("invalid trusted IPv6 prefix")
		}
		c.Prefixes[i] = p.Masked().String()
	}
	for i, raw := range c.DNS {
		ip, err := netip.ParseAddr(raw)
		if err != nil || !ip.Is6() || ip.Is4In6() || ip.Zone() != "" || ip.IsMulticast() || ip.IsUnspecified() {
			return fmt.Errorf("invalid trusted IPv6 DNS address")
		}
		c.DNS[i] = ip.WithZone("").String()
	}
	return nil
}
func Violations(o Observation, c Config) []string {
	var out []string
	trusted := func(peers []Peer) bool {
		ip, err := netip.ParseAddr(o.Source)
		if err != nil {
			return false
		}
		for _, p := range peers {
			if p.IP == ip.WithZone("").String() && strings.EqualFold(p.MAC, o.MAC) {
				return true
			}
		}
		return false
	}
	if o.Kind == "router_advertisement" {
		if len(c.Routers) > 0 && !trusted(c.Routers) {
			out = append(out, "Router advertisement from an unapproved IP/MAC pair")
		}
		for _, raw := range o.Prefixes {
			p, _ := netip.ParsePrefix(raw)
			approved := len(c.Prefixes) == 0
			for _, expected := range c.Prefixes {
				allowed, _ := netip.ParsePrefix(expected)
				if allowed.Bits() <= p.Bits() && allowed.Contains(p.Addr()) {
					approved = true
				}
			}
			if !approved {
				out = append(out, "Unapproved advertised prefix "+raw)
			}
		}
	}
	if o.Kind == "dhcpv6_server" && len(c.DHCPServers) > 0 && !trusted(c.DHCPServers) {
		out = append(out, "DHCPv6 server response from an unapproved IP/MAC pair")
	}
	candidates := o.DNS
	if o.Kind == "wpad_query" {
		ip, e := netip.ParseAddr(o.Destination)
		if e == nil {
			candidates = []string{ip.WithZone("").String()}
		}
	}
	for _, raw := range candidates {
		approved := len(c.DNS) == 0
		for _, expected := range c.DNS {
			if expected == raw {
				approved = true
			}
		}
		if !approved {
			out = append(out, "Unapproved IPv6 DNS address "+raw)
		}
	}
	return out
}

type Status struct {
	PersistenceError string    `json:"persistence_error,omitempty"`
	Active           bool      `json:"active"`
	Interface        string    `json:"interface"`
	Error            string    `json:"error,omitempty"`
	Packets          uint64    `json:"packets"`
	Observations     uint64    `json:"observations"`
	Malformed        uint64    `json:"malformed"`
	Dropped          uint64    `json:"dropped"`
	LastPacket       time.Time `json:"last_packet"`
}

var errNoPacket = errors.New("no packet before capture deadline")

type packetReader interface {
	Read([]byte) (int, error)
	Close() error
}
type Monitor struct {
	control sync.Mutex
	mu      sync.Mutex
	status  Status
	pending map[[32]byte]Observation
	cancel  context.CancelFunc
	done    chan struct{}
	consume func([]Observation, Config)
}

func New(consume func([]Observation, Config)) *Monitor {
	return &Monitor{consume: consume, pending: map[[32]byte]Observation{}}
}
func (m *Monitor) Status() Status { m.mu.Lock(); defer m.mu.Unlock(); return m.status }
func (m *Monitor) stop() {
	if m.cancel != nil {
		m.cancel()
		<-m.done
		m.cancel = nil
	}
}
func (m *Monitor) Stop() { m.control.Lock(); defer m.control.Unlock(); m.stop() }
func (m *Monitor) Configure(c Config) error {
	m.control.Lock()
	defer m.control.Unlock()
	if err := c.Validate(); err != nil {
		return err
	}
	m.stop()
	m.mu.Lock()
	m.status = Status{Interface: c.Interface}
	m.mu.Unlock()
	if !c.Enabled {
		return nil
	}
	reader, err := openCapture(c.Interface)
	if err != nil {
		m.mu.Lock()
		m.status.Error = err.Error()
		m.mu.Unlock()
		return err
	}
	ctx, cancel := context.WithCancel(context.Background())
	m.cancel = cancel
	m.done = make(chan struct{})
	m.mu.Lock()
	m.status.Active = true
	m.mu.Unlock()
	go func() {
		defer close(m.done)
		defer reader.Close()
		defer m.flush(c)
		defer func() { m.mu.Lock(); m.status.Active = false; m.mu.Unlock() }()
		buffer := make([]byte, 65536)
		flushed := time.Now()
		for {
			if ctx.Err() != nil {
				return
			}
			n, err := reader.Read(buffer)
			if err != nil && !errors.Is(err, errNoPacket) {
				m.mu.Lock()
				m.status.Error = err.Error()
				m.mu.Unlock()
				return
			}
			if n > 0 {
				m.Observe(buffer[:n], c.Interface, time.Now().UTC())
			}
			if time.Since(flushed) >= 5*time.Second {
				m.flush(c)
				flushed = time.Now()
			}
		}
	}()
	return nil
}

// Observe is also the deterministic packet replay seam used by synthetic tests.
func (m *Monitor) Observe(frame []byte, iface string, at time.Time) {
	o, err := ParseFrame(frame, iface, at)
	m.mu.Lock()
	defer m.mu.Unlock()
	m.status.Packets++
	m.status.LastPacket = at
	if err != nil {
		m.status.Malformed++
		return
	}
	if o.Kind == "" {
		return
	}
	m.status.Observations++
	keyValue := o
	keyValue.FirstSeen = time.Time{}
	keyValue.LastSeen = time.Time{}
	keyValue.Count = 0
	raw, _ := json.Marshal(keyValue)
	key := sha256.Sum256(raw)
	if prev, ok := m.pending[key]; ok {
		o.FirstSeen = prev.FirstSeen
		o.Count += prev.Count
	} else if len(m.pending) >= 1024 {
		m.status.Dropped++
		return
	}
	m.pending[key] = o
}
func (m *Monitor) flush(c Config) {
	m.mu.Lock()
	batch := make([]Observation, 0, len(m.pending))
	for _, o := range m.pending {
		batch = append(batch, o)
	}
	clear(m.pending)
	m.mu.Unlock()
	if len(batch) > 0 && m.consume != nil {
		m.consume(batch, c)
	}
}

func (m *Monitor) PersistenceResult(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.status.PersistenceError = ""
	if err != nil {
		m.status.PersistenceError = err.Error()
	}
}
