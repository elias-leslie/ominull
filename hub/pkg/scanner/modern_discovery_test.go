package scanner

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"ominull/hub/pkg/storage"
)

func TestTLSIdentityMatching(t *testing.T) {
	tests := []struct {
		input      string
		wantName   string
		wantCat    string
		wantStated bool
	}{
		{
			input:      "tls-cert:CN=pve.proxmox.lan | O=Proxmox Server Solutions | SAN=pve.proxmox.lan",
			wantName:   "Proxmox VE Hypervisor",
			wantCat:    "Hypervisor / Virtualization",
			wantStated: true,
		},
		{
			input:      "tls-cert:CN=fortigate.corp.lan | O=Fortinet | SAN=fortigate.corp.lan",
			wantName:   "Fortinet FortiGate Firewall",
			wantCat:    "Security Gateway / Firewall",
			wantStated: true,
		},
		{
			input:      "tls-cert:CN=vpn.enterprise.com | O=Palo Alto Networks | SAN=vpn.enterprise.com",
			wantName:   "Palo Alto Networks PAN-OS Firewall",
			wantCat:    "Security Gateway / Firewall",
			wantStated: true,
		},
		{
			input:      "tls-cert:CN=sonicwall.lan | O=SonicWall Inc. | SAN=sonicwall.lan",
			wantName:   "SonicWall Security Gateway",
			wantCat:    "Security Gateway / Firewall",
			wantStated: true,
		},
		{
			input:      "tls-cert:CN=firebox.branch.lan | O=WatchGuard | SAN=firebox.branch.lan",
			wantName:   "WatchGuard Firebox Gateway",
			wantCat:    "Security Gateway / Firewall",
			wantStated: true,
		},
		{
			input:      "tls-cert:CN=idrac-SRV01 | O=Dell Inc. | SAN=idrac-SRV01.corp",
			wantName:   "Dell iDRAC Remote Access Controller",
			wantCat:    "Out-of-Band Management / IPMI",
			wantStated: true,
		},
		{
			input:      "tls-cert:CN=ilo-ESX01 | O=Hewlett Packard Enterprise | SAN=ilo-ESX01.corp",
			wantName:   "HPE iLO Remote Management",
			wantCat:    "Out-of-Band Management / IPMI",
			wantStated: true,
		},
		{
			input:      "tls-cert:CN=synology.home | O=Synology Inc. | SAN=synology.home",
			wantName:   "Synology DiskStation NAS",
			wantCat:    "Storage / NAS",
			wantStated: true,
		},
		{
			input:      "tls-cert:CN=unifi.local | O=Ubiquiti Networks | SAN=unifi.local",
			wantName:   "Ubiquiti UniFi Console",
			wantCat:    "Network Gear",
			wantStated: true,
		},
		{
			input:      "tls-cert:CN=esxi-host-01 | O=VMware, Inc. | SAN=esxi-host-01",
			wantName:   "VMware ESXi / vCenter Server",
			wantCat:    "Hypervisor / Virtualization",
			wantStated: true,
		},
		{
			input:      "tls-cert:CN=truenas.local | SAN=truenas.local",
			wantName:   "TrueNAS Storage Server",
			wantCat:    "Storage / NAS",
			wantStated: true,
		},
		{
			input:      "tls-cert:CN=kube-apiserver | SAN=kubernetes,kubernetes.default",
			wantName:   "Kubernetes Control Plane Node",
			wantCat:    "Container Orchestrator",
			wantStated: true,
		},
	}

	for _, tc := range tests {
		id := identityFromTLSCert(tc.input)
		if id == nil {
			t.Fatalf("identityFromTLSCert(%q) returned nil", tc.input)
		}
		if id.Name != tc.wantName {
			t.Errorf("identityFromTLSCert(%q) Name = %q; want %q", tc.input, id.Name, tc.wantName)
		}
		if id.Category != tc.wantCat {
			t.Errorf("identityFromTLSCert(%q) Category = %q; want %q", tc.input, id.Category, tc.wantCat)
		}
		if tc.wantStated && id.Confidence < confStated {
			t.Errorf("identityFromTLSCert(%q) Confidence = %v; want >= %v", tc.input, id.Confidence, confStated)
		}
	}
}

func TestHTTPTitleIdentityMatching(t *testing.T) {
	tests := []struct {
		input    string
		wantName string
		wantCat  string
	}{
		{
			input:    "http-title:Proxmox Virtual Environment",
			wantName: "Proxmox VE Hypervisor (Proxmox Virtual Environment)",
			wantCat:  "Hypervisor / Virtualization",
		},
		{
			input:    "http-title:VMware ESXi - Welcome to VMware ESXi",
			wantName: "VMware vSphere / ESXi (VMware ESXi - Welcome to VMware ESXi)",
			wantCat:  "Hypervisor / Virtualization",
		},
		{
			input:    "http-title:FortiGate Login",
			wantName: "Fortinet FortiGate Firewall (FortiGate Login)",
			wantCat:  "Security Gateway / Firewall",
		},
		{
			input:    "http-title:Palo Alto Networks - GlobalProtect Portal",
			wantName: "Palo Alto Networks Firewall (Palo Alto Networks - GlobalProtect Portal)",
			wantCat:  "Security Gateway / Firewall",
		},
		{
			input:    "http-title:SonicWall - Network Security Appliance",
			wantName: "SonicWall Security Gateway (SonicWall - Network Security Appliance)",
			wantCat:  "Security Gateway / Firewall",
		},
		{
			input:    "http-title:WatchGuard Fireware Web UI",
			wantName: "WatchGuard Firebox (WatchGuard Fireware Web UI)",
			wantCat:  "Security Gateway / Firewall",
		},
		{
			input:    "http-title:iDRAC - Integrated Dell Remote Access Controller 9",
			wantName: "Dell iDRAC Remote Access Controller",
			wantCat:  "Out-of-Band Management / IPMI",
		},
		{
			input:    "http-title:iLO 5 - Integrated Lights-Out",
			wantName: "HPE iLO Remote Management",
			wantCat:  "Out-of-Band Management / IPMI",
		},
		{
			input:    "http-title:Home Assistant",
			wantName: "Home Assistant OS",
			wantCat:  "Smart Home / IoT",
		},
		{
			input:    "http-title:Pi-hole - Admin Console",
			wantName: "Pi-hole DNS Sinkhole",
			wantCat:  "Network Gear",
		},
		{
			input:    "http-title:UniFi Network",
			wantName: "Ubiquiti UniFi Gateway (UniFi Network)",
			wantCat:  "Network Gear",
		},
		{
			input:    "http-title:OpenWrt - LuCI",
			wantName: "OpenWrt Linux Router",
			wantCat:  "Network Gear",
		},
		{
			input:    "http-title:ESPHome Node - Living Room Light",
			wantName: "ESPHome Smart Device",
			wantCat:  "Smart Home / IoT",
		},
	}

	for _, tc := range tests {
		id := identityFromHTTPTitle(tc.input)
		if id == nil {
			t.Fatalf("identityFromHTTPTitle(%q) returned nil", tc.input)
		}
		if id.Name != tc.wantName {
			t.Errorf("identityFromHTTPTitle(%q) Name = %q; want %q", tc.input, id.Name, tc.wantName)
		}
		if id.Category != tc.wantCat {
			t.Errorf("identityFromHTTPTitle(%q) Category = %q; want %q", tc.input, id.Category, tc.wantCat)
		}
	}
}

func TestHTTPServerBannerMatching(t *testing.T) {
	tests := []struct {
		input    string
		wantName string
		wantCat  string
	}{
		{
			input:    "Microsoft-IIS/10.0",
			wantName: "Windows Server (Microsoft-IIS)",
			wantCat:  "Web Server",
		},
		{
			input:    "Apache/2.4.58 (Ubuntu)",
			wantName: "Ubuntu Linux (Apache/2.4.58 (Ubuntu))",
			wantCat:  "Server",
		},
		{
			input:    "Apache/2.4.58",
			wantName: "Apache HTTP Server (Apache/2.4.58)",
			wantCat:  "Web Server",
		},
		{
			input:    "nginx/1.24.0",
			wantName: "Nginx Web Server (nginx/1.24.0)",
			wantCat:  "Web Server",
		},
		{
			input:    "Caddy",
			wantName: "Caddy Web Server",
			wantCat:  "Web Server",
		},
		{
			input:    "LiteSpeed",
			wantName: "LiteSpeed Web Server",
			wantCat:  "Web Server",
		},
		{
			input:    "FortiGate-SSL-VPN",
			wantName: "Fortinet FortiGate Firewall",
			wantCat:  "Security Gateway / Firewall",
		},
		{
			input:    "SonicWALL",
			wantName: "SonicWall Security Gateway",
			wantCat:  "Security Gateway / Firewall",
		},
	}

	for _, tc := range tests {
		id := identityFromHTTPServer(tc.input)
		if id == nil {
			t.Fatalf("identityFromHTTPServer(%q) returned nil", tc.input)
		}
		if id.Name != tc.wantName {
			t.Errorf("identityFromHTTPServer(%q) Name = %q; want %q", tc.input, id.Name, tc.wantName)
		}
		if id.Category != tc.wantCat {
			t.Errorf("identityFromHTTPServer(%q) Category = %q; want %q", tc.input, id.Category, tc.wantCat)
		}
	}
}

func TestDHCPFingerprintMatching(t *testing.T) {
	tests := []struct {
		input    string
		wantName string
		wantCat  string
	}{
		{
			input:    "dhcp:vendor=android-dhcp-14,host=Galaxy-S24",
			wantName: "Android Mobile Device",
			wantCat:  "Mobile",
		},
		{
			input:    "dhcp:vendor=Apple-iPhone,host=Alex-iPhone",
			wantName: "Apple iOS Device (iPhone/iPad)",
			wantCat:  "Mobile",
		},
		{
			input:    "dhcp:vendor=MSFT 5.0,host=DESKTOP-TEST01",
			wantName: "Windows Host (DHCP MSFT 5.0)",
			wantCat:  "Workstation",
		},
		{
			input:    "dhcp:vendor=Roku/DV-1.0,host=Living-Room-Roku",
			wantName: "Roku Streaming Player",
			wantCat:  "Smart TV / Media Streamer",
		},
		{
			input:    "dhcp:vendor=shellyplugus-1234,host=shelly-kitchen",
			wantName: "Shelly Smart Relay / Sensor",
			wantCat:  "Smart Home / IoT",
		},
	}

	for _, tc := range tests {
		id := identityFromDHCP(tc.input)
		if id == nil {
			t.Fatalf("identityFromDHCP(%q) returned nil", tc.input)
		}
		if id.Name != tc.wantName {
			t.Errorf("identityFromDHCP(%q) Name = %q; want %q", tc.input, id.Name, tc.wantName)
		}
		if id.Category != tc.wantCat {
			t.Errorf("identityFromDHCP(%q) Category = %q; want %q", tc.input, id.Category, tc.wantCat)
		}
	}
}

func TestExpandedOUIVendorLookup(t *testing.T) {
	tests := []struct {
		mac        string
		wantVendor string
	}{
		{"CC:50:E3:11:22:33", "Shelly / Allterco Robotics"},
		{"00:17:88:AA:BB:CC", "Philips Lighting (Hue)"},
		{"00:0E:58:12:34:56", "Sonos, Inc."},
		{"D0:52:A8:99:88:77", "Roku, Inc."},
		{"60:A4:4C:44:55:66", "Tuya Smart Inc. (IoT)"},
		{"E0:63:DA:01:02:03", "Ubiquiti Networks"},
		{"18:66:DA:77:88:99", "Dell Inc."},
		{"B4:2E:99:11:33:55", "Intel Corporation"},
	}

	for _, tc := range tests {
		got := LookupVendor(tc.mac)
		if got != tc.wantVendor {
			t.Errorf("LookupVendor(%q) = %q; want %q", tc.mac, got, tc.wantVendor)
		}
	}
}

func TestDHCPPacketParser(t *testing.T) {
	// Construct a synthetic RFC-2131 DHCP Request packet
	buf := make([]byte, 300)
	buf[0] = 0x01                                                // BootRequest
	buf[1] = 0x01                                                // 10mb ethernet
	buf[2] = 0x06                                                // hlen
	copy(buf[28:34], []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}) // CHAddr

	// Magic cookie at 236
	buf[236] = 0x63
	buf[237] = 0x82
	buf[238] = 0x53
	buf[239] = 0x63

	// Option 53: DHCP Request (3)
	buf[240] = 53
	buf[241] = 1
	buf[242] = 3

	// Option 12: Hostname "test-device"
	buf[243] = 12
	buf[244] = 11
	copy(buf[245:256], []byte("test-device"))

	// Option 60: Vendor Class "android-dhcp-14"
	buf[256] = 60
	buf[257] = 15
	copy(buf[258:273], []byte("android-dhcp-14"))

	// Option 255: End
	buf[273] = 255

	pkt := parseDHCPPacket(buf)
	if pkt == nil {
		t.Fatalf("parseDHCPPacket returned nil for valid DHCP packet")
	}
	if pkt.CHAddr.String() != "00:11:22:33:44:55" {
		t.Errorf("CHAddr = %q; want 00:11:22:33:44:55", pkt.CHAddr.String())
	}
	if pkt.Hostname != "test-device" {
		t.Errorf("Hostname = %q; want 'test-device'", pkt.Hostname)
	}
	if pkt.VendorClass != "android-dhcp-14" {
		t.Errorf("VendorClass = %q; want 'android-dhcp-14'", pkt.VendorClass)
	}
}

func TestLiveTLSCertAndHTTPProbe(t *testing.T) {
	// Spin up mock TLS server with self-signed certificate
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate rsa key: %v", err)
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "proxmox.test.lan",
			Organization: []string{"Proxmox Server Solutions"},
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:              []string{"proxmox.test.lan", "pve.test.lan"},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}

	tlsCert := tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  priv,
	}

	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "pve-api-daemon/3.0")
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<!DOCTYPE html><html><head><title>Proxmox Virtual Environment</title></head><body><h1>PVE</h1></body></html>`))
	}))
	ts.TLS = &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
	}
	ts.StartTLS()
	defer ts.Close()

	host, portStr, err := net.SplitHostPort(ts.Listener.Addr().String())
	if err != nil {
		t.Fatalf("split host port: %v", err)
	}
	port, _ := strconv.Atoi(portStr)

	// 1. Test probeTLSCert
	certInfo := probeTLSCert(host, port)
	if !strings.Contains(certInfo, "CN=proxmox.test.lan") || !strings.Contains(certInfo, "O=Proxmox Server Solutions") {
		t.Errorf("probeTLSCert = %q; expected CN and O to match", certInfo)
	}

	// 2. Test probeHTTPInfo (TLS)
	title, server, banner := probeHTTPInfo(host, port, true)
	if title != "Proxmox Virtual Environment" {
		t.Errorf("probeHTTPInfo title = %q; want 'Proxmox Virtual Environment'", title)
	}
	if server != "pve-api-daemon/3.0" {
		t.Errorf("probeHTTPInfo server = %q; want 'pve-api-daemon/3.0'", server)
	}
	if !strings.Contains(banner, "HTTP 200") {
		t.Errorf("probeHTTPInfo banner = %q; want HTTP 200", banner)
	}

	// 3. Test IdentifyHost with the probe outputs
	ident := IdentifyHost("00:50:56:01:02:03", 64, []int{port}, []string{"Server: " + server}, []string{certInfo, "http-title:" + title}, 1.2, nil)
	if !strings.Contains(ident.Name, "Proxmox VE") {
		t.Errorf("IdentifyHost = %q; want Proxmox VE", ident.Name)
	}
}

func TestSchedulerAnomalyDetection(t *testing.T) {
	dbPath := t.TempDir() + "/test-scheduler.db"
	store, err := storage.New(dbPath)
	if err != nil {
		t.Fatalf("open temp store: %v", err)
	}
	defer store.Close()

	sc := New(store)
	defer sc.StopBackground()

	// Seed cached unmanaged asset
	sc.mu.Lock()
	sc.cachedAssets["10.0.0.199"] = DiscoveredAsset{
		IP:             "10.0.0.199",
		MAC:            "CC:50:E3:99:88:77",
		Vendor:         "Shelly / Allterco Robotics",
		Hostname:       "shelly-plug-novel",
		OSGuess:        "Shelly Smart Relay / Sensor",
		Category:       "Smart Home / IoT",
		Confidence:     0.95,
		RiskScore:      "HIGH",
		OpenPorts:      []PortInfo{{Port: 80, Service: "HTTP", RiskLevel: "MEDIUM"}},
		IdentityMethod: "http-title",
	}
	sc.mu.Unlock()

	scheduler := NewScheduler(sc, store, 1*time.Hour, []string{"10.0.0.0/24"})
	knownMap := map[string]bool{"10.0.0.1": true} // 10.0.0.199 is novel

	scheduler.evaluateNewDevices(knownMap)

	// Verify alert was inserted into SQLite
	alerts, err := store.ListAnomalyAlerts("default", 10)
	if err != nil {
		t.Fatalf("list alerts: %v", err)
	}
	if len(alerts) != 1 {
		t.Fatalf("expected 1 anomaly alert, got %d", len(alerts))
	}
	if alerts[0].DstIP != "10.0.0.199" {
		t.Errorf("alert DstIP = %q; want 10.0.0.199", alerts[0].DstIP)
	}
	if !strings.Contains(alerts[0].Title, "New Unmanaged Device") {
		t.Errorf("alert Title = %q; want New Unmanaged Device", alerts[0].Title)
	}
}

func TestSchedulerOffByDefault(t *testing.T) {
	dbPath := t.TempDir() + "/test-scheduler-off.db"
	store, err := storage.New(dbPath)
	if err != nil {
		t.Fatalf("open temp store: %v", err)
	}
	defer store.Close()

	sc := New(store)
	defer sc.StopBackground()

	// Fresh install: scheduler created with nil subnets
	sched := NewScheduler(sc, store, 1*time.Hour, nil)
	if len(sched.Subnets()) != 0 {
		t.Errorf("expected 0 subnets by default, got %d", len(sched.Subnets()))
	}
	sched.Start()
	if sched.isRunning {
		t.Errorf("scheduler should not be running when subnets list is empty")
	}
	sched.Stop()

	// Configure explicit subnets
	sched.SetSubnets([]string{"10.0.0.0/24"})
	if len(sched.Subnets()) != 1 || sched.Subnets()[0] != "10.0.0.0/24" {
		t.Errorf("SetSubnets did not update subnets: %v", sched.Subnets())
	}
	sched.Start()
	if !sched.isRunning {
		t.Errorf("scheduler should be running when explicit subnets are configured")
	}
	sched.Stop()
	if sched.isRunning {
		t.Errorf("scheduler should be stopped after Stop()")
	}
}

func TestDHCPSnooperLifecycle(t *testing.T) {
	sc := New(nil)
	snooper := NewDHCPSnooper(sc)
	if snooper.IsServing() {
		t.Errorf("expected IsServing() false on new instance")
	}
	// Stop on inactive instance is a safe no-op
	snooper.Stop()
	if snooper.IsServing() {
		t.Errorf("expected IsServing() false after Stop()")
	}
}
