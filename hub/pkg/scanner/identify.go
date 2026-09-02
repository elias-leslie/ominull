package scanner

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// Identity is what the scanner concluded about a host and why.
//
// The "why" is not decoration. The console reported "Ubuntu Linux" for hosts
// that were plainly not Ubuntu, and there was no way to see what had persuaded
// it - the answer was a regex that matched the word "OpenSSH" in a signature
// whose name happened to say Ubuntu. A conclusion that cannot show its working
// cannot be corrected.
type Identity struct {
	Name       string   `json:"name"`       // "Ubuntu 24.04 LTS", "Windows 11", "MikroTik RouterOS"
	Category   string   `json:"category"`   // Workstation, Server, Network Gear, ...
	Confidence float64  `json:"confidence"` // 0..1
	Method     string   `json:"method"`     // "ssh-banner", "mdns-device-info", "signature", ...
	Evidence   []string `json:"evidence"`   // the exact strings that decided it
}

// identityConfidence separates the three kinds of answer this scanner can give.
//
//   - stated: the host told us, in a string that names its own product and
//     version. An SSH banner reading "OpenSSH_9.6p1 Ubuntu-3ubuntu13.5" is not
//     a guess.
//   - derived: an unambiguous protocol answered, but it names a family rather
//     than a release.
//   - weak: something answered, but what it said narrows the field rather than
//     naming anything. "A Unix of some kind" is the honest reading of an
//     OpenSSH banner with no distribution suffix, and it has to rank below a
//     match that actually points at a platform.
//   - inferred: the weighted signature match, which is where every wrong answer
//     came from and which now only speaks when nothing better has.
const (
	confStated   = 0.97
	confDerived  = 0.85
	confWeak     = 0.70
	confInferred = 0.55
)

// IdentifyHost decides what a host is from everything the sweep collected,
// strongest evidence first. Order matters: a definitive banner outranks a
// signature score however high that score happens to be, because the score is
// a heuristic and the banner is the host's own answer.
func IdentifyHost(mac string, ttl int, openPorts []int, banners []string, extras []string, appDeltaMs float64, customSigs []DeviceSignature) Identity {
	all := append(append([]string{}, banners...), extras...)

	if id := bestStatedIdentity(all); id != nil {
		refine(id, openPorts, all)
		return *id
	}

	// Nothing stated its name. Fall back to the weighted signature match, which
	// is now required to win by a margin and to clear a floor before it is
	// allowed to put a product name on a host.
	name, score, category, why := matchSignature(mac, ttl, openPorts, banners, appDeltaMs, customSigs)
	ev := append([]string{}, why...)
	if len(all) > 0 {
		ev = append(ev, "banners: "+strings.Join(trimAll(all, 60), " | "))
	}
	return Identity{Name: name, Category: category, Confidence: score, Method: "signature", Evidence: ev}
}

// bestStatedIdentity asks every matcher and keeps the most confident answer,
// rather than the first one to speak.
//
// Order used to decide this, and it produced exactly the wrong result on a Mac:
// the SSH matcher ran first and returned "Unix-like host" - true, weak, and
// enough to stop anything else being consulted - while the mDNS service list
// sitting in the same evidence said plainly that it was a Mac. Evidence should
// be ranked by what it proves, not by where it appears in a list.
//
// Each matcher still returns nil rather than a low-confidence guess: a shrug
// from this layer must not outrank a good signature match.
func bestStatedIdentity(strs []string) *Identity {
	var best *Identity
	consider := func(id *Identity) {
		if id == nil {
			return
		}
		if best == nil || id.Confidence > best.Confidence {
			best = id
		}
	}
	for _, matcher := range []func(string) *Identity{
		identityFromDeviceInfo,
		identityFromTLSCert,
		identityFromHTTPTitle,
		identityFromSNMP,
		identityFromSSH,
		identityFromHTTPServer,
		identityFromSSDP,
		identityFromNetBIOS,
		identityFromDHCP,
		identityFromHostname,
	} {
		for _, s := range strs {
			consider(matcher(s))
		}
	}
	// The published service list is read from the evidence as a whole rather
	// than one string at a time, so it is offered separately.
	consider(identityFromPublishedServices(strs))
	return best
}

// ---------------------------------------------------------------- SSH

var reSSH = regexp.MustCompile(`(?i)^SSH-2\.0-(.+?)\s*$`)

// identityFromSSH reads the software string an SSH server sends before any
// negotiation. On a Debian-family host it carries the distribution's own
// package suffix, which is the single most precise identity available on a
// network without credentials.
func identityFromSSH(s string) *Identity {
	m := reSSH.FindStringSubmatch(strings.TrimSpace(s))
	if m == nil {
		return nil
	}
	soft := strings.TrimSpace(m[1])
	low := strings.ToLower(soft)
	ev := []string{"SSH-2.0-" + soft}

	stated := func(name, category string) *Identity {
		return &Identity{Name: name, Category: category, Confidence: confStated, Method: "ssh-banner", Evidence: ev}
	}

	switch {
	case strings.Contains(low, "openssh_for_windows"):
		return stated("Windows (OpenSSH for Windows)", "Workstation")
	case strings.Contains(low, "ubuntu"):
		return stated("Ubuntu Linux ("+opensshVersion(soft)+")", "Server")
	case strings.Contains(low, "debian"):
		return stated("Debian GNU/Linux ("+opensshVersion(soft)+")", "Server")
	case strings.Contains(low, "raspbian"):
		return stated("Raspberry Pi OS ("+opensshVersion(soft)+")", "Appliance")
	case strings.Contains(low, "freebsd"):
		return stated("FreeBSD ("+opensshVersion(soft)+")", "Server")
	case strings.Contains(low, "rosssh") || strings.Contains(low, "mikrotik"):
		return stated("MikroTik RouterOS", "Network Gear")
	case strings.Contains(low, "cisco"):
		return stated("Cisco IOS", "Network Gear")
	case strings.Contains(low, "dropbear"):
		return stated("Embedded Linux (Dropbear SSH)", "Appliance")
	case strings.Contains(low, "romsshell"):
		return stated("Embedded appliance (RomSShell)", "Appliance")
	case strings.Contains(low, "sun_ssh"):
		return stated("Oracle Solaris", "Server")
	}

	// Plain "OpenSSH_9.6" with no distribution suffix. This is the case that
	// used to be reported as Ubuntu, and it is exactly the case where the only
	// honest answer is that it is a Unix host running OpenSSH.
	if strings.HasPrefix(low, "openssh") {
		return &Identity{
			Name: "Unix-like host (" + opensshVersion(soft) + ")", Category: "Server",
			Confidence: confWeak, Method: "ssh-banner", Evidence: ev,
		}
	}
	return nil
}

var reOpenSSHVer = regexp.MustCompile(`(?i)OpenSSH[_-]([0-9]+\.[0-9]+(p[0-9]+)?)`)

func opensshVersion(soft string) string {
	if m := reOpenSSHVer.FindStringSubmatch(soft); m != nil {
		return "OpenSSH " + m[1]
	}
	return strings.TrimSpace(soft)
}

// ------------------------------------------------------- mDNS device-info

var reModel = regexp.MustCompile(`(?i)model=([A-Za-z0-9,._-]+)`)
var reAppleModel = regexp.MustCompile(`^[A-Za-z]+[0-9]+,[0-9]+$`)

// notAnAppleModel recognises the labels other software publishes in Apple's
// own field.
func notAnAppleModel(model, raw string) *Identity {
	switch strings.ToLower(model) {
	case "macsamba":
		return &Identity{
			Name: "Samba file server", Category: "Server", Confidence: confDerived,
			Method: "mdns-device-info",
			Evidence: []string{strings.TrimSpace(raw),
				"model=MacSamba is Samba's icon hint for macOS Finder, not Apple hardware"},
		}
	case "timecapsule", "airport":
		return nil // genuinely Apple, handled by the model-name table
	}
	return nil
}

var reOSXVers = regexp.MustCompile(`(?i)osxvers=([0-9]+)`)

// identityFromDeviceInfo reads the _device-info._tcp.local TXT record, which
// Apple hardware answers with its own model identifier. osxvers is the major
// macOS version plus four, so osxvers=24 is macOS 15.
func identityFromDeviceInfo(s string) *Identity {
	if !strings.Contains(strings.ToLower(s), "model=") {
		return nil
	}
	m := reModel.FindStringSubmatch(s)
	if m == nil {
		return nil
	}
	model := m[1]

	// Samba publishes a _device-info record with model=MacSamba so that macOS
	// Finder draws the right icon for it, and Netatalk does the same. The
	// record is an icon hint, not a hardware identifier, and reading it as one
	// identified a Linux file server as an Apple Mac.
	if id := notAnAppleModel(model, s); id != nil {
		return id
	}
	// A genuine Apple model identifier is a word followed by two numbers, as in
	// Macmini9,1. Anything else in this field is somebody else's label.
	if !reAppleModel.MatchString(model) {
		return nil
	}
	name := appleModelName(model)
	category := "Workstation"
	lowModel := strings.ToLower(model)
	if strings.HasPrefix(lowModel, "airport") || strings.HasPrefix(lowModel, "appletv") {
		category = "Appliance"
	}
	if v := reOSXVers.FindStringSubmatch(s); v != nil {
		if n, err := strconv.Atoi(v[1]); err == nil && n >= 14 {
			// 10.9 was osxvers 13; from Big Sur the major version is n-4.
			if n >= 24 {
				name = fmt.Sprintf("%s, macOS %d", name, n-9)
			} else {
				name = fmt.Sprintf("%s, macOS 10.%d", name, n-4)
			}
		}
	}
	return &Identity{
		Name: name, Category: category, Confidence: confStated,
		Method: "mdns-device-info", Evidence: []string{strings.TrimSpace(s)},
	}
}

// appleModelName turns a model identifier into something a person recognises,
// falling back to the identifier itself rather than inventing a product name.
// appleModelPrefixes is ordered longest-first and iterated in order. A map
// would be iterated at random, so "Macmini9,1" matched "mac" about as often as
// it matched "macmini" - a bug that only shows up some of the time, which is
// the worst kind.
var appleModelPrefixes = []struct{ prefix, label string }{
	{"macbookpro", "Apple MacBook Pro"},
	{"macbookair", "Apple MacBook Air"},
	{"macbook", "Apple MacBook"},
	{"macstudio", "Apple Mac Studio"},
	{"macmini", "Apple Mac mini"},
	{"macpro", "Apple Mac Pro"},
	{"imacpro", "Apple iMac Pro"},
	{"imac", "Apple iMac"},
	{"appletv", "Apple TV"},
	{"airport", "Apple AirPort"},
	{"iphone", "Apple iPhone"},
	{"ipad", "Apple iPad"},
	{"watch", "Apple Watch"},
	{"mac", "Apple Mac"},
}

func appleModelName(model string) string {
	low := strings.ToLower(model)
	for _, e := range appleModelPrefixes {
		if strings.HasPrefix(low, e.prefix) {
			return e.label + " (" + model + ")"
		}
	}
	return "Apple device (" + model + ")"
}

// ---------------------------------------------------------- HTTP Server

var reServerHdr = regexp.MustCompile(`(?im)^Server:\s*(.+?)\s*$`)

func identityFromHTTPServer(s string) *Identity {
	server := strings.TrimSpace(s)
	if m := reServerHdr.FindStringSubmatch(s); m != nil {
		server = strings.TrimSpace(m[1])
	} else if strings.HasPrefix(strings.ToLower(s), "server:") {
		server = strings.TrimSpace(s[7:])
	}
	if server == "" {
		return nil
	}
	low := strings.ToLower(server)
	ev := []string{"Server: " + server}

	stated := func(name, cat string) *Identity {
		return &Identity{Name: name, Category: cat, Confidence: confStated, Method: "http-server", Evidence: ev}
	}
	derived := func(name, cat string) *Identity {
		return &Identity{Name: name, Category: cat, Confidence: confDerived, Method: "http-server", Evidence: ev}
	}

	switch {
	case strings.Contains(low, "(ubuntu)"):
		return stated("Ubuntu Linux ("+server+")", "Server")
	case strings.Contains(low, "(debian)"):
		return stated("Debian GNU/Linux ("+server+")", "Server")
	case strings.Contains(low, "centos") || strings.Contains(low, "red hat") || strings.Contains(low, "(rhel)"):
		return stated("Red Hat family Linux ("+server+")", "Server")
	case strings.Contains(low, "microsoft-iis"):
		return stated("Windows Server (Microsoft-IIS)", "Web Server")
	case strings.Contains(low, "microsoft-httpapi"):
		return derived("Windows Host (HTTPAPI)", "Server")
	case strings.Contains(low, "apache"):
		return derived("Apache HTTP Server ("+server+")", "Web Server")
	case strings.Contains(low, "nginx"):
		return derived("Nginx Web Server ("+server+")", "Web Server")
	case strings.Contains(low, "caddy"):
		return stated("Caddy Web Server", "Web Server")
	case strings.Contains(low, "litespeed"):
		return stated("LiteSpeed Web Server", "Web Server")
	case strings.Contains(low, "traefik"):
		return stated("Traefik Ingress Gateway", "Web Server")
	case strings.Contains(low, "fortigate") || strings.Contains(low, "fortios"):
		return stated("Fortinet FortiGate Firewall", "Security Gateway / Firewall")
	case strings.Contains(low, "pan-os") || strings.Contains(low, "globalprotect"):
		return stated("Palo Alto Networks PAN-OS Firewall", "Security Gateway / Firewall")
	case strings.Contains(low, "sonicwall") || strings.Contains(low, "sonicos"):
		return stated("SonicWall Security Gateway", "Security Gateway / Firewall")
	case strings.Contains(low, "watchguard") || strings.Contains(low, "firebox"):
		return stated("WatchGuard Firebox Gateway", "Security Gateway / Firewall")
	case strings.Contains(low, "sophos") || strings.Contains(low, "cyberoam"):
		return stated("Sophos Security Appliance", "Security Gateway / Firewall")
	case strings.Contains(low, "check point") || strings.Contains(low, "gaia"):
		return stated("Check Point Security Gateway", "Security Gateway / Firewall")
	case strings.Contains(low, "synology"):
		return stated("Synology DiskStation", "Storage / NAS")
	case strings.Contains(low, "qnap"):
		return stated("QNAP NAS", "Storage / NAS")
	case strings.Contains(low, "netapp"):
		return stated("NetApp Storage System", "Storage / SAN")
	case strings.Contains(low, "sharkninja") || strings.Contains(low, "shark"):
		return stated("SharkNinja Smart Robot Vacuum / Appliance", "Smart Home / IoT")
	case strings.Contains(low, "hp http server") || strings.Contains(low, "jetdirect"):
		return stated("HP network printer", "Printer / Appliance")
	case strings.Contains(low, "cups"):
		return derived("CUPS print host ("+server+")", "Printer / Appliance")
	case strings.Contains(low, "mikrotik"):
		return stated("MikroTik RouterOS", "Network Gear")
	case strings.Contains(low, "openwrt"):
		return stated("OpenWrt", "Network Gear")
	case strings.Contains(low, "boa") || strings.Contains(low, "goahead") || strings.Contains(low, "lwip") || strings.Contains(low, "mini_httpd"):
		return derived("Embedded appliance ("+server+")", "Appliance")
	case strings.Contains(low, "proxmox"):
		return stated("Proxmox VE Hypervisor", "Hypervisor / Virtualization")
	case strings.Contains(low, "unifi"):
		return stated("Ubiquiti UniFi", "Network Gear")
	case strings.Contains(low, "idrac"):
		return stated("Dell iDRAC Remote Access Controller", "Out-of-Band Management / IPMI")
	case strings.Contains(low, "ilo"):
		return stated("HPE iLO Remote Management", "Out-of-Band Management / IPMI")
	}
	return nil
}

// ------------------------------------------------------------------ SSDP

var reSSDPServer = regexp.MustCompile(`(?im)^SERVER:\s*(.+?)\s*$`)

// identityFromSSDP reads the SERVER header of an M-SEARCH reply, which by
// convention carries "OS/version UPnP/1.0 product/version".
func identityFromSSDP(s string) *Identity {
	m := reSSDPServer.FindStringSubmatch(s)
	if m == nil {
		return nil
	}
	server := strings.TrimSpace(m[1])
	low := strings.ToLower(server)
	ev := []string{"SSDP: " + server}

	stated := func(name, cat string) *Identity {
		return &Identity{Name: name, Category: cat, Confidence: confStated, Method: "ssdp-server", Evidence: ev}
	}
	derived := func(name, cat string) *Identity {
		return &Identity{Name: name, Category: cat, Confidence: confDerived, Method: "ssdp-server", Evidence: ev}
	}

	switch {
	case strings.Contains(low, "sonos"):
		return stated("Sonos Smart Audio Device", "Smart Home / Audio")
	case strings.Contains(low, "roku"):
		return stated("Roku Streaming Player", "Smart TV / Media Streamer")
	case strings.Contains(low, "synology"):
		return stated("Synology DiskStation NAS", "Storage / NAS")
	case strings.Contains(low, "qnap"):
		return stated("QNAP NAS", "Storage / NAS")
	case strings.Contains(low, "philips-hue") || strings.Contains(low, "ipbridge"):
		return stated("Philips Hue Bridge", "Smart Home / IoT")
	case strings.Contains(low, "windows"):
		return derived("Windows host (UPnP)", "Workstation")
	case strings.Contains(low, "linux"):
		return derived("Linux host (UPnP)", "Server")
	}
	return nil
}

// --------------------------------------------------------------- NetBIOS

// identityFromNetBIOS reads a node status reply. A host that answers NBSTAT is
// running an SMB stack: Windows, or Samba. The <00> and <20> suffixes in the
// name table distinguish a workstation entry from a file server entry.
func identityFromNetBIOS(s string) *Identity {
	if !strings.HasPrefix(s, "netbios:") {
		return nil
	}
	body := strings.TrimSpace(strings.TrimPrefix(s, "netbios:"))
	if body == "" {
		return nil
	}
	name := "SMB host"
	if strings.Contains(body, "<20>") {
		name = "SMB file server"
	}
	return &Identity{
		Name: name + " (" + body + ")", Category: "Server",
		Confidence: confDerived, Method: "netbios", Evidence: []string{"NBSTAT: " + body},
	}
}

// ----------------------------------------------------------------- SNMP

// identityFromSNMP reads sysDescr from an SNMP sweep response.
func identityFromSNMP(s string) *Identity {
	if !strings.HasPrefix(strings.ToLower(s), "sysdescr:") {
		return nil
	}
	descr := strings.TrimSpace(strings.TrimPrefix(s, "sysdescr:"))
	if descr == "" {
		return nil
	}
	low := strings.ToLower(descr)
	cat := "Network Gear"
	if strings.Contains(low, "printer") || strings.Contains(low, "laserjet") {
		cat = "Printer / Appliance"
	} else if strings.Contains(low, "fortigate") || strings.Contains(low, "palo alto") || strings.Contains(low, "sonicwall") {
		cat = "Security Gateway / Firewall"
	} else if strings.Contains(low, "linux") {
		cat = "Server"
	}
	return &Identity{
		Name: descr, Category: cat, Confidence: confStated,
		Method: "snmp-sysdescr", Evidence: []string{"sysDescr: " + descr},
	}
}

// ---------------------------------------------------------------- TLS Cert

// identityFromTLSCert parses TLS certificate CN, Organization, SANs, and Issuer
func identityFromTLSCert(s string) *Identity {
	if !strings.HasPrefix(s, "tls-cert:") {
		return nil
	}
	certStr := strings.TrimPrefix(s, "tls-cert:")
	low := strings.ToLower(certStr)
	ev := []string{s}

	stated := func(name, cat string) *Identity {
		return &Identity{Name: name, Category: cat, Confidence: confStated, Method: "tls-cert", Evidence: ev}
	}
	derived := func(name, cat string) *Identity {
		return &Identity{Name: name, Category: cat, Confidence: confDerived, Method: "tls-cert", Evidence: ev}
	}

	switch {
	// Hypervisors & Virtualization
	case strings.Contains(low, "proxmox") || strings.Contains(low, "pve"):
		return stated("Proxmox VE Hypervisor", "Hypervisor / Virtualization")
	case strings.Contains(low, "vmware") || strings.Contains(low, "esxi") || strings.Contains(low, "vcenter"):
		return stated("VMware ESXi / vCenter Server", "Hypervisor / Virtualization")
	case strings.Contains(low, "nutanix") || strings.Contains(low, "prism"):
		return stated("Nutanix AHV / Prism Cluster", "Hypervisor / Virtualization")
	case strings.Contains(low, "xcp-ng") || strings.Contains(low, "xenserver"):
		return stated("XCP-ng / Citrix XenServer", "Hypervisor / Virtualization")

	// Enterprise Firewalls & Gateways
	case strings.Contains(low, "fortigate") || strings.Contains(low, "fortinet") || strings.Contains(low, "fortisslvpn"):
		return stated("Fortinet FortiGate Firewall", "Security Gateway / Firewall")
	case strings.Contains(low, "palo alto") || strings.Contains(low, "pan-os") || strings.Contains(low, "globalprotect"):
		return stated("Palo Alto Networks PAN-OS Firewall", "Security Gateway / Firewall")
	case strings.Contains(low, "sonicwall") || strings.Contains(low, "sonicos"):
		return stated("SonicWall Security Gateway", "Security Gateway / Firewall")
	case strings.Contains(low, "watchguard") || strings.Contains(low, "firebox"):
		return stated("WatchGuard Firebox Gateway", "Security Gateway / Firewall")
	case strings.Contains(low, "sophos"):
		return stated("Sophos Security Appliance", "Security Gateway / Firewall")
	case strings.Contains(low, "check point") || strings.Contains(low, "gaia"):
		return stated("Check Point Security Gateway", "Security Gateway / Firewall")
	case strings.Contains(low, "cisco asa") || strings.Contains(low, "firepower") || strings.Contains(low, "anyconnect"):
		return stated("Cisco ASA / Firepower Security Gateway", "Security Gateway / Firewall")
	case strings.Contains(low, "pfsense"):
		return stated("pfSense Firewall", "Security Gateway / Firewall")
	case strings.Contains(low, "opnsense"):
		return stated("OPNsense Firewall", "Security Gateway / Firewall")

	// Storage & NAS / SAN
	case strings.Contains(low, "synology"):
		return stated("Synology DiskStation NAS", "Storage / NAS")
	case strings.Contains(low, "qnap"):
		return stated("QNAP NAS", "Storage / NAS")
	case strings.Contains(low, "truenas") || strings.Contains(low, "freenas"):
		return stated("TrueNAS Storage Server", "Storage / NAS")
	case strings.Contains(low, "powerstore") || strings.Contains(low, "powervault") || strings.Contains(low, "isilon"):
		return stated("Dell EMC Storage Appliance", "Storage / SAN")
	case strings.Contains(low, "netapp") || strings.Contains(low, "ontap"):
		return stated("NetApp ONTAP Storage System", "Storage / SAN")

	// Out-of-Band IPMI / BMC
	case strings.Contains(low, "idrac") || strings.Contains(low, "integrated dell remote access controller"):
		return stated("Dell iDRAC Remote Access Controller", "Out-of-Band Management / IPMI")
	case strings.Contains(low, "integrated lights-out") || strings.Contains(low, "ilo"):
		return stated("HPE iLO Remote Management", "Out-of-Band Management / IPMI")
	case strings.Contains(low, "supermicro") || strings.Contains(low, "atennology"):
		return stated("Supermicro IPMI Management", "Out-of-Band Management / IPMI")
	case strings.Contains(low, "xclarity") || strings.Contains(low, "lenovo imm"):
		return stated("Lenovo XClarity Management Controller", "Out-of-Band Management / IPMI")

	// Networking & Kubernetes
	case strings.Contains(low, "ubiquiti") || strings.Contains(low, "unifi"):
		return stated("Ubiquiti UniFi Console", "Network Gear")
	case strings.Contains(low, "mikrotik"):
		return stated("MikroTik RouterOS", "Network Gear")
	case strings.Contains(low, "openwrt"):
		return stated("OpenWrt Gateway", "Network Gear")
	case strings.Contains(low, "kube-apiserver") || strings.Contains(low, "kubernetes"):
		return stated("Kubernetes Control Plane Node", "Container Orchestrator")
	case strings.Contains(low, "traefik") || strings.Contains(low, "caddy") || strings.Contains(low, "nginx"):
		return derived("Reverse Proxy Gateway ("+certStr+")", "Web Server")
	}
	return nil
}

// ------------------------------------------------------------- HTTP Title

// identityFromHTTPTitle parses HTML <title> elements from open web ports
func identityFromHTTPTitle(s string) *Identity {
	if !strings.HasPrefix(s, "http-title:") {
		return nil
	}
	title := strings.TrimPrefix(s, "http-title:")
	low := strings.ToLower(title)
	ev := []string{"HTTP Title: " + title}

	stated := func(name, cat string) *Identity {
		return &Identity{Name: name, Category: cat, Confidence: confStated, Method: "http-title", Evidence: ev}
	}
	derived := func(name, cat string) *Identity {
		return &Identity{Name: name, Category: cat, Confidence: confDerived, Method: "http-title", Evidence: ev}
	}

	switch {
	// Hypervisors & Virtualization
	case strings.Contains(low, "proxmox virtual environment") || strings.Contains(low, "proxmox mail gateway"):
		return stated("Proxmox VE Hypervisor ("+title+")", "Hypervisor / Virtualization")
	case strings.Contains(low, "vmware esxi") || strings.Contains(low, "vcenter server"):
		return stated("VMware vSphere / ESXi ("+title+")", "Hypervisor / Virtualization")
	case strings.Contains(low, "nutanix") || strings.Contains(low, "prism element"):
		return stated("Nutanix Prism Cluster ("+title+")", "Hypervisor / Virtualization")

	// Enterprise Firewalls & Gateways
	case strings.Contains(low, "fortigate") || strings.Contains(low, "fortios"):
		return stated("Fortinet FortiGate Firewall ("+title+")", "Security Gateway / Firewall")
	case strings.Contains(low, "palo alto networks") || strings.Contains(low, "globalprotect portal"):
		return stated("Palo Alto Networks Firewall ("+title+")", "Security Gateway / Firewall")
	case strings.Contains(low, "sonicwall"):
		return stated("SonicWall Security Gateway ("+title+")", "Security Gateway / Firewall")
	case strings.Contains(low, "watchguard") || strings.Contains(low, "fireware web ui"):
		return stated("WatchGuard Firebox ("+title+")", "Security Gateway / Firewall")
	case strings.Contains(low, "sophos"):
		return stated("Sophos XG / UTM Gateway ("+title+")", "Security Gateway / Firewall")
	case strings.Contains(low, "pfsense"):
		return stated("pfSense Firewall ("+title+")", "Security Gateway / Firewall")
	case strings.Contains(low, "opnsense"):
		return stated("OPNsense Firewall ("+title+")", "Security Gateway / Firewall")

	// Out-of-Band IPMI / BMC
	case strings.Contains(low, "idrac") || strings.Contains(low, "integrated dell remote access"):
		return stated("Dell iDRAC Remote Access Controller", "Out-of-Band Management / IPMI")
	case strings.Contains(low, "integrated lights-out") || strings.Contains(low, "ilo 5") || strings.Contains(low, "ilo 4") || strings.Contains(low, "ilo 6"):
		return stated("HPE iLO Remote Management", "Out-of-Band Management / IPMI")
	case strings.Contains(low, "supermicro ipmi") || strings.Contains(low, "ipmi web"):
		return stated("Supermicro IPMI Interface", "Out-of-Band Management / IPMI")

	// Storage & Backup
	case strings.Contains(low, "synology") || strings.Contains(low, "diskstation manager"):
		return stated("Synology DiskStation ("+title+")", "Storage / NAS")
	case strings.Contains(low, "qnap") || strings.Contains(low, "qts"):
		return stated("QNAP Turbo NAS ("+title+")", "Storage / NAS")
	case strings.Contains(low, "truenas") || strings.Contains(low, "freenas"):
		return stated("TrueNAS Storage Server", "Storage / NAS")
	case strings.Contains(low, "veeam"):
		return stated("Veeam Backup & Replication Console", "Backup Appliance")

	// Smart Home & IoT
	case strings.Contains(low, "home assistant"):
		return stated("Home Assistant OS", "Smart Home / IoT")
	case strings.Contains(low, "esphome"):
		return stated("ESPHome Smart Device", "Smart Home / IoT")
	case strings.Contains(low, "tasmota"):
		return stated("Tasmota Smart Device", "Smart Home / IoT")
	case strings.Contains(low, "wled"):
		return stated("WLED Smart Lighting Controller", "Smart Home / IoT")
	case strings.Contains(low, "sonos"):
		return stated("Sonos Smart Audio Device", "Smart Home / Audio")

	// Network & Infrastructure Services
	case strings.Contains(low, "nest wifi") || strings.Contains(low, "google wifi"):
		return stated("Google Nest WiFi Pro 6E Gateway", "Network Gear")
	case strings.Contains(low, "pi-hole"):
		return stated("Pi-hole DNS Sinkhole", "Network Gear")
	case strings.Contains(low, "adguard home"):
		return stated("AdGuard Home DNS", "Network Gear")
	case strings.Contains(low, "unifi network") || strings.Contains(low, "unifi os"):
		return stated("Ubiquiti UniFi Gateway ("+title+")", "Network Gear")
	case strings.Contains(low, "grafana"):
		return stated("Grafana Observability Server", "Web Server / Observability")
	case strings.Contains(low, "portainer"):
		return stated("Portainer Container Management", "Container Infrastructure")
	case strings.Contains(low, "openwrt") || strings.Contains(low, "luci"):
		return stated("OpenWrt Linux Router", "Network Gear")
	case strings.Contains(low, "mikrotik") || strings.Contains(low, "routeros"):
		return stated("MikroTik RouterOS", "Network Gear")
	case strings.Contains(low, "cockpit"):
		return stated("Cockpit Linux Management Console", "Server")
	case strings.Contains(low, "octoprint"):
		return stated("OctoPrint 3D Print Server", "Printer / Appliance")
	case strings.Contains(low, "plex"):
		return derived("Plex Media Server", "Media Streamer")
	}
	return nil
}

// ------------------------------------------------------------------ DHCP

// identityFromDHCP parses DHCP options (Vendor Class ID, Hostname, Option 55 list)
func identityFromDHCP(s string) *Identity {
	if !strings.HasPrefix(s, "dhcp:") {
		return nil
	}
	dhcpInfo := strings.TrimPrefix(s, "dhcp:")
	low := strings.ToLower(dhcpInfo)
	ev := []string{s}

	stated := func(name, cat string) *Identity {
		return &Identity{Name: name, Category: cat, Confidence: confStated, Method: "dhcp-fingerprint", Evidence: ev}
	}

	switch {
	case strings.Contains(low, "android-dhcp"):
		return stated("Android Mobile Device", "Mobile")
	case strings.Contains(low, "apple-iphone") || strings.Contains(low, "ios"):
		return stated("Apple iOS Device (iPhone/iPad)", "Mobile")
	case strings.Contains(low, "msft 5.0") || strings.Contains(low, "msft 98"):
		return stated("Windows Host (DHCP MSFT 5.0)", "Workstation")
	case strings.Contains(low, "roku"):
		return stated("Roku Streaming Player", "Smart TV / Media Streamer")
	case strings.Contains(low, "playstation") || strings.Contains(low, "ps5") || strings.Contains(low, "ps4"):
		return stated("Sony PlayStation Gaming Console", "Gaming Console")
	case strings.Contains(low, "xbox"):
		return stated("Microsoft Xbox Gaming Console", "Gaming Console")
	case strings.Contains(low, "cisco ap") || strings.Contains(low, "cisco-ap"):
		return stated("Cisco Wireless Access Point", "Network Gear")
	case strings.Contains(low, "ring"):
		return stated("Ring Smart Home Camera", "Smart Home / IoT")
	case strings.Contains(low, "nest") || strings.Contains(low, "google-nest"):
		return stated("Google Nest Smart Device", "Smart Home / IoT")
	case strings.Contains(low, "shelly"):
		return stated("Shelly Smart Relay / Sensor", "Smart Home / IoT")
	case strings.Contains(low, "espressif") || strings.Contains(low, "esp_"):
		return stated("Espressif IoT Device", "Smart Home / IoT")
	case strings.Contains(low, "hue-bridge") || strings.Contains(low, "philips-hue"):
		return stated("Philips Hue Bridge", "Smart Home / IoT")
	case strings.Contains(low, "sonos"):
		return stated("Sonos Smart Audio Device", "Smart Home / Audio")
	}
	return nil
}

// ------------------------------------------------------------- Hostname

// identityFromHostname extracts platform indicators from mDNS names, DHCP hostnames, and reverse DNS names
func identityFromHostname(s string) *Identity {
	var host string
	if strings.HasPrefix(s, "mdns-name:") {
		host = strings.TrimPrefix(s, "mdns-name:")
	} else if strings.HasPrefix(s, "host:") {
		host = strings.TrimPrefix(s, "host:")
	} else {
		return nil
	}
	host = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".local")
	host = strings.TrimSuffix(host, ".lan")
	if host == "" {
		return nil
	}
	ev := []string{s}
	derived := func(name, cat string) *Identity {
		return &Identity{Name: name, Category: cat, Confidence: confDerived, Method: "hostname-match", Evidence: ev}
	}

	switch {
	case strings.Contains(host, "amazon-") || strings.Contains(host, "echo-") || strings.Contains(host, "alexa"):
		return derived("Amazon Echo / Smart Device", "Smart Home / IoT")
	case strings.Contains(host, "iphone"):
		return derived("Apple iPhone", "Mobile")
	case strings.Contains(host, "ipad"):
		return derived("Apple iPad", "Mobile")
	case strings.Contains(host, "pixel-"):
		return derived("Google Pixel Smartphone", "Mobile")
	case strings.Contains(host, "s24") || strings.Contains(host, "s23") || strings.Contains(host, "s22") || strings.Contains(host, "s21") || strings.Contains(host, "galaxy"):
		return derived("Samsung Galaxy Smartphone", "Mobile")
	case strings.Contains(host, "samsung"):
		return derived("Samsung Smart TV / Device", "Smart TV / Media Streamer")
	case strings.Contains(host, "emporia"):
		return derived("Emporia Vue Smart Energy Monitor", "Smart Home / IoT")
	case strings.Contains(host, "neakasa"):
		return derived("Neakasa Smart Appliance", "Smart Home / IoT")
	case strings.Contains(host, "sonos"):
		return derived("Sonos Smart Audio Device", "Smart Home / Audio")
	case strings.Contains(host, "roku"):
		return derived("Roku Streaming Player", "Smart TV / Media Streamer")
	case strings.Contains(host, "shelly"):
		return derived("Shelly Smart Relay / Sensor", "Smart Home / IoT")
	case strings.Contains(host, "eufy") || strings.HasPrefix(host, "t8416") || strings.HasPrefix(host, "t8"):
		return derived("Eufy Smart Security Device", "Smart Home / IoT")
	case strings.Contains(host, "synology"):
		return derived("Synology DiskStation", "Storage / NAS")
	case strings.Contains(host, "qnap"):
		return derived("QNAP Turbo NAS", "Storage / NAS")
	case host == "mac" || host == "mac.lan" || strings.Contains(host, "-mac"):
		return derived("Apple Mac", "Workstation")
	case strings.Contains(host, "ep40"):
		return derived("Linux IoT Controller / Appliance", "Appliance")
	case strings.Contains(host, "s380hb"):
		return derived("Eufy HomeBase S380 / Security Gateway", "Smart Home / IoT")
	case strings.Contains(host, "desktop-") || strings.Contains(host, "laptop-") || strings.Contains(host, "win-"):
		return derived("Windows Workstation ("+host+")", "Workstation")
	}
	return nil
}

// -------------------------------------------------- published mDNS services

// identityFromPublishedServices reads the service list a host answers
// _services._dns-sd._udp.local with.
func identityFromPublishedServices(all []string) *Identity {
	var services, localName string
	for _, s := range all {
		if strings.HasPrefix(s, "mdns-services:") {
			services = strings.ToLower(strings.TrimPrefix(s, "mdns-services:"))
		}
		if strings.HasPrefix(s, "mdns-name:") {
			localName = strings.TrimPrefix(s, "mdns-name:")
		}
	}
	if services == "" {
		return nil
	}
	ev := []string{"mDNS services: " + services}
	if localName != "" {
		ev = append(ev, "mDNS name: "+localName)
	}
	named := func(n string) string {
		if localName != "" {
			return n + " (" + localName + ")"
		}
		return n
	}

	has := func(name string) bool { return strings.Contains(services, name) }

	switch {
	case has("_googlecast") || has("_cast"):
		return &Identity{Name: named("Google Cast / Chromecast / Nest Smart Device"), Category: "Smart Home / Audio",
			Confidence: confStated, Method: "mdns-services", Evidence: ev}
	case has("_spotify-connect"):
		return &Identity{Name: named("Spotify Connect Smart Audio Player"), Category: "Smart Home / Audio",
			Confidence: confDerived, Method: "mdns-services", Evidence: ev}
	case has("_airplay") && has("_raop"):
		return &Identity{Name: named("Apple AirPlay device"), Category: "Smart TV / Media Streamer",
			Confidence: confDerived, Method: "mdns-services", Evidence: ev}
	case has("_companion-link") || (has("_rfb") && has("_sftp-ssh")):
		return &Identity{Name: named("Apple macOS"), Category: "Workstation",
			Confidence: confDerived, Method: "mdns-services", Evidence: ev}
	case has("_ipp") || has("_pdl-datastream") || has("_printer"):
		return &Identity{Name: named("Network printer"), Category: "Printer / Appliance",
			Confidence: confDerived, Method: "mdns-services", Evidence: ev}
	case has("_workstation"):
		return &Identity{Name: named("Linux host (Avahi)"), Category: "Server",
			Confidence: confInferred, Method: "mdns-services", Evidence: ev}
	}
	return nil
}

// ------------------------------------------------------------- refinement

// refine sharpens an identity that is right but not specific, using evidence
// that only means something once the base platform is known. Proxmox is Debian,
// so "Debian" is a correct answer that stops one step short of the useful one;
// port 8006 on a Debian base is what finishes it.
func refine(id *Identity, openPorts []int, all []string) {
	has := func(p int) bool {
		for _, o := range openPorts {
			if o == p {
				return true
			}
		}
		return false
	}
	low := strings.ToLower(id.Name)

	if strings.Contains(low, "debian") && has(8006) {
		id.Name = "Proxmox VE on " + id.Name
		id.Category = "Server"
		id.Evidence = append(id.Evidence, "port 8006 is the Proxmox VE management interface")
		return
	}
	for _, s := range all {
		if strings.HasPrefix(s, "mdns-name:") && !strings.Contains(id.Name, "(") {
			id.Name = id.Name + " (" + strings.TrimPrefix(s, "mdns-name:") + ")"
			id.Evidence = append(id.Evidence, s)
			return
		}
	}
}

func trimAll(in []string, n int) []string {
	out := make([]string, 0, len(in))
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if len(s) > n {
			s = s[:n] + "…"
		}
		out = append(out, s)
	}
	return out
}
