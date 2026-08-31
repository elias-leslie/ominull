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
		identityFromSNMP,
		identityFromSSH,
		identityFromHTTPServer,
		identityFromSSDP,
		identityFromNetBIOS,
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

// identityFromHTTPServer reads the Server header. The parenthesised platform on
// a distribution-packaged nginx or Apache is put there by the distribution and
// is as good as the SSH suffix.
func identityFromHTTPServer(s string) *Identity {
	m := reServerHdr.FindStringSubmatch(s)
	if m == nil {
		return nil
	}
	server := strings.TrimSpace(m[1])
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
		return stated("Windows Server ("+server+")", "Server")
	case strings.Contains(low, "microsoft-httpapi"):
		return derived("Windows host ("+server+")", "Server")
	case strings.Contains(low, "synology"):
		return stated("Synology DiskStation", "Storage / NAS")
	case strings.Contains(low, "qnap"):
		return stated("QNAP NAS", "Storage / NAS")
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
		return stated("Proxmox VE", "Server")
	case strings.Contains(low, "unifi"):
		return stated("Ubiquiti UniFi", "Network Gear")
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
	ev := []string{"SSDP SERVER: " + server}

	switch {
	case strings.Contains(low, "windows"):
		return &Identity{Name: "Windows host (" + server + ")", Category: "Workstation", Confidence: confStated, Method: "ssdp", Evidence: ev}
	case strings.Contains(low, "darwin"):
		return &Identity{Name: "Apple macOS (" + server + ")", Category: "Workstation", Confidence: confStated, Method: "ssdp", Evidence: ev}
	case strings.Contains(low, "roku"):
		return &Identity{Name: "Roku media player", Category: "Smart TV / Media Streamer", Confidence: confStated, Method: "ssdp", Evidence: ev}
	case strings.Contains(low, "sonos"):
		return &Identity{Name: "Sonos speaker", Category: "Smart TV / Media Streamer", Confidence: confStated, Method: "ssdp", Evidence: ev}
	case strings.Contains(low, "linux"):
		return &Identity{Name: "Linux host (" + server + ")", Category: "Server", Confidence: confDerived, Method: "ssdp", Evidence: ev}
	}
	return &Identity{Name: "UPnP device (" + server + ")", Category: "Appliance", Confidence: confWeak, Method: "ssdp", Evidence: ev}
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

// ------------------------------------------------------------------ SNMP

func identityFromSNMP(s string) *Identity {
	if !strings.HasPrefix(s, "sysdescr:") {
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
	} else if strings.Contains(low, "linux") {
		cat = "Server"
	}
	return &Identity{
		Name: descr, Category: cat, Confidence: confStated,
		Method: "snmp-sysdescr", Evidence: []string{"sysDescr: " + descr},
	}
}

// -------------------------------------------------- published mDNS services

// identityFromPublishedServices reads the service list a host answers
// _services._dns-sd._udp.local with.
//
// This exists because macOS is the one platform that names itself nowhere: its
// OpenSSH carries no distribution suffix, it publishes no Server header, and it
// answers _device-info only under its own instance name, which it will not
// always give up. What it does do is advertise Screen Sharing and SFTP
// together - Apple's default Sharing set - which Avahi on Linux does not.
//
// Both are required, deliberately. Matching either one alone would be the same
// class of mistake as matching the word "OpenSSH" and calling the result Ubuntu.
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

	// Matched on the bare service name rather than the full "_x._tcp": the
	// reply's transport label sits behind a DNS compression pointer that this
	// decoder deliberately does not follow, so it arrives as "_sftp-ssh".
	has := func(name string) bool { return strings.Contains(services, name) }

	switch {
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
		// Avahi's own advertisement. It says Linux, not which Linux.
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
