package scanner

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// DeviceSignature defines an extensible multi-factor fingerprint rule
type DeviceSignature struct {
	ID              string   `json:"id"`
	Name            string   `json:"name"`             // e.g. "NVIDIA Shield TV Pro (Android 11)"
	Vendor          string   `json:"vendor"`           // e.g. "NVIDIA Corporation"
	Category        string   `json:"category"`         // "Media Streaming / Smart TV", "Workstation", "Server", "Network Gear", "NAS", "Printer"
	OUIPrefixes     []string `json:"oui_prefixes"`     // e.g. ["00:04:4b", "48:b0:2d", "00:e0:4c"]
	ExpectedTTL     []int    `json:"expected_ttl"`     // [64] for Linux/Android, [128] for Windows, [255] for Cisco
	ExpectedPorts   []int    `json:"expected_ports"`   // Ports commonly open
	ProhibitedPorts []int    `json:"prohibited_ports"` // Ports that disqualify this signature
	BannerPatterns  []string `json:"banner_patterns"`  // Regex patterns matching service banners
	MinAppDeltaMs   float64  `json:"min_app_delta_ms"` // Lower bound of application response latency
	MaxAppDeltaMs   float64  `json:"max_app_delta_ms"` // Upper bound of application response latency
	ConfidenceBase  float64  `json:"confidence_base"`  // Base confidence score (e.g. 0.85)
	IsCustom        bool     `json:"is_custom"`        // True if learned via user/agent feedback loop
}

// Built-in Seed Signatures (Extensible & Trainable at Runtime)
var defaultSignatures = []DeviceSignature{
	{
		ID:             "sig-nvidia-shield",
		Name:           "NVIDIA Shield TV Pro (Android 11/12)",
		Vendor:         "NVIDIA Corporation",
		Category:       "Smart TV / Media Streamer",
		OUIPrefixes:    []string{"00:04:4B", "48:B0:2D", "B8:27:EB"},
		ExpectedTTL:    []int{64},
		ExpectedPorts:  []int{8008, 8009, 5555, 8443, 9000},
		BannerPatterns: []string{"(?i)android", "(?i)shield", "(?i)chromecast", "(?i)nvidia", "(?i)upnp"},
		MinAppDeltaMs:  10.0,
		MaxAppDeltaMs:  90.0,
		ConfidenceBase: 0.88,
		IsCustom:       false,
	},
	{
		ID:       "sig-win11-workstation",
		Name:     "Windows 11 Enterprise / Pro (x86_64)",
		Vendor:   "Microsoft Corporation",
		Category: "Workstation",
		// Deliberately no hypervisor prefixes. BC:24:11 is Proxmox, 00:50:56 is
		// VMware and 52:54:00 is QEMU, and every guest on those platforms wears
		// them whatever it is running - so crediting them to an operating
		// system made the same three prefixes vote for Windows, Ubuntu and
		// macOS at once. Virtualisation is recognised separately, as a
		// platform, which is the only thing the address actually proves.
		// Windows runs on everyone's hardware, so it has no prefix of its own.
		// Hyper-V's 00:15:5D used to be listed here, which is the same mistake
		// in a subtler form: a Hyper-V guest is often Linux.
		OUIPrefixes:    []string{},
		ExpectedTTL:    []int{128},
		ExpectedPorts:  []int{135, 139, 445, 3389, 5985},
		BannerPatterns: []string{"(?i)microsoft", "(?i)windows", "(?i)ms-wbt-server", "(?i)ms-smb"},
		MinAppDeltaMs:  0.2,
		MaxAppDeltaMs:  15.0,
		ConfidenceBase: 0.92,
		IsCustom:       false,
	},
	{
		ID:            "sig-ubuntu-server",
		Name:          "Ubuntu Linux 22.04/24.04 LTS (Kernel 6.x)",
		Vendor:        "Canonical / Linux Foundation",
		Category:      "Server",
		OUIPrefixes:   []string{},
		ExpectedTTL:   []int{64},
		ExpectedPorts: []int{22, 80, 443, 9999},
		// Only patterns that actually name Ubuntu. "openssh", "nginx" and
		// "apache" appear on every Unix host there is, and matching them here
		// is why hosts that were plainly not Ubuntu were reported as Ubuntu.
		BannerPatterns: []string{"(?i)\\bubuntu\\b"},
		MinAppDeltaMs:  0.1,
		MaxAppDeltaMs:  8.0,
		ConfidenceBase: 0.90,
		IsCustom:       false,
	},
	{
		ID:             "sig-macos-sonoma",
		Name:           "Apple macOS 14 Sonoma / 15 Sequoia",
		Vendor:         "Apple, Inc.",
		Category:       "Workstation",
		OUIPrefixes:    []string{"F0:18:98", "3C:06:30", "AC:DE:48"},
		ExpectedTTL:    []int{64},
		ExpectedPorts:  []int{22, 5900, 5000, 7000},
		BannerPatterns: []string{"(?i)apple", "(?i)darwin", "(?i)airplay", "(?i)cups"},
		MinAppDeltaMs:  0.2,
		MaxAppDeltaMs:  12.0,
		ConfidenceBase: 0.89,
		IsCustom:       false,
	},
	{
		ID:             "sig-synology-nas",
		Name:           "Synology DiskStation NAS (DSM 7.x)",
		Vendor:         "Synology Inc.",
		Category:       "Storage / NAS",
		OUIPrefixes:    []string{"00:11:32"},
		ExpectedTTL:    []int{64},
		ExpectedPorts:  []int{5000, 5001, 445, 22},
		BannerPatterns: []string{"(?i)synology", "(?i)diskstation", "(?i)dsm"},
		MinAppDeltaMs:  2.0,
		MaxAppDeltaMs:  25.0,
		ConfidenceBase: 0.94,
		IsCustom:       false,
	},
	{
		ID:             "sig-hp-printer",
		Name:           "HP LaserJet Enterprise Multifunction Printer",
		Vendor:         "HP Inc.",
		Category:       "Printer / Appliance",
		OUIPrefixes:    []string{"00:1E:0B", "00:25:B3", "70:5A:0F"},
		ExpectedTTL:    []int{64, 255},
		ExpectedPorts:  []int{80, 443, 515, 631, 9100},
		BannerPatterns: []string{"(?i)hp-pjl", "(?i)laserjet", "(?i)jetdirect", "(?i)hewlett-packard"},
		MinAppDeltaMs:  15.0,
		MaxAppDeltaMs:  80.0,
		ConfidenceBase: 0.95,
		IsCustom:       false,
	},
	{
		ID:             "sig-cisco-switch",
		Name:           "Cisco Catalyst / IOS Core Switch",
		Vendor:         "Cisco Systems, Inc.",
		Category:       "Network Gear",
		OUIPrefixes:    []string{"00:00:0C", "00:01:42", "00:1A:A1"},
		ExpectedTTL:    []int{255},
		ExpectedPorts:  []int{22, 23, 80, 443, 161},
		BannerPatterns: []string{"(?i)cisco", "(?i)ios", "(?i)catalyst"},
		MinAppDeltaMs:  0.5,
		MaxAppDeltaMs:  10.0,
		ConfidenceBase: 0.93,
		IsCustom:       false,
	},
}

// OUI Vendor Database (Embedded Hardware Manufacturers Table)
var ouiVendorTable = map[string]string{
	"00:04:4B": "NVIDIA Corporation",
	"48:B0:2D": "NVIDIA Corporation",
	"BC:24:11": "Proxmox QEMU / KVM Virtual",
	"00:50:56": "VMware, Inc.",
	"00:0C:29": "VMware, Inc.",
	"00:15:5D": "Microsoft Hyper-V",
	"52:54:00": "QEMU Virtual NIC",
	"F0:18:98": "Apple, Inc.",
	"3C:06:30": "Apple, Inc.",
	"AC:DE:48": "Apple, Inc.",
	"B8:27:EB": "Raspberry Pi Foundation",
	"DC:A6:32": "Raspberry Pi Foundation",
	"00:11:32": "Synology Inc.",
	"00:1E:0B": "HP Inc.",
	"00:25:B3": "HP Inc.",
	"00:00:0C": "Cisco Systems, Inc.",
	"74:83:C2": "Ubiquiti Networks",
	"24:A4:3C": "Ubiquiti Networks",
	"A4:2B:B0": "Espressif Inc. (IoT / Smart Device)",
	"D8:32:14": "Espressif Inc. (IoT / Smart Device)",
	"00:1A:7D": "Sony Interactive Entertainment",
	"08:00:27": "Oracle VirtualBox",
}

// LookupVendor returns the hardware manufacturer for a given MAC address
func LookupVendor(mac string) string {
	cleanMAC := strings.ToUpper(strings.ReplaceAll(strings.ReplaceAll(mac, "-", ":"), ".", ":"))
	parts := strings.Split(cleanMAC, ":")
	if len(parts) >= 3 {
		prefix := parts[0] + ":" + parts[1] + ":" + parts[2]
		if vendor, ok := ouiVendorTable[prefix]; ok {
			return vendor
		}
	}
	return "Generic / Unassigned Hardware"
}

// hypervisorOUIs are the prefixes a virtual machine wears regardless of what it
// is running. They say "this is a guest", never "this is Windows".
var hypervisorOUIs = map[string]string{
	"BC:24:11": "Proxmox VE guest",
	"00:50:56": "VMware guest",
	"00:0C:29": "VMware guest",
	"52:54:00": "QEMU/KVM guest",
	"00:15:5D": "Hyper-V guest",
	"08:00:27": "VirtualBox guest",
	"00:16:3E": "Xen guest",
	"02:42:AC": "Docker container",
}

// VirtualPlatform names the hypervisor an address belongs to, or "".
func VirtualPlatform(mac string) string {
	return hypervisorOUIs[macPrefix(mac)]
}

func macPrefix(mac string) string {
	clean := strings.ToUpper(strings.ReplaceAll(strings.ReplaceAll(mac, "-", ":"), ".", ":"))
	parts := strings.Split(clean, ":")
	if len(parts) < 3 {
		return ""
	}
	return parts[0] + ":" + parts[1] + ":" + parts[2]
}

// signatureFloor is the normalised score a signature has to reach before it may
// put a product name on a host, and signatureMargin is how far ahead of the
// runner-up it has to be.
//
// Both are new. The matcher used to return whatever scored highest, with a
// floor of 0.20 - so on a host with no distinguishing evidence at all, the
// signature that happened to sort first won, and a name appeared on screen with
// nothing behind it. Two signatures within a few points of each other are not
// a match; they are a tie, and a tie is not an identification.
const (
	signatureFloor  = 0.45
	signatureMargin = 0.08
)

// MatchDeviceSignature evaluates multi-factor heuristics against a discovered
// asset. Kept for callers and tests that want the bare verdict; matchSignature
// is the same computation with its reasoning attached.
func MatchDeviceSignature(mac string, ttl int, openPorts []int, banners []string, appDeltaMs float64, customSigs []DeviceSignature) (string, float64, string) {
	name, score, category, _ := matchSignature(mac, ttl, openPorts, banners, appDeltaMs, customSigs)
	return name, score, category
}

type sigScore struct {
	name     string
	category string
	ratio    float64
	why      []string
}

// matchSignature scores every signature on the same scale and returns the
// winner only if it is both good enough and clearly ahead.
func matchSignature(mac string, ttl int, openPorts []int, banners []string, appDeltaMs float64, customSigs []DeviceSignature) (string, float64, string, []string) {
	allSigs := append(append([]DeviceSignature{}, customSigs...), defaultSignatures...)
	vendor := LookupVendor(mac)
	prefix := macPrefix(mac)

	scored := make([]sigScore, 0, len(allSigs))
	for _, sig := range allSigs {
		s := scoreSignature(sig, prefix, vendor, ttl, openPorts, banners, appDeltaMs)
		scored = append(scored, s)
	}
	sort.SliceStable(scored, func(i, j int) bool { return scored[i].ratio > scored[j].ratio })

	platform := VirtualPlatform(mac)
	fallback := func(reason string) (string, float64, string, []string) {
		why := []string{reason}
		if platform != "" {
			why = append(why, "MAC prefix "+prefix+" belongs to a hypervisor ("+platform+"), which says nothing about the guest OS")
			return platform, 0.60, "Server", why
		}
		low := strings.ToLower(vendor)
		switch {
		case strings.Contains(low, "apple"):
			return "Apple device", 0.62, "Workstation", append(why, "OUI "+prefix+" is registered to "+vendor)
		case strings.Contains(low, "nvidia"):
			return "NVIDIA device", 0.62, "Smart TV / Media Streamer", append(why, "OUI "+prefix+" is registered to "+vendor)
		case vendor != "" && vendor != "Generic / Unassigned Hardware":
			return vendor + " device", 0.55, "Unclassified", append(why, "OUI "+prefix+" is registered to "+vendor)
		}
		return "Unidentified host", 0.25, "Unclassified", why
	}

	if len(scored) == 0 {
		return fallback("no signatures are loaded")
	}
	best := scored[0]
	if best.ratio < signatureFloor {
		return fallback(fmt.Sprintf("best signature %q scored %.2f, below the %.2f floor", best.name, best.ratio, signatureFloor))
	}
	if len(scored) > 1 && best.ratio-scored[1].ratio < signatureMargin {
		return fallback(fmt.Sprintf("%q and %q are within %.2f of each other (%.2f vs %.2f), which is a tie rather than a match",
			best.name, scored[1].name, signatureMargin, best.ratio, scored[1].ratio))
	}
	why := best.why
	if platform != "" {
		why = append(why, "running on "+platform)
	}
	return best.name, best.ratio, best.category, why
}

// scoreSignature scores one signature. Every factor divides by the same total,
// so two signatures are comparable - which they were not when a signature with
// no latency bounds was scored out of 110 and one with them out of 125.
func scoreSignature(sig DeviceSignature, prefix, vendor string, ttl int, openPorts []int, banners []string, appDeltaMs float64) sigScore {
	const (
		wOUI    = 35.0
		wTTL    = 20.0
		wPorts  = 25.0
		wBanner = 30.0
		wDelta  = 15.0
		wTotal  = wOUI + wTTL + wPorts + wBanner + wDelta
	)
	score := 0.0
	why := []string{}

	// 1. OUI. A hypervisor prefix is worth nothing here by construction: it is
	// not in any signature's list any more.
	matched := false
	for _, p := range sig.OUIPrefixes {
		if strings.EqualFold(p, prefix) {
			score += wOUI
			why = append(why, "OUI "+prefix+" is listed for "+sig.Name)
			matched = true
			break
		}
	}
	if !matched && sig.Vendor != "" && strings.Contains(strings.ToLower(vendor), strings.ToLower(sig.Vendor)) {
		score += wOUI * 0.7
		why = append(why, "hardware vendor "+vendor+" matches "+sig.Vendor)
	}

	// 2. TTL. Only scored when it was actually measured. A hard-coded 64 used
	// to be handed to every signature, which awarded a fifth of the available
	// points to every Linux-shaped signature on every host on the network.
	if ttl > 0 {
		for _, exp := range sig.ExpectedTTL {
			if ttl == exp || ttl == exp-1 || ttl == exp-2 || ttl == exp-3 {
				score += wTTL
				why = append(why, fmt.Sprintf("measured TTL %d is consistent with an initial %d", ttl, exp))
				break
			}
		}
	}

	// 3. Ports.
	if len(sig.ExpectedPorts) > 0 && len(openPorts) > 0 {
		hits := []string{}
		for _, p := range sig.ExpectedPorts {
			for _, op := range openPorts {
				if op == p {
					hits = append(hits, strconv.Itoa(p))
					break
				}
			}
		}
		if len(hits) > 0 {
			score += (float64(len(hits)) / float64(len(sig.ExpectedPorts))) * wPorts
			why = append(why, "open ports "+strings.Join(hits, ", ")+" are expected for "+sig.Name)
		}
	}
	for _, p := range sig.ProhibitedPorts {
		for _, op := range openPorts {
			if op == p {
				return sigScore{name: sig.Name, category: sig.Category, ratio: 0,
					why: []string{fmt.Sprintf("port %d rules out %s", p, sig.Name)}}
			}
		}
	}

	// 4. Banners.
	for _, pat := range sig.BannerPatterns {
		re, err := regexp.Compile(pat)
		if err != nil {
			continue
		}
		hit := ""
		for _, b := range banners {
			if re.MatchString(b) {
				hit = b
				break
			}
		}
		if hit != "" {
			score += wBanner
			why = append(why, "banner matched "+pat+": "+trimTo(hit, 60))
			break
		}
	}

	// 5. Application response latency, scored on the same denominator whether
	// or not the signature declares bounds.
	if appDeltaMs > 0 && sig.MaxAppDeltaMs > 0 {
		if appDeltaMs >= sig.MinAppDeltaMs && appDeltaMs <= sig.MaxAppDeltaMs {
			score += wDelta
			why = append(why, fmt.Sprintf("service latency %.1fms is inside the expected %.1f-%.1fms", appDeltaMs, sig.MinAppDeltaMs, sig.MaxAppDeltaMs))
		} else if appDeltaMs > sig.MaxAppDeltaMs && appDeltaMs <= sig.MaxAppDeltaMs*1.5 {
			score += wDelta * 0.5
		}
	}

	base := sig.ConfidenceBase
	if sig.IsCustom {
		base = 0.98
	}
	if base <= 0 {
		base = 0.85
	}
	return sigScore{name: sig.Name, category: sig.Category, ratio: (score / wTotal) * base, why: why}
}

func trimTo(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}
