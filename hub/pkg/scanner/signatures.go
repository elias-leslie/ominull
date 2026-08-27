package scanner

import (
	"regexp"
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
		ID:              "sig-nvidia-shield",
		Name:            "NVIDIA Shield TV Pro (Android 11/12)",
		Vendor:          "NVIDIA Corporation",
		Category:        "Smart TV / Media Streamer",
		OUIPrefixes:     []string{"00:04:4B", "48:B0:2D", "B8:27:EB"},
		ExpectedTTL:     []int{64},
		ExpectedPorts:   []int{8008, 8009, 5555, 8443, 9000},
		BannerPatterns:  []string{"(?i)android", "(?i)shield", "(?i)chromecast", "(?i)nvidia", "(?i)upnp"},
		MinAppDeltaMs:   10.0,
		MaxAppDeltaMs:   90.0,
		ConfidenceBase:  0.88,
		IsCustom:        false,
	},
	{
		ID:              "sig-win11-workstation",
		Name:            "Windows 11 Enterprise / Pro (x86_64)",
		Vendor:          "Microsoft Corporation",
		Category:        "Workstation",
		OUIPrefixes:     []string{"BC:24:11", "00:50:56", "00:15:5D"},
		ExpectedTTL:     []int{128},
		ExpectedPorts:   []int{135, 139, 445, 3389, 5985},
		BannerPatterns:  []string{"(?i)microsoft", "(?i)windows", "(?i)ms-wbt-server", "(?i)ms-smb"},
		MinAppDeltaMs:   0.2,
		MaxAppDeltaMs:   15.0,
		ConfidenceBase:  0.92,
		IsCustom:        false,
	},
	{
		ID:              "sig-ubuntu-server",
		Name:            "Ubuntu Linux 22.04/24.04 LTS (Kernel 6.x)",
		Vendor:          "Canonical / Linux Foundation",
		Category:        "Server",
		OUIPrefixes:     []string{"BC:24:11", "00:50:56", "52:54:00"},
		ExpectedTTL:     []int{64},
		ExpectedPorts:   []int{22, 80, 443, 9999},
		BannerPatterns:  []string{"(?i)ubuntu", "(?i)openssh", "(?i)debian", "(?i)nginx", "(?i)apache"},
		MinAppDeltaMs:   0.1,
		MaxAppDeltaMs:   8.0,
		ConfidenceBase:  0.90,
		IsCustom:        false,
	},
	{
		ID:              "sig-macos-sonoma",
		Name:            "Apple macOS 14 Sonoma / 15 Sequoia",
		Vendor:          "Apple, Inc.",
		Category:        "Workstation",
		OUIPrefixes:     []string{"BC:24:11", "F0:18:98", "3C:06:30", "AC:DE:48"},
		ExpectedTTL:     []int{64},
		ExpectedPorts:   []int{22, 5900, 5000, 7000},
		BannerPatterns:  []string{"(?i)apple", "(?i)darwin", "(?i)airplay", "(?i)cups"},
		MinAppDeltaMs:   0.2,
		MaxAppDeltaMs:   12.0,
		ConfidenceBase:  0.89,
		IsCustom:        false,
	},
	{
		ID:              "sig-synology-nas",
		Name:            "Synology DiskStation NAS (DSM 7.x)",
		Vendor:          "Synology Inc.",
		Category:        "Storage / NAS",
		OUIPrefixes:     []string{"00:11:32"},
		ExpectedTTL:     []int{64},
		ExpectedPorts:   []int{5000, 5001, 445, 22},
		BannerPatterns:  []string{"(?i)synology", "(?i)diskstation", "(?i)dsm"},
		MinAppDeltaMs:   2.0,
		MaxAppDeltaMs:   25.0,
		ConfidenceBase:  0.94,
		IsCustom:        false,
	},
	{
		ID:              "sig-hp-printer",
		Name:            "HP LaserJet Enterprise Multifunction Printer",
		Vendor:          "HP Inc.",
		Category:        "Printer / Appliance",
		OUIPrefixes:     []string{"00:1E:0B", "00:25:B3", "70:5A:0F"},
		ExpectedTTL:     []int{64, 255},
		ExpectedPorts:   []int{80, 443, 515, 631, 9100},
		BannerPatterns:  []string{"(?i)hp-pjl", "(?i)laserjet", "(?i)jetdirect", "(?i)hewlett-packard"},
		MinAppDeltaMs:   15.0,
		MaxAppDeltaMs:   80.0,
		ConfidenceBase:  0.95,
		IsCustom:        false,
	},
	{
		ID:              "sig-cisco-switch",
		Name:            "Cisco Catalyst / IOS Core Switch",
		Vendor:          "Cisco Systems, Inc.",
		Category:        "Network Gear",
		OUIPrefixes:     []string{"00:00:0C", "00:01:42", "00:1A:A1"},
		ExpectedTTL:     []int{255},
		ExpectedPorts:   []int{22, 23, 80, 443, 161},
		BannerPatterns:  []string{"(?i)cisco", "(?i)ios", "(?i)catalyst"},
		MinAppDeltaMs:   0.5,
		MaxAppDeltaMs:   10.0,
		ConfidenceBase:  0.93,
		IsCustom:        false,
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

// MatchDeviceSignature evaluates multi-factor heuristics against a discovered asset
func MatchDeviceSignature(mac string, ttl int, openPorts []int, banners []string, appDeltaMs float64, customSigs []DeviceSignature) (string, float64, string) {
	allSigs := append(customSigs, defaultSignatures...)
	vendor := LookupVendor(mac)
	cleanMAC := strings.ToUpper(strings.ReplaceAll(strings.ReplaceAll(mac, "-", ":"), ".", ":"))
	var prefix string
	parts := strings.Split(cleanMAC, ":")
	if len(parts) >= 3 {
		prefix = parts[0] + ":" + parts[1] + ":" + parts[2]
	}

	bestMatch := "Generic Network Asset"
	bestCategory := "Unclassified"
	bestScore := 0.20

	for _, sig := range allSigs {
		score := 0.0
		weights := 0.0

		// 1. OUI Vendor Matching (Weight: 35)
		weights += 35.0
		ouiMatched := false
		for _, p := range sig.OUIPrefixes {
			if strings.EqualFold(p, prefix) {
				score += 35.0
				ouiMatched = true
				break
			}
		}
		if !ouiMatched && strings.Contains(strings.ToLower(vendor), strings.ToLower(sig.Vendor)) {
			score += 25.0
		}

		// 2. Initial TTL Heuristics (Weight: 20)
		weights += 20.0
		for _, expTTL := range sig.ExpectedTTL {
			// TTLs can decrement by 1-3 hops across local routers
			if ttl > 0 && (ttl == expTTL || ttl == expTTL-1 || ttl == expTTL-2) {
				score += 20.0
				break
			}
		}

		// 3. Port Fingerprint Matching (Weight: 25)
		weights += 25.0
		matchedPorts := 0
		for _, p := range sig.ExpectedPorts {
			for _, op := range openPorts {
				if op == p {
					matchedPorts++
					break
				}
			}
		}
		if len(sig.ExpectedPorts) > 0 {
			portRatio := float64(matchedPorts) / float64(len(sig.ExpectedPorts))
			score += portRatio * 25.0
		}

		// 4. Banner Regex Heuristics (Weight: 30)
		weights += 30.0
		bannerMatched := false
		for _, pat := range sig.BannerPatterns {
			re, err := regexp.Compile(pat)
			if err != nil {
				continue
			}
			for _, b := range banners {
				if re.MatchString(b) {
					score += 30.0
					bannerMatched = true
					break
				}
			}
			if bannerMatched {
				break
			}
		}

		// 5. Application Response Delta Timing (Weight: 15)
		if appDeltaMs > 0 && sig.MaxAppDeltaMs > 0 {
			weights += 15.0
			if appDeltaMs >= sig.MinAppDeltaMs && appDeltaMs <= sig.MaxAppDeltaMs {
				score += 15.0
			} else if appDeltaMs > sig.MaxAppDeltaMs && appDeltaMs <= sig.MaxAppDeltaMs*1.5 {
				score += 7.5
			}
		}

		// Custom Feedback Boost
		finalRatio := (score / weights) * sig.ConfidenceBase
		if sig.IsCustom {
			finalRatio = (score / weights) * 0.98 // Higher confidence for analyst-trained signatures
		}

		if finalRatio > bestScore {
			bestScore = finalRatio
			bestMatch = sig.Name
			bestCategory = sig.Category
		}
	}

	if bestScore < 0.35 {
		if strings.Contains(strings.ToLower(vendor), "apple") {
			return "Apple Device (macOS / iOS)", 0.65, "Workstation"
		} else if strings.Contains(strings.ToLower(vendor), "nvidia") {
			return "NVIDIA Embedded Device", 0.68, "Smart TV / Media Streamer"
		} else if strings.Contains(strings.ToLower(vendor), "vmware") || strings.Contains(strings.ToLower(vendor), "hyper-v") || strings.Contains(strings.ToLower(vendor), "proxmox") {
			return "Virtual Machine Guest OS", 0.70, "Server"
		}
	}

	return bestMatch, bestScore, bestCategory
}
