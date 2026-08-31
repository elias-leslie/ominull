package scanner

import (
	"strings"
	"testing"
)

func id(t *testing.T, banners, extras []string) Identity {
	t.Helper()
	return IdentifyHost("52:54:00:11:22:33", 0, []int{22}, banners, extras, 2.0, nil)
}

// The reported defect: hosts that were plainly not Ubuntu were reported as
// Ubuntu, because the Ubuntu signature matched the word "OpenSSH".
func TestAPlainOpenSSHHostIsNotCalledUbuntu(t *testing.T) {
	got := id(t, []string{"SSH-2.0-OpenSSH_9.6"}, nil)
	if strings.Contains(strings.ToLower(got.Name), "ubuntu") {
		t.Fatalf("a bare OpenSSH banner was reported as %q", got.Name)
	}
	if !strings.Contains(got.Name, "OpenSSH 9.6") {
		t.Errorf("the version the host stated was dropped: %q", got.Name)
	}
	if got.Method != "ssh-banner" {
		t.Errorf("method is %q", got.Method)
	}
}

// When a host does say Ubuntu, it says so in its own package suffix.
func TestADebianFamilyBannerNamesItsDistribution(t *testing.T) {
	for banner, want := range map[string]string{
		"SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5": "Ubuntu",
		"SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u3":   "Debian",
		"SSH-2.0-OpenSSH_8.4p1 Raspbian-5+deb11u3": "Raspberry Pi",
		"SSH-2.0-OpenSSH_for_Windows_9.5":          "Windows",
		"SSH-2.0-ROSSSH":                           "MikroTik",
		"SSH-2.0-dropbear_2022.83":                 "Embedded",
	} {
		got := id(t, []string{banner}, nil)
		if !strings.Contains(got.Name, want) {
			t.Errorf("%q identified as %q, expected something containing %q", banner, got.Name, want)
		}
		if got.Confidence < confDerived {
			t.Errorf("%q scored only %.2f", banner, got.Confidence)
		}
		if len(got.Evidence) == 0 {
			t.Errorf("%q produced a verdict with no evidence", banner)
		}
	}
}

// An Apple device answers _device-info._tcp.local with its own model.
func TestAppleDeviceInfoIsReadExactly(t *testing.T) {
	got := id(t, nil, []string{"model=Macmini9,1 osxvers=24 ecolor=226,226,224"})
	if !strings.Contains(got.Name, "Mac mini") {
		t.Errorf("model identifier not resolved: %q", got.Name)
	}
	if !strings.Contains(got.Name, "macOS 15") {
		t.Errorf("osxvers=24 should read as macOS 15, got %q", got.Name)
	}
	if got.Method != "mdns-device-info" {
		t.Errorf("method is %q", got.Method)
	}
}

// The distribution that packaged the web server put its own name in the header.
func TestTheServerHeaderNamesThePlatform(t *testing.T) {
	for header, want := range map[string]string{
		"HTTP/1.1 200 OK\r\nServer: nginx/1.24.0 (Ubuntu)\r\n":    "Ubuntu",
		"HTTP/1.1 200 OK\r\nServer: Apache/2.4.57 (Debian)\r\n":   "Debian",
		"HTTP/1.1 200 OK\r\nServer: Microsoft-IIS/10.0\r\n":       "Windows Server",
		"HTTP/1.1 200 OK\r\nServer: MikroTik HttpProxy\r\n":       "MikroTik",
		"HTTP/1.1 200 OK\r\nServer: Synology DiskStation 7.2\r\n": "Synology",
	} {
		got := id(t, []string{header}, nil)
		if !strings.Contains(got.Name, want) {
			t.Errorf("%q identified as %q, expected %q", strings.TrimSpace(header), got.Name, want)
		}
	}
}

// A host that says nothing gets an honest non-answer, not a product name.
func TestAHostWithNoEvidenceIsNotGivenAName(t *testing.T) {
	got := IdentifyHost("52:54:00:aa:bb:cc", 0, nil, nil, nil, 0, nil)
	low := strings.ToLower(got.Name)
	for _, forbidden := range []string{"ubuntu", "windows 11", "macos", "sonoma"} {
		if strings.Contains(low, forbidden) {
			t.Fatalf("an empty host was identified as %q", got.Name)
		}
	}
	if got.Confidence > 0.70 {
		t.Errorf("no evidence produced %.2f confidence", got.Confidence)
	}
	if len(got.Evidence) == 0 {
		t.Error("the refusal did not say why")
	}
}

// A hypervisor MAC is evidence of virtualisation and nothing else. All three of
// these prefixes used to be listed under an operating system's signature, so the
// same address voted for Windows, Ubuntu and macOS at the same time.
func TestAHypervisorAddressDoesNotIdentifyAnOperatingSystem(t *testing.T) {
	for mac, want := range map[string]string{
		"BC:24:11:00:00:01": "Proxmox",
		"00:50:56:00:00:01": "VMware",
		"52:54:00:00:00:01": "QEMU",
		"00:15:5D:00:00:01": "Hyper-V",
	} {
		if p := VirtualPlatform(mac); !strings.Contains(p, want) {
			t.Errorf("%s recognised as %q, expected %q", mac, p, want)
		}
		got := IdentifyHost(mac, 0, nil, nil, nil, 0, nil)
		if strings.Contains(strings.ToLower(got.Name), "ubuntu") {
			t.Errorf("%s alone identified a host as %q", mac, got.Name)
		}
	}

	for _, sig := range defaultSignatures {
		for _, oui := range sig.OUIPrefixes {
			if p := hypervisorOUIs[strings.ToUpper(oui)]; p != "" {
				t.Errorf("signature %q still claims hypervisor prefix %s (%s)", sig.Name, oui, p)
			}
		}
	}
}

// A host's own words outrank a heuristic, however confident the heuristic is.
func TestStatedEvidenceOutranksTheSignatureScore(t *testing.T) {
	// Ports and latency that suit the Windows signature, plus an SSH banner
	// that says Debian. The banner has to win.
	got := IdentifyHost("00:15:5D:01:02:03", 128, []int{135, 139, 445, 3389, 5985},
		[]string{"SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u3"}, nil, 1.0, nil)
	if !strings.Contains(got.Name, "Debian") {
		t.Fatalf("the signature score beat the host's own banner: %q via %s", got.Name, got.Method)
	}
}

// Two signatures within a hair of each other are a tie, and a tie is not an
// identification. The matcher used to return whichever sorted first.
func TestATieIsNotAMatch(t *testing.T) {
	tied := []DeviceSignature{
		{ID: "a", Name: "Device A", Category: "Server", ExpectedPorts: []int{22}, ConfidenceBase: 0.9},
		{ID: "b", Name: "Device B", Category: "Server", ExpectedPorts: []int{22}, ConfidenceBase: 0.9},
	}
	name, _, _, why := matchSignature("aa:bb:cc:dd:ee:ff", 0, []int{22}, nil, 0, tied)
	if name == "Device A" || name == "Device B" {
		t.Fatalf("a tie was reported as %q", name)
	}
	joined := strings.Join(why, " ")
	if !strings.Contains(joined, "tie") && !strings.Contains(joined, "floor") {
		t.Errorf("the refusal did not explain itself: %v", why)
	}
}

// Every conclusion carries the strings that produced it.
func TestEveryIdentificationShowsItsWorking(t *testing.T) {
	for _, c := range []struct {
		name    string
		banners []string
		extras  []string
	}{
		{"ssh", []string{"SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5"}, nil},
		{"mdns", nil, []string{"model=MacBookPro18,3 osxvers=24"}},
		{"nothing", nil, nil},
	} {
		got := IdentifyHost("aa:bb:cc:00:00:01", 0, []int{22}, c.banners, c.extras, 1.0, nil)
		if len(got.Evidence) == 0 {
			t.Errorf("%s: no evidence recorded", c.name)
		}
		if got.Method == "" {
			t.Errorf("%s: no method recorded", c.name)
		}
	}
}

// Samba publishes a _device-info record saying model=MacSamba so that macOS
// Finder draws the right icon for it. Read as hardware, it identified a Linux
// file server on this network as an Apple Mac.
func TestSambasIconHintIsNotAppleHardware(t *testing.T) {
	got := id(t, nil, []string{"model=MacSamba"})
	low := strings.ToLower(got.Name)
	if strings.Contains(low, "apple") || strings.Contains(low, "mac mini") || strings.Contains(low, "macbook") {
		t.Fatalf("model=MacSamba identified as %q", got.Name)
	}
	if !strings.Contains(low, "samba") {
		t.Errorf("expected a Samba server, got %q", got.Name)
	}
	if strings.Join(got.Evidence, " ") == "" {
		t.Error("no evidence recorded")
	}
}

// Only a real Apple model identifier - a word followed by two numbers - may be
// read as Apple hardware.
func TestOnlyAWellFormedModelIdentifierIsAppleHardware(t *testing.T) {
	if got := id(t, nil, []string{"model=Macmini9,1"}); !strings.Contains(got.Name, "Mac mini") {
		t.Errorf("a genuine model identifier was rejected: %q", got.Name)
	}
	for _, junk := range []string{"model=Nas", "model=RackStation", "model=Printer"} {
		got := id(t, nil, []string{junk})
		if strings.Contains(strings.ToLower(got.Name), "apple") {
			t.Errorf("%q identified as %q", junk, got.Name)
		}
	}
}

// A Mac with Sharing switched on is the one platform that names itself nowhere:
// its OpenSSH has no distribution suffix. It does publish Screen Sharing and
// SFTP together, and that has to outrank the shrug the SSH banner produces.
func TestPublishedServicesOutrankAVagueBanner(t *testing.T) {
	got := id(t,
		[]string{"SSH-2.0-OpenSSH_9.9"},
		[]string{"mdns-name:studio.local", "mdns-services:_rfb._tcp _ssh _sftp-ssh"})
	if !strings.Contains(got.Name, "macOS") {
		t.Fatalf("identified as %q via %s; the service list was ignored", got.Name, got.Method)
	}
	if got.Category != "Workstation" {
		t.Errorf("category is %q", got.Category)
	}
}

// Screen Sharing on its own is not a Mac, and neither is SFTP. Requiring both
// is what stops this becoming the next "matched the word OpenSSH".
func TestOneAppleServiceAloneIsNotAMac(t *testing.T) {
	for _, services := range []string{"mdns-services:_rfb._tcp", "mdns-services:_sftp-ssh"} {
		got := id(t, []string{"SSH-2.0-OpenSSH_9.9"}, []string{services})
		if strings.Contains(got.Name, "macOS") {
			t.Errorf("%q alone identified a host as %q", services, got.Name)
		}
	}
}

// Proxmox is Debian, so "Debian" is right but stops one step short. Port 8006
// is what finishes it - and it must not promote anything that is not Debian.
func TestProxmoxIsRecognisedOnTopOfItsBase(t *testing.T) {
	got := IdentifyHost("aa:bb:cc:00:00:01", 0, []int{22, 8006},
		[]string{"SSH-2.0-OpenSSH_10.0p2 Debian-7+deb13u1"}, nil, 1.0, nil)
	if !strings.Contains(got.Name, "Proxmox") {
		t.Fatalf("identified as %q", got.Name)
	}
	if !strings.Contains(strings.Join(got.Evidence, " "), "8006") {
		t.Error("the reasoning does not mention the port that decided it")
	}

	notDebian := IdentifyHost("aa:bb:cc:00:00:01", 0, []int{22, 8006},
		[]string{"SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5"}, nil, 1.0, nil)
	if strings.Contains(notDebian.Name, "Proxmox") {
		t.Errorf("port 8006 promoted a non-Debian host to %q", notDebian.Name)
	}
}
