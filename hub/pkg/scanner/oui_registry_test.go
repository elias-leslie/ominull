package scanner

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"ominull/hub/pkg/storage"
)

// The hand-written table knew 94 prefixes. Anything outside them was reported
// as unidentified hardware, which is how an Amazon device came back as
// "Generic / Unassigned Hardware".
func TestRegistryNamesBlocksTheHandTableNeverHeld(t *testing.T) {
	for _, tc := range []struct{ mac, want string }{
		{"F4:03:2A:11:22:33", "Amazon Technologies Inc."},
		{"68:B6:91:AA:BB:CC", "Amazon Technologies Inc."},
		{"00:0D:4B:01:02:03", "Roku, Inc."},
	} {
		if got := LookupVendor(tc.mac); got != tc.want {
			t.Errorf("LookupVendor(%q) = %q; want %q", tc.mac, got, tc.want)
		}
	}
}

// IEEE subdivides many /24s and holds the enclosing block under its own name.
// Matching on 24 bits alone would report the registry itself as the
// manufacturer for every device in 13,000-odd sub-assignments.
// IAB sub-assignees verified directly against IEEE iab.csv, September 2026.
func TestIABSubAssignments(t *testing.T) {
	for _, tc := range []struct{ mac, want string }{
		{"40:D8:55:0D:70:01", "Avant Technologies"},
		{"00:50:C2:F7:10:01", "RF Code"},
	} {
		if got := LookupVendor(tc.mac); got != tc.want {
			t.Errorf("%s: got %q, want %q", tc.mac, got, tc.want)
		}
	}
}

func TestLongestAssignmentWins(t *testing.T) {
	for _, tc := range []struct{ mac, want string }{
		{"00:55:DA:01:22:33", "Shinko Technos co.,ltd."}, // MA-M, 28 bits
		{"00:1B:C5:00:0A:BC", "Converging Systems Inc."}, // MA-S, 36 bits
	} {
		got := LookupVendor(tc.mac)
		if got != tc.want {
			t.Errorf("LookupVendor(%q) = %q; want %q", tc.mac, got, tc.want)
		}
		if got == "IEEE Registration Authority" {
			t.Errorf("LookupVendor(%q) fell back to the enclosing block holder", tc.mac)
		}
	}
}

// A randomised address is the ordinary case for a modern phone, not a lookup
// failure, and saying so is more useful than calling it unassigned hardware.
func TestRandomisedAddressIsNamedAsSuch(t *testing.T) {
	name, known := LookupVendorDetail("DA:BB:CC:DD:EE:FF")
	if name != VendorRandomised {
		t.Errorf("got %q; want %q", name, VendorRandomised)
	}
	if known {
		t.Error("a randomised address names no manufacturer, so known must be false")
	}
}

// Eighteen 1980s assignments carry the locally-administered bit because they
// predate the convention. The registry has to be consulted before the bit is
// interpreted, or DEC's blocks read as randomised.
func TestHistoricAssignmentBeatsTheLocalBit(t *testing.T) {
	name, known := LookupVendorDetail("AA:00:04:00:11:22")
	if name != "DIGITAL EQUIPMENT CORPORATION" {
		t.Errorf("got %q; want DIGITAL EQUIPMENT CORPORATION", name)
	}
	if !known {
		t.Error("a real assignment must count as a known vendor")
	}
}

// IEEE lets a registrant withhold its name. The block is assigned, but there
// is no manufacturer to report, so this must not read as one.
func TestPrivateRegistrantNamesNoManufacturer(t *testing.T) {
	name, known := LookupVendorDetail("00:01:01:11:22:33")
	if name != VendorPrivate {
		t.Errorf("got %q; want %q", name, VendorPrivate)
	}
	if known {
		t.Error("a withheld registrant is not a known vendor")
	}
}

func TestUnassignedGloballyAdministeredAddressIsUnknown(t *testing.T) {
	name, known := LookupVendorDetail("99:99:99:11:22:33")
	if name != VendorUnknown || known {
		t.Errorf("got (%q, %v); want (%q, false)", name, known, VendorUnknown)
	}
}

func TestPartialOrGarbageAddressIsNotAttributed(t *testing.T) {
	for _, mac := range []string{"", "F4:03", "not-a-mac", "F4:03:2A:11:22", "F4:03:2A:11:22:33:44"} {
		if _, known := LookupVendorDetail(mac); known {
			t.Errorf("LookupVendorDetail(%q) claimed a known vendor", mac)
		}
	}
}

func TestAddressSpellingsAgree(t *testing.T) {
	want := LookupVendor("F4:03:2A:11:22:33")
	for _, mac := range []string{"f4:03:2a:11:22:33", "F4-03-2A-11-22-33", "f403.2a11.2233", "F4032A112233"} {
		if got := LookupVendor(mac); got != want {
			t.Errorf("LookupVendor(%q) = %q; want %q", mac, got, want)
		}
	}
}

// knownRenames are the overlay entries whose label does not share a word with
// the registrant because the company was renamed or the platform is recorded
// under the firm that originated it. Each is deliberate.
var knownRenames = map[string]string{
	"08:00:27": "VirtualBox's OUI is registered to innotek's successor PCS Systemtechnik",
	"00:1E:0B": "Hewlett Packard split into HP Inc. and HPE",
	"00:25:B3": "Hewlett Packard split into HP Inc. and HPE",
	"00:0B:86": "Hewlett Packard Enterprise, Aruba product line",
	"3C:A8:2A": "Hewlett Packard, ProLiant product line",
	"D4:85:64": "Hewlett Packard, iLO product line",
}

// The overlay exists to add product context, never to disagree about who
// holds a block. It once claimed Apple's, Siemens' and ASUSTek's blocks for
// WatchGuard, Palo Alto and Tuya. This keeps that class of error out.
func TestOverlayNeverContradictsTheRegistry(t *testing.T) {
	ouiOnce.Do(loadOUIRegistry)
	for prefix, label := range ouiVendorTable {
		hex := strings.ReplaceAll(prefix, ":", "")
		registrant, assigned := ouiBlock[hex]
		if !assigned {
			continue // no registry entry to contradict
		}
		if _, ok := knownRenames[prefix]; ok {
			continue
		}
		if !sharesWord(label, registrant) {
			t.Errorf("overlay %s = %q contradicts IEEE registrant %q; correct it, or record the rename in knownRenames",
				prefix, label, registrant)
		}
	}
}

// sharesWord reports whether two organisation names have a substantive word in
// common, ignoring the corporate-form noise that differs between spellings of
// the same company.
func sharesWord(a, b string) bool {
	noise := map[string]bool{
		"inc": true, "inc.": true, "corp": true, "corp.": true, "co": true,
		"co.": true, "ltd": true, "ltd.": true, "llc": true, "gmbh": true,
		"technologies": true, "technology": true, "systems": true, "the": true,
		"limited": true, "corporation": true, "company": true, "networks": true,
	}
	words := func(s string) map[string]bool {
		out := map[string]bool{}
		for _, w := range strings.FieldsFunc(strings.ToLower(s), func(r rune) bool {
			return !(r >= 'a' && r <= 'z') && !(r >= '0' && r <= '9')
		}) {
			if len(w) > 1 && !noise[w] {
				out[w] = true
			}
		}
		return out
	}
	bw := words(b)
	for w := range words(a) {
		if bw[w] {
			return true
		}
	}
	return false
}

// A device's own address can never carry the group bit, so such a row could
// only ever produce a false match. The generator drops them.
func TestRegistryHoldsNoGroupAddresses(t *testing.T) {
	ouiOnce.Do(loadOUIRegistry)
	for prefix := range ouiBlock {
		b, ok := hexByte(prefix)
		if !ok {
			t.Fatalf("registry prefix %q is not hex", prefix)
		}
		if b&0x01 != 0 {
			t.Errorf("registry prefix %q has the group bit set", prefix)
		}
	}
}

func TestRegistryLoadedAtExpectedScale(t *testing.T) {
	ouiOnce.Do(loadOUIRegistry)
	if len(ouiBlock) < 50000 {
		t.Errorf("registry holds %d assignments; expected the full IEEE listing (~53k)", len(ouiBlock))
	}
}

func TestVendorClaimDropsOnlyTheUselessAnswer(t *testing.T) {
	for _, tc := range []struct{ mac, want string }{
		{"F4:03:2A:11:22:33", "Amazon Technologies Inc."},
		// Randomised and withheld addresses explain why there is no
		// manufacturer, so they are worth recording.
		{"DA:BB:CC:DD:EE:FF", VendorRandomised},
		{"00:01:01:11:22:33", VendorPrivate},
		// "Generic / Unassigned Hardware" is not a vendor and storing it as
		// one is worse than storing nothing.
		{"99:99:99:11:22:33", ""},
		{"garbage", ""},
	} {
		if got := VendorClaim(tc.mac); got != tc.want {
			t.Errorf("VendorClaim(%q) = %q; want %q", tc.mac, got, tc.want)
		}
	}
}

// Router leases may resolve a manufacturer, but never derive an OS from it.
func TestRouterDHCPDoesNotTurnVendorIntoOS(t *testing.T) {
	store, err := storage.New(filepath.Join(t.TempDir(), "scan.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	_, _, err = store.RecordRouterLeases("gateway", []storage.RouterLease{
		{IP: "10.0.0.77", MAC: "DA:BB:CC:DD:EE:FF", Hostname: "phone"},
		{IP: "10.0.0.78", MAC: "F4:03:2A:11:22:33", Hostname: "echo"},
	}, VendorClaim, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	for _, ip := range []string{"10.0.0.77", "10.0.0.78"} {
		a, err := store.GetAsset(ip)
		if err != nil {
			t.Fatal(err)
		}
		if a.OS != "" {
			t.Fatalf("vendor became an OS guess: %q", a.OS)
		}
		if ip == "10.0.0.77" && a.Vendor != VendorRandomised {
			t.Fatalf("randomised-MAC explanation lost: %q", a.Vendor)
		}
		if ip == "10.0.0.78" && a.Vendor != "Amazon Technologies Inc." {
			t.Fatalf("manufacturer lost: %q", a.Vendor)
		}
	}
}
