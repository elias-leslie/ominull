package threatintel

import (
	"net/netip"
	"sort"
	"strings"
	"sync"
)

// Offline network attribution: which country and which network owner an address
// belongs to.
//
// This used to answer every address. Addresses outside its small table were run
// through fnv32a(ip) %% len(fallbackProfiles) and assigned whichever of fourteen
// plausible profiles the hash landed on - a country, a city, an ASN and an
// organisation, returned in the same shape and with the same apparent
// confidence as a real answer. It was labelled a fallback "for test/unallocated
// public IPs"; on a real network it caught the overwhelming majority of
// destinations. Measured on the production fleet, it reported Google's
// 74.125.26.188 as Amazon, two addresses inside Akamai's 23.192.0.0/11 as OVH
// in France and Telstra in Australia, and Cloudflare's 104.26.12.157 as
// WorldStream in the Netherlands.
//
// That was not a cosmetic defect. The detector's quiet-organisation list - the
// operator's own statement that Google, Akamai, Cloudflare, Amazon, Microsoft
// and Apple are normal here - is matched against this answer, so inventing a
// different owner meant the list never matched and every CDN keepalive was
// reported as C2 beaconing. It also fed the console's country rankings, which
// showed a home LAN talking to Sweden and Japan more than to anywhere real.
//
// Two rules now:
//
//   - Anything not in the table is *unresolved*. Not a guess, not a plausible
//     profile: Country "UNKNOWN" and an empty Org, which the quiet lists treat
//     as no match and the console prints as unknown. A wrong owner is worse
//     than no owner, because everything downstream trusts it.
//   - Matching is by CIDR, longest prefix wins. The old table matched decimal
//     string prefixes in list order, so "17." (Apple) captured 172.217.0.0/16
//     (Google), 173.255.0.0/16 (Linode) and 178.32.0.0/16 (OVH), and "18."
//     (Amazon) captured 185.199.108.0/22 (GitHub Pages) - the later, more
//     specific entries were unreachable.
//
// The table is a coarse, hand-maintained list of the large networks an estate
// actually talks to, kept deliberately to allocations that are published and
// stable. It is not a substitute for a real GeoIP database, and it does not
// pretend to be: everything it does not know, it says it does not know.

type GeoRecord struct {
	Country     string `json:"country"`
	CountryName string `json:"country_name"`
	City        string `json:"city"`
	ASN         string `json:"asn"`
	Org         string `json:"org"`
}

// Resolved reports whether this record names a real network owner, as opposed
// to the unresolved answer returned for an address the table does not cover.
func (g GeoRecord) Resolved() bool { return strings.TrimSpace(g.Org) != "" }

type prefixRule struct {
	prefix netip.Prefix
	record GeoRecord
}

var (
	geoCache   = make(map[string]GeoRecord)
	geoCacheMu sync.RWMutex

	// unresolvedRecord is what an address outside the table gets. The country
	// code is the same "UNKNOWN" an unparseable address has always produced, so
	// nothing downstream meets a value it has not already had to handle.
	unresolvedRecord = GeoRecord{
		Country:     "UNKNOWN",
		CountryName: "Unknown Network",
		ASN:         "",
		Org:         "",
	}

	loopbackRecord = GeoRecord{
		Country:     "LOCAL",
		CountryName: "Loopback Interface",
		ASN:         "AS-LOCAL",
		Org:         "Local Loopback",
	}

	privateRecord = GeoRecord{
		Country:     "LOCAL",
		CountryName: "Internal Network",
		ASN:         "AS-PRIVATE",
		Org:         "Enterprise Intranet",
	}

	// knownBlocks is built once, sorted longest-prefix-first, so the first
	// match is also the most specific one.
	knownBlocks []prefixRule
	blocksOnce  sync.Once
)

// ownerBlocks lists the networks the table knows, as CIDR strings against one
// owner each. City is deliberately absent: an owner's allocation spans
// continents, and naming a city for it would be the same invention this file
// exists to remove.
var ownerBlocks = []struct {
	owner GeoRecord
	cidrs []string
}{
	{
		GeoRecord{Country: "US", CountryName: "United States", ASN: "AS15169", Org: "Google LLC"},
		[]string{
			"8.8.4.0/24", "8.8.8.0/24", "8.34.208.0/20", "8.35.192.0/20",
			"23.236.48.0/20", "23.251.128.0/19",
			"34.64.0.0/10", "34.128.0.0/10",
			"35.184.0.0/13", "35.192.0.0/14", "35.196.0.0/15", "35.198.0.0/16",
			"35.199.0.0/17", "35.200.0.0/13", "35.208.0.0/12", "35.224.0.0/12",
			"35.240.0.0/13",
			"64.233.160.0/19", "66.102.0.0/20", "66.249.64.0/19", "72.14.192.0/18",
			"74.125.0.0/16", "108.177.0.0/17", "130.211.0.0/16",
			"142.250.0.0/15", "142.251.0.0/16",
			"172.217.0.0/16", "172.253.0.0/16", "173.194.0.0/16",
			"209.85.128.0/17", "216.58.192.0/19", "216.239.32.0/19",
		},
	},
	{
		GeoRecord{Country: "US", CountryName: "United States", ASN: "AS20940", Org: "Akamai Technologies"},
		[]string{
			"2.16.0.0/13", "23.32.0.0/11", "23.64.0.0/14", "23.192.0.0/11",
			"88.221.0.0/16", "92.122.0.0/15", "95.100.0.0/15", "96.16.0.0/15",
			"104.64.0.0/10", "184.24.0.0/13", "184.50.0.0/15",
		},
	},
	{
		GeoRecord{Country: "US", CountryName: "United States", ASN: "AS13335", Org: "Cloudflare, Inc."},
		[]string{
			"1.0.0.0/24", "1.1.1.0/24",
			"103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
			"104.16.0.0/13", "104.24.0.0/14",
			"108.162.192.0/18", "131.0.72.0/22", "141.101.64.0/18",
			"162.158.0.0/15", "172.64.0.0/13", "173.245.48.0/20",
			"188.114.96.0/20", "190.93.240.0/20", "197.234.240.0/22",
			"198.41.128.0/17",
		},
	},
	{
		GeoRecord{Country: "US", CountryName: "United States", ASN: "AS8075", Org: "Microsoft Corporation"},
		[]string{
			"13.64.0.0/11", "20.0.0.0/8", "40.64.0.0/10", "51.104.0.0/15",
			"52.96.0.0/12", "52.112.0.0/14", "65.52.0.0/14", "104.40.0.0/13",
			"131.253.0.0/16", "157.55.0.0/16", "168.61.0.0/16",
			"191.232.0.0/13", "204.79.195.0/24",
		},
	},
	{
		GeoRecord{Country: "US", CountryName: "United States", ASN: "AS16509", Org: "Amazon.com, Inc."},
		[]string{
			"3.0.0.0/8", "13.32.0.0/15", "13.224.0.0/14", "15.177.0.0/16",
			"18.0.0.0/8", "44.192.0.0/10", "52.0.0.0/11", "52.32.0.0/11",
			"52.64.0.0/12", "52.84.0.0/15", "52.88.0.0/13", "54.0.0.0/8",
			"99.77.0.0/16", "143.204.0.0/16", "205.251.192.0/18",
		},
	},
	{
		GeoRecord{Country: "US", CountryName: "United States", ASN: "AS714", Org: "Apple Inc."},
		[]string{"17.0.0.0/8"},
	},
	{
		GeoRecord{Country: "US", CountryName: "United States", ASN: "AS54113", Org: "Fastly, Inc."},
		[]string{"146.75.0.0/16", "151.101.0.0/16", "199.232.0.0/16"},
	},
	{
		GeoRecord{Country: "US", CountryName: "United States", ASN: "AS36459", Org: "GitHub, Inc."},
		[]string{"140.82.112.0/20", "185.199.108.0/22", "192.30.252.0/22"},
	},
	{
		GeoRecord{Country: "US", CountryName: "United States", ASN: "AS14061", Org: "DigitalOcean, LLC"},
		[]string{"104.248.0.0/16", "138.68.0.0/16", "159.65.0.0/16", "165.227.0.0/16", "167.71.0.0/16"},
	},
	{
		GeoRecord{Country: "DE", CountryName: "Germany", ASN: "AS24940", Org: "Hetzner Online GmbH"},
		[]string{"88.198.0.0/16", "136.243.0.0/16", "148.251.0.0/16", "159.69.0.0/16", "65.108.0.0/16", "116.202.0.0/16"},
	},
	{
		GeoRecord{Country: "FR", CountryName: "France", ASN: "AS16276", Org: "OVH SAS"},
		[]string{"51.15.0.0/16", "145.239.0.0/16", "178.32.0.0/15", "51.68.0.0/14", "54.36.0.0/14"},
	},
	{
		GeoRecord{Country: "US", CountryName: "United States", ASN: "AS63949", Org: "Akamai Connected Cloud (Linode)"},
		[]string{"45.33.32.0/19", "173.255.192.0/18", "172.104.0.0/15", "139.162.0.0/16"},
	},
	{
		GeoRecord{Country: "US", CountryName: "United States", ASN: "AS19281", Org: "Quad9"},
		[]string{"9.9.9.0/24", "149.112.112.0/24"},
	},
	{
		GeoRecord{Country: "US", CountryName: "United States", ASN: "AS13414", Org: "Twitter, Inc."},
		[]string{"104.244.40.0/21", "192.133.76.0/22"},
	},
}

func buildBlocks() {
	for _, owner := range ownerBlocks {
		for _, cidr := range owner.cidrs {
			prefix, err := netip.ParsePrefix(cidr)
			if err != nil {
				// A malformed entry is dropped rather than approximated. The
				// address it covered then resolves as unknown, which is the
				// honest outcome and is caught by the table's own test.
				continue
			}
			knownBlocks = append(knownBlocks, prefixRule{prefix: prefix.Masked(), record: owner.owner})
		}
	}
	// Longest prefix first: 52.96.0.0/12 (Microsoft 365) has to be consulted
	// before 52.0.0.0/11 (AWS), and a list in authoring order would not.
	sort.SliceStable(knownBlocks, func(i, j int) bool {
		return knownBlocks[i].prefix.Bits() > knownBlocks[j].prefix.Bits()
	})
}

// ResolveGeoIP attributes an address to a country and a network owner, offline.
// An address the table does not cover comes back unresolved rather than
// guessed; callers must treat an empty Org as "not known", never as a name.
func ResolveGeoIP(ipStr string) GeoRecord {
	ipStr = strings.TrimSpace(ipStr)
	if ipStr == "" {
		return unresolvedRecord
	}

	addr, err := netip.ParseAddr(ipStr)
	if err != nil {
		return unresolvedRecord
	}
	addr = addr.Unmap()
	if addr.IsLoopback() || addr.IsUnspecified() {
		return loopbackRecord
	}
	if addr.IsPrivate() || addr.IsLinkLocalUnicast() || addr.IsLinkLocalMulticast() {
		return privateRecord
	}

	geoCacheMu.RLock()
	rec, found := geoCache[ipStr]
	geoCacheMu.RUnlock()
	if found {
		return rec
	}

	blocksOnce.Do(buildBlocks)

	result := unresolvedRecord
	for _, b := range knownBlocks {
		if b.prefix.Contains(addr) {
			result = b.record
			break
		}
	}

	geoCacheMu.Lock()
	geoCache[ipStr] = result
	geoCacheMu.Unlock()
	return result
}

// ResolveCountry returns a 2-letter ISO country code, or "UNKNOWN".
func ResolveCountry(ipStr string) string {
	return ResolveGeoIP(ipStr).Country
}

// ResolveASN returns the ASN and organisation for an address. Both are empty
// when the address is not attributable.
func ResolveASN(ipStr string) (string, string) {
	rec := ResolveGeoIP(ipStr)
	return rec.ASN, rec.Org
}
