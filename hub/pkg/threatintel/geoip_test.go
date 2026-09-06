package threatintel

import "testing"

// Every address here was mis-attributed on the production fleet by the hash
// fallback this table replaced, and each mis-attribution had a consequence: the
// detector's quiet-organisation list is matched against the Org field, so
// naming the wrong owner meant a CDN keepalive was reported as C2 beaconing.
func TestMajorNetworksResolveToTheirRealOwner(t *testing.T) {
	cases := []struct {
		ip      string
		org     string
		country string
		why     string
	}{
		{"74.125.26.188", "Google LLC", "US", "Google's push endpoint was reported as Amazon"},
		{"23.194.240.70", "Akamai Technologies", "US", "an Akamai edge was reported as OVH in France"},
		{"23.194.224.227", "Akamai Technologies", "US", "a second address in the same Akamai block was reported as Telstra in Australia"},
		{"104.26.12.157", "Cloudflare, Inc.", "US", "a Cloudflare edge was reported as WorldStream in the Netherlands"},
		{"142.251.107.188", "Google LLC", "US", "Google"},
		{"108.177.12.188", "Google LLC", "US", "Google"},
		// The string-prefix table matched in list order, so a short early entry
		// swallowed every longer one that came after it.
		{"172.217.203.188", "Google LLC", "US", "\"17.\" (Apple) captured Google's 172.217.0.0/16"},
		{"173.255.200.1", "Akamai Connected Cloud (Linode)", "US", "\"17.\" captured Linode's range"},
		{"178.32.10.1", "OVH SAS", "FR", "\"17.\" captured OVH's range"},
		{"185.199.108.153", "GitHub, Inc.", "US", "\"18.\" (Amazon) captured GitHub Pages"},
		{"52.110.6.24", "Microsoft Corporation", "US", "Microsoft 365 sits inside a range AWS also holds; longest prefix decides"},
		{"52.10.0.1", "Amazon.com, Inc.", "US", "the surrounding AWS range still resolves to AWS"},
		{"17.253.144.10", "Apple Inc.", "US", "Apple"},
		{"1.1.1.1", "Cloudflare, Inc.", "US", "Cloudflare's resolver"},
	}
	for _, c := range cases {
		got := ResolveGeoIP(c.ip)
		if got.Org != c.org {
			t.Errorf("%s resolved to %q, want %q (%s)", c.ip, got.Org, c.org, c.why)
		}
		if got.Country != c.country {
			t.Errorf("%s resolved to country %q, want %q", c.ip, got.Country, c.country)
		}
	}
}

// The defect this file exists to remove: an address the table does not cover
// used to be assigned a plausible country, city, ASN and organisation by
// hashing its text. Everything downstream then treated that as a measurement.
func TestAnUnknownAddressIsUnresolvedRatherThanGuessed(t *testing.T) {
	// Two addresses one apart. Under the hash fallback they landed in different
	// profiles and were reported as different countries and owners.
	for _, ip := range []string{"198.51.100.7", "198.51.100.8", "203.0.113.19"} {
		got := ResolveGeoIP(ip)
		if got.Resolved() {
			t.Errorf("%s was attributed to %q; an address outside the table must be unresolved", ip, got.Org)
		}
		if got.Org != "" || got.ASN != "" {
			t.Errorf("%s carries owner detail %q/%q it cannot know", ip, got.ASN, got.Org)
		}
		if got.Country != "UNKNOWN" {
			t.Errorf("%s reported country %q; want UNKNOWN", ip, got.Country)
		}
		if got.City != "" {
			t.Errorf("%s named a city (%q) for an address it cannot place", ip, got.City)
		}
	}
}

// Resolution has to be a function of the address, not of its text: the same
// network must not answer differently for two of its own hosts.
func TestTheSameNetworkAnswersConsistently(t *testing.T) {
	first := ResolveGeoIP("23.192.0.1")
	for _, ip := range []string{"23.194.240.70", "23.194.224.227", "23.223.255.254"} {
		if got := ResolveGeoIP(ip); got.Org != first.Org || got.Country != first.Country {
			t.Errorf("%s resolved to %q/%q but %q/%q for the same block",
				ip, got.Country, got.Org, first.Country, first.Org)
		}
	}
}

func TestLocalAddressesAreNotAttributedToAnOwner(t *testing.T) {
	for _, ip := range []string{"10.0.0.58", "10.0.0.1", "172.18.0.4", "169.254.1.1"} {
		if got := ResolveGeoIP(ip); got.Country != "LOCAL" {
			t.Errorf("%s resolved to %q; a private address is local", ip, got.Country)
		}
	}
	for _, ip := range []string{"127.0.0.1", "::1", "0.0.0.0"} {
		if got := ResolveGeoIP(ip); got.Country != "LOCAL" {
			t.Errorf("%s resolved to %q; loopback is local", ip, got.Country)
		}
	}
}

// A malformed entry in the table would silently widen or narrow somebody's
// network, so the table has to parse in full.
func TestEveryTableEntryIsAValidPrefix(t *testing.T) {
	built := table()
	declared := 0
	for _, owner := range ownerBlocks {
		declared += len(owner.cidrs)
	}
	if built.count != declared {
		t.Fatalf("%d of %d table entries parsed; the rest were dropped", built.count, declared)
	}
	for i := 1; i < len(built.rules); i++ {
		if built.rules[i-1].prefix.Bits() < built.rules[i].prefix.Bits() {
			t.Fatalf("table is not sorted longest-prefix-first at %d: /%d before /%d",
				i, built.rules[i-1].prefix.Bits(), built.rules[i].prefix.Bits())
		}
	}
}

// Every built-in owner has to declare how its range is tenanted, because that
// is what decides whether anything may ever be vouched for on it.
func TestEveryBuiltinOwnerDeclaresItsTenancy(t *testing.T) {
	for _, owner := range ownerBlocks {
		switch owner.owner.Tenancy {
		case TenancyVendor, TenancySharedCDN, TenancyHosting:
		default:
			t.Errorf("%s declares tenancy %q", owner.owner.Org, owner.owner.Tenancy)
		}
	}
}
