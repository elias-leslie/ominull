package threatintel

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
)

// A feed is remote input from a machine nobody here controls. These tests hold
// shut the two ways that goes wrong: a bad download quietly wiping attribution,
// and a rented range being presented as though the vendor ran it.

func TestATruncatedFeedLeavesThePreviousTableInPlace(t *testing.T) {
	before := AttributionInfo()
	if before.Count == 0 {
		t.Fatal("expected the built-in table to be in force before the test")
	}

	// Half a JSON document, which is what a connection dropped mid-transfer
	// actually delivers.
	entries, err := parseAWSRanges(strings.NewReader(`{"prefixes":[{"ip_prefix":"52.0.0.0/8","serv`))
	if err == nil {
		t.Fatal("expected a truncated feed to fail parsing")
	}
	if len(entries) != 0 {
		t.Fatalf("expected nothing usable from a truncated feed, got %d entries", len(entries))
	}

	if _, err := LoadAttribution(entries, "truncated feed"); err == nil {
		t.Fatal("expected an undersized table to be refused")
	}

	after := AttributionInfo()
	if after.Count != before.Count || after.Source != before.Source {
		t.Fatalf("the previous table was disturbed: %+v became %+v", before, after)
	}
	if !ResolveGeoIP("8.8.8.8").Resolved() {
		t.Fatal("attribution stopped working after a refused refresh")
	}
}

func TestRentedRangesAreNeverEligibleToBeVouchedFor(t *testing.T) {
	aws, err := parseAWSRanges(strings.NewReader(`{
		"prefixes": [
			{"ip_prefix": "52.94.0.0/22", "region": "us-east-1", "service": "EC2"},
			{"ip_prefix": "52.94.0.0/22", "region": "us-east-1", "service": "AMAZON"},
			{"ip_prefix": "13.32.0.0/15", "region": "GLOBAL", "service": "CLOUDFRONT"}
		],
		"ipv6_prefixes": [
			{"ipv6_prefix": "2600:1f00::/40", "region": "us-east-1", "service": "EC2"}
		]
	}`))
	if err != nil {
		t.Fatalf("parsing the AWS feed: %v", err)
	}

	tenancy := map[string]string{}
	for _, e := range aws {
		tenancy[e.Prefix] = e.Tenancy
	}
	if tenancy["52.94.0.0/22"] != TenancyHosting {
		t.Fatalf("an EC2 range must be rented compute, got %q", tenancy["52.94.0.0/22"])
	}
	if tenancy["2600:1f00::/40"] != TenancyHosting {
		t.Fatalf("an IPv6 EC2 range must be rented compute, got %q", tenancy["2600:1f00::/40"])
	}
	if tenancy["13.32.0.0/15"] != TenancySharedCDN {
		t.Fatalf("CloudFront is shared edge, got %q", tenancy["13.32.0.0/15"])
	}

	for _, e := range aws {
		if e.Tenancy != TenancyHosting {
			continue
		}
		rec := GeoRecord{Country: e.Country, ASN: e.ASN, Org: e.Org, Tenancy: e.Tenancy}
		if CanAutoVouch(rec) {
			t.Fatalf("%s (%s) was eligible for automatic vouching", e.Prefix, e.Org)
		}
	}
}

func TestGoogleCustomerRangesOutrankGoogleOwnRanges(t *testing.T) {
	own, err := parseGoogleRanges(TenancyVendor, "Google LLC", "AS15169")(strings.NewReader(
		`{"prefixes":[{"ipv4Prefix":"34.0.0.0/8"}]}`))
	if err != nil {
		t.Fatalf("parsing goog.json: %v", err)
	}
	customer, err := parseGoogleRanges(TenancyHosting, "Google Cloud (customer range)", "AS396982")(strings.NewReader(
		`{"prefixes":[{"ipv4Prefix":"34.0.0.0/8","scope":"us-central1"}]}`))
	if err != nil {
		t.Fatalf("parsing cloud.json: %v", err)
	}

	// The same bits appear in both files. Whoever rented the range today is the
	// answer that has to win, or every GCP tenant inherits Google's standing.
	built := buildTable(append(own, customer...), "test")
	if len(built.rules) == 0 {
		t.Fatal("expected the table to hold both entries")
	}
	if got := built.rules[0].record.Tenancy; got != TenancyHosting {
		t.Fatalf("the customer answer must sort first, got %q", got)
	}
	if CanAutoVouch(built.rules[0].record) {
		t.Fatal("a GCP customer range was eligible for automatic vouching")
	}
}

func TestTheWarninglistParserTakesAddressesAndIgnoresNames(t *testing.T) {
	entries, err := parseMISPWarninglist("Akamai Technologies", "AS20940", TenancySharedCDN)(strings.NewReader(
		`{"name":"akamai","list":["23.32.0.0/11","2.16.0.0/13","a23-32-0-1.deploy.akamaitechnologies.com","104.64.0.5",""]}`))
	if err != nil {
		t.Fatalf("parsing the warning list: %v", err)
	}
	want := map[string]bool{"23.32.0.0/11": true, "2.16.0.0/13": true, "104.64.0.5/32": true}
	if len(entries) != len(want) {
		t.Fatalf("expected %d address entries, got %d: %+v", len(want), len(entries), entries)
	}
	for _, e := range entries {
		if !want[e.Prefix] {
			t.Fatalf("unexpected entry %q; hostnames must be skipped, not coerced into prefixes", e.Prefix)
		}
		if e.Tenancy != TenancySharedCDN {
			t.Fatalf("%s lost its tenancy: %q", e.Prefix, e.Tenancy)
		}
	}
}

func TestAPlainPrefixListSkipsCommentsAndRubbish(t *testing.T) {
	entries, err := parsePlainPrefixList("Cloudflare, Inc.", "AS13335", "US", "United States", TenancySharedCDN)(
		strings.NewReader("# Cloudflare IPv4\n103.21.244.0/22\n\nnot-a-prefix\n104.16.0.0/13\n"))
	if err != nil {
		t.Fatalf("parsing the prefix list: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("expected the two real prefixes, got %+v", entries)
	}
}

func TestAFeedServingRubbishIsAnErrorNotAnEmptyTable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// What a captive portal or a proxy error page actually returns.
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<html><body>Sign in to continue</body></html>"))
	}))
	defer srv.Close()

	feed := netFeed{name: "test", url: srv.URL, parse: parseAWSRanges}
	if _, err := fetchFeed(context.Background(), srv.Client(), feed); err == nil {
		t.Fatal("expected an HTML error page to be rejected by the parser")
	}
}

func TestAFeedIsSizeCapped(t *testing.T) {
	if feedByteLimit <= 0 {
		t.Fatal("feeds must be size-capped; a hostile or broken mirror can serve without end")
	}
}

func TestEveryFeedDeclaresATenancyThatIsNotGuessed(t *testing.T) {
	for _, feed := range networkFeeds() {
		if feed.name == "" || feed.url == "" || feed.parse == nil {
			t.Fatalf("feed %+v is incomplete", feed)
		}
		if !strings.HasPrefix(feed.url, "https://") {
			t.Fatalf("feed %s is not fetched over TLS: %s", feed.name, feed.url)
		}
	}
}

// The MISP collection holds hostname, substring and regex lists under the same
// filename shape as the address lists. Reading one of those as addresses would
// attribute whichever entries happened to parse and quietly drop the rest.
func TestAWarninglistOfTheWrongTypeIsRejectedOutright(t *testing.T) {
	_, err := parseMISPWarninglist("Example", "AS64496", TenancyVendor)(strings.NewReader(
		`{"name":"example domains","type":"hostname","list":["example.com","1.2.3.4"]}`))
	if err == nil {
		t.Fatal("expected a hostname list to be refused rather than half-read")
	}
}

// Lookups are bucketed by first octet, and a bucketed table that misses a range
// the old linear scan would have found is a silent loss of attribution.
func TestBucketedLookupsFindShortPrefixesAndIPv6(t *testing.T) {
	built := buildTable([]NetworkPrefix{
		{Prefix: "8.0.0.0/7", Org: "Short Prefix Co", Tenancy: TenancyVendor},
		{Prefix: "8.8.8.0/24", Org: "Specific Co", Tenancy: TenancyVendor},
		{Prefix: "2620:149::/32", Org: "Apple Inc.", Tenancy: TenancyVendor},
	}, "test")

	cases := map[string]string{
		"8.8.8.8":     "Specific Co",
		"8.1.2.3":     "Short Prefix Co",
		"9.4.5.6":     "Short Prefix Co",
		"2620:149::4": "Apple Inc.",
	}
	for ip, want := range cases {
		addr := mustAddr(t, ip)
		rec, ok := built.lookup(addr)
		if !ok {
			t.Fatalf("%s resolved to nothing; the bucket index lost it", ip)
		}
		if rec.Org != want {
			t.Fatalf("%s resolved to %q, want %q", ip, rec.Org, want)
		}
	}

	if _, ok := built.lookup(mustAddr(t, "10.20.30.40")); ok {
		t.Fatal("an address in no listed range resolved to something")
	}
}

func mustAddr(t *testing.T, s string) netip.Addr {
	t.Helper()
	addr, err := netip.ParseAddr(s)
	if err != nil {
		t.Fatalf("parsing %s: %v", s, err)
	}
	return addr
}

// GitHub rents thousands of Azure prefixes for hosted runners and publishes
// them in the same document as its own front ends. An aggregate that flattens
// the two hands every tenant of those Azure ranges GitHub's standing, which is
// the precise mistake the tenancy model exists to prevent.
func TestGitHubsRentedRunnerRangesAreNotAttributedToGitHub(t *testing.T) {
	entries, err := parseGitHubMeta(strings.NewReader(`{
		"verifiable_password_authentication": false,
		"ssh_key_fingerprints": {"SHA256_RSA": "abc"},
		"web": ["192.30.252.0/22"],
		"api": ["140.82.112.0/20"],
		"git": ["185.199.108.0/22"],
		"actions": ["4.148.0.0/16", "40.126.32.0/23"],
		"codespaces": ["20.42.11.16/28"],
		"importer": ["52.23.85.212/32"]
	}`))
	if err != nil {
		t.Fatalf("parsing the GitHub meta document: %v", err)
	}

	byPrefix := map[string]NetworkPrefix{}
	for _, e := range entries {
		byPrefix[e.Prefix] = e
	}

	for _, own := range []string{"192.30.252.0/22", "140.82.112.0/20", "185.199.108.0/22"} {
		if byPrefix[own].Tenancy != TenancyVendor {
			t.Fatalf("%s is GitHub's own range, got tenancy %q", own, byPrefix[own].Tenancy)
		}
	}
	for _, rented := range []string{"4.148.0.0/16", "40.126.32.0/23", "20.42.11.16/28", "52.23.85.212/32"} {
		e := byPrefix[rented]
		if e.Tenancy != TenancyHosting {
			t.Fatalf("%s is rented cloud, got tenancy %q", rented, e.Tenancy)
		}
		if CanAutoVouch(GeoRecord{Country: e.Country, ASN: e.ASN, Org: e.Org, Tenancy: e.Tenancy}) {
			t.Fatalf("%s was eligible for automatic vouching", rented)
		}
	}
}

func TestAGitHubMetaDocumentWithNoRangesIsAnError(t *testing.T) {
	if _, err := parseGitHubMeta(strings.NewReader(`{"ssh_keys":["ssh-ed25519 AAAA"]}`)); err == nil {
		t.Fatal("expected a document with no ranges to be refused rather than swapped in empty")
	}
}
