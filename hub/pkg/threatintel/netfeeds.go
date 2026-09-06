package threatintel

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"ominull/hub/pkg/storage"
)

// Published network attribution, fetched rather than retyped.
//
// The table compiled into geoip.go is a hand-written list of a dozen owners,
// which is why most findings on a live estate read "unattributed network": the
// addresses are real, ordinary, and simply not in it. Every one of these owners
// publishes their ranges, and MISP maintains a public-domain collection of the
// same lists that every other tool uses. There is no reason to keep guessing.
//
// Two rules govern what arrives here:
//
//   - Attribution is not vouching. Naming a range "Google Cloud customer range"
//     is an answer; it is never grounds to silence anything. The tenancy on each
//     entry carries that distinction into the detector.
//   - A feed may fail, arrive truncated, or arrive malformed, and none of those
//     may take detection with them. Everything is size-capped, parsed into a
//     candidate table, checked for a sane floor, and only then swapped in.

const (
	// feedByteLimit caps any single feed. AWS is the largest at roughly 1MB.
	feedByteLimit = 16 << 20

	// feedTimeout is per feed, not for the set: one slow mirror must not stop
	// the others being refreshed.
	feedTimeout = 30 * time.Second

	// firstRefreshDelay keeps the first fetch out of the hub's start-up path.
	firstRefreshDelay = 30 * time.Second
)

// netFeed is one published source of ranges.
type netFeed struct {
	name  string
	url   string
	parse func(io.Reader) ([]NetworkPrefix, error)
}

// Hetzner is deliberately absent: its warning list is 167,000 single addresses,
// which is a great deal of table for an owner the built-in blocks already name,
// and rented compute is never vouched for anyway.
func networkFeeds() []netFeed {
	return []netFeed{
		{name: "aws", url: "https://ip-ranges.amazonaws.com/ip-ranges.json", parse: parseAWSRanges},
		{name: "google", url: "https://www.gstatic.com/ipranges/goog.json", parse: parseGoogleRanges(TenancyVendor, "Google LLC", "AS15169")},
		{name: "google-cloud", url: "https://www.gstatic.com/ipranges/cloud.json", parse: parseGoogleRanges(TenancyHosting, "Google Cloud (customer range)", "AS396982")},
		{name: "cloudflare-v4", url: "https://www.cloudflare.com/ips-v4/", parse: parsePlainPrefixList("Cloudflare, Inc.", "AS13335", "US", "United States", TenancySharedCDN)},
		{name: "cloudflare-v6", url: "https://www.cloudflare.com/ips-v6/", parse: parsePlainPrefixList("Cloudflare, Inc.", "AS13335", "US", "United States", TenancySharedCDN)},
		{name: "misp-akamai", url: mispList("akamai"), parse: parseMISPWarninglist("Akamai Technologies", "AS20940", TenancySharedCDN)},
		{name: "misp-fastly", url: mispList("fastly"), parse: parseMISPWarninglist("Fastly, Inc.", "AS54113", TenancySharedCDN)},
		{name: "misp-office365", url: mispList("microsoft-office365-ip"), parse: parseMISPWarninglist("Microsoft 365", "AS8075", TenancyVendor)},
		{name: "misp-microsoft-azure", url: mispList("microsoft-azure"), parse: parseMISPWarninglist("Microsoft Azure (customer range)", "AS8075", TenancyHosting)},
		{name: "misp-apple", url: mispList("apple"), parse: parseMISPWarninglist("Apple Inc.", "AS714", TenancyVendor)},
		{name: "github", url: "https://api.github.com/meta", parse: parseGitHubMeta},
		{name: "misp-digitalocean", url: mispList("digitalocean"), parse: parseMISPWarninglist("DigitalOcean, LLC", "AS14061", TenancyHosting)},
		{name: "misp-linode", url: mispList("linode"), parse: parseMISPWarninglist("Linode, LLC", "AS63949", TenancyHosting)},
		{name: "misp-vultr", url: mispList("vultr"), parse: parseMISPWarninglist("Vultr Holdings", "AS20473", TenancyHosting)},
		{name: "misp-ovh", url: mispList("ovh-cluster"), parse: parseMISPWarninglist("OVH SAS", "AS16276", TenancyHosting)},
		{name: "misp-oracle-cloud", url: mispList("oracle-oci"), parse: parseMISPWarninglist("Oracle Cloud (customer range)", "AS31898", TenancyHosting)},
		{name: "misp-zscaler", url: mispList("zscaler"), parse: parseMISPWarninglist("Zscaler, Inc.", "AS22616", TenancyVendor)},
		{name: "misp-cdn77", url: mispList("cdn77"), parse: parseMISPWarninglist("CDN77", "AS60068", TenancySharedCDN)},
	}
}

// mispList addresses one warning list in the MISP collection, which is CC0 and
// carries the same vendor ranges every other tool consumes.
func mispList(name string) string {
	return "https://raw.githubusercontent.com/MISP/misp-warninglists/main/lists/" + name + "/list.json"
}

// SyncNetworkAttribution fetches every feed, merges what came back with the
// built-in table, and swaps the result in. The built-in entries stay underneath
// as the floor: a feed that disappears cannot take an owner's attribution with
// it, and a hub with no internet resolves from them alone.
func SyncNetworkAttribution(ctx context.Context, client *http.Client) ([]NetworkPrefix, AttributionStatus, error) {
	if client == nil {
		client = &http.Client{Timeout: feedTimeout}
	}

	merged := BuiltinAttribution()
	fetched, failed := 0, 0
	var firstErr error

	for _, feed := range networkFeeds() {
		entries, err := fetchFeed(ctx, client, feed)
		if err != nil {
			failed++
			if firstErr == nil {
				firstErr = fmt.Errorf("%s: %w", feed.name, err)
			}
			log.Printf("[-] Network attribution feed %s could not be refreshed: %v", feed.name, err)
			continue
		}
		fetched += len(entries)
		merged = append(merged, entries...)
	}

	status, err := LoadAttribution(merged, attributionSourceLabel(fetched, failed))
	if err != nil {
		return nil, status, err
	}
	log.Printf("[+] Network attribution: %d prefixes in force (%d from published feeds, %d feeds unavailable)",
		status.Count, fetched, failed)
	return merged, status, firstErr
}

func attributionSourceLabel(fetched, failed int) string {
	if fetched == 0 {
		return "built-in"
	}
	if failed > 0 {
		return fmt.Sprintf("published feeds (%d unavailable)", failed)
	}
	return "published feeds"
}

func fetchFeed(ctx context.Context, client *http.Client, feed netFeed) ([]NetworkPrefix, error) {
	reqCtx, cancel := context.WithTimeout(ctx, feedTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, feed.url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Ominull-NetworkAttribution/1.0")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	entries, err := feed.parse(io.LimitReader(resp.Body, feedByteLimit))
	if err != nil {
		return nil, err
	}
	for i := range entries {
		entries[i].Source = feed.name
	}
	return entries, nil
}

// parseAWSRanges reads ip-ranges.json. The per-prefix service tag is the whole
// reason for going to AWS directly rather than taking an aggregate: EC2 is
// rented compute and CloudFront is edge, and the same file holds both.
func parseAWSRanges(r io.Reader) ([]NetworkPrefix, error) {
	var doc struct {
		Prefixes []struct {
			IPPrefix string `json:"ip_prefix"`
			Region   string `json:"region"`
			Service  string `json:"service"`
		} `json:"prefixes"`
		IPv6Prefixes []struct {
			IPv6Prefix string `json:"ipv6_prefix"`
			Region     string `json:"region"`
			Service    string `json:"service"`
		} `json:"ipv6_prefixes"`
	}
	if err := json.NewDecoder(r).Decode(&doc); err != nil {
		return nil, err
	}

	// A prefix appears once per service it belongs to. Rented wins: if any
	// entry for a range says EC2, the range can hold anybody's workload.
	tenancy := make(map[string]string)
	// S3 is worth carrying separately. A range that holds files is where bulk
	// egress goes, and the storage rule needs to be able to say so; the tenancy
	// still says the range is rented, so nothing is vouched for by being named.
	isStorage := make(map[string]bool)
	order := make([]string, 0, len(doc.Prefixes))
	note := func(prefix, service string) {
		if prefix == "" {
			return
		}
		if _, seen := tenancy[prefix]; !seen {
			order = append(order, prefix)
		}
		if strings.EqualFold(strings.TrimSpace(service), "S3") {
			isStorage[prefix] = true
		}
		t := awsTenancy(service)
		if cur, seen := tenancy[prefix]; !seen || tenancyRank(t) < tenancyRank(cur) {
			tenancy[prefix] = t
		}
	}
	for _, p := range doc.Prefixes {
		note(p.IPPrefix, p.Service)
	}
	for _, p := range doc.IPv6Prefixes {
		note(p.IPv6Prefix, p.Service)
	}

	out := make([]NetworkPrefix, 0, len(order))
	for _, prefix := range order {
		org := "Amazon Web Services"
		if tenancy[prefix] == TenancyHosting {
			org = "Amazon Web Services (customer range)"
		}
		if isStorage[prefix] {
			org = "Amazon S3 (" + org + ")"
		}
		out = append(out, NetworkPrefix{
			Prefix: prefix, Country: "US", CountryName: "United States",
			ASN: "AS16509", Org: org, Tenancy: tenancy[prefix],
		})
	}
	return out, nil
}

func awsTenancy(service string) string {
	switch strings.ToUpper(strings.TrimSpace(service)) {
	case "EC2", "AMAZON":
		// AMAZON is the catch-all superset that covers customer ranges too, so
		// it is treated as rented rather than as Amazon's own service.
		return TenancyHosting
	case "CLOUDFRONT", "CLOUDFRONT_ORIGIN_FACING", "GLOBALACCELERATOR":
		return TenancySharedCDN
	default:
		return TenancyVendor
	}
}

// parseGitHubMeta reads api.github.com/meta, keeping GitHub's own service
// ranges apart from the rented ones.
//
// This is why the aggregate list is not used here: it flattens every key in
// this document into one set, and the `actions` key alone is seven thousand
// Azure prefixes that GitHub rents for hosted runners. Attributed as "GitHub"
// they would be eligible for vouching, and an implant on an Azure VM would
// inherit GitHub's standing.
func parseGitHubMeta(r io.Reader) ([]NetworkPrefix, error) {
	var doc map[string]json.RawMessage
	if err := json.NewDecoder(r).Decode(&doc); err != nil {
		return nil, err
	}

	// GitHub's own front ends, and the ranges GitHub rents from a cloud.
	own := []string{"hooks", "web", "api", "git", "pages", "packages", "copilot", "github_enterprise_importer"}
	rented := []string{"actions", "actions_macos", "codespaces", "importer", "dependabot"}

	var out []NetworkPrefix
	take := func(keys []string, org, tenancy string) error {
		for _, key := range keys {
			raw, ok := doc[key]
			if !ok {
				continue
			}
			var list []string
			if err := json.Unmarshal(raw, &list); err != nil {
				// A key that is not a list of ranges is not an error in this
				// document; several of them are keys and fingerprints.
				continue
			}
			for _, entry := range list {
				prefix, ok := asPrefix(entry)
				if !ok {
					continue
				}
				out = append(out, NetworkPrefix{
					Prefix: prefix, Country: "US", CountryName: "United States",
					ASN: "AS36459", Org: org, Tenancy: tenancy,
				})
			}
		}
		return nil
	}
	if err := take(own, "GitHub, Inc.", TenancyVendor); err != nil {
		return nil, err
	}
	if err := take(rented, "Rented cloud, listed by GitHub", TenancyHosting); err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("the GitHub meta document held no ranges")
	}
	return out, nil
}

// parseGoogleRanges reads goog.json and cloud.json, which share a shape. The
// two files matter separately: cloud.json is the customer ranges inside
// goog.json, and conflating them vouches for whatever is rented today.
func parseGoogleRanges(tenancy, org, asn string) func(io.Reader) ([]NetworkPrefix, error) {
	return func(r io.Reader) ([]NetworkPrefix, error) {
		var doc struct {
			Prefixes []struct {
				IPv4Prefix string `json:"ipv4Prefix"`
				IPv6Prefix string `json:"ipv6Prefix"`
				Scope      string `json:"scope"`
			} `json:"prefixes"`
		}
		if err := json.NewDecoder(r).Decode(&doc); err != nil {
			return nil, err
		}
		out := make([]NetworkPrefix, 0, len(doc.Prefixes))
		for _, p := range doc.Prefixes {
			prefix := p.IPv4Prefix
			if prefix == "" {
				prefix = p.IPv6Prefix
			}
			if prefix == "" {
				continue
			}
			out = append(out, NetworkPrefix{
				Prefix: prefix, Country: "US", CountryName: "United States",
				ASN: asn, Org: org, Tenancy: tenancy,
			})
		}
		return out, nil
	}
}

// parsePlainPrefixList reads one CIDR per line, which is how Cloudflare
// publishes.
func parsePlainPrefixList(org, asn, country, countryName, tenancy string) func(io.Reader) ([]NetworkPrefix, error) {
	return func(r io.Reader) ([]NetworkPrefix, error) {
		var out []NetworkPrefix
		scanner := bufio.NewScanner(r)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			if _, err := netip.ParsePrefix(line); err != nil {
				continue
			}
			out = append(out, NetworkPrefix{
				Prefix: line, Country: country, CountryName: countryName,
				ASN: asn, Org: org, Tenancy: tenancy,
			})
		}
		return out, scanner.Err()
	}
}

// parseMISPWarninglist reads the CC0 warning lists.
//
// Only lists declaring themselves `cidr` are accepted. The collection also
// holds hostname, substring and regex lists under the same filename shape, and
// reading one of those as addresses would attribute whatever happened to parse
// while silently dropping the rest - an attribution table that is wrong in
// places is worse than one that is missing an owner.
func parseMISPWarninglist(org, asn, tenancy string) func(io.Reader) ([]NetworkPrefix, error) {
	return func(r io.Reader) ([]NetworkPrefix, error) {
		var doc struct {
			Name string   `json:"name"`
			Type string   `json:"type"`
			List []string `json:"list"`
		}
		if err := json.NewDecoder(r).Decode(&doc); err != nil {
			return nil, err
		}
		if t := strings.ToLower(strings.TrimSpace(doc.Type)); t != "" && t != "cidr" {
			return nil, fmt.Errorf("warning list %q is of type %q, not cidr", doc.Name, doc.Type)
		}
		out := make([]NetworkPrefix, 0, len(doc.List))
		for _, raw := range doc.List {
			prefix, ok := asPrefix(raw)
			if !ok {
				continue
			}
			out = append(out, NetworkPrefix{
				Prefix: prefix, Country: "", CountryName: "",
				ASN: asn, Org: org, Tenancy: tenancy,
			})
		}
		return out, nil
	}
}

// asPrefix accepts "1.2.3.0/24" and "1.2.3.4", and rejects everything else.
func asPrefix(raw string) (string, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", false
	}
	if strings.Contains(raw, "/") {
		if _, err := netip.ParsePrefix(raw); err != nil {
			return "", false
		}
		return raw, true
	}
	addr, err := netip.ParseAddr(raw)
	if err != nil {
		return "", false
	}
	return netip.PrefixFrom(addr, addr.BitLen()).String(), true
}

// StartNetworkAttribution restores the last stored snapshot, then keeps it
// refreshed.
//
// Order matters. The snapshot is loaded before the first fetch so a hub that
// boots without internet is attributed from the moment it starts, rather than
// spending its first minutes reporting every destination as unnamed.
func (m *Manager) StartNetworkAttribution(ctx context.Context, interval time.Duration) {
	m.restoreAttribution()

	subCtx, cancel := context.WithCancel(ctx)
	m.attributionCancel = cancel

	go func() {
		// The first fetch waits a moment rather than racing the rest of start-up
		// for the network. Attribution is already in force from the stored
		// snapshot and the built-in table, so nothing is unattributed meanwhile.
		select {
		case <-subCtx.Done():
			return
		case <-time.After(firstRefreshDelay):
		}
		m.refreshAttribution(subCtx)

		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-subCtx.Done():
				return
			case <-ticker.C:
				m.refreshAttribution(subCtx)
			}
		}
	}()
}

func (m *Manager) restoreAttribution() {
	rows, err := m.store.ListNetworkAttribution()
	if err != nil {
		log.Printf("[-] The stored network attribution could not be read: %v", err)
		return
	}
	if len(rows) == 0 {
		return
	}

	entries := make([]NetworkPrefix, 0, len(rows))
	for _, r := range rows {
		entries = append(entries, NetworkPrefix{
			Prefix: r.Prefix, Country: r.Country, CountryName: r.CountryName,
			ASN: r.ASN, Org: r.Org, Tenancy: r.Tenancy, Source: r.Source,
		})
	}
	// The built-in table stays underneath as the floor, so a snapshot that was
	// itself written from a partial fetch cannot lose an owner we already knew.
	entries = append(entries, BuiltinAttribution()...)

	status, err := LoadAttribution(entries, "stored snapshot")
	if err != nil {
		log.Printf("[-] The stored network attribution was not usable: %v", err)
		return
	}
	log.Printf("[+] Network attribution restored from the stored snapshot: %d prefixes", status.Count)
}

func (m *Manager) refreshAttribution(ctx context.Context) {
	entries, status, err := SyncNetworkAttribution(ctx, m.httpClient)
	if err != nil && entries == nil {
		// Every feed failed and nothing was swapped in. Whatever was already in
		// force stays in force; this is a diagnostics warning, not an outage.
		log.Printf("[-] Network attribution could not be refreshed, the previous table stays in force: %v", err)
		return
	}

	rows := make([]storage.NetworkPrefixRow, 0, len(entries))
	for _, e := range entries {
		rows = append(rows, storage.NetworkPrefixRow{
			Prefix: e.Prefix, Country: e.Country, CountryName: e.CountryName,
			ASN: e.ASN, Org: e.Org, Tenancy: e.Tenancy, Source: e.Source,
		})
	}
	if err := m.store.ReplaceNetworkAttribution(rows, status.Source, minimumAttributionEntries); err != nil {
		log.Printf("[-] The refreshed network attribution could not be stored: %v", err)
	}
}
