package threatintel

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"ominull/hub/pkg/storage"
)

// Where a destination's address actually lives, which is a different question
// from who owns it.
//
// The quiet lists are the operator's statement that some traffic is ordinary.
// Applied to an owner alone, that statement is far wider than it looks: an
// address inside AWS or Google Cloud belongs to whoever rented it this morning,
// and CDN edge addresses front every site behind them, which is precisely why
// published allowlists are where command-and-control hides. So an address
// carries how its range is tenanted, and nothing may be vouched for
// automatically on a range that anybody can rent.
const (
	// TenancyVendor: the range runs the owner's own services. Apple's 17/8,
	// Google's own front ends, Microsoft 365. Vouching for one of these says
	// something bounded.
	TenancyVendor = storage.TenancyVendor

	// TenancySharedCDN: edge infrastructure serving other people's sites.
	// Cloudflare, Akamai, Fastly, CloudFront. Ordinary browser traffic goes
	// here constantly, and so does a domain-fronted implant; the process is
	// what separates them, never the address.
	TenancySharedCDN = storage.TenancySharedCDN

	// TenancyHosting: rented compute. EC2, Google Cloud customer ranges,
	// DigitalOcean, Hetzner, OVH, Linode. Never automatically vouched.
	TenancyHosting = storage.TenancyHosting
)

// NetworkPrefix is one attributed range. It is the unit the built-in table, the
// synced feeds and the database snapshot all speak in.
type NetworkPrefix struct {
	Prefix      string `json:"prefix"`
	Country     string `json:"country"`
	CountryName string `json:"country_name"`
	ASN         string `json:"asn"`
	Org         string `json:"org"`
	Tenancy     string `json:"tenancy"`
	Source      string `json:"source"`
}

type prefixRule struct {
	prefix netip.Prefix
	record GeoRecord
}

// attributionTable is immutable once built and swapped in whole, so a refresh
// that fails or arrives malformed can never leave the resolver half-populated.
//
// The published feeds bring twenty thousand prefixes where the hand-written
// table had a hundred, so lookups are bucketed by the first octet rather than
// scanning the lot. Every flow from every endpoint passes through here; a
// millisecond of linear scan per unseen destination is a cost the ingest path
// would feel.
type attributionTable struct {
	rules   []prefixRule
	v4      [256][]prefixRule
	v6      []prefixRule
	source  string
	builtAt time.Time
	count   int
}

// lookup returns the most specific rule covering addr.
func (t *attributionTable) lookup(addr netip.Addr) (GeoRecord, bool) {
	candidates := t.v6
	if addr.Is4() {
		candidates = t.v4[addr.As4()[0]]
	}
	for _, rule := range candidates {
		if rule.prefix.Contains(addr) {
			return rule.record, true
		}
	}
	return GeoRecord{}, false
}

var (
	currentAttribution atomic.Pointer[attributionTable]
	attributionOnce    sync.Once
)

// AttributionStatus describes the table in force, for diagnostics and the
// console. A hub that never reached the feeds still attributes traffic from the
// table compiled into this binary, and says so.
type AttributionStatus struct {
	Source  string    `json:"source"`
	Count   int       `json:"count"`
	BuiltAt time.Time `json:"built_at"`
}

func table() *attributionTable {
	attributionOnce.Do(func() {
		if currentAttribution.Load() == nil {
			currentAttribution.Store(buildTable(BuiltinAttribution(), "built-in"))
		}
	})
	return currentAttribution.Load()
}

// buildTable sorts longest-prefix-first so the first match is the most specific
// one, and puts a shared or rented range ahead of a vendor range that covers the
// same bits - Google's cloud.json ranges sit inside goog.json, and the customer
// answer is the one that must win.
func buildTable(entries []NetworkPrefix, source string) *attributionTable {
	rules := make([]prefixRule, 0, len(entries))
	for _, e := range entries {
		prefix, err := netip.ParsePrefix(strings.TrimSpace(e.Prefix))
		if err != nil {
			// A malformed entry is dropped rather than approximated. What it
			// covered then resolves as unknown, which is the honest outcome.
			continue
		}
		tenancy := e.Tenancy
		if tenancy == "" {
			tenancy = TenancyHosting
		}
		rules = append(rules, prefixRule{
			prefix: prefix.Masked(),
			record: GeoRecord{
				Country:     e.Country,
				CountryName: e.CountryName,
				ASN:         e.ASN,
				Org:         e.Org,
				Tenancy:     tenancy,
				Source:      e.Source,
			},
		})
	}
	sort.SliceStable(rules, func(i, j int) bool {
		if rules[i].prefix.Bits() != rules[j].prefix.Bits() {
			return rules[i].prefix.Bits() > rules[j].prefix.Bits()
		}
		return tenancyRank(rules[i].record.Tenancy) < tenancyRank(rules[j].record.Tenancy)
	})
	built := &attributionTable{rules: rules, source: source, builtAt: time.Now().UTC(), count: len(rules)}
	for _, rule := range rules {
		if !rule.prefix.Addr().Is4() {
			built.v6 = append(built.v6, rule)
			continue
		}
		first := int(rule.prefix.Addr().As4()[0])
		if rule.prefix.Bits() >= 8 {
			built.v4[first] = append(built.v4[first], rule)
			continue
		}
		// A prefix shorter than /8 spans several buckets, so it is filed in
		// each one it covers rather than being missed by all of them.
		span := 1 << (8 - rule.prefix.Bits())
		for i := 0; i < span && first+i < 256; i++ {
			built.v4[first+i] = append(built.v4[first+i], rule)
		}
	}
	return built
}

// tenancyRank decides which answer wins when two ranges are equally specific.
// The more permissive the range, the earlier it sorts: saying "anyone can rent
// this" about an address that is also inside a vendor allocation is the safe
// direction to be wrong in.
func tenancyRank(tenancy string) int {
	switch tenancy {
	case TenancyHosting:
		return 0
	case TenancySharedCDN:
		return 1
	default:
		return 2
	}
}

// LoadAttribution swaps in a freshly synced table. It refuses a table small
// enough to suggest a truncated download, so a half-served feed cannot blank
// out attribution for the whole estate; the caller keeps what it had.
func LoadAttribution(entries []NetworkPrefix, source string) (AttributionStatus, error) {
	next := buildTable(entries, source)
	if next.count < minimumAttributionEntries {
		return statusOf(table()), fmt.Errorf("attribution table from %s held only %d usable prefixes; keeping the previous table", source, next.count)
	}
	attributionOnce.Do(func() {})
	currentAttribution.Store(next)

	geoCacheMu.Lock()
	geoCache = make(map[string]GeoRecord)
	geoCacheMu.Unlock()

	return statusOf(next), nil
}

// minimumAttributionEntries is a sanity floor, not a quality bar: the built-in
// table alone is over a hundred prefixes, so anything below this is a failed
// download rather than a small answer.
const minimumAttributionEntries = 64

// AttributionInfo reports the table in force.
func AttributionInfo() AttributionStatus { return statusOf(table()) }

func statusOf(t *attributionTable) AttributionStatus {
	if t == nil {
		return AttributionStatus{Source: "none"}
	}
	return AttributionStatus{Source: t.source, Count: t.count, BuiltAt: t.builtAt}
}

// CanAutoVouch reports whether this destination may be added to a quiet list by
// something other than the operator typing it - the Expected button, or a
// learning proposal. Rented compute never qualifies, however many times it has
// been seen: "we have talked to this AWS instance for a week" is exactly what a
// patient implant looks like.
func CanAutoVouch(rec GeoRecord) bool {
	if !rec.Resolved() {
		return false
	}
	return rec.Tenancy != TenancyHosting
}
