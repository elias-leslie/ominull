package threatintel

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"

	"ominull/hub/pkg/storage"
)

// Domain feeds: bad-domain lists (abuse.ch ThreatFox and URLhaus host files)
// the hub matches against the gateway's DNS log. They are held apart from the
// IOC table on purpose: that table goes to agents as threat_indicators, and a
// list of tens of thousands of names must not. Which lists, and how sure each
// is, is detection tuning (domain_intel_feeds), not code.

// DomainFeedStatus is how one list fared at its last fetch.
type DomainFeedStatus struct {
	Name      string     `json:"name"`
	Domains   int        `json:"domains"`
	FetchedAt *time.Time `json:"fetched_at,omitempty"` // the last good fetch; absent before one
	// Error is the last failure; the names from the last good fetch stay in
	// force meanwhile (Domains counts them).
	Error string `json:"error,omitempty"`
}

type domainFeedSet struct {
	names      map[string]bool
	confidence int
	status     DomainFeedStatus
}

const (
	domainFeedMaxBytes = 64 << 20
	domainFeedMaxNames = 2_000_000
	domainFeedTimeout  = 2 * time.Minute
	// AbuseCHKeyFileDefault holds the free abuse.ch Auth-Key, one line;
	// OMINULL_ABUSECH_KEY_FILE overrides it.
	AbuseCHKeyFileDefault = "/etc/ominull/abusech.key"
)

var authKeyRe = regexp.MustCompile(`^[A-Za-z0-9_-]{8,128}$`)

// newDomainFeedClient follows no redirect: a redirect would carry the key-
// bearing URL to the next host as the Referer. The timeout covers a host file
// of several megabytes on a slow uplink.
func newDomainFeedClient() *http.Client {
	return &http.Client{
		Timeout:       domainFeedTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

// AbuseCHKeyFile is where the hub reads the abuse.ch Auth-Key.
func AbuseCHKeyFile() string {
	if p := strings.TrimSpace(os.Getenv("OMINULL_ABUSECH_KEY_FILE")); p != "" {
		return p
	}
	return AbuseCHKeyFileDefault
}

// feedRequestURL fills {auth_key} from keyFile. The key is only ever sent to
// an https abuse.ch host, whatever the tuning says, so a feed URL edited to
// point elsewhere cannot carry it off.
func feedRequestURL(raw, keyFile string) (string, string, error) {
	if !strings.Contains(raw, "{auth_key}") {
		return raw, "", nil
	}
	u, err := url.Parse(strings.ReplaceAll(raw, "{auth_key}", "k"))
	if err != nil || u.Scheme != "https" || u.User != nil {
		return "", "", fmt.Errorf("an {auth_key} URL must be https")
	}
	if rest := strings.TrimPrefix(raw, "https://"); strings.Contains(strings.SplitN(rest, "/", 2)[0], "{auth_key}") {
		return "", "", fmt.Errorf("{auth_key} belongs in the path, never the host (the host is looked up in DNS)")
	}
	host := strings.ToLower(u.Hostname())
	if host != "abuse.ch" && !strings.HasSuffix(host, ".abuse.ch") {
		return "", "", fmt.Errorf("{auth_key} is only sent to abuse.ch, not %s", host)
	}
	raw2, err := os.ReadFile(keyFile)
	if err != nil {
		return "", "", fmt.Errorf("no abuse.ch Auth-Key at %s", keyFile)
	}
	key := strings.TrimSpace(strings.SplitN(string(raw2), "\n", 2)[0])
	if !authKeyRe.MatchString(key) {
		return "", "", fmt.Errorf("the abuse.ch Auth-Key at %s is not one word of letters and digits", keyFile)
	}
	return strings.ReplaceAll(raw, "{auth_key}", key), key, nil
}

// fetchDomainFeed downloads one list. Errors never carry the key.
func fetchDomainFeed(ctx context.Context, client *http.Client, feed storage.DomainIntelFeed, keyFile string) (map[string]bool, error) {
	target, key, err := feedRequestURL(feed.URL, keyFile)
	if err != nil {
		return nil, err
	}
	redact := func(err error) error {
		if key == "" {
			return err
		}
		return fmt.Errorf("%s", strings.ReplaceAll(err.Error(), key, "<auth-key>"))
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, redact(err)
	}
	req.Header.Set("User-Agent", "ominull-hub")
	resp, err := client.Do(req)
	if err != nil {
		return nil, redact(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	names, err := ParseDomainList(io.LimitReader(resp.Body, domainFeedMaxBytes+1))
	if err != nil {
		return nil, redact(err)
	}
	if len(names) == 0 {
		// An empty answer is a broken export, not a clean internet.
		return nil, fmt.Errorf("the list held no names")
	}
	return names, nil
}

// ParseDomainList reads a hosts file ("0.0.0.0 name") or one name per line.
// Comments (#) and the hosts file's own entries (localhost and the like) are
// skipped; anything that is not a DNS name is ignored.
func ParseDomainList(r io.Reader) (map[string]bool, error) {
	out := map[string]bool{}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 64*1024)
	read := 0
	for sc.Scan() {
		line := sc.Text()
		read += len(line) + 1
		if read > domainFeedMaxBytes {
			return nil, fmt.Errorf("the list is larger than %d MiB", domainFeedMaxBytes>>20)
		}
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		name := fields[0]
		if _, err := netip.ParseAddr(name); err == nil {
			if len(fields) < 2 {
				continue
			}
			name = fields[1]
		}
		name = strings.TrimSuffix(strings.ToLower(name), ".")
		switch name {
		case "localhost", "localhost.localdomain", "local", "broadcasthost", "ip6-localhost", "ip6-loopback":
			continue
		}
		if !storage.DNSName(name) {
			continue
		}
		if len(out) >= domainFeedMaxNames {
			return nil, fmt.Errorf("the list holds more than %d names", domainFeedMaxNames)
		}
		out[name] = true
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

// RefreshDomainFeeds fetches every listed feed. A feed that fails keeps the
// names of its last good fetch; a feed no longer listed is dropped.
func (m *Manager) RefreshDomainFeeds(ctx context.Context, feeds []storage.DomainIntelFeed, keyFile string) {
	m.domainRefresh.Lock()
	defer m.domainRefresh.Unlock()
	m.domainMu.RLock()
	previous := m.domainFeeds
	m.domainMu.RUnlock()

	next := make(map[string]*domainFeedSet, len(feeds))
	for _, feed := range feeds {
		set := &domainFeedSet{confidence: feed.Confidence, status: DomainFeedStatus{Name: feed.Name}}
		if old := previous[feed.Name]; old != nil {
			set.names, set.status.FetchedAt = old.names, old.status.FetchedAt
		}
		names, err := fetchDomainFeed(ctx, m.domainHTTP, feed, keyFile)
		if err != nil {
			set.status.Error = err.Error()
			log.Printf("[-] domain feed %s: %v (kept %d names from the last good fetch)", feed.Name, err, len(set.names))
		} else {
			fetched := time.Now().UTC()
			set.names, set.status.FetchedAt = names, &fetched
			log.Printf("[+] domain feed %s: %d names", feed.Name, len(names))
		}
		set.status.Domains = len(set.names)
		next[feed.Name] = set
	}
	m.domainMu.Lock()
	m.domainFeeds = next
	m.domainMu.Unlock()
}

// CheckDomain says whether a looked-up name is on a feed: the name itself,
// at the highest confidence any feed gives it.
func (m *Manager) CheckDomain(name string) (*storage.IOC, bool) {
	name = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(name)), ".")
	if name == "" {
		return nil, false
	}
	m.domainMu.RLock()
	defer m.domainMu.RUnlock()
	var best *storage.IOC
	for feedName, set := range m.domainFeeds {
		if !set.names[name] {
			continue
		}
		if best == nil || set.confidence > best.Confidence || (set.confidence == best.Confidence && feedName < best.Source) {
			best = &storage.IOC{Value: name, Type: "domain", Source: feedName, ThreatType: "malicious domain", Confidence: set.confidence, Active: true}
		}
	}
	return best, best != nil
}

// DomainFeedStatuses reports each feed, by name.
func (m *Manager) DomainFeedStatuses() []DomainFeedStatus {
	m.domainMu.RLock()
	defer m.domainMu.RUnlock()
	out := make([]DomainFeedStatus, 0, len(m.domainFeeds))
	for _, set := range m.domainFeeds {
		out = append(out, set.status)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// StartDomainFeeds refreshes the feeds the tuning lists now and every
// interval after (abuse.ch rebuilds its host files every few minutes and asks
// for no more than that).
func (m *Manager) StartDomainFeeds(ctx context.Context, interval time.Duration, feeds func() []storage.DomainIntelFeed) {
	subCtx, cancel := context.WithCancel(ctx)
	m.domainCancel = cancel
	go func() {
		select {
		case <-subCtx.Done():
			return
		case <-time.After(firstRefreshDelay):
		}
		for {
			m.RefreshDomainFeeds(subCtx, feeds(), AbuseCHKeyFile())
			select {
			case <-subCtx.Done():
				return
			case <-time.After(interval):
			}
		}
	}()
}
