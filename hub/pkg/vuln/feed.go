package vuln

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// CPEMatchCriteria defines a CPE match criterion with version boundaries.
type CPEMatchCriteria struct {
	Vulnerable            bool   `json:"vulnerable"`
	Criteria              string `json:"criteria"`
	VersionStartIncluding string `json:"versionStartIncluding,omitempty"`
	VersionStartExcluding string `json:"versionStartExcluding,omitempty"`
	VersionEndIncluding   string `json:"versionEndIncluding,omitempty"`
	VersionEndExcluding   string `json:"versionEndExcluding,omitempty"`
	MatchCriteriaID       string `json:"matchCriteriaId,omitempty"`
}

// CISAKEVItem represents a record in the CISA Known Exploited Vulnerabilities catalog.
type CISAKEVItem struct {
	CVEID                      string `json:"cveID"`
	VendorProject              string `json:"vendorProject"`
	Product                    string `json:"product"`
	VulnerabilityName          string `json:"vulnerabilityName"`
	DateAdded                  string `json:"dateAdded"`
	ShortDescription           string `json:"shortDescription"`
	RequiredAction             string `json:"requiredAction"`
	DueDate                    string `json:"dueDate"`
	KnownRansomwareCampaignUse string `json:"knownRansomwareCampaignUse"`
}

// EPSSScore represents an exploit prediction score record.
type EPSSScore struct {
	CVEID      string    `json:"cve"`
	Score      float64   `json:"epss"`
	Percentile float64   `json:"percentile"`
	Date       time.Time `json:"date"`
}

// NVD 2.0 Ingestion Structs
type nvdVulnerabilityWrapper struct {
	CVE struct {
		ID           string `json:"id"`
		Published    string `json:"published"`
		LastModified string `json:"lastModified"`
		Descriptions []struct {
			Lang  string `json:"lang"`
			Value string `json:"value"`
		} `json:"descriptions"`
		Metrics struct {
			CVSSMetricV31 []struct {
				CVSSData struct {
					BaseScore    float64 `json:"baseScore"`
					BaseSeverity string  `json:"baseSeverity"`
				} `json:"cvssData"`
			} `json:"cvssMetricV31"`
			CVSSMetricV30 []struct {
				CVSSData struct {
					BaseScore    float64 `json:"baseScore"`
					BaseSeverity string  `json:"baseSeverity"`
				} `json:"cvssData"`
			} `json:"cvssMetricV30"`
		} `json:"metrics"`
		Configurations []struct {
			Nodes []struct {
				CPEMatch []CPEMatchCriteria `json:"cpeMatch"`
			} `json:"nodes"`
		} `json:"configurations"`
	} `json:"cve"`
}

type nvd20Envelope struct {
	TotalResults    int                       `json:"totalResults"`
	Format          string                    `json:"format"`
	Version         string                    `json:"version"`
	Vulnerabilities []nvdVulnerabilityWrapper `json:"vulnerabilities"`
}

// ParseNVD20 parses an official NVD 2.0 JSON payload into normalized Vulnerability records.
func ParseNVD20(r io.Reader) ([]Vulnerability, error) {
	var env nvd20Envelope
	if err := json.NewDecoder(r).Decode(&env); err != nil {
		return nil, fmt.Errorf("failed to decode NVD 2.0 JSON: %w", err)
	}

	var results []Vulnerability
	for _, wrap := range env.Vulnerabilities {
		cve := wrap.CVE
		if cve.ID == "" {
			continue
		}

		desc := ""
		for _, d := range cve.Descriptions {
			if strings.EqualFold(d.Lang, "en") {
				desc = d.Value
				break
			}
		}
		if desc == "" && len(cve.Descriptions) > 0 {
			desc = cve.Descriptions[0].Value
		}

		score := 0.0
		severity := "UNKNOWN"
		if len(cve.Metrics.CVSSMetricV31) > 0 {
			score = cve.Metrics.CVSSMetricV31[0].CVSSData.BaseScore
			severity = strings.ToUpper(cve.Metrics.CVSSMetricV31[0].CVSSData.BaseSeverity)
		} else if len(cve.Metrics.CVSSMetricV30) > 0 {
			score = cve.Metrics.CVSSMetricV30[0].CVSSData.BaseScore
			severity = strings.ToUpper(cve.Metrics.CVSSMetricV30[0].CVSSData.BaseSeverity)
		}

		published, _ := time.Parse(time.RFC3339, cve.Published)
		if published.IsZero() {
			published = time.Now().UTC()
		}

		// Extract CPE match criteria
		var cpeMatches []CPEMatchCriteria
		for _, config := range cve.Configurations {
			for _, node := range config.Nodes {
				for _, match := range node.CPEMatch {
					if match.Vulnerable {
						cpeMatches = append(cpeMatches, match)
					}
				}
			}
		}

		cpePatternJSON, _ := json.Marshal(cpeMatches)

		results = append(results, Vulnerability{
			CVEID:       cve.ID,
			Title:       cve.ID,
			Description: desc,
			Severity:    severity,
			CVSS:        score,
			IsKEV:       false,
			EPSS:        0.0,
			CPEPattern:  string(cpePatternJSON),
			PublishedAt: published,
		})
	}

	return results, nil
}

// ParseCISAKEV parses the official CISA KEV JSON catalog.
func ParseCISAKEV(r io.Reader) ([]CISAKEVItem, error) {
	var env struct {
		CatalogVersion  string        `json:"catalogVersion"`
		Vulnerabilities []CISAKEVItem `json:"vulnerabilities"`
	}
	if err := json.NewDecoder(r).Decode(&env); err != nil {
		return nil, fmt.Errorf("failed to decode CISA KEV JSON: %w", err)
	}
	if len(env.Vulnerabilities) == 0 {
		return nil, errors.New("empty CISA KEV catalog")
	}
	return env.Vulnerabilities, nil
}

// ParseEPSSJSON parses EPSS API JSON data into a map keyed by CVE ID.
func ParseEPSSJSON(r io.Reader) (map[string]EPSSScore, error) {
	var env struct {
		Status string `json:"status"`
		Data   []struct {
			CVE        string `json:"cve"`
			EPSS       string `json:"epss"`
			Percentile string `json:"percentile"`
			Date       string `json:"date"`
		} `json:"data"`
	}
	if err := json.NewDecoder(r).Decode(&env); err != nil {
		return nil, fmt.Errorf("failed to decode EPSS JSON: %w", err)
	}

	scores := make(map[string]EPSSScore)
	for _, item := range env.Data {
		scoreVal, _ := strconv.ParseFloat(item.EPSS, 64)
		pctVal, _ := strconv.ParseFloat(item.Percentile, 64)
		d, _ := time.Parse("2006-01-02", item.Date)
		scores[item.CVE] = EPSSScore{
			CVEID:      item.CVE,
			Score:      scoreVal,
			Percentile: pctVal,
			Date:       d,
		}
	}

	return scores, nil
}

const (
	DefaultCISAKEVURL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
	DefaultNVD20URL   = "https://services.nvd.nist.gov/rest/json/cves/2.0"
	DefaultEPSSURL    = "https://api.first.org/data/v1/epss"
)

// FeedSyncOptions configures the vulnerability feed ingestion pipeline.
type FeedSyncOptions struct {
	HTTPClient    *http.Client
	NVDURL        string
	NVDApiKey     string
	CISAKEVURL    string
	EPSSURL       string
	MaxNVDResults int
}

// FetchCISAKEV retrieves and parses the CISA KEV feed from the given URL.
func FetchCISAKEV(ctx context.Context, client *http.Client, url string) ([]CISAKEVItem, error) {
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	if url == "" {
		url = DefaultCISAKEVURL
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create CISA KEV request: %w", err)
	}
	req.Header.Set("User-Agent", "Ominull-Hub-VulnerabilitySync/1.0")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch CISA KEV: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusTooManyRequests {
		return nil, errors.New("CISA KEV rate limit exceeded (HTTP 429)")
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("CISA KEV feed returned HTTP %d %s", resp.StatusCode, resp.Status)
	}

	return ParseCISAKEV(io.LimitReader(resp.Body, 50<<20))
}

// FetchEPSS retrieves and parses the EPSS feed from the given URL.
func FetchEPSS(ctx context.Context, client *http.Client, url string) (map[string]EPSSScore, error) {
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	if url == "" {
		url = DefaultEPSSURL
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create EPSS request: %w", err)
	}
	req.Header.Set("User-Agent", "Ominull-Hub-VulnerabilitySync/1.0")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch EPSS: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusTooManyRequests {
		return nil, errors.New("EPSS rate limit exceeded (HTTP 429)")
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("EPSS feed returned HTTP %d %s", resp.StatusCode, resp.Status)
	}

	return ParseEPSSJSON(io.LimitReader(resp.Body, 50<<20))
}

// ParseNVD20WithTotal parses NVD 2.0 JSON and returns the totalResults count alongside the slice.
func ParseNVD20WithTotal(r io.Reader) ([]Vulnerability, int, error) {
	var env nvd20Envelope
	if err := json.NewDecoder(r).Decode(&env); err != nil {
		return nil, 0, fmt.Errorf("failed to decode NVD 2.0 JSON: %w", err)
	}

	var results []Vulnerability
	for _, wrap := range env.Vulnerabilities {
		cve := wrap.CVE
		if cve.ID == "" {
			continue
		}

		desc := ""
		for _, d := range cve.Descriptions {
			if strings.EqualFold(d.Lang, "en") {
				desc = d.Value
				break
			}
		}
		if desc == "" && len(cve.Descriptions) > 0 {
			desc = cve.Descriptions[0].Value
		}

		score := 0.0
		severity := "UNKNOWN"
		if len(cve.Metrics.CVSSMetricV31) > 0 {
			score = cve.Metrics.CVSSMetricV31[0].CVSSData.BaseScore
			severity = strings.ToUpper(cve.Metrics.CVSSMetricV31[0].CVSSData.BaseSeverity)
		} else if len(cve.Metrics.CVSSMetricV30) > 0 {
			score = cve.Metrics.CVSSMetricV30[0].CVSSData.BaseScore
			severity = strings.ToUpper(cve.Metrics.CVSSMetricV30[0].CVSSData.BaseSeverity)
		}

		published, _ := time.Parse(time.RFC3339, cve.Published)
		if published.IsZero() {
			published = time.Now().UTC()
		}

		var cpeMatches []CPEMatchCriteria
		for _, config := range cve.Configurations {
			for _, node := range config.Nodes {
				for _, match := range node.CPEMatch {
					if match.Vulnerable {
						cpeMatches = append(cpeMatches, match)
					}
				}
			}
		}

		cpePatternJSON, _ := json.Marshal(cpeMatches)

		results = append(results, Vulnerability{
			CVEID:       cve.ID,
			Title:       cve.ID,
			Description: desc,
			Severity:    severity,
			CVSS:        score,
			IsKEV:       false,
			EPSS:        0.0,
			CPEPattern:  string(cpePatternJSON),
			PublishedAt: published,
		})
	}

	return results, env.TotalResults, nil
}

// FetchNVD20Page retrieves and parses a single page from the NVD 2.0 API.
func FetchNVD20Page(ctx context.Context, client *http.Client, baseURL, apiKey string, startIndex, resultsPerPage int) ([]Vulnerability, int, error) {
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	if baseURL == "" {
		baseURL = DefaultNVD20URL
	}

	sep := "?"
	if strings.Contains(baseURL, "?") {
		sep = "&"
	}
	targetURL := fmt.Sprintf("%s%sstartIndex=%d&resultsPerPage=%d", baseURL, sep, startIndex, resultsPerPage)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to create NVD request: %w", err)
	}
	req.Header.Set("User-Agent", "Ominull-Hub-VulnerabilitySync/1.0")
	if apiKey != "" {
		req.Header.Set("apiKey", apiKey)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to fetch NVD page: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusTooManyRequests {
		return nil, 0, errors.New("NVD 2.0 API rate limit exceeded (HTTP 429)")
	}
	if resp.StatusCode != http.StatusOK {
		return nil, 0, fmt.Errorf("NVD 2.0 API returned HTTP %d %s", resp.StatusCode, resp.Status)
	}

	return ParseNVD20WithTotal(io.LimitReader(resp.Body, 100<<20))
}

// SyncFeeds coordinates pulling feeds, building a snapshot off to the side, and activating it.
func SyncFeeds(ctx context.Context, store *Store, opts FeedSyncOptions, snapshotID, metadata string) (*FeedSnapshot, error) {
	if snapshotID == "" {
		snapshotID = fmt.Sprintf("snap-%s", time.Now().UTC().Format("20060102-150405"))
	}
	if metadata == "" {
		metadata = `{"sources":["nvd20","cisa_kev","epss"]}`
	}

	_, err := store.CreateSnapshot(snapshotID, metadata)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize snapshot: %w", err)
	}

	failAndReturn := func(err error) (*FeedSnapshot, error) {
		_ = store.FailSnapshot(snapshotID, err.Error())
		return nil, err
	}

	// 1. Fetch CISA KEV
	var kevItems []CISAKEVItem
	if opts.CISAKEVURL != "disabled" {
		items, err := FetchCISAKEV(ctx, opts.HTTPClient, opts.CISAKEVURL)
		if err != nil {
			return failAndReturn(fmt.Errorf("CISA KEV fetch failed: %w", err))
		}
		kevItems = items
	}

	// 2. Fetch EPSS (optional)
	var epssScores map[string]EPSSScore
	if opts.EPSSURL != "" && opts.EPSSURL != "disabled" {
		scores, err := FetchEPSS(ctx, opts.HTTPClient, opts.EPSSURL)
		if err == nil {
			epssScores = scores
		}
	}

	// 3. Fetch NVD 2.0
	var allVulns []Vulnerability
	if opts.NVDURL != "disabled" {
		pageSize := 100
		startIndex := 0
		maxResults := opts.MaxNVDResults
		if maxResults <= 0 {
			maxResults = 2000
		}

		for {
			select {
			case <-ctx.Done():
				return failAndReturn(ctx.Err())
			default:
			}

			pageVulns, totalResults, err := FetchNVD20Page(ctx, opts.HTTPClient, opts.NVDURL, opts.NVDApiKey, startIndex, pageSize)
			if err != nil {
				return failAndReturn(fmt.Errorf("NVD fetch failed at startIndex %d: %w", startIndex, err))
			}

			allVulns = append(allVulns, pageVulns...)
			startIndex += len(pageVulns)

			if len(pageVulns) == 0 || startIndex >= totalResults || startIndex >= maxResults {
				break
			}
		}
	}

	// Verify we have records
	if len(allVulns) == 0 && len(kevItems) == 0 {
		return failAndReturn(errors.New("feed sync yielded zero vulnerability records; refusing to activate"))
	}

	// 4. Ingest snapshot data off to the side
	if err := store.IngestSnapshotData(snapshotID, allVulns, kevItems, epssScores); err != nil {
		return failAndReturn(fmt.Errorf("failed to ingest snapshot data: %w", err))
	}

	// 5. Atomically activate snapshot
	if err := store.ActivateSnapshot(snapshotID); err != nil {
		return failAndReturn(fmt.Errorf("failed to activate snapshot: %w", err))
	}

	return store.GetActiveSnapshot()
}
