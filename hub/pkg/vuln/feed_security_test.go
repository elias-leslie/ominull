package vuln

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func TestDefaultFeedClientRejectsCustomTargets(t *testing.T) {
	var calls atomic.Int32
	local := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Write([]byte(`{"vulnerabilities":[{"cveID":"CVE-2026-0001"}],"data":[],"totalResults":0}`))
	}))
	defer local.Close()
	for _, kind := range []string{"cisa", "epss", "nvd"} {
		var err error
		switch kind {
		case "cisa":
			_, err = FetchCISAKEV(context.Background(), nil, local.URL)
		case "epss":
			_, err = FetchEPSS(context.Background(), nil, local.URL)
		case "nvd":
			_, _, err = FetchNVD20Page(context.Background(), nil, local.URL, "", 0, 1)
		}
		if err == nil {
			t.Errorf("%s accepted a caller-selected target", kind)
		}
	}
	if calls.Load() != 0 {
		t.Errorf("caller-selected target received %d requests", calls.Load())
	}
}

type recordingTransport struct{ urls []string }

func (t *recordingTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	t.urls = append(t.urls, r.URL.String())
	return &http.Response{
		StatusCode: http.StatusOK,
		Status:     "200 OK",
		Body:       io.NopCloser(strings.NewReader(`{"vulnerabilities":[],"data":[],"totalResults":0}`)),
		Request:    r,
	}, nil
}

// TestConfiguredFeedClientTargets pins which URL each feed requests through a
// configured client: the default when none is given, otherwise the caller's.
func TestConfiguredFeedClientTargets(t *testing.T) {
	const custom = "https://feeds.example.invalid/mirror"
	cases := []struct {
		kind, url, want string
	}{
		{"cisa", "", DefaultCISAKEVURL},
		{"cisa", custom, custom},
		{"epss", "", DefaultEPSSURL},
		{"epss", custom, custom},
		{"nvd", "", DefaultNVD20URL + "?startIndex=40&resultsPerPage=20"},
		{"nvd", custom, custom + "?startIndex=40&resultsPerPage=20"},
		{"nvd", custom + "?keywordSearch=x", custom + "?keywordSearch=x&startIndex=40&resultsPerPage=20"},
	}
	for _, c := range cases {
		rt := &recordingTransport{}
		client := &http.Client{Transport: rt}
		// Only the requested URL matters here; parsing an empty catalog may fail.
		switch c.kind {
		case "cisa":
			_, _ = FetchCISAKEV(context.Background(), client, c.url)
		case "epss":
			_, _ = FetchEPSS(context.Background(), client, c.url)
		case "nvd":
			_, _, _ = FetchNVD20Page(context.Background(), client, c.url, "", 40, 20)
		}
		if len(rt.urls) != 1 || rt.urls[0] != c.want {
			t.Errorf("%s %q requested %v, want [%s]", c.kind, c.url, rt.urls, c.want)
		}
	}
}

func TestDefaultFeedClientRefusesRedirects(t *testing.T) {
	client, url, err := feedClient(nil, "", DefaultEPSSURL)
	if err != nil || url != DefaultEPSSURL {
		t.Fatalf("feedClient(nil, \"\") = %q, %v", url, err)
	}
	if client.CheckRedirect == nil || client.CheckRedirect(nil, nil) != http.ErrUseLastResponse {
		t.Error("default feed client follows redirects")
	}
	if client.Timeout <= 0 {
		t.Error("default feed client has no timeout")
	}
	configured := &http.Client{}
	if got, _, _ := feedClient(configured, "", DefaultEPSSURL); got != configured {
		t.Error("configured client replaced")
	}
}
