package vuln

import (
	"context"
	"net/http"
	"net/http/httptest"
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
