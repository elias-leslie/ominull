package server

import (
	"bytes"
	"compress/gzip"
	"io"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestSnapshotNegotiatesCompressionAndPreservesValidators(t *testing.T) {
	var cache responseCache
	raw := []byte(`{"observations":[` + strings.Repeat(`{"source":"10.0.0.1","target":"2001:db8::1"},`, 10000) + `{}]}`)
	entry, err := cache.snapshot("fixture", func() ([]byte, error) { return raw, nil })
	if err != nil {
		t.Fatal(err)
	}
	for _, encoding := range []string{"gzip", "br, gzip;q=0.5", "gzip;q=0", "identity", ""} {
		r := httptest.NewRequest("GET", "/fixture", nil)
		r.Header.Set("Accept-Encoding", encoding)
		w := httptest.NewRecorder()
		writeSnapshot(w, r, entry)
		want := encoding == "gzip" || encoding == "br, gzip;q=0.5"
		if (w.Header().Get("Content-Encoding") == "gzip") != want {
			t.Fatalf("negotiation %q: %v", encoding, w.Header())
		}
		got := w.Body.Bytes()
		if want {
			reader, err := gzip.NewReader(bytes.NewReader(got))
			if err != nil {
				t.Fatal(err)
			}
			got, err = io.ReadAll(reader)
			reader.Close()
			if err != nil {
				t.Fatal(err)
			}
			if w.Body.Len() >= len(raw)/4 {
				t.Fatal("fixture compression ineffective")
			}
			t.Logf("identity_bytes=%d gzip_bytes=%d", len(raw), w.Body.Len())
		}
		if !bytes.Equal(got, raw) {
			t.Fatal("representation changed")
		}
		r.Header.Set("If-None-Match", w.Header().Get("ETag"))
		repeat := httptest.NewRecorder()
		writeSnapshot(repeat, r, entry)
		if repeat.Code != 304 || repeat.Body.Len() != 0 {
			t.Fatal("conditional request transferred body")
		}
	}
	// Failed/expired builds must not serve a misleading new timestamp.
	if entry.computed.IsZero() || time.Since(entry.computed) > time.Minute {
		t.Fatal("snapshot age missing")
	}
}
