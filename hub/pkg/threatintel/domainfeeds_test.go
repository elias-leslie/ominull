package threatintel

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"ominull/hub/pkg/storage"
)

func TestParseDomainListReadsHostsFilesAndPlainLists(t *testing.T) {
	in := "# ThreatFox host file\n127.0.0.1\tlocalhost\n0.0.0.0 Evil.Example.com. # c2\n::1 ip6-localhost\nplain.example.net\n\nnot a name\n127.0.0.1\n0.0.0.0 bad_label.example.org\n"
	got, err := ParseDomainList(strings.NewReader(in))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"evil.example.com", "plain.example.net", "bad_label.example.org"} {
		if !got[want] {
			t.Errorf("missing %s in %v", want, got)
		}
	}
	if len(got) != 3 {
		t.Fatalf("want 3 names, got %v", got)
	}
}

// The abuse.ch key is only ever put into an https abuse.ch URL, and never
// shows up in an error.
func TestAuthKeyOnlyGoesToAbuseCH(t *testing.T) {
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "abusech.key")
	if err := os.WriteFile(keyFile, []byte("abc123DEF456ghi789\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if u, _, err := feedRequestURL("https://threatfox-api.abuse.ch/v2/files/exports/{auth_key}/hostfile.txt", keyFile); err != nil ||
		u != "https://threatfox-api.abuse.ch/v2/files/exports/abc123DEF456ghi789/hostfile.txt" {
		t.Fatalf("abuse.ch URL: %q %v", u, err)
	}
	for _, bad := range []string{
		"https://evil.example/{auth_key}",
		"https://abuse.ch.evil.example/{auth_key}",
		"http://urlhaus-api.abuse.ch/{auth_key}",
		"https://user@threatfox-api.abuse.ch/{auth_key}",
		"https://{auth_key}.abuse.ch/hostfile.txt",
	} {
		if u, _, err := feedRequestURL(bad, keyFile); err == nil {
			t.Errorf("%s was filled: %s", bad, u)
		}
	}
	if _, _, err := feedRequestURL("https://threatfox-api.abuse.ch/{auth_key}", filepath.Join(dir, "missing")); err == nil {
		t.Error("a missing key file was not refused")
	}
	if err := os.WriteFile(keyFile, []byte("abc/../x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := feedRequestURL("https://threatfox-api.abuse.ch/{auth_key}", keyFile); err == nil {
		t.Error("a key with a slash was put into a URL")
	}
	if u, key, err := feedRequestURL("https://lists.example/hosts.txt", filepath.Join(dir, "missing")); err != nil || key != "" || u != "https://lists.example/hosts.txt" {
		t.Fatalf("a URL without {auth_key} needs no key: %q %q %v", u, key, err)
	}
}

// A feed that fails keeps its last good names; a feed taken out of the
// tuning is dropped; a name on two feeds carries the higher confidence.
func TestRefreshDomainFeedsKeepsLastGoodList(t *testing.T) {
	var fail atomic.Bool
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if fail.Load() && r.URL.Path == "/a" {
			http.Error(w, "down", http.StatusServiceUnavailable)
			return
		}
		switch r.URL.Path {
		case "/a":
			w.Write([]byte("0.0.0.0 c2.bad.example\n0.0.0.0 both.bad.example\n"))
		case "/b":
			w.Write([]byte("both.bad.example\ndrop.bad.example\n"))
		case "/empty":
			w.Write([]byte("# nothing\n"))
		}
	}))
	defer srv.Close()
	m := New(nil)
	m.domainHTTP = srv.Client()
	feeds := []storage.DomainIntelFeed{
		{Name: "a", URL: srv.URL + "/a", Confidence: 90},
		{Name: "b", URL: srv.URL + "/b", Confidence: 60},
		{Name: "empty", URL: srv.URL + "/empty", Confidence: 90},
	}
	m.RefreshDomainFeeds(context.Background(), feeds, "/nonexistent")
	if ioc, ok := m.CheckDomain("Both.Bad.Example."); !ok || ioc.Confidence != 90 || ioc.Source != "a" {
		t.Fatalf("both.bad.example: %+v %v", ioc, ok)
	}
	if ioc, ok := m.CheckDomain("drop.bad.example"); !ok || ioc.Confidence != 60 {
		t.Fatalf("drop.bad.example: %+v %v", ioc, ok)
	}
	if _, ok := m.CheckDomain("sub.c2.bad.example"); ok {
		t.Fatal("a name under a listed name matched")
	}
	st := m.DomainFeedStatuses()
	if len(st) != 3 || st[2].Name != "empty" || st[2].Error == "" || st[0].Domains != 2 {
		t.Fatalf("statuses: %+v", st)
	}

	fail.Store(true)
	m.RefreshDomainFeeds(context.Background(), feeds[:1], "/nonexistent")
	if _, ok := m.CheckDomain("c2.bad.example"); !ok {
		t.Fatal("a failed fetch dropped the last good list")
	}
	if _, ok := m.CheckDomain("drop.bad.example"); ok {
		t.Fatal("a feed taken out of the tuning still matched")
	}
	if st := m.DomainFeedStatuses(); len(st) != 1 || st[0].Error != "HTTP 503" || st[0].Domains != 2 {
		t.Fatalf("status after failure: %+v", st)
	}
}

// A feed fetch follows no redirect: the key-bearing URL would go to the next
// host as the Referer.
func TestDomainFeedFollowsNoRedirect(t *testing.T) {
	var hops atomic.Int32
	other := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hops.Add(1)
		w.Write([]byte("evil.example.com\n"))
	}))
	defer other.Close()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL+"/list", http.StatusFound)
	}))
	defer srv.Close()
	client := newDomainFeedClient()
	client.Transport = srv.Client().Transport
	_, err := fetchDomainFeed(context.Background(), client, storage.DomainIntelFeed{Name: "x", URL: srv.URL + "/a", Confidence: 90}, "/nonexistent")
	if err == nil || err.Error() != "HTTP 302" || hops.Load() != 0 {
		t.Fatalf("redirect followed: err %v, hops %d", err, hops.Load())
	}
}
