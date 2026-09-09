package server

import (
	"net/http/httptest"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// The operator console is a hand-written IIFE and a hand-written stylesheet
// with no component tests and no build step, so the two files can disagree
// without anything noticing: a class name that has no rule renders an
// unstyled element, and a custom property that was never defined makes the
// browser drop the whole declaration. Neither is a syntax error, so neither
// `go build`, `go vet` nor `node --check` sees it - the first report is an
// operator looking at a broken panel in production.
//
// These three checks are the cheapest thing that closes that gap, and they
// run in the same `go test ./...` that gates every release.

func consoleSource(t *testing.T, name string) string {
	t.Helper()
	b, err := consoleFS.ReadFile("web/" + name)
	if err != nil {
		t.Fatalf("read web/%s: %v", name, err)
	}
	return string(b)
}

var (
	cssCommentRe = regexp.MustCompile(`(?s)/\*.*?\*/`)
	jsLineRe     = regexp.MustCompile(`(?m)^\s*//.*$`)
)

func stripComments(src string) string {
	return jsLineRe.ReplaceAllString(cssCommentRe.ReplaceAllString(src, " "), " ")
}

func sortedMissing(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// TestConsoleCustomPropertiesAreDefined fails when the stylesheet or app.js
// reads a --token that nothing declares. A var() with no definition and no
// fallback does not fall back to anything: the declaration is invalid at
// computed-value time and is discarded, so the element silently loses that
// property. Properties written at runtime by h()'s `vars` prop count as
// defined, because setProperty() is the sanctioned escape hatch under
// style-src 'self' and those names exist only on the element.
func TestConsoleCustomPropertiesAreDefined(t *testing.T) {
	css := stripComments(consoleSource(t, "app.css"))
	js := stripComments(consoleSource(t, "app.js"))

	defined := map[string]bool{}
	for _, m := range regexp.MustCompile(`(--[A-Za-z0-9_-]+)\s*:`).FindAllStringSubmatch(css, -1) {
		defined[m[1]] = true
	}
	for _, block := range regexp.MustCompile(`(?s)vars\s*:\s*\{(.*?)\}`).FindAllStringSubmatch(js, -1) {
		for _, m := range regexp.MustCompile(`["'](--[A-Za-z0-9_-]+)["']`).FindAllStringSubmatch(block[1], -1) {
			defined[m[1]] = true
		}
	}

	missing := map[string]bool{}
	for _, m := range regexp.MustCompile(`var\(\s*(--[A-Za-z0-9_-]+)\s*\)`).FindAllStringSubmatch(css, -1) {
		if !defined[m[1]] {
			missing[m[1]] = true
		}
	}
	for _, m := range regexp.MustCompile(`cssVar\(\s*"(--[A-Za-z0-9_-]+)"\s*[,)]`).FindAllStringSubmatch(js, -1) {
		if !defined[m[1]] {
			missing[m[1]] = true
		}
	}
	if len(missing) > 0 {
		t.Errorf("custom properties used but never defined: %v", sortedMissing(missing))
	}
}

// TestConsoleClassesHaveRules fails when the console writes a class name that
// the stylesheet never mentions. Only literal names are checked: a name built
// by concatenation cannot be resolved statically, and guessing would make this
// noisy enough that somebody would turn it off.
func TestConsoleClassesHaveRules(t *testing.T) {
	css := stripComments(consoleSource(t, "app.css"))
	js := stripComments(consoleSource(t, "app.js"))
	html := consoleSource(t, "index.html")

	styled := map[string]bool{}
	for _, m := range regexp.MustCompile(`\.(-?[A-Za-z_][A-Za-z0-9_-]*)`).FindAllStringSubmatch(css, -1) {
		styled[m[1]] = true
	}

	used := map[string]bool{}
	collect := func(src string, re *regexp.Regexp) {
		for _, loc := range re.FindAllStringSubmatchIndex(src, -1) {
			// A literal spliced into a concatenation is a fragment of a name
			// computed at runtime, not a name in itself.
			before := strings.TrimRight(src[max(0, loc[0]-3):loc[0]], " ")
			after := strings.TrimLeft(src[loc[1]:min(len(src), loc[1]+3)], " ")
			if strings.HasSuffix(before, "+") || strings.HasPrefix(after, "+") {
				continue
			}
			for _, name := range strings.Fields(src[loc[2]:loc[3]]) {
				used[name] = true
			}
		}
	}
	collect(js, regexp.MustCompile(`cls\s*:\s*"([^"]+)"`))
	collect(js, regexp.MustCompile(`className\s*=\s*"([^"]+)"`))
	collect(html, regexp.MustCompile(`class="([^"]+)"`))

	missing := map[string]bool{}
	for name := range used {
		if !styled[name] {
			missing[name] = true
		}
	}
	if len(missing) > 0 {
		t.Errorf("classes written by the console with no CSS rule: %v", sortedMissing(missing))
	}
}

// TestServiceWorkerCacheTracksVersion guards a failure that already happened:
// sw.js carried a hardcoded "v1.8.1" while VERSION moved on twice, so the
// cache name never changed, the activate purge that deletes every other cache
// had nothing to delete, and every release's assets piled up in one bucket
// that was never invalidated. The precache entries must also carry the same
// ?v= query the document requests, or they cache a URL nobody asks for.
func TestServiceWorkerCacheTracksVersion(t *testing.T) {
	sw := stripComments(consoleSource(t, "sw.js"))

	if !strings.Contains(sw, hubVersionPlaceholder) {
		t.Fatalf("sw.js has no %s placeholder: the cache name cannot track VERSION", hubVersionPlaceholder)
	}
	if !strings.Contains(sw, `"ominull-shell-v" + HUB_VERSION`) {
		t.Error("sw.js CACHE_NAME must be derived from HUB_VERSION")
	}
	if m := regexp.MustCompile(`"v?[0-9]+\.[0-9]+\.[0-9]+"`).FindString(sw); m != "" {
		t.Errorf("sw.js contains a hardcoded version literal %s: use HUB_VERSION", m)
	}
	for _, asset := range []string{"app.css", "app.js"} {
		want := `"/` + asset + `?v=" + HUB_VERSION`
		if !strings.Contains(sw, want) {
			t.Errorf("sw.js precache entry for %s must be %s, or it never matches the request the document makes", asset, want)
		}
	}
}

// TestServedConsoleAssetsSubstituteVersion proves the placeholder is actually
// replaced on the way out, rather than being shipped to the browser as the
// literal string "{{HUB_VERSION}}".
func TestServedConsoleAssetsSubstituteVersion(t *testing.T) {
	s := &Server{agentVersion: "9.9.9"}
	asset, ok := s.consoleAssetFor("sw.js")
	if !ok {
		t.Fatal("sw.js is not a served console asset")
	}
	body := string(asset.body)
	if strings.Contains(body, hubVersionPlaceholder) {
		t.Error("served sw.js still contains the raw placeholder")
	}
	if !strings.Contains(body, "9.9.9") {
		t.Error("served sw.js does not carry the hub version")
	}
	plain, _ := s.consoleAssetFor("app.css")
	if plain.etag == asset.etag {
		t.Error("substituted and plain assets share an etag")
	}
}

// TestConsoleCSPHasNoUnsafeInline pins the policy that the console document is
// served under. style-src was widened to 'unsafe-inline' to stop xterm's
// runtime stylesheet being refused, which admitted every inline style on the
// page - including one arriving in injected markup - to fix one library.
// index.html stamps the response nonce onto style elements as they are
// created instead, so the directive can name the nonce and nothing else.
func TestConsoleCSPHasNoUnsafeInline(t *testing.T) {
	w := httptest.NewRecorder()
	setConsoleSecurityHeaders(w, "n0nc3")
	csp := w.Header().Get("Content-Security-Policy")

	if strings.Contains(csp, "unsafe-inline") {
		t.Errorf("console CSP still allows unsafe-inline: %s", csp)
	}
	if strings.Contains(csp, "unsafe-eval") {
		t.Errorf("console CSP allows unsafe-eval: %s", csp)
	}
	if !strings.Contains(csp, "style-src 'self' 'nonce-n0nc3'") {
		t.Errorf("style-src must be 'self' plus the response nonce: %s", csp)
	}
	if !strings.Contains(csp, "script-src 'self' 'nonce-n0nc3'") {
		t.Errorf("script-src must be 'self' plus the response nonce: %s", csp)
	}

	// Without a nonce the policy must fall back to 'self' alone rather than
	// emitting an empty nonce, which no element can ever match.
	plain := httptest.NewRecorder()
	setConsoleSecurityHeaders(plain, "")
	if got := plain.Header().Get("Content-Security-Policy"); strings.Contains(got, "nonce-") {
		t.Errorf("empty nonce must not appear in the policy: %s", got)
	}
}

// TestConsoleStampsStyleNonce proves the shim that makes the above possible is
// actually in the document, ahead of the vendored xterm bundle that needs it.
func TestConsoleStampsStyleNonce(t *testing.T) {
	html := consoleSource(t, "index.html")

	shim := strings.Index(html, `document.createElement = function (tag)`)
	if shim < 0 {
		t.Fatal("index.html does not stamp a nonce onto runtime-created style elements")
	}
	xterm := strings.Index(html, "app.js?v=")
	if xterm < 0 {
		t.Fatal("index.html does not load the feature loader")
	}
	if shim > xterm {
		t.Error("the style-nonce shim must run before the feature loader")
	}
	if !strings.Contains(html[shim-800:shim], cspNoncePlaceholder) {
		t.Error("the shim must read the serve-time nonce placeholder")
	}
}

// TestConsoleSpriteReferencesResolve fails when app.js asks for a sprite
// symbol that index.html does not define. A <use href="#missing"> is not an
// error in any engine: the <svg> renders empty, so a state badge loses its
// glyph and keeps its stripe and its word, which looks like a design choice
// rather than a bug. g-quarantine had five call sites and no symbol.
func TestConsoleSpriteReferencesResolve(t *testing.T) {
	js := stripComments(consoleSource(t, "app.js"))
	html := consoleSource(t, "index.html")

	defined := map[string]bool{}
	for _, m := range regexp.MustCompile(`<symbol\s+id="([^"]+)"`).FindAllStringSubmatch(html, -1) {
		defined[m[1]] = true
	}
	if len(defined) == 0 {
		t.Fatal("index.html defines no sprite symbols; the extraction is wrong")
	}

	missing := map[string]bool{}
	// A literal id only. `iconId: "i-" + sec.id` builds its name at runtime and
	// is skipped the same way the class check skips concatenations - the
	// trailing quote must be the end of the string, not the start of a join.
	collect := func(pattern string) {
		for _, m := range regexp.MustCompile(pattern).FindAllStringSubmatch(js, -1) {
			id := m[1]
			if strings.HasSuffix(id, "-") || defined[id] {
				continue
			}
			missing[id] = true
		}
	}
	// icon("i-name") and icon("g-name", true) are how the console draws one.
	collect(`icon\("([a-z0-9-]+)"\s*[,)]`)
	// Sprite ids also travel as data on menu and palette items,
	collect(`iconId:\s*"([a-z0-9-]+)"\s*[,}]`)
	// and on the state vocabulary, which builds every badge in the console.
	collect(`glyph:\s*"([a-z0-9-]+)"\s*[,}]`)

	if len(missing) > 0 {
		t.Fatalf("app.js references sprite symbols index.html does not define: %s",
			strings.Join(sortedMissing(missing), ", "))
	}
}
