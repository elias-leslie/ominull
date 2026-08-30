package server

import (
	"crypto/rand"
	"crypto/sha256"
	"embed"
	"encoding/base64"
	"encoding/hex"
	"io/fs"
	"mime"
	"net/http"
	"path"
	"strings"
	"sync"
)

// The operator console. It used to be a 209 KB Go string constant in
// dashboard.go; it is now real files so the stylesheet, the script and the
// fonts can be edited, diffed and reviewed like code.
//
// Embedding keeps the hub a single binary with no build step and no runtime
// network dependency: the IBM Plex faces ship inside the executable, so an
// airgapped fleet renders exactly like a connected one. Nothing here is
// fetched from a CDN.
//
//go:embed web
var consoleFS embed.FS

// consoleAsset is one embedded file, prepared once at first use.
type consoleAsset struct {
	body        []byte
	contentType string
	etag        string
}

var (
	consoleOnce   sync.Once
	consoleAssets map[string]consoleAsset
	consoleIndex  []byte
)

// adminKeyPlaceholder and hubVersionPlaceholder are substituted into index.html
// at serve time. The console needs the admin key to call the REST API, and the
// document is only ever written to a caller who already presented that key, so
// the key lives in the served HTML and never in a tracked file.
const (
	adminKeyPlaceholder   = "{{ADMIN_KEY}}"
	operatorPlaceholder   = "{{OPERATOR}}"
	rolePlaceholder       = "{{OPERATOR_ROLE}}"
	hubVersionPlaceholder = "{{HUB_VERSION}}"
	// cspNoncePlaceholder marks the two inline scripts the document needs: the
	// serve-time configuration and the pre-paint theme selection. Both have to
	// run before app.js does, so neither can move into a file, and a content
	// security policy that allows every inline script would allow an injected
	// one too. A per-response nonce allows exactly these two.
	cspNoncePlaceholder = "{{CSP_NONCE}}"
)

func loadConsole() {
	consoleAssets = make(map[string]consoleAsset)

	err := fs.WalkDir(consoleFS, "web", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		body, readErr := consoleFS.ReadFile(p)
		if readErr != nil {
			return readErr
		}
		name := strings.TrimPrefix(p, "web/")
		if name == "index.html" {
			consoleIndex = body
			return nil
		}
		sum := sha256.Sum256(body)
		consoleAssets[name] = consoleAsset{
			body:        body,
			contentType: consoleContentType(name),
			etag:        `"` + hex.EncodeToString(sum[:8]) + `"`,
		}
		return nil
	})
	if err != nil {
		// A missing embed is a build error, not a runtime condition: the
		// walk only fails if the embedded tree is malformed.
		panic("ominull: embedded console is unreadable: " + err.Error())
	}
}

func consoleContentType(name string) string {
	switch path.Ext(name) {
	case ".css":
		return "text/css; charset=utf-8"
	case ".js":
		return "text/javascript; charset=utf-8"
	case ".woff2":
		return "font/woff2"
	case ".txt":
		return "text/plain; charset=utf-8"
	}
	if ct := mime.TypeByExtension(path.Ext(name)); ct != "" {
		return ct
	}
	return "application/octet-stream"
}

// consoleDocument renders index.html with the serve-time substitutions applied
// and returns the script nonce the caller must name in the Content-Security-Policy
// header for that response.
func consoleDocument(adminKey, hubVersion string, viewer accessOperator) ([]byte, string) {
	consoleOnce.Do(loadConsole)
	nonce := newCSPNonce()
	html := string(consoleIndex)
	html = strings.ReplaceAll(html, adminKeyPlaceholder, jsStringEscape(adminKey))
	html = strings.ReplaceAll(html, hubVersionPlaceholder, jsStringEscape(hubVersion))
	// Who the console thinks it is rendering for. The console hides what this
	// operator cannot use; the hub refuses it regardless, because a hidden
	// button is a courtesy and not a control.
	html = strings.ReplaceAll(html, operatorPlaceholder, jsStringEscape(viewer.Email))
	html = strings.ReplaceAll(html, rolePlaceholder, jsStringEscape(viewer.Role))
	html = strings.ReplaceAll(html, cspNoncePlaceholder, nonce)
	return []byte(html), nonce
}

// newCSPNonce is 128 bits of randomness per response. Reusing one across
// responses would let an attacker who saw one document authorise a script in
// the next.
func newCSPNonce() string {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		// Without a nonce the policy still holds; the inline scripts simply do
		// not run, which fails visibly rather than silently opening the policy.
		return ""
	}
	return base64.RawStdEncoding.EncodeToString(raw[:])
}

// jsStringEscape makes a value safe to drop inside a double-quoted JavaScript
// string literal in the served document. Admin keys are operator-chosen, so a
// quote or a backslash in one must not be able to break out of the literal.
func jsStringEscape(v string) string {
	var b strings.Builder
	for _, r := range v {
		switch r {
		case '\\':
			b.WriteString(`\\`)
		case '"':
			b.WriteString(`\"`)
		case '\'':
			b.WriteString(`\'`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '<':
			b.WriteString(`<`)
		case '>':
			b.WriteString(`>`)
		case '&':
			b.WriteString(`&`)
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// consoleGate is the key-entry page shown before the console is unlocked. It
// links the same stylesheet as the console, so it is themed and carries no
// colours of its own.
//
// The form posts. As a GET it put the admin key in the query string of the very
// next request, which is the one place a credential is guaranteed to be written
// down: browser history, bookmarks, and the access log of every proxy and CDN
// between the operator and the hub. None of those are reachable by a cache purge.
func consoleGate() []byte {
	return []byte(`<!DOCTYPE html>
<html lang="en" data-theme="ash">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Ominull Console</title>
<link rel="stylesheet" href="/app.css">
</head>
<body>
<div class="gate">
  <form method="POST" action="/">
    <h1>Ominull Console</h1>
    <p>Admin API key required.</p>
    <input type="password" name="key" placeholder="Admin API key" autofocus aria-label="Admin API key">
    <button class="btn btn-primary" type="submit">Unlock</button>
  </form>
</div>
</body>
</html>
`)
}

// handleConsoleAsset serves the stylesheet, the script and the embedded fonts.
// These carry no credential — the key is only ever in index.html — so they are
// not behind the admin-key gate: a browser does not attach an API key to a
// <link> or a @font-face fetch, and gating them would leave the console
// unstyled and unable to render on an authenticated page.
func (s *Server) handleConsoleAsset(w http.ResponseWriter, r *http.Request) {
	consoleOnce.Do(loadConsole)

	name := strings.TrimPrefix(r.URL.Path, "/")
	asset, ok := consoleAssets[name]
	if !ok {
		http.NotFound(w, r)
		return
	}

	setConsoleSecurityHeaders(w, "")
	w.Header().Set("Content-Type", asset.contentType)
	w.Header().Set("ETag", asset.etag)
	// Revalidate every load: the console ships with the binary, so a hub
	// upgrade must not leave an operator on a cached stylesheet from the
	// previous build.
	w.Header().Set("Cache-Control", "no-cache")

	if match := r.Header.Get("If-None-Match"); match != "" && strings.Contains(match, asset.etag) {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	w.Write(asset.body)
}

// consoleAssetPaths lists the URL paths the console loads, so Start can route
// them explicitly rather than swallowing every unmatched request.
func consoleAssetPaths() []string {
	consoleOnce.Do(loadConsole)
	paths := make([]string, 0, len(consoleAssets))
	for name := range consoleAssets {
		paths = append(paths, "/"+name)
	}
	return paths
}
