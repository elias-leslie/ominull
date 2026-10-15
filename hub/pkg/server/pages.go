package server

import (
	"bytes"
	"embed"
	"html/template"
	"log"
	"net/http"
	"net/url"
	"strings"
	"sync"
)

// Server-rendered console pages. The single-page console in web/app.js grew to
// 11k lines; views move out of it one at a time into pages the hub renders
// with html/template, each with at most a small script of its own (built from
// web-src/ with esbuild). They share the console's stylesheet, theme and
// session cookie, so moving between a page and the console is a plain link.
//
//go:embed pages/*.tmpl
var pageFS embed.FS

var (
	pageOnce      sync.Once
	pageTemplates map[string]*template.Template
)

func loadPages() {
	pageTemplates = map[string]*template.Template{}
	for _, name := range []string{"timeline", "terminal"} {
		t := template.New("layout.tmpl").Funcs(pageFuncs)
		pageTemplates[name] = template.Must(t.ParseFS(pageFS, "pages/layout.tmpl", "pages/"+name+".tmpl"))
	}
}

var pageFuncs = template.FuncMap{
	"lower": strings.ToLower,
}

// pageData is what every page's layout needs; Body is the page's own data.
type pageData struct {
	Title    string
	Version  string
	Nonce    string
	Operator string
	Role     string
	// Back is the console section the header links back to.
	Back string
	// Script names this page's script under web/, if it has one.
	Script string
	Body   any
}

// pageViewer resolves who is asking, the same ways the console document
// accepts after its first load: a Cloudflare Access assertion or the console
// session cookie. The admin key is presented only to the console document,
// which sets that cookie, so a page never receives or embeds the key.
func (s *Server) pageViewer(r *http.Request) (accessOperator, bool) {
	if op, ok := s.access.Verify(r); ok {
		return op, true
	}
	return s.consoleSession(r)
}

// servePage renders one page, or sends a caller without a session to the
// console's sign-in, which returns them to the console.
func (s *Server) servePage(w http.ResponseWriter, r *http.Request, name string, data pageData) {
	pageOnce.Do(loadPages)
	data.Nonce = newCSPNonce()
	data.Version = s.agentVersion
	var buf bytes.Buffer
	if err := pageTemplates[name].Execute(&buf, data); err != nil {
		log.Printf("[!] console page %s: %v", name, err)
		http.Error(w, "page could not be rendered", http.StatusInternalServerError)
		return
	}
	setConsoleSecurityHeaders(w, data.Nonce)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(buf.Bytes())
}

// requirePageViewer answers for a caller with no session and reports whether
// the page may be rendered.
func (s *Server) requirePageViewer(w http.ResponseWriter, r *http.Request) (accessOperator, bool) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return accessOperator{}, false
	}
	viewer, ok := s.pageViewer(r)
	if !ok {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return accessOperator{}, false
	}
	return viewer, true
}

// pageURL builds a page link with its query, for templates.
func pageURL(path string, query url.Values) string {
	if len(query) == 0 {
		return path
	}
	return path + "?" + query.Encode()
}
