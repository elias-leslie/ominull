package detector

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// Detection keeps working whatever happens to the remote-admin features
// (terminal, screen, scripts, maintenance), so nothing it builds on may import
// them. Walks the imports from this package down, tests excluded.
func TestDetectionDoesNotDependOnRemoteAdmin(t *testing.T) {
	const prefix = "ominull/hub/pkg/"
	forbidden := map[string]bool{"terminal": true, "screen": true, "scripts": true, "response": true, "grants": true, "server": true}
	seen := map[string]bool{}
	var walk func(pkg string, from []string)
	walk = func(pkg string, from []string) {
		if seen[pkg] {
			return
		}
		seen[pkg] = true
		if forbidden[pkg] {
			t.Errorf("detection reaches remote admin: %s -> %s", strings.Join(from, " -> "), pkg)
			return
		}
		dir := filepath.Join("..", pkg)
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatalf("read %s: %v", dir, err)
		}
		for _, e := range entries {
			if !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
				continue
			}
			f, err := parser.ParseFile(token.NewFileSet(), filepath.Join(dir, e.Name()), nil, parser.ImportsOnly)
			if err != nil {
				t.Fatalf("parse %s: %v", e.Name(), err)
			}
			for _, imp := range f.Imports {
				path, _ := strconv.Unquote(imp.Path.Value)
				if rest, ok := strings.CutPrefix(path, prefix); ok {
					walk(rest, append(from[:len(from):len(from)], pkg))
				}
			}
		}
	}
	walk("detector", nil)
	if !seen["storage"] {
		t.Fatalf("walked %v; the walk should have reached storage", seen)
	}
}
