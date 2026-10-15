package hub_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// A Go test that can skip makes the required native go stage of acceptance
// "unavailable" unless .st-check.toml declares it not applicable. An
// undeclared opt-in benchmark failed the nightly publication of 710d15e this
// way. Every test that calls t.Skip must be declared there.
func TestEverySkippingTestIsDeclared(t *testing.T) {
	cfg, err := os.ReadFile(filepath.Join("..", ".st-check.toml"))
	if err != nil {
		t.Fatal(err)
	}
	declared := map[string]bool{}
	for _, m := range regexp.MustCompile(`(?m)^"(ominull/hub/[^"]+)"\s*=`).FindAllStringSubmatch(string(cfg), -1) {
		declared[m[1]] = true
	}
	fset := token.NewFileSet()
	err = filepath.WalkDir(".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && (d.Name() == "node_modules" || strings.HasPrefix(d.Name(), ".")) && path != "." {
			return filepath.SkipDir
		}
		if d.IsDir() || !strings.HasSuffix(path, "_test.go") {
			return nil
		}
		f, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			return err
		}
		pkg := "ominull/hub"
		if dir := filepath.ToSlash(filepath.Dir(path)); dir != "." {
			pkg += "/" + dir
		}
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil || !strings.HasPrefix(fn.Name.Name, "Test") {
				continue
			}
			skips := false
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				if sel, ok := n.(*ast.SelectorExpr); ok && (sel.Sel.Name == "Skip" || sel.Sel.Name == "Skipf" || sel.Sel.Name == "SkipNow") {
					skips = true
				}
				return !skips
			})
			if id := pkg + "." + fn.Name.Name; skips && !declared[id] {
				t.Errorf("%s (%s) can skip but is not in .st-check.toml [native.stages.evidence.not_applicable_tests]", id, path)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
