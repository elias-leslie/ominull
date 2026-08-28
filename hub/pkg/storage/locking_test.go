package storage

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// A read lock held across a call that takes the read lock again is a deadlock
// waiting for a writer. sync.RWMutex is not reentrant: once a writer queues
// between the two acquisitions, the inner RLock waits for the writer, the
// writer waits for the outer read lock to drop, and every subsequent reader
// piles up behind them. GetAnalyticsSummary did exactly this, and it took the
// production hub down once the asset graph made writes frequent enough for a
// writer to land in the gap.
func TestAnalyticsSummaryDoesNotDeadlockUnderWrites(t *testing.T) {
	store, err := New(filepath.Join(t.TempDir(), "locking.db"))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer store.Close()

	now := time.Now().UTC()
	if err := store.UpsertEndpoint(Endpoint{
		ID: "win11-a", TenantID: "default", Hostname: "win11-a", OS: "Windows 11",
		IP: "10.0.4.15", RoleTag: "workstation", DriverVersion: "1.2.0",
		Status: "online", LastSeenAt: now, CreatedAt: now,
	}); err != nil {
		t.Fatalf("UpsertEndpoint: %v", err)
	}
	var events []Event
	for i := 0; i < 200; i++ {
		events = append(events, Event{
			TenantID: "default", EndpointID: "win11-a", Timestamp: now.Add(-time.Duration(i) * time.Minute),
			Layer: "ALE_AUTH_CONNECT", Action: "PERMIT", Direction: "OUTBOUND", Protocol: 6,
			SrcIP: "10.0.4.15", DstIP: "10.0.4.12", SrcPort: 49000, DstPort: 443,
			BytesIn: 1000, BytesOut: 500, ProcessPath: "C:\\Windows\\explorer.exe",
		})
	}
	if err := store.InsertEventsBatch(events); err != nil {
		t.Fatalf("InsertEventsBatch: %v", err)
	}

	stop := make(chan struct{})
	var wg sync.WaitGroup

	// Writers, so a writer is very likely to queue between the two read-lock
	// acquisitions rather than only rarely.
	for w := 0; w < 4; w++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				store.UpsertEndpoint(Endpoint{
					ID: "win11-a", TenantID: "default", Hostname: "win11-a", OS: "Windows 11",
					IP: "10.0.4.15", RoleTag: "workstation", DriverVersion: "1.2.0",
					Status: "online", LastSeenAt: time.Now().UTC(), CreatedAt: now,
				})
			}
		}(w)
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 40; i++ {
			if _, err := store.GetAnalyticsSummary(""); err != nil {
				t.Errorf("GetAnalyticsSummary: %v", err)
				return
			}
		}
	}()

	select {
	case <-done:
	case <-time.After(20 * time.Second):
		close(stop)
		wg.Wait()
		t.Fatal("GetAnalyticsSummary deadlocked against concurrent writers: a lock-holding method called another method that takes the same lock")
	}
	close(stop)
	wg.Wait()
}

// The deadlock above is one instance of a class, and the package has enough
// lock-taking methods that spotting the next one by eye is not realistic. This
// walks the package and fails on any method that acquires the mutex and then
// calls another method that acquires it too. The fix is always the same: split
// the callee into an unlocked `...Locked` helper.
func TestNoMethodHoldsTheLockAcrossALockingCall(t *testing.T) {
	fset := token.NewFileSet()
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatalf("glob: %v", err)
	}

	type method struct {
		name  string
		fn    *ast.FuncDecl
		fset  *token.FileSet
		locks bool
	}
	methods := map[string]*method{}

	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, f, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", f, err)
		}
		for _, d := range file.Decls {
			fn, ok := d.(*ast.FuncDecl)
			if !ok || fn.Recv == nil || fn.Body == nil {
				continue
			}
			m := &method{name: fn.Name.Name, fn: fn, fset: fset}
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				sel, ok := n.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				if sel.Sel.Name == "Lock" || sel.Sel.Name == "RLock" {
					if inner, ok := sel.X.(*ast.SelectorExpr); ok && inner.Sel.Name == "mu" {
						m.locks = true
					}
				}
				return true
			})
			methods[m.name] = m
		}
	}

	for _, m := range methods {
		if !m.locks {
			continue
		}
		// Find where the lock is taken, then look only at calls after it.
		var lockPos token.Pos
		ast.Inspect(m.fn.Body, func(n ast.Node) bool {
			if lockPos != token.NoPos {
				return false
			}
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			if sel.Sel.Name == "Lock" || sel.Sel.Name == "RLock" {
				if inner, ok := sel.X.(*ast.SelectorExpr); ok && inner.Sel.Name == "mu" {
					lockPos = call.Pos()
				}
			}
			return true
		})
		if lockPos == token.NoPos {
			continue
		}
		ast.Inspect(m.fn.Body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok || call.Pos() <= lockPos {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			ident, ok := sel.X.(*ast.Ident)
			if !ok || ident.Name != "s" {
				return true
			}
			callee, ok := methods[sel.Sel.Name]
			if !ok || !callee.locks || callee.name == m.name {
				return true
			}
			t.Errorf("%s: %s holds the mutex and calls s.%s, which takes it again — "+
				"sync.RWMutex is not reentrant; split %s into an unlocked ...Locked helper",
				fset.Position(call.Pos()), m.name, callee.name, callee.name)
			return true
		})
	}
}
