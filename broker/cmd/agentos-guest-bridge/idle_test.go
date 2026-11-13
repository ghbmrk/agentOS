package main

// REQ: ARC-6, ARC-7

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

// GUEST-bridge-tree-dead: agentosd serves no managed_tree tool
// (MIG-4-untrusted-learn), so the bridge's idle work makes no broker tool
// call at all: the only request it sends unprompted is the owner poll.
// Failure path: the bridge polls a removed tool forever and logs the
// unknown-tool answer. The test stops the poll through its context, so no
// goroutine keeps polling a closed server for the rest of the package run
// (GUEST-bridge-tree-dead-fu).
func TestBridgeMakesNoToolCallAtIdle(t *testing.T) {
	var mu sync.Mutex
	paths := map[string]int{}
	broker := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		paths[r.URL.Path]++
		mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	}))
	defer broker.Close()
	u, _ := url.Parse(broker.URL)

	ctx, cancel := context.WithCancel(context.Background())
	done := background(ctx, &http.Client{Transport: rewrite{u}}, "http://127.0.0.1:1", "m", "tok")
	defer func() {
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("the idle work did not stop when its context was cancelled")
		}
	}()
	deadline := time.Now().Add(2 * time.Second)
	for {
		mu.Lock()
		polled := paths["/owner/next"]
		mu.Unlock()
		if polled > 0 || time.Now().After(deadline) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	time.Sleep(200 * time.Millisecond)

	mu.Lock()
	defer mu.Unlock()
	if paths["/owner/next"] == 0 {
		t.Fatal("the owner poll never ran")
	}
	for p, n := range paths {
		if p != "/owner/next" {
			t.Errorf("idle bridge sent %d request(s) to %s", n, p)
		}
	}
}

// The idle work stops once its context ends, even while the owner poll
// is backing off after a failed request (GUEST-bridge-tree-dead-fu).
// Failure path: the back-off sleeps through the cancel and the goroutine
// outlives its caller.
func TestBackgroundStopsWhenItsContextEnds(t *testing.T) {
	broker := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError) // every poll fails and backs off
	}))
	defer broker.Close()
	u, _ := url.Parse(broker.URL)

	ctx, cancel := context.WithCancel(context.Background())
	done := background(ctx, &http.Client{Transport: rewrite{u}}, "http://127.0.0.1:1", "m", "tok")
	time.Sleep(100 * time.Millisecond) // inside the 2 s back-off
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("the idle work outlived its context")
	}
}

// Every goroutine the bridge starts is one of a fixed set: the request
// server and the signal relay in main, which act only when the guest or
// the system asks, and the idle work, which background starts and
// TestBridgeMakesNoToolCallAtIdle covers. A new go statement anywhere in
// the command fails this test, so idle work cannot be started around
// background (GUEST-bridge-tree-dead-fu, acceptance 3 of #4491).
// Failure path: a goroutine started directly from main brings back an
// idle tool poll, and the idle test still passes.
func TestEveryGoroutineIsKnown(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	var got []string
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, d := range f.Decls {
			fn, ok := d.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				g, ok := n.(*ast.GoStmt)
				if !ok {
					return true
				}
				got = append(got, fn.Name.Name+": "+callee(g.Call.Fun))
				return true
			})
		}
	}
	sort.Strings(got)
	want := []string{
		"background: owner",
		"main: func literal",
		"main: http.Serve",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("go statements:\n%s\nwant:\n%s\n(route new idle work through background)",
			strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	// The signal relay only forwards a signal to the runtime.
	src, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	f, _ := parser.ParseFile(fset, "main.go", src, 0)
	ast.Inspect(f, func(n ast.Node) bool {
		g, ok := n.(*ast.GoStmt)
		if !ok {
			return true
		}
		if lit, ok := g.Call.Fun.(*ast.FuncLit); ok {
			body := string(src[fset.Position(lit.Body.Pos()).Offset:fset.Position(lit.Body.End()).Offset])
			if strings.Contains(body, "broker") || strings.Contains(body, "for ") {
				t.Errorf("main's goroutine literal does more than relay a signal:\n%s", body)
			}
		}
		return true
	})
}

func callee(e ast.Expr) string {
	switch f := e.(type) {
	case *ast.Ident:
		return f.Name
	case *ast.SelectorExpr:
		return callee(f.X) + "." + f.Sel.Name
	case *ast.FuncLit:
		return "func literal"
	}
	return "?"
}
