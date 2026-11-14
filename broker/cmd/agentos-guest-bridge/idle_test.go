package main

// REQ: PLN-5

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

// A failed owner poll is retried after its 2 s back-off, neither at once
// nor never (mutgate on #5640, main.go:177 and :179). Failure paths: with
// the back-off select deleted, the owner loop spins on /owner/next against
// a failing broker; with its timer case deleted, the first failure parks
// the loop until cancel and owner messages stop arriving.
func TestOwnerPollBacksOffThenRetries(t *testing.T) {
	var mu sync.Mutex
	polls := 0
	broker := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/owner/next" {
			mu.Lock()
			polls++
			mu.Unlock()
		}
		w.WriteHeader(http.StatusInternalServerError) // every poll fails
	}))
	defer broker.Close()
	u, _ := url.Parse(broker.URL)

	ctx, cancel := context.WithCancel(context.Background())
	done := background(ctx, &http.Client{Transport: rewrite{u}}, "http://127.0.0.1:1", "m", "tok")
	time.Sleep(2700 * time.Millisecond) // one back-off and a margin, short of a second
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the idle work outlived its context")
	}
	mu.Lock()
	defer mu.Unlock()
	if polls < 2 {
		t.Errorf("owner poll ran %d time(s) in 2.7 s; a failed poll must be retried after its back-off", polls)
	}
	if polls > 3 {
		t.Errorf("owner poll ran %d times in 2.7 s; a failed poll must back off 2 s before retrying", polls)
	}
}

// A cancel also ends an /owner/next request the broker is holding open
// (L3 release 2 on #5640). Failure path: the poll's request ignores ctx,
// so a held-open poll keeps the idle work alive after its caller stops.
func TestBackgroundCancelsAHeldPoll(t *testing.T) {
	held := make(chan struct{}, 1)
	broker := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case held <- struct{}{}:
		default:
		}
		select {
		case <-r.Context().Done():
		case <-time.After(10 * time.Second):
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer broker.Close()
	u, _ := url.Parse(broker.URL)

	ctx, cancel := context.WithCancel(context.Background())
	done := background(ctx, &http.Client{Transport: rewrite{u}}, "http://127.0.0.1:1", "m", "tok")
	select {
	case <-held:
	case <-time.After(2 * time.Second):
		t.Fatal("the owner poll never reached the broker")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("a held-open poll kept the idle work alive after its context ended")
	}
}

// Every goroutine the bridge starts is one of a fixed set: the request
// server and the signal relay in main, which act only when the guest or
// the system asks, and the idle work, which background starts and
// TestBridgeMakesNoToolCallAtIdle covers. Any other go statement or timer
// start anywhere in the command's files (goroutineStarts) fails this test, so idle work cannot be started around
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
		got = append(got, goroutineStarts(f)...)
	}
	sort.Strings(got)
	want := []string{
		"background: go owner",
		"main: go func literal",
		"main: go http.Serve",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("goroutine starts:\n%s\nwant:\n%s\n(route new idle work through background)",
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

// The inventory sees a goroutine start anywhere in a file: in a package
// variable's initializer as well as a function body, and a timer that
// runs a function or ticks (time.AfterFunc, time.NewTicker, time.Tick) as
// well as a go statement (L3 blocker 1 and Potency release 2 on #5640).
// Failure path: a poll started from a var initializer or a timer slips
// past TestEveryGoroutineIsKnown.
func TestGoroutineStartsSeesTheWholeFile(t *testing.T) {
	src := `package main

import "time"

var _ = func() int { go poll(); return 0 }()

var t = time.AfterFunc(time.Second, poll)

func f() {
	_ = time.NewTicker(time.Second)
	for range time.Tick(time.Second) {
	}
}

func poll() {}
`
	f, err := parser.ParseFile(token.NewFileSet(), "x.go", src, 0)
	if err != nil {
		t.Fatal(err)
	}
	got := goroutineStarts(f)
	sort.Strings(got)
	want := []string{
		"f: time.NewTicker",
		"f: time.Tick",
		"var: go poll",
		"var: time.AfterFunc",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("goroutine starts:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

// The inventory sees a timer start whatever name the file imports "time"
// under: an alias or a dot import as well as the plain name (L3 release
// on #5640, GUEST-bridge-time-alias). Failure path: a file that does
// import tm "time" and calls tm.Tick starts timed work the inventory never
// sees, and TestEveryGoroutineIsKnown still passes. A local named "time"
// in a file that imports it under another name is not the package.
func TestGoroutineStartsSeesAnAliasedTimeImport(t *testing.T) {
	for _, c := range []struct {
		name, src string
		want      []string
	}{
		{"alias", `package main

import tm "time"

func f() {
	_ = tm.NewTicker(tm.Second)
	for range tm.Tick(tm.Second) {
	}
	tm.AfterFunc(tm.Second, f)
}
`, []string{"f: time.AfterFunc", "f: time.NewTicker", "f: time.Tick"}},
		{"dot", `package main

import . "time"

var t = AfterFunc(Second, f)

func f() {
	_ = NewTicker(Second)
	for range Tick(Second) {
	}
}
`, []string{"f: time.NewTicker", "f: time.Tick", "var: time.AfterFunc"}},
		{"double", `package main

import (
	"time"
	tm "time"
)

var _ = time.Second

func f() { tm.AfterFunc(tm.Second, f) }
`, []string{"f: time.AfterFunc"}},
		{"double-dot", `package main

import (
	"time"
	. "time"
)

var _ = time.Second

func f() { _ = NewTicker(Second) }
`, []string{"f: time.NewTicker"}},
		{"shadowed", `package main

import tm "time"

type clock struct{}

func (clock) Tick(tm.Duration) {}

func f() {
	var time clock
	time.Tick(tm.Second)
}
`, nil},
	} {
		f, err := parser.ParseFile(token.NewFileSet(), "x.go", c.src, 0)
		if err != nil {
			t.Fatal(err)
		}
		got := goroutineStarts(f)
		sort.Strings(got)
		if strings.Join(got, "\n") != strings.Join(c.want, "\n") {
			t.Errorf("%s: goroutine starts:\n%s\nwant:\n%s", c.name, strings.Join(got, "\n"), strings.Join(c.want, "\n"))
		}
	}
}

// goroutineStarts lists each go statement and each timer that starts
// work in f, labelled with its enclosing function, or with the declaring
// keyword (var, const) for a package-level initializer. A timer is
// matched under the name the file imports "time" as (timeName), so an
// aliased or dot import is seen too; each is reported as time.<Func>.
func goroutineStarts(f *ast.File) []string {
	prefixes := timeNames(f)
	var got []string
	for _, d := range f.Decls {
		where := ""
		switch d := d.(type) {
		case *ast.FuncDecl:
			where = d.Name.Name
		case *ast.GenDecl:
			where = d.Tok.String()
		}
		ast.Inspect(d, func(n ast.Node) bool {
			switch n := n.(type) {
			case *ast.GoStmt:
				got = append(got, where+": go "+callee(n.Call.Fun))
			case *ast.CallExpr:
				c := callee(n.Fun)
				for _, prefix := range prefixes {
					switch fn := strings.TrimPrefix(c, prefix); {
					case !strings.HasPrefix(c, prefix):
					case fn == "AfterFunc", fn == "NewTicker", fn == "Tick":
						got = append(got, where+": time."+fn)
					}
				}
			}
			return true
		})
	}
	return got
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

// timeNames lists every qualifier a call into package time carries in f,
// one per import of "time": "time." or "<alias>." for a named import, ""
// for a dot import. Go allows a file to import "time" more than once
// under different names, so each import counts (L3 fix-list 1 on #5681).
// A blank import adds nothing; with no list, no call in f starts a timer.
func timeNames(f *ast.File) []string {
	seen := map[string]bool{}
	var names []string
	for _, imp := range f.Imports {
		if imp.Path.Value != `"time"` {
			continue
		}
		name := "time."
		if imp.Name != nil {
			switch imp.Name.Name {
			case "_":
				continue
			case ".":
				name = ""
			default:
				name = imp.Name.Name + "."
			}
		}
		if !seen[name] {
			seen[name] = true
			names = append(names, name)
		}
	}
	return names
}
