package main

// REQ: HW-8, OWN-17

import (
	"bytes"
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/control"
	"github.com/ghbmrk/agentos/broker/daemon"
)

// wipeWiring is main's statement that puts the failed-wipe note in STATUS
// (MOR-wipe-owner, #6094).
const wipeWiring = "cfg.Notes = append(cfg.Notes, wipeNote(wipeFailed))"

// mainStatements is main.go's func main body, each top-level statement
// printed, with the position of the daemon.Run call among them.
func mainStatements(t *testing.T) (stmts []string, run int) {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "main.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	run = -1
	for _, d := range f.Decls {
		fn, ok := d.(*ast.FuncDecl)
		if !ok || fn.Recv != nil || fn.Name.Name != "main" {
			continue
		}
		for i, s := range fn.Body.List {
			var b bytes.Buffer
			if err := printer.Fprint(&b, fset, s); err != nil {
				t.Fatal(err)
			}
			stmts = append(stmts, b.String())
			if strings.Contains(b.String(), "daemon.Run(ctx, cfg)") {
				if run >= 0 {
					t.Fatalf("main calls daemon.Run at statements %d and %d", run, i)
				}
				run = i
			}
		}
	}
	if run < 0 {
		t.Fatal("main.go: no func main calling daemon.Run(ctx, cfg)")
	}
	return stmts, run
}

// MOR-wipe-status-e2e (#6127): agentosd's own wiring puts a failed wipe in
// STATUS. main itself needs root, the box's sockets and its units, so no
// test runs it; this one pins main's statement in its parsed body
// (unconditional, once, before daemon.Run copies the notes) and then asks
// STATUS, as the owner's channel does, with that statement's note over
// the shipped record paths moved into a temp root. It fails when the
// statement is removed, moved under a branch or after daemon.Run, or
// given other paths.
func TestMainWiresTheWipeNoteIntoStatus(t *testing.T) {
	stmts, run := mainStatements(t)
	at := -1
	for i, s := range stmts {
		if s == wipeWiring {
			if at >= 0 {
				t.Fatalf("main wires the wipe note at statements %d and %d", at, i)
			}
			at = i
		}
	}
	if at < 0 {
		t.Fatalf("main's body has no top-level %q", wipeWiring)
	}
	if at > run {
		t.Fatalf("main wires the wipe note at statement %d, after daemon.Run at %d", at, run)
	}
	for i, s := range stmts {
		if i != at && strings.Contains(s, "wipeNote(") {
			t.Fatalf("main also builds a wipe note at statement %d: %s", i, s)
		}
	}

	// The shipped records, under a temp root.
	root := t.TempDir()
	shipped := wipeFailed
	t.Cleanup(func() { wipeFailed = shipped })
	wipeFailed = nil
	for _, p := range shipped {
		wipeFailed = append(wipeFailed, filepath.Join(root, p))
		if err := os.MkdirAll(filepath.Dir(wipeFailed[len(wipeFailed)-1]), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	cfg := daemon.Config{}
	// main's statement, as pinned above.
	cfg.Notes = append(cfg.Notes, wipeNote(wipeFailed))
	h := &control.Handler{Engine: statusEngine{}, Machines: func() string { return "" }, Notes: cfg.Notes}
	told := func(want bool, when string) {
		t.Helper()
		if got := strings.Contains(h.Status(), wipeFailedLine); got != want {
			t.Fatalf("%s: STATUS has the wipe line %v, want %v:\n%s", when, got, want, h.Status())
		}
	}
	told(false, "no record")
	for _, p := range wipeFailed {
		if err := os.WriteFile(p, []byte("exit-code exited 1\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		told(true, p)
		if err := os.Remove(p); err != nil {
			t.Fatal(err)
		}
		told(false, "after "+p+" is removed")
	}
}
