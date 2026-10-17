package modemlink

import (
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/bridgeproto"
	"github.com/ghbmrk/agentos/broker/modem"
)

// quick is rig with a short SendWait, for the timeout cases.
func quick(t *testing.T) *Link {
	t.Helper()
	clk := &clock{t: time.Date(2026, 10, 5, 13, 5, 0, 0, time.UTC)}
	l := New(Config{Owner: ownerNum, Now: clk.now, SendWait: 150 * time.Millisecond, PollWait: 50 * time.Millisecond})
	call(t, l, bridgeproto.OpState, bridgeproto.State{OwnerLine: bridgeproto.StateOK}, nil)
	return l
}

type receipted struct {
	r   Receipt
	err error
}

func receiptAsync(l *Link, text string) chan receipted {
	done := make(chan receipted, 1)
	go func() { r, err := l.SendReceipt(ownerNum, text); done <- receipted{r, err} }()
	return done
}

// REQ: OP-2 (W5-Db DB-3)
func TestSendReceiptOKCarriesID(t *testing.T) {
	l, _ := rig(t)
	done := receiptAsync(l, "Digest.")
	it := poll(t, l)
	call(t, l, bridgeproto.OpSent, bridgeproto.Sent{ID: it.ID, Code: bridgeproto.CodeOK}, nil)
	got := <-done
	if got.err != nil || got.r.Outcome != ReceiptAccepted || got.r.Evidence != it.ID || got.r.Code != bridgeproto.CodeOK {
		t.Fatalf("%+v", got)
	}
}

// REQ: OP-2 (W5-Db DB-3)
func TestSendReceiptRefusedBeforeQueueIsNotSent(t *testing.T) {
	l, _ := rig(t)
	if r, err := l.SendReceipt("+15550200001", "Digest."); !errors.Is(err, ErrRecipient) || r.Outcome != ReceiptNotSent || r.Evidence == "" {
		t.Fatalf("wrong recipient: %+v %v", r, err)
	}
	call(t, l, bridgeproto.OpState, bridgeproto.State{OwnerLine: bridgeproto.StateDown}, nil)
	if r, err := l.SendReceipt(ownerNum, "Digest."); !errors.Is(err, modem.ErrNotSent) || r.Outcome != ReceiptNotSent || r.Evidence == "" {
		t.Fatalf("line down: %+v %v", r, err)
	}
	l, _ = rig(t)
	for i := 0; i < MaxQueued; i++ {
		sendAsync(l, ownerNum, "hi")
	}
	time.Sleep(100 * time.Millisecond)
	if r, err := l.SendReceipt(ownerNum, "Digest."); !errors.Is(err, modem.ErrNotSent) || r.Outcome != ReceiptNotSent {
		t.Fatalf("queue full: %+v %v", r, err)
	}
}

// REQ: OP-2 (W5-Db DB-3)
func TestSendReceiptTimeoutBeforeHandIsNotSent(t *testing.T) {
	l := quick(t)
	r, err := l.SendReceipt(ownerNum, "Digest.")
	if !errors.Is(err, modem.ErrNotSent) || r.Outcome != ReceiptNotSent || !strings.HasPrefix(r.Evidence, "not-handed:") {
		t.Fatalf("%+v %v", r, err)
	}
	if l.TimedOut() != 1 {
		t.Fatal("timeout not counted", l.TimedOut())
	}
	// The dropped text is never handed out later.
	var out struct{ Item *bridgeproto.Item }
	call(t, l, bridgeproto.OpOutbox, struct{}{}, &out)
	if out.Item != nil {
		t.Fatal("a not-sent text was handed out", out.Item)
	}
}

// REQ: OP-2 (W5-Db DB-3)
func TestSendReceiptTimeoutAfterHandIsUnknown(t *testing.T) {
	l := quick(t)
	done := receiptAsync(l, "Digest.")
	it := poll(t, l)
	got := <-done
	if !errors.Is(got.err, modem.ErrDown) || errors.Is(got.err, modem.ErrNotSent) || got.r.Outcome != ReceiptUnknown || got.r.Evidence != it.ID {
		t.Fatalf("%+v", got)
	}
}

// REQ: OP-2 (W5-Db DB-3)
// The first timer fires while the item is queued, but the outbox takes it
// before the timeout path gets mu: it was handed, so the receipt is unknown.
// Pins the under-mu queued check (L3 #1, Security F1 on #573).
func TestSendReceiptTimeoutRacingHandIsUnknown(t *testing.T) {
	l := quick(t)
	done := receiptAsync(l, "Digest.")
	for {
		l.mu.Lock()
		if len(l.queue) == 1 {
			break
		}
		l.mu.Unlock()
		time.Sleep(time.Millisecond)
	}
	time.Sleep(300 * time.Millisecond) // SendWait passes; deliver blocks on mu
	it := l.queue[0]                   // what outbox does under mu
	l.queue = l.queue[1:]
	l.out[it.ID] = it
	close(it.handed)
	l.mu.Unlock()
	if got := <-done; got.r.Outcome != ReceiptUnknown || got.r.Evidence != it.ID {
		t.Fatalf("handed text reported %+v", got)
	}
}

// REQ: OP-2 (W5-Db DB-3)
// CodeRecipient is the bridge refusing the item before any modem call (see
// TestRecipientCodeOnlyBeforeModemSend); every other failure code may follow
// a modem attempt, so it proves nothing.
func TestSendReceiptRecipientIsNotSent(t *testing.T) {
	l, _ := rig(t)
	done := receiptAsync(l, "Digest.")
	it := poll(t, l)
	call(t, l, bridgeproto.OpSent, bridgeproto.Sent{ID: it.ID, Code: bridgeproto.CodeRecipient}, nil)
	got := <-done
	if !errors.Is(got.err, modem.ErrNotSent) || got.r.Outcome != ReceiptNotSent || got.r.Evidence != "recipient:"+it.ID {
		t.Fatalf("%+v", got)
	}
}

// REQ: OP-2 (W5-Db DB-3)
func TestSendReceiptOtherCodesAreUnknown(t *testing.T) {
	for _, code := range []string{bridgeproto.CodeDown, bridgeproto.CodeUnreachable, bridgeproto.CodeLimited,
		bridgeproto.CodeRefused, bridgeproto.CodeTooLong} {
		l, _ := rig(t)
		done := receiptAsync(l, "Digest.")
		it := poll(t, l)
		call(t, l, bridgeproto.OpSent, bridgeproto.Sent{ID: it.ID, Code: code}, nil)
		got := <-done
		if !errors.Is(got.err, modem.ErrDown) || errors.Is(got.err, modem.ErrNotSent) || got.r.Outcome != ReceiptUnknown || got.r.Evidence != it.ID || got.r.Code != code {
			t.Fatalf("%s: %+v", code, got)
		}
	}
	if receiptOf("item", "no-such-code").Outcome != ReceiptUnknown {
		t.Fatal("an unknown code proved something")
	}
}

// REQ: OP-2 (W5-Db DB-3)
// The proof behind CodeRecipient => not sent, pinned against drift: in
// production the bridge emits CodeRecipient only for a non-owner item, before
// calling the modem, or by mapping at.ErrNumber, which only Dial returns, never
// Send. Every non-test file of both packages is scanned, so a new file cannot
// move either use out of sight. If this fails, re-prove and update
// ASSUMPTIONS.md.
func TestRecipientCodeOnlyBeforeModemSend(t *testing.T) {
	at := pkgFuncs(t, "../modem/at")
	bridge := pkgFuncs(t, "../modem/bridge")
	if got := identUses(at, "ErrNumber"); len(got) != 1 || got["Dial"] == 0 {
		t.Fatalf("at.ErrNumber returned outside Dial: %v", got)
	}
	// Dial's own name is its one use: no call, method value or method
	// expression in at can route ErrNumber into Send.
	if got := identUses(at, "Dial"); len(got) != 1 || got["Dial"] != 1 {
		t.Fatalf("at refers to Dial, so ErrNumber may reach Send: %v", got)
	}
	if got := identUses(bridge, "CodeRecipient"); len(got) != 2 || got["outbox"] != 1 || got["codeOf"] != 1 {
		t.Fatalf("bridge emits CodeRecipient elsewhere: %v", got)
	}
	outbox := bridge["outbox"].(*ast.FuncDecl)
	var assign, send token.Pos
	var sendGuarded bool
	var walk func(n ast.Node, guarded bool)
	walk = func(n ast.Node, guarded bool) {
		ast.Inspect(n, func(n ast.Node) bool {
			switch n := n.(type) {
			case *ast.IfStmt:
				if n.Init != nil {
					walk(n.Init, guarded)
				}
				walk(n.Cond, guarded)
				walk(n.Body, guarded || isOwnerLine(n.Cond))
				if n.Else != nil {
					walk(n.Else, guarded)
				}
				return false
			case *ast.AssignStmt:
				for _, r := range n.Rhs {
					if sel, ok := r.(*ast.SelectorExpr); ok && sel.Sel.Name == "CodeRecipient" {
						assign = n.Pos()
					}
				}
			case *ast.CallExpr:
				if sel, ok := n.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "Send" {
					if send != token.NoPos {
						t.Fatal("outbox sends twice")
					}
					send, sendGuarded = n.Pos(), guarded
				}
			}
			return true
		})
	}
	walk(outbox.Body, false)
	if assign == token.NoPos || send == token.NoPos || assign > send || !sendGuarded {
		t.Fatalf("outbox no longer sets CodeRecipient before an owner-line-only m.Send (assign %v, send %v, guarded %v)", assign, send, sendGuarded)
	}
}

// pkgFuncs parses every non-test Go file in dir and returns its functions by
// name, plus its package-level initialisers. Each file goes through parser.ParseFile: parser.ParseDir is deprecated
// and would add nothing here.
func pkgFuncs(t *testing.T, dir string) map[string]ast.Node {
	t.Helper()
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	fns := map[string]ast.Node{}
	for _, e := range ents {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, filepath.Join(dir, name), nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, decl := range f.Decls {
			switch d := decl.(type) {
			case *ast.FuncDecl:
				key := d.Name.Name
				if fns[key] != nil {
					key = name + ":" + key // same name on two receivers
				}
				fns[key] = d
			case *ast.GenDecl:
				// Package-level initialisers can alias Dial or ErrNumber too;
				// the declared names themselves are not uses.
				for _, spec := range d.Specs {
					if vs, ok := spec.(*ast.ValueSpec); ok {
						for i, v := range vs.Values {
							fns[fmt.Sprintf("%s:var%d.%d", name, fset.Position(vs.Pos()).Line, i)] = v
						}
					}
				}
			}
		}
	}
	if len(fns) == 0 {
		t.Fatalf("no functions found in %s", dir)
	}
	return fns
}

// identUses counts ident in each function (name, signature, body) and
// package-level initialiser.
func identUses(fns map[string]ast.Node, ident string) map[string]int {
	in := map[string]int{}
	for name, fn := range fns {
		if n := countIdent(fn, ident); n > 0 {
			in[name] = n
		}
	}
	return in
}

// isOwnerLine reports whether cond is exactly `<x>.Line == <pkg>.LineOwner`,
// so a flipped or widened guard does not pass as the owner-line check.
func isOwnerLine(cond ast.Expr) bool {
	b, ok := cond.(*ast.BinaryExpr)
	if !ok || b.Op != token.EQL {
		return false
	}
	sel := func(e ast.Expr, name string) bool {
		s, ok := e.(*ast.SelectorExpr)
		return ok && s.Sel.Name == name
	}
	return (sel(b.X, "Line") && sel(b.Y, "LineOwner")) || (sel(b.X, "LineOwner") && sel(b.Y, "Line"))
}

func countIdent(n ast.Node, ident string) int {
	c := 0
	ast.Inspect(n, func(n ast.Node) bool {
		if id, ok := n.(*ast.Ident); ok && id.Name == ident {
			c++
		}
		return true
	})
	return c
}
