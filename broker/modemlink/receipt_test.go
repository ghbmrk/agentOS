package modemlink

import (
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
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
	if r, err := l.SendReceipt(ownerNum, "Digest."); !errors.Is(err, modem.ErrDown) || r.Outcome != ReceiptNotSent || r.Evidence == "" {
		t.Fatalf("line down: %+v %v", r, err)
	}
	l, _ = rig(t)
	for i := 0; i < MaxQueued; i++ {
		sendAsync(l, ownerNum, "hi")
	}
	time.Sleep(100 * time.Millisecond)
	if r, err := l.SendReceipt(ownerNum, "Digest."); !errors.Is(err, modem.ErrDown) || r.Outcome != ReceiptNotSent {
		t.Fatalf("queue full: %+v %v", r, err)
	}
}

// REQ: OP-2 (W5-Db DB-3)
func TestSendReceiptTimeoutBeforeHandIsNotSent(t *testing.T) {
	l := quick(t)
	r, err := l.SendReceipt(ownerNum, "Digest.")
	if !errors.Is(err, modem.ErrDown) || r.Outcome != ReceiptNotSent || !strings.HasPrefix(r.Evidence, "not-handed:") {
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
	if !errors.Is(got.err, modem.ErrDown) || got.r.Outcome != ReceiptUnknown || got.r.Evidence != it.ID {
		t.Fatalf("%+v", got)
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
	if !errors.Is(got.err, modem.ErrDown) || got.r.Outcome != ReceiptNotSent || got.r.Evidence != "recipient:"+it.ID {
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
		if !errors.Is(got.err, modem.ErrDown) || got.r.Outcome != ReceiptUnknown || got.r.Evidence != it.ID || got.r.Code != code {
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
// Send. If either file changes these, re-prove and update ASSUMPTIONS.md.
func TestRecipientCodeOnlyBeforeModemSend(t *testing.T) {
	uses := func(path, ident string) map[string]int {
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		in := map[string]int{}
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok {
				continue
			}
			ast.Inspect(fn, func(n ast.Node) bool {
				if id, ok := n.(*ast.Ident); ok && id.Name == ident {
					in[fn.Name.Name]++
				}
				return true
			})
		}
		return in
	}
	if got := uses("../modem/at/driver.go", "ErrNumber"); len(got) != 1 || got["Dial"] == 0 {
		t.Fatalf("at.ErrNumber returned outside Dial: %v", got)
	}
	if got := uses("../modem/bridge/bridge.go", "CodeRecipient"); len(got) != 2 || got["outbox"] != 1 || got["codeOf"] != 1 {
		t.Fatalf("bridge emits CodeRecipient elsewhere: %v", got)
	}
}
