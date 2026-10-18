package main

import (
	"context"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/bridgeproto"
	"github.com/ghbmrk/agentos/broker/change"
	"github.com/ghbmrk/agentos/broker/digestqueue"
	"github.com/ghbmrk/agentos/broker/modemlink"
	"github.com/ghbmrk/agentos/broker/sockets"
)

// REQ: CH-1 (#1291, #2170). A temporary change to the digest sender that
// lasts only until DIG-RM-b deletes the digest (D-097, DIG-RM).

// TestDigestWaitsForTheOwnerLine: a digest due while the owner line is
// down is not handed to the transport; it stays Ready, costing no
// attempt, and goes at the first step after the line is back, once.
func TestDigestWaitsForTheOwnerLine(t *testing.T) {
	r := newDigestRig(t, &change.MemStore{}, nil)
	// The line comes back at 08:41, between two 30-minute retries: the
	// first step after it sends, not the next retry.
	up := day0.Add(8*time.Hour + 41*time.Minute)
	r.down = func() bool { return r.now.Before(up) }
	r.at(0, 8, 0)
	r.at(0, 8, 30)
	r.at(0, 8, 40)
	if got := r.tr.sent(); len(got) != 0 {
		t.Fatalf("sent with the line down: %q", got)
	}
	if bs := r.batches(); len(bs) != 1 || bs[0].State != digestqueue.Ready || bs[0].Attempts != 0 {
		t.Fatalf("batches with the line down: %+v", bs)
	}
	r.at(0, 8, 41)
	if got := r.tr.sent(); len(got) != 1 || !strings.HasPrefix(got[0], fmt.Sprintf(digestHead, "Mon 5 Oct")) {
		t.Fatalf("once the line is back: %q", got)
	}
	r.at(0, 8, 42)
	r.at(0, 12, 0)
	if got := r.tr.sent(); len(got) != 1 {
		t.Fatalf("sent again: %q", got)
	}
}

// TestDigestAtBootLeavesNoRecoveryNotice: over a real modem link, as main
// wires it, a digest due before the bridge's first state report is not
// counted as a missed text, so the line's first OK report queues no
// recovery notice (#1291's acceptance via #2170: a phone-control run after
// setup passes over none). Without LineDown the same boot queues one,
// which is what main's image runs showed (texts=1, via the digest sender).
func TestDigestAtBootLeavesNoRecoveryNotice(t *testing.T) {
	for _, wired := range []bool{true, false} {
		t.Run(fmt.Sprintf("wired=%v", wired), func(t *testing.T) {
			link := modemlink.New(modemlink.Config{Owner: "+15550100001", SendWait: 50 * time.Millisecond})
			r := &digestRig{t: t, now: day0.Add(7 * time.Hour), queue: &change.MemStore{}, state: &change.MemStore{}, tr: &fakeDigestTransport{}}
			r.make(nil)
			r.d.cfg.Transport = newDigestTransport(link, "+15550100001")
			if wired {
				r.d.cfg.LineDown = digestLineDown(link)
			}
			r.d.open(context.Background())
			r.at(0, 8, 0) // due at boot, the bridge not yet reporting
			report(t, link, bridgeproto.StateOK)
			want := 0
			if !wired {
				want = 1
			}
			if got := link.Queued(); got != want {
				t.Fatalf("queued after the first OK report: %d, want %d", got, want)
			}
		})
	}
}

// TestDigestLineDownFollowsTheLink: the digest reads the line as down
// before any report, up once the bridge reports OK, and down again on any
// other state.
func TestDigestLineDownFollowsTheLink(t *testing.T) {
	link := modemlink.New(modemlink.Config{Owner: "+15550100001"})
	down := digestLineDown(link)
	if !down() {
		t.Fatal("up before the bridge's first state report")
	}
	report(t, link, bridgeproto.StateOK)
	if down() {
		t.Fatal("down after an OK report")
	}
	for _, st := range []string{bridgeproto.StateDown, bridgeproto.StateSwapped, bridgeproto.StateUnbound} {
		report(t, link, st)
		if !down() {
			t.Errorf("up after a %s report", st)
		}
		report(t, link, bridgeproto.StateOK)
	}
}

// report sends link a state report as the bridge does.
func report(t *testing.T, link *modemlink.Link, st string) {
	t.Helper()
	args, err := json.Marshal(bridgeproto.State{OwnerLine: st})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := link.Ops()[bridgeproto.OpState](context.Background(), sockets.Peer{}, args); err != nil {
		t.Fatalf("state %s: %v", st, err)
	}
}

// lineDownWired checks main's source: each block that gives a digest
// box its owner-line transport, `X.cfg.Transport = newDigestTransport(L,
// …)`, also sets `X.cfg.LineDown = digestLineDown(L)` for the same box and
// link, so the wait above cannot be unwired without failing CI.
func lineDownWired(src string) error {
	f, err := parser.ParseFile(token.NewFileSet(), "main.go", src, 0)
	if err != nil {
		return err
	}
	// cfgSet returns the box and the call's first argument of `X.cfg.<field>
	// = fn(L, …)`, or "" when s is not that.
	cfgSet := func(s ast.Stmt, field, fn string) (box, link string) {
		as, ok := s.(*ast.AssignStmt)
		if !ok || len(as.Lhs) != 1 || len(as.Rhs) != 1 || as.Tok != token.ASSIGN {
			return "", ""
		}
		sel, ok := as.Lhs[0].(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != field {
			return "", ""
		}
		cfg, ok := sel.X.(*ast.SelectorExpr)
		if !ok || cfg.Sel.Name != "cfg" {
			return "", ""
		}
		x, ok := cfg.X.(*ast.Ident)
		call, ok2 := as.Rhs[0].(*ast.CallExpr)
		if !ok || !ok2 || len(call.Args) == 0 {
			return "", ""
		}
		name, ok := call.Fun.(*ast.Ident)
		arg, ok2 := call.Args[0].(*ast.Ident)
		if !ok || !ok2 || name.Name != fn {
			return "", ""
		}
		return x.Name, arg.Name
	}
	transports := 0
	var bad error
	ast.Inspect(f, func(n ast.Node) bool {
		b, ok := n.(*ast.BlockStmt)
		if !ok {
			return true
		}
		for _, s := range b.List {
			box, link := cfgSet(s, "Transport", "newDigestTransport")
			if box == "" {
				continue
			}
			transports++
			wired := false
			for _, o := range b.List {
				if ob, ol := cfgSet(o, "LineDown", "digestLineDown"); ob == box && ol == link {
					wired = true
				}
			}
			if !wired && bad == nil {
				bad = fmt.Errorf("%s.cfg.Transport is set over %s with no %s.cfg.LineDown = digestLineDown(%s) beside it", box, link, box, link)
			}
		}
		return true
	})
	if bad == nil && transports == 0 {
		bad = fmt.Errorf("no digest transport is set")
	}
	return bad
}

// TestDigestLineDownIsWired: main sets the digest's LineDown over the
// same link as its transport, and the check fails each unwiring mutant:
// the line deleted, read over another link, or set on another box.
func TestDigestLineDownIsWired(t *testing.T) {
	b, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	src := string(b)
	if err := lineDownWired(src); err != nil {
		t.Fatalf("main.go: %v", err)
	}
	const wire = "dg.cfg.LineDown = digestLineDown(link)"
	if strings.Count(src, wire) != 1 {
		t.Fatalf("main.go has %d copies of %q, want 1", strings.Count(src, wire), wire)
	}
	for name, to := range map[string]string{
		"deleted":    "",
		"nil":        "dg.cfg.LineDown = nil",
		"other box":  "other.cfg.LineDown = digestLineDown(link)",
		"other link": "dg.cfg.LineDown = digestLineDown(spare)",
		"never down": "dg.cfg.LineDown = func() bool { return false }",
	} {
		if err := lineDownWired(strings.Replace(src, wire, to, 1)); err == nil {
			t.Errorf("mutant %s passed", name)
		}
	}
}
