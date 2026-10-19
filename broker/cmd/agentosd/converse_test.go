package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/binary"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/control"
	"github.com/ghbmrk/agentos/broker/daemon"
	"github.com/ghbmrk/agentos/broker/loops"
	ownerch "github.com/ghbmrk/agentos/broker/owner"
)

// REQ: CH-15
// An agent reply from the evidence outbox, wired by wireOwner as attach
// wires it, is conversation: in quiet hours and with the hour's texts
// spent it goes at once behind the agent prefix, and with no owner
// channel yet it fails rather than sends. The source check pins that
// attach wires through wireOwner and that nothing else sets e.notify, so
// reverting attach to the paced Notify fails here.
func TestAgentReplyIsConversation(t *testing.T) {
	r := pacedOwner(t, quiet22to7(), at23)
	for i := 0; i < ownerch.DefaultTextsPerHour; i++ {
		if err := r.ch.Post(ownerch.ClassSecurity, "Alert."); err != nil {
			t.Fatal(err)
		}
	}
	r.sent()
	ev := &evidence{logf: t.Logf}
	ev.wireOwner(func() *ownerch.Channel { return r.ch })
	ev.send("agent", "Your invoice is drafted.")
	if got := r.sent(); len(got) != 1 || got[0] != ownerch.AgentPrefix+"Your invoice is drafted." {
		t.Fatalf("agent reply in quiet hours past the allowance: %q, want it sent at once", got)
	}
	ev.wireOwner(func() *ownerch.Channel { return nil })
	if err := ev.notify("x"); err == nil || !strings.Contains(err.Error(), "no owner channel") {
		t.Fatalf("no channel: %v", err)
	}
	if bad := notifyWiring(t); len(bad) != 0 {
		t.Fatalf("reply wiring: %v", bad)
	}
}

// notifyWiring checks the package's non-test sources: evidence.attach
// calls e.wireOwner(d.Owner), and only wireOwner assigns a notify field.
func notifyWiring(t *testing.T) []string {
	t.Helper()
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	var bad []string
	wired := false
	fs := token.NewFileSet()
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		src, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		f, err := parser.ParseFile(fs, name, src, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, d := range f.Decls {
			fn, ok := d.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			isEvidence := fn.Recv != nil && strings.Contains(string(src[fs.Position(fn.Recv.Pos()).Offset:fs.Position(fn.Recv.End()).Offset]), "evidence")
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				switch n := n.(type) {
				case *ast.AssignStmt:
					for _, l := range n.Lhs {
						if s, ok := l.(*ast.SelectorExpr); ok && s.Sel.Name == "notify" && !(isEvidence && fn.Name.Name == "wireOwner") {
							bad = append(bad, fs.Position(n.Pos()).String()+": notify set outside wireOwner")
						}
					}
				case *ast.CallExpr:
					if s, ok := n.Fun.(*ast.SelectorExpr); ok && s.Sel.Name == "wireOwner" && isEvidence && fn.Name.Name == "attach" &&
						len(n.Args) == 1 && strings.TrimSpace(string(src[fs.Position(n.Args[0].Pos()).Offset:fs.Position(n.Args[0].End()).Offset])) == "d.Owner" {
						wired = true
					}
				}
				return true
			})
		}
	}
	if !wired {
		bad = append(bad, "evidence.attach does not call e.wireOwner(d.Owner)")
	}
	return bad
}

// REQ: CH-15
// TestCH15AgentReplyInWindowIsConversation: the question book's chat hook,
// wired as questions.open wires it, reads the owner channel's chat window
// with the owner's CHAT setting: an agent question 45 minutes after task
// chat reached the agent is conversation under CHAT 60, and a push once
// the hour has passed. Under the 30-minute default the same 45 minutes is
// a push.
func TestCH15AgentReplyInWindowIsConversation(t *testing.T) {
	for _, tc := range []struct {
		chat int
		open bool
	}{{0, false}, {60, true}} {
		start := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)
		r := pacedOwner(t, ownerch.Pacing{}, start)
		ch, err := ownerch.New(ownerch.Config{
			Owner: ownerNum, Modem: r.box, Engine: pacingEngine{}, Store: &ownerch.MemStore{},
			Agent:    acceptAgent{},
			Secrets:  ownerch.Secrets{TOTPSeed: []byte(chatSeed), GridSeed: []byte("synthetic-grid-seed")},
			Location: time.UTC, Now: r.clock,
		})
		if err != nil {
			t.Fatal(err)
		}
		say := func(s string) string { return strings.Join(ch.Handle(context.Background(), ownerNum, s), " | ") }
		r.set(start.Add(30 * time.Second))
		if got := say(chatCode(r.clock())); !strings.HasPrefix(got, "Unlocked until") {
			t.Fatalf("unlock: %q", got)
		}
		if tc.chat != 0 {
			if got := say(fmt.Sprintf("CHAT %d", tc.chat)); !strings.HasPrefix(got, "Chat set") {
				t.Fatalf("CHAT %d: %q", tc.chat, got)
			}
		}
		chatting := questionChatting(ch)
		if chatting() {
			t.Fatal("chat open before task chat reached the agent")
		}
		say("find me a dentist")
		if !chatting() {
			t.Fatal("chat closed right after task chat reached the agent")
		}
		r.set(r.clock().Add(45 * time.Minute))
		if got := chatting(); got != tc.open {
			t.Fatalf("CHAT %d, 45 minutes on: chat open %v, want %v", tc.chat, got, tc.open)
		}
		r.set(r.clock().Add(16 * time.Minute))
		if chatting() {
			t.Fatalf("CHAT %d: chat open 61 minutes on", tc.chat)
		}
	}
}

// acceptAgent is an agent that takes every delivery.
type acceptAgent struct{}

func (acceptAgent) Deliver(context.Context, string, bool) error { return nil }

const chatSeed = "12345678901234567890"

// chatCode is the owner's code-generator code at t (RFC 6238, 30 s, 6
// digits), from the synthetic seed.
func chatCode(t time.Time) string {
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], uint64(t.Unix()/30))
	m := hmac.New(sha1.New, []byte(chatSeed))
	m.Write(msg[:])
	sum := m.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	return fmt.Sprintf("%06d", (binary.BigEndian.Uint32(sum[off:off+4])&0x7fffffff)%1_000_000)
}

// REQ: CH-15, OWN-4
// HELP as agentosd sends it, with the learning line (on or off) and RENEW
// wired as main wires them, fits one owner text uncut and names CHAT
// (combined F1 on #2390): a check on the pacing constant alone missed that
// CHAT never reached the owner. Fit cuts every reply to control.MaxText, so
// a length check cannot fail; the reply is whole only if it still ends with
// the pacing line's last item, which is HELP's last piece.
func TestCH15HelpNamesChatUncut(t *testing.T) {
	for _, learning := range []bool{true, false} {
		var dc daemon.Config
		if learning {
			dc.HelpExtra = loops.HelpLine
		} else {
			learningOff(&dc)
		}
		(&ownerRenew{now: time.Now}).wire(&dc)
		r := pacedOwner(t, ownerch.Pacing{}, at23)
		ch, err := ownerch.New(ownerch.Config{
			Owner: ownerNum, Modem: r.box, Engine: pacingEngine{}, Store: &ownerch.MemStore{},
			Agent: acceptAgent{}, HelpExtra: dc.HelpExtra,
			Secrets:  ownerch.Secrets{TOTPSeed: []byte(chatSeed), GridSeed: []byte("synthetic-grid-seed")},
			Location: time.UTC, Now: r.clock,
		})
		if err != nil {
			t.Fatal(err)
		}
		got := ch.Handle(context.Background(), ownerNum, "HELP")
		if len(got) != 1 || len(got[0]) > control.MaxText || !strings.HasSuffix(got[0], "ACK 5.") {
			t.Fatalf("learning %v: HELP is not one whole text (cut at %d bytes): %q", learning, control.MaxText, got)
		}
		for _, word := range []string{"STOP", "RESUME", "STATUS", "YES", "NO", "UNDO", "MORE", "NAME", "PUBLIC",
			"LOOPS", "HELP LOOPS", "RENEW", "QUIET", "TEXTS", "URGENT", "CHAT 30", "ACK 5"} {
			if !learning && (word == "LOOPS" || word == "HELP LOOPS") {
				word = "Spare-time"
			}
			if !strings.Contains(got[0], word) {
				t.Fatalf("learning %v: HELP (%d bytes) lacks %s: %q", learning, len(got[0]), word, got[0])
			}
		}
	}
}
