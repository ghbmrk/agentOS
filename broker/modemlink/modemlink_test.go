package modemlink

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/bridgeproto"
	"github.com/ghbmrk/agentos/broker/modem"
	"github.com/ghbmrk/agentos/broker/sockets"
)

// REQ: CH-1, CH-2, ADP-12

const ownerNum = "+15550000999"

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

func rig(t *testing.T) (*Link, *clock) {
	t.Helper()
	clk := &clock{t: time.Date(2026, 10, 5, 13, 5, 0, 0, time.UTC)}
	l := New(Config{Owner: ownerNum, Now: clk.now, SendWait: 2 * time.Second, PollWait: 200 * time.Millisecond})
	call(t, l, bridgeproto.OpState, bridgeproto.State{OwnerLine: bridgeproto.StateOK}, nil)
	return l, clk
}

func call(t *testing.T, l *Link, op string, args, out any) error {
	t.Helper()
	b, _ := json.Marshal(args)
	res, err := l.Ops()[op](context.Background(), sockets.Peer{Kind: "owner"}, b)
	if err == nil && out != nil {
		raw, _ := json.Marshal(res)
		if err := json.Unmarshal(raw, out); err != nil {
			t.Fatal(err)
		}
	}
	return err
}

// poll pulls the next item, or fails the test after a few polls.
func poll(t *testing.T, l *Link) bridgeproto.Item {
	t.Helper()
	for i := 0; i < 20; i++ {
		var out struct{ Item *bridgeproto.Item }
		if err := call(t, l, bridgeproto.OpOutbox, struct{}{}, &out); err != nil {
			t.Fatal(err)
		}
		if out.Item != nil {
			return *out.Item
		}
	}
	t.Fatal("no outbox item")
	return bridgeproto.Item{}
}

func sendAsync(l *Link, to, text string) chan error {
	done := make(chan error, 1)
	go func() { done <- l.Send(to, text) }()
	return done
}

// P2-3w part 1: the owner channel's texts go out through the bridge's
// outbox, addressed by agentosd, and Send returns the bridge's result.
func TestOwnerTextsGoOutThroughTheOutbox(t *testing.T) {
	l, _ := rig(t)
	done := sendAsync(l, ownerNum, "Box: all well.")
	it := poll(t, l)
	if it.Line != bridgeproto.LineOwner || it.To != ownerNum || it.Text != "Box: all well." {
		t.Fatalf("item %+v", it)
	}
	if err := call(t, l, bridgeproto.OpSent, bridgeproto.Sent{ID: it.ID, Code: bridgeproto.CodeOK}, nil); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatalf("send: %v", err)
	}
	done = sendAsync(l, ownerNum, "second")
	it = poll(t, l)
	call(t, l, bridgeproto.OpSent, bridgeproto.Sent{ID: it.ID, Code: bridgeproto.CodeUnreachable}, nil)
	if err := <-done; !errors.Is(err, modem.ErrDown) {
		t.Fatalf("a failed send: %v", err)
	}
}

// The owner channel texts only the owner (CH-1); the bridge never chooses
// a recipient.
func TestOnlyTheOwnerIsTexted(t *testing.T) {
	l, _ := rig(t)
	if err := l.Send("+15550200001", "hi"); !errors.Is(err, ErrRecipient) {
		t.Fatalf("send to another number: %v", err)
	}
}

// A bridge that never answers makes Send fail as down after SendWait, so
// the channel's existing handling applies (CH-2).
func TestASilentBridgeIsDown(t *testing.T) {
	l, _ := rig(t)
	start := time.Now()
	if err := l.Send(ownerNum, "hi"); !errors.Is(err, modem.ErrDown) {
		t.Fatalf("send with no bridge: %v", err)
	}
	if time.Since(start) < time.Second {
		t.Fatal("send gave up before SendWait")
	}
}

// Security S-B3: item IDs are unguessable and single-use while outstanding;
// unknown or finished IDs are ignored and counted.
func TestSentIDsAreSingleUse(t *testing.T) {
	l, _ := rig(t)
	seen := map[string]bool{}
	for i := 0; i < 3; i++ {
		done := sendAsync(l, ownerNum, "hi")
		it := poll(t, l)
		if len(it.ID) < 32 || seen[it.ID] {
			t.Fatalf("id %q", it.ID)
		}
		seen[it.ID] = true
		call(t, l, bridgeproto.OpSent, bridgeproto.Sent{ID: it.ID, Code: bridgeproto.CodeOK}, nil)
		if err := <-done; err != nil {
			t.Fatal(err)
		}
		call(t, l, bridgeproto.OpSent, bridgeproto.Sent{ID: it.ID, Code: bridgeproto.CodeOK}, nil)
	}
	call(t, l, bridgeproto.OpSent, bridgeproto.Sent{ID: "guess", Code: bridgeproto.CodeOK}, nil)
	if n := l.Stray(); n != 4 {
		t.Fatalf("stray results counted %d, want 4", n)
	}
	if err := call(t, l, bridgeproto.OpSent, bridgeproto.Sent{ID: "x", Code: "made up"}, nil); err == nil {
		t.Fatal("an unknown code was taken")
	}
}

// Security S-B4: inbound texts are bounded, agentosd stamps its own
// receive time, and a named sender is never the owner.
func TestInboundTextsAreCheckedAndStamped(t *testing.T) {
	l, clk := rig(t)
	for _, in := range []bridgeproto.Inbound{
		{Line: bridgeproto.LineOwner, From: ownerNum, Text: strings.Repeat("a", bridgeproto.MaxText+1)},
		{Line: bridgeproto.LineOwner, From: "+1555 0000999", Text: "STATUS"},
		{Line: bridgeproto.LineOwner, From: strings.Repeat("9", bridgeproto.MaxFrom+1), Text: "STATUS"},
		{Line: bridgeproto.LineOwner, From: "Bank\x07", Text: "STATUS", Named: true},
		{Line: "third", From: ownerNum, Text: "STATUS"},
	} {
		if err := call(t, l, bridgeproto.OpInbound, in, nil); err == nil {
			t.Errorf("%+v was taken", in)
		}
	}
	clk.add(time.Minute)
	for _, in := range []bridgeproto.Inbound{
		{Line: bridgeproto.LineOwner, From: ownerNum, Text: "STATUS"},
		{Line: bridgeproto.LineOwner, From: ownerNum, Text: strings.Repeat("é", bridgeproto.MaxText/2)},
		{Line: bridgeproto.LineOwner, From: "MyBank", Text: "code 1234", Named: true},
	} {
		if err := call(t, l, bridgeproto.OpInbound, in, nil); err != nil {
			t.Fatalf("%+v: %v", in, err)
		}
		m := <-l.Inbox()
		if m.From != in.From || m.Text != in.Text || m.To != "" && m.To != ownerNum || !m.At.Equal(clk.now()) || m.Alphanumeric != in.Named {
			t.Fatalf("delivered %+v for %+v", m, in)
		}
	}
}

// Security S-B8: the line decides trust. A text on the second line never
// reaches the owner channel, even from the owner's number; a swapped or
// unbound owner line stops the owner channel both ways.
func TestTheLineDecidesTrust(t *testing.T) {
	l, _ := rig(t)
	if err := call(t, l, bridgeproto.OpInbound, bridgeproto.Inbound{Line: bridgeproto.LineSecond, From: ownerNum, Text: "STOP"}, nil); err == nil {
		t.Fatal("a second-line text was taken")
	}
	for _, st := range []string{bridgeproto.StateSwapped, bridgeproto.StateUnbound} {
		call(t, l, bridgeproto.OpState, bridgeproto.State{OwnerLine: st}, nil)
		start := time.Now()
		if err := l.Send(ownerNum, "hi"); !errors.Is(err, modem.ErrDown) || time.Since(start) > time.Second {
			t.Fatalf("%s: send %v after %v", st, err, time.Since(start))
		}
		if err := call(t, l, bridgeproto.OpInbound, bridgeproto.Inbound{Line: bridgeproto.LineOwner, From: ownerNum, Text: "STOP"}, nil); err == nil {
			t.Fatalf("%s: an owner-line text was taken", st)
		}
		var out struct{ Item *bridgeproto.Item }
		call(t, l, bridgeproto.OpOutbox, struct{}{}, &out)
		if out.Item != nil {
			t.Fatalf("%s: outbox handed out %+v", st, out.Item)
		}
	}
	select {
	case m := <-l.Inbox():
		t.Fatalf("delivered %+v", m)
	default:
	}
	if err := call(t, l, bridgeproto.OpState, bridgeproto.State{OwnerLine: "fine"}, nil); err == nil {
		t.Fatal("an unknown state was taken")
	}
}

// Security S-B4: inbound texts are rate limited per minute; past the
// limit they are dropped and noted once.
func TestInboundIsRateLimited(t *testing.T) {
	l, clk := rig(t)
	in := bridgeproto.Inbound{Line: bridgeproto.LineOwner, From: ownerNum, Text: "hi"}
	for i := 0; i < InboundPerMinute; i++ {
		if err := call(t, l, bridgeproto.OpInbound, in, nil); err != nil {
			t.Fatalf("text %d: %v", i+1, err)
		}
		<-l.Inbox()
	}
	if l.Dropped() {
		t.Fatal("dropped under the limit")
	}
	if err := call(t, l, bridgeproto.OpInbound, in, nil); err == nil {
		t.Fatal("a text past the limit was taken")
	}
	if !l.Dropped() {
		t.Fatal("the drop was not noted")
	}
	clk.add(time.Minute)
	if err := call(t, l, bridgeproto.OpInbound, in, nil); err != nil {
		t.Fatalf("after a minute: %v", err)
	}
}

// UX U-B1, U-B2: texts that could not go while the owner line was down
// are not replayed; on recovery the owner gets one text with the outage's
// times and a count.
func TestRecoveryTextCountsWhatWasNotSent(t *testing.T) {
	l, clk := rig(t)
	call(t, l, bridgeproto.OpState, bridgeproto.State{OwnerLine: bridgeproto.StateDown}, nil)
	for i := 0; i < 3; i++ {
		if err := l.Send(ownerNum, "approve? code 1234"); !errors.Is(err, modem.ErrDown) {
			t.Fatalf("send while down: %v", err)
		}
		clk.add(30 * time.Minute)
	}
	clk.add(45 * time.Minute)
	call(t, l, bridgeproto.OpState, bridgeproto.State{OwnerLine: bridgeproto.StateOK}, nil)
	it := poll(t, l)
	want := "I couldn't text you from 13:05 to 15:20. 3 texts weren't sent; see my Wi-Fi page."
	if it.Text != want || it.To != ownerNum {
		t.Fatalf("recovery text %q, want %q", it.Text, want)
	}
	call(t, l, bridgeproto.OpSent, bridgeproto.Sent{ID: it.ID, Code: bridgeproto.CodeOK}, nil)
	var out struct{ Item *bridgeproto.Item }
	call(t, l, bridgeproto.OpOutbox, struct{}{}, &out)
	if out.Item != nil {
		t.Fatalf("replayed %+v", out.Item)
	}
	if n := l.LastOutage(); n.Missed != 3 {
		t.Fatalf("outage %+v", n)
	}
	// An outage that cost nothing sends nothing.
	call(t, l, bridgeproto.OpState, bridgeproto.State{OwnerLine: bridgeproto.StateDown}, nil)
	call(t, l, bridgeproto.OpState, bridgeproto.State{OwnerLine: bridgeproto.StateOK}, nil)
	call(t, l, bridgeproto.OpOutbox, struct{}{}, &out)
	if out.Item != nil {
		t.Fatalf("sent %+v after an outage that cost nothing", out.Item)
	}
}

// UX U-B1, U-B3, U-B4: the owner line's state is a fixed line for the box's
// local page, empty while the line is fine; a bridge that stops reporting
// reads as down.
func TestOwnerLineNoteForTheLocalPage(t *testing.T) {
	l, clk := rig(t)
	if n := l.OwnerLineNote(); n != "" {
		t.Fatalf("note while ok: %q", n)
	}
	for st, want := range map[string]string{
		bridgeproto.StateDown:    "I can't reach my phone modem. Check it's plugged in.",
		bridgeproto.StateSwapped: "The SIM in my phone modem changed. Texts to and from you are paused until you confirm it on my Wi-Fi page.",
		bridgeproto.StateUnbound: "My phone modem has no SIM, or its number isn't set up. Set it up on my Wi-Fi page.",
	} {
		call(t, l, bridgeproto.OpState, bridgeproto.State{OwnerLine: st}, nil)
		if n := l.OwnerLineNote(); n != want {
			t.Errorf("%s: %q", st, n)
		}
	}
	call(t, l, bridgeproto.OpState, bridgeproto.State{OwnerLine: bridgeproto.StateOK}, nil)
	clk.add(Silent + time.Second)
	if n := l.OwnerLineNote(); !strings.HasPrefix(n, "I can't reach my phone modem.") {
		t.Fatalf("silent bridge: %q", n)
	}
	if err := l.Send(ownerNum, "hi"); !errors.Is(err, modem.ErrDown) {
		t.Fatalf("send to a silent bridge: %v", err)
	}
}

// A poll that began before an outage may be a dead bridge's connection:
// it is handed nothing after the line recovers, so the recovery text goes
// to the bridge that came back.
func TestAPollFromBeforeAnOutageGetsNothing(t *testing.T) {
	l, clk := rig(t)
	stale := make(chan *bridgeproto.Item, 1)
	go func() {
		var out struct{ Item *bridgeproto.Item }
		call(t, l, bridgeproto.OpOutbox, struct{}{}, &out)
		stale <- out.Item
	}()
	time.Sleep(20 * time.Millisecond)
	clk.add(time.Second)
	call(t, l, bridgeproto.OpState, bridgeproto.State{OwnerLine: bridgeproto.StateDown}, nil)
	l.Send(ownerNum, "lost")
	clk.add(time.Minute)
	call(t, l, bridgeproto.OpState, bridgeproto.State{OwnerLine: bridgeproto.StateOK}, nil)
	if it := <-stale; it != nil {
		t.Fatalf("a stale poll took %+v", it)
	}
	if it := poll(t, l); !strings.HasPrefix(it.Text, "I couldn't text you") {
		t.Fatalf("got %+v", it)
	}
}
