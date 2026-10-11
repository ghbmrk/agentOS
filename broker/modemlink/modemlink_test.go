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
	if n := l.TimedOut(); n != 1 {
		t.Fatalf("timed out sends counted %d, want 1", n)
	}
}

// L3 on #170: SendWait covers the slowest send that can still succeed (a
// poll's wait, then three segments at the modem's 60 s each).
func TestSendWaitCoversTheSlowestSend(t *testing.T) {
	if SendWait <= bridgeproto.OutboxWait+3*time.Minute {
		t.Fatalf("SendWait %v", SendWait)
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
// receive time, and only the owner's texts reach the owner channel: a named
// sender is never the owner, whatever it spells.
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
	} {
		if err := call(t, l, bridgeproto.OpInbound, in, nil); err != nil {
			t.Fatalf("%+v: %v", in, err)
		}
		m := <-l.Inbox()
		if m.From != in.From || m.Text != in.Text || m.To != "" && m.To != ownerNum || !m.At.Equal(clk.now()) || m.Alphanumeric != in.Named {
			t.Fatalf("delivered %+v for %+v", m, in)
		}
	}
	for _, in := range []bridgeproto.Inbound{
		{Line: bridgeproto.LineOwner, From: "MyBank", Text: "code 1234", Named: true},
		{Line: bridgeproto.LineOwner, From: ownerNum, Text: "STOP", Named: true},
		{Line: bridgeproto.LineOwner, From: "+15550000123", Text: "STOP"},
	} {
		if err := call(t, l, bridgeproto.OpInbound, in, nil); err != nil {
			t.Fatalf("%+v: %v", in, err)
		}
	}
	select {
	case m := <-l.Inbox():
		t.Fatalf("a text not from the owner was delivered: %+v", m)
	default:
	}
	if n := l.Others(); n != 3 {
		t.Fatalf("others counted %d, want 3", n)
	}
}

// L3 on #170: texts from anyone but the owner are set aside before the
// rate limit and the inbox, so a stranger's flood cannot crowd out the
// owner's STOP.
func TestStrangersCannotCrowdOutTheOwner(t *testing.T) {
	l, _ := rig(t)
	for i := 0; i < 10*InboundPerMinute; i++ {
		call(t, l, bridgeproto.OpInbound, bridgeproto.Inbound{Line: bridgeproto.LineOwner, From: "+15550000123", Text: "spam"}, nil)
	}
	if err := call(t, l, bridgeproto.OpInbound, bridgeproto.Inbound{Line: bridgeproto.LineOwner, From: ownerNum, Text: "STOP"}, nil); err != nil {
		t.Fatalf("the owner's STOP after a stranger's flood: %v", err)
	}
	if m := <-l.Inbox(); m.From != ownerNum || m.Text != "STOP" {
		t.Fatalf("delivered %+v", m)
	}
	if l.Dropped() {
		t.Fatal("the stranger's texts were counted against the owner's limit")
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
		send := l.Send
		if i > 0 {
			send = l.SendRequest
		}
		if err := send(ownerNum, "approve? code 1234"); !errors.Is(err, modem.ErrDown) {
			t.Fatalf("send while down: %v", err)
		}
		clk.add(30 * time.Minute)
	}
	clk.add(45 * time.Minute)
	call(t, l, bridgeproto.OpState, bridgeproto.State{OwnerLine: bridgeproto.StateOK}, nil)
	it := poll(t, l)
	want := "I couldn't text you from 13:05 to 15:20. 2 approval requests and 1 other text didn't reach you; your agent can ask again."
	if it.Text != want || it.To != ownerNum {
		t.Fatalf("recovery text %q, want %q", it.Text, want)
	}
	call(t, l, bridgeproto.OpSent, bridgeproto.Sent{ID: it.ID, Code: bridgeproto.CodeOK}, nil)
	var out struct{ Item *bridgeproto.Item }
	call(t, l, bridgeproto.OpOutbox, struct{}{}, &out)
	if out.Item != nil {
		t.Fatalf("replayed %+v", out.Item)
	}
	if n := l.LastOutage(); n.Missed != 3 || n.Requests != 2 {
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
		bridgeproto.StateSwapped: "The SIM in my phone modem changed, and I can't read it. Texts to and from you are paused. Check the SIM is in properly.",
		bridgeproto.StateUnbound: "My phone modem has no SIM I can read. Put the SIM for my number in it.",
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

// UX on #170: the recovery text counts approval requests apart and says
// the agent can ask again only when one was lost.
func TestRecoveryTextWording(t *testing.T) {
	at := func(h, m int) time.Time { return time.Date(2026, 10, 5, h, m, 0, 0, time.UTC) }
	for _, c := range []struct {
		o    Outage
		want string
	}{
		{Outage{at(13, 5), at(15, 20), 1, 0}, "I couldn't text you from 13:05 to 15:20. 1 text didn't reach you."},
		{Outage{at(13, 5), at(15, 20), 3, 0}, "I couldn't text you from 13:05 to 15:20. 3 texts didn't reach you."},
		{Outage{at(13, 5), at(15, 20), 1, 1}, "I couldn't text you from 13:05 to 15:20. 1 approval request didn't reach you; your agent can ask again."},
		{Outage{at(13, 5), at(15, 20), 2, 2}, "I couldn't text you from 13:05 to 15:20. 2 approval requests didn't reach you; your agent can ask again."},
		{Outage{at(23, 5), at(9, 0).AddDate(0, 0, 1), 2, 1}, "I couldn't text you from Oct 5 23:05 to Oct 6 09:00. 1 approval request and 1 other text didn't reach you; your agent can ask again."},
	} {
		if got := recoveryText(c.o, time.UTC); got != c.want {
			t.Errorf("%+v: %q", c.o, got)
		}
	}
}

// L3 on #170: the bridge offers a text again when an answer is lost; a
// try already taken is answered ok and not delivered twice, so a repeated
// approval code never counts as a wrong one.
func TestATextOfferedAgainIsTakenOnce(t *testing.T) {
	l, clk := rig(t)
	in := bridgeproto.Inbound{Line: bridgeproto.LineOwner, From: ownerNum, Text: "123456", ID: "t1"}
	for i := 0; i < 3; i++ {
		if err := call(t, l, bridgeproto.OpInbound, in, nil); err != nil {
			t.Fatalf("try %d: %v", i+1, err)
		}
	}
	select {
	case <-l.Inbox():
	case <-time.After(5 * time.Second):
		t.Fatal("not delivered")
	}
	select {
	case m := <-l.Inbox():
		t.Fatalf("delivered twice: %+v", m)
	default:
	}
	in.ID = strings.Repeat("x", bridgeproto.MaxID+1)
	if err := call(t, l, bridgeproto.OpInbound, in, nil); err == nil {
		t.Fatal("an oversized ID was taken")
	}
	clk.add(IDTTL + time.Minute)
	in.ID = "t1"
	if err := call(t, l, bridgeproto.OpInbound, in, nil); err != nil {
		t.Fatal(err)
	}
	select {
	case m := <-l.Inbox():
		if m.Text != "123456" {
			t.Fatalf("delivered %+v", m)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("an ID past IDTTL was not taken")
	}
}

// L3 on #170 (M15): the outbox hands texts out in the order they were
// sent.
func TestTheOutboxIsFirstInFirstOut(t *testing.T) {
	l, _ := rig(t)
	for _, text := range []string{"one", "two", "three"} {
		sendAsync(l, ownerNum, text)
		time.Sleep(30 * time.Millisecond)
	}
	for _, want := range []string{"one", "two", "three"} {
		if it := poll(t, l); it.Text != want {
			t.Fatalf("handed out %q, want %q", it.Text, want)
		}
	}
}

// L3 on #170 (M16, M17): the line is usable up to Silent after the bridge
// was last heard and down past it; on recovery the recovery text goes out
// ahead of a text queued before the outage.
func TestTheSilentRuleAndTheRecoveryTextGoesFirst(t *testing.T) {
	l, clk := rig(t)
	clk.add(Silent)
	sendAsync(l, ownerNum, "queued")
	time.Sleep(30 * time.Millisecond)
	clk.add(time.Second)
	start := time.Now()
	if err := l.Send(ownerNum, "lost"); !errors.Is(err, modem.ErrDown) || time.Since(start) > time.Second {
		t.Fatalf("send past Silent: %v after %v", err, time.Since(start))
	}
	call(t, l, bridgeproto.OpState, bridgeproto.State{OwnerLine: bridgeproto.StateOK}, nil)
	if it := poll(t, l); !strings.HasPrefix(it.Text, "I couldn't text you") {
		t.Fatalf("first after recovery: %q", it.Text)
	}
	if it := poll(t, l); it.Text != "queued" {
		t.Fatalf("second after recovery: %q", it.Text)
	}
}

// L3 on #170 (M19): past MaxQueued texts waiting for the bridge, a send
// fails at once as down.
func TestTheQueueIsCapped(t *testing.T) {
	l, _ := rig(t)
	for i := 0; i < MaxQueued; i++ {
		sendAsync(l, ownerNum, "hi")
	}
	time.Sleep(100 * time.Millisecond)
	start := time.Now()
	if err := l.Send(ownerNum, "one more"); !errors.Is(err, modem.ErrDown) || time.Since(start) > time.Second {
		t.Fatalf("send past MaxQueued: %v after %v", err, time.Since(start))
	}
}

// L3 on #170: a poll whose bridge hung up is handed nothing; the text
// waits for the next poll.
func TestAHungUpPollGetsNothing(t *testing.T) {
	l, _ := rig(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	sendAsync(l, ownerNum, "hi")
	time.Sleep(30 * time.Millisecond)
	if res, err := l.Ops()[bridgeproto.OpOutbox](ctx, sockets.Peer{Kind: "owner"}, []byte("{}")); err == nil {
		t.Fatalf("a hung-up poll got %v", res)
	}
	if it := poll(t, l); it.Text != "hi" {
		t.Fatalf("handed out %q", it.Text)
	}
}

// L3 on #170: the recovery text's times are in the box's zone, whatever
// zone the clock reads in.
func TestRecoveryTextUsesTheBoxsZone(t *testing.T) {
	zone := time.FixedZone("box", -7*3600)
	o := Outage{time.Date(2026, 10, 5, 20, 5, 0, 0, time.UTC), time.Date(2026, 10, 5, 22, 20, 0, 0, time.UTC), 1, 0}
	if got, want := recoveryText(o, zone), "I couldn't text you from 13:05 to 15:20. 1 text didn't reach you."; got != want {
		t.Fatalf("%q", got)
	}
}

// L3 on #170: SendWait runs from when the bridge takes a text, not from
// when it was queued: a text behind a slow one is not reported down while
// it can still go.
func TestSendWaitRunsFromHandOff(t *testing.T) {
	l, _ := rig(t) // SendWait 2 s
	sendAsync(l, ownerNum, "slow")
	poll(t, l)
	done := sendAsync(l, ownerNum, "next")
	time.Sleep(1500 * time.Millisecond)
	it := poll(t, l)
	time.Sleep(1000 * time.Millisecond) // 2.5 s after it was queued
	call(t, l, bridgeproto.OpSent, bridgeproto.Sent{ID: it.ID, Code: bridgeproto.CodeOK}, nil)
	if err := <-done; err != nil {
		t.Fatalf("a text sent within SendWait of hand-off: %v", err)
	}
}

// L3 on #170 (N8): a text offered again five minutes later (a bridge
// restart) is still taken once.
func TestATextOfferedAgainMinutesLaterIsTakenOnce(t *testing.T) {
	l, clk := rig(t)
	in := bridgeproto.Inbound{Line: bridgeproto.LineOwner, From: ownerNum, Text: "YES 123456", ID: "t1"}
	call(t, l, bridgeproto.OpInbound, in, nil)
	<-l.Inbox()
	clk.add(5 * time.Minute)
	if err := call(t, l, bridgeproto.OpInbound, in, nil); err != nil {
		t.Fatal(err)
	}
	select {
	case m := <-l.Inbox():
		t.Fatalf("taken twice: %+v", m)
	default:
	}
}

const newSIM = "89012600000000012345"

// P2-2w d2b, UX U-B1 (P2-3w carry): a swapped or unbound line with a SIM
// the bridge can read says so and points below, at the page's control;
// the page is told only a tag and the serial's last four digits, never
// the serial (the local UI is treated as compromised).
func TestASIMToConfirmIsOfferedBelow(t *testing.T) {
	l, _ := rig(t)
	if tag, ends := l.SIM(); tag != "" || ends != "" {
		t.Fatalf("a SIM offered while ok: %q %q", tag, ends)
	}
	for st, want := range map[string]string{
		bridgeproto.StateSwapped: "The SIM in my phone modem changed. Texts to and from you are paused until you confirm it below.",
		bridgeproto.StateUnbound: "My phone modem's SIM isn't set up as my number yet. Set it up below.",
	} {
		call(t, l, bridgeproto.OpState, bridgeproto.State{OwnerLine: st, ICCID: newSIM}, nil)
		if n := l.OwnerLineNote(); n != want {
			t.Errorf("%s: %q", st, n)
		}
		tag, ends := l.SIM()
		if ends != "2345" || len(tag) != 16 || strings.Contains(tag, "2345") {
			t.Errorf("%s: SIM() = %q, %q", st, tag, ends)
		}
	}
	// An ok line, or a down one, offers nothing, whatever it carries.
	for _, st := range []string{bridgeproto.StateOK, bridgeproto.StateDown} {
		call(t, l, bridgeproto.OpState, bridgeproto.State{OwnerLine: st, ICCID: newSIM}, nil)
		if tag, _ := l.SIM(); tag != "" {
			t.Errorf("%s: a SIM offered", st)
		}
	}
	// A serial that is not one is refused, as any bad state is.
	if err := call(t, l, bridgeproto.OpState, bridgeproto.State{OwnerLine: bridgeproto.StateSwapped, ICCID: "8901 x"}, nil); err == nil {
		t.Fatal("a malformed serial was taken")
	}
}

// P2-2w d2b, CH-19: adopting records exactly the serial the bridge
// reported, and only for the tag the page showed: a SIM changed since, or
// a line no longer swapped or unbound, is refused and nothing is recorded.
func TestAdoptRecordsOnlyTheShownSIM(t *testing.T) {
	var got []string
	clk := &clock{t: time.Date(2026, 10, 5, 13, 5, 0, 0, time.UTC)}
	l := New(Config{Owner: ownerNum, Now: clk.now, Record: func(iccid string) error { got = append(got, iccid); return nil }})
	call(t, l, bridgeproto.OpState, bridgeproto.State{OwnerLine: bridgeproto.StateSwapped, ICCID: newSIM}, nil)
	tag, _ := l.SIM()
	call(t, l, bridgeproto.OpState, bridgeproto.State{OwnerLine: bridgeproto.StateSwapped, ICCID: "89012600000000099999"}, nil)
	if err := l.Adopt(tag); !errors.Is(err, ErrStale) {
		t.Fatalf("adopt after the SIM changed: %v", err)
	}
	call(t, l, bridgeproto.OpState, bridgeproto.State{OwnerLine: bridgeproto.StateSwapped, ICCID: newSIM}, nil)
	if err := l.Adopt(""); !errors.Is(err, ErrStale) {
		t.Fatalf("adopt with no tag: %v", err)
	}
	if err := l.Adopt(tag); err != nil {
		t.Fatalf("adopt: %v", err)
	}
	if len(got) != 1 || got[0] != newSIM {
		t.Fatalf("recorded %q", got)
	}
	// Until the bridge opens the new SIM, the page says it is under way and
	// offers nothing more.
	if n := l.OwnerLineNote(); n != "Setting up the SIM ending in 2345 as my number. Texts with you start again within a minute." {
		t.Fatalf("note after adopting: %q", n)
	}
	if tag, _ := l.SIM(); tag != "" {
		t.Fatal("a SIM offered again after adopting")
	}
	call(t, l, bridgeproto.OpState, bridgeproto.State{OwnerLine: bridgeproto.StateOK}, nil)
	if err := l.Adopt(tag); !errors.Is(err, ErrStale) {
		t.Fatalf("adopt on an ok line: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("recorded %q", got)
	}
	// A box without a recorder refuses.
	l2, _ := rig(t)
	call(t, l2, bridgeproto.OpState, bridgeproto.State{OwnerLine: bridgeproto.StateUnbound, ICCID: newSIM}, nil)
	tag2, _ := l2.SIM()
	if err := l2.Adopt(tag2); err == nil || errors.Is(err, ErrStale) {
		t.Fatalf("adopt with no recorder: %v", err)
	}
}
