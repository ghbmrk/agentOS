package modemlink

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/bridgeproto"
	"github.com/ghbmrk/agentos/broker/sockets"
)

// REQ: CH-1, CH-2, CH-12. #1445: the lines a mutant survived on in the
// owner line's outage, inbound, outbox and setup code, each pinned by what
// it changes.

const (
	zzPhone = "+15550000101"
	zzSIM   = "89010000000000000001"
)

// zzWithin fails the test unless fn returns within d.
func zzWithin(t *testing.T, d time.Duration, what string, fn func()) {
	t.Helper()
	done := make(chan struct{})
	go func() { fn(); close(done) }()
	select {
	case <-done:
	case <-time.After(d):
		t.Fatalf("%s: not done within %v", what, d)
	}
}

// zzSetupCall runs op on a SetupLine as owner.sock would.
func zzSetupCall(s *SetupLine, op string, args any) (any, error) {
	b, _ := json.Marshal(args)
	return s.Ops()[op](context.Background(), sockets.Peer{Kind: "owner"}, b)
}

func zzSetupOK(t *testing.T, s *SetupLine) {
	t.Helper()
	if _, err := zzSetupCall(s, bridgeproto.OpState, bridgeproto.State{OwnerLine: bridgeproto.StateOK}); err != nil {
		t.Fatal(err)
	}
}

// zzSetupPoll polls the setup outbox once and returns the item, or nil.
func zzSetupPoll(t *testing.T, s *SetupLine) *bridgeproto.Item {
	t.Helper()
	res, err := zzSetupCall(s, bridgeproto.OpOutbox, struct{}{})
	if err != nil {
		t.Fatal(err)
	}
	var out struct{ Item *bridgeproto.Item }
	raw, _ := json.Marshal(res)
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	return out.Item
}

// zzQueued waits until s.queue holds n items.
func zzQueued(t *testing.T, s *SetupLine, n int) {
	t.Helper()
	for range 400 {
		s.mu.Lock()
		got := len(s.queue)
		s.mu.Unlock()
		if got == n {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("queue never held %d", n)
}

func TestZZConfigDefaults(t *testing.T) {
	l := New(Config{})
	if l.cfg.SendWait != SendWait || l.cfg.PollWait != bridgeproto.OutboxWait {
		t.Fatalf("link defaults: send %v poll %v", l.cfg.SendWait, l.cfg.PollWait)
	}
	l = New(Config{SendWait: 3 * time.Second, PollWait: 4 * time.Second})
	if l.cfg.SendWait != 3*time.Second || l.cfg.PollWait != 4*time.Second {
		t.Fatalf("link config overwritten: send %v poll %v", l.cfg.SendWait, l.cfg.PollWait)
	}
	s := NewSetup(SetupConfig{})
	if s.cfg.SendWait != 40*time.Second || s.cfg.PollWait != bridgeproto.OutboxWait {
		t.Fatalf("setup defaults: send %v poll %v", s.cfg.SendWait, s.cfg.PollWait)
	}
	s = NewSetup(SetupConfig{SendWait: 3 * time.Second, PollWait: 4 * time.Second})
	if s.cfg.SendWait != 3*time.Second || s.cfg.PollWait != 4*time.Second {
		t.Fatalf("setup config overwritten: send %v poll %v", s.cfg.SendWait, s.cfg.PollWait)
	}
}

// An outage that opens because the line went silent (reported ok, then
// nothing for Silent) began when it was last heard; one that opens on a
// reported state began when it was reported, not when a text first failed.
func TestZZOutageStartsWhenTheLineWasLastHeardOrReported(t *testing.T) {
	l, clk := rig(t)
	heard := clk.now()
	clk.add(Silent + time.Minute)
	if err := l.Send(ownerNum, "x"); err == nil {
		t.Fatal("a send on a silent line went")
	}
	call(t, l, bridgeproto.OpState, bridgeproto.State{OwnerLine: bridgeproto.StateOK}, nil)
	if o := l.LastOutage(); !o.From.Equal(heard) {
		t.Fatalf("silent outage began %v, want when last heard %v", o.From, heard)
	}

	reported := clk.now()
	call(t, l, bridgeproto.OpState, bridgeproto.State{OwnerLine: bridgeproto.StateSwapped, ICCID: zzSIM}, nil)
	clk.add(10 * time.Minute)
	if err := l.Send(ownerNum, "y"); err == nil {
		t.Fatal("a send on a swapped line went")
	}
	call(t, l, bridgeproto.OpState, bridgeproto.State{OwnerLine: bridgeproto.StateOK}, nil)
	if o := l.LastOutage(); !o.From.Equal(reported) {
		t.Fatalf("swapped outage began %v, want when reported %v", o.From, reported)
	}
}

// zzEastern is US Eastern time with its daylight-saving rule, built from
// TZif bytes in the test, not the tzdata package: a blank import's init
// would reach every test of the package. The zone has no transitions, so
// every instant follows the rule string.
func zzEastern(t *testing.T) *time.Location {
	t.Helper()
	header := "TZif2" + strings.Repeat("\x00", 15) +
		"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" + // isut, isstd, leap
		"\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x04" // time, type, char counts
	data := "\xff\xff\xb9\xb0\x00\x00" + "EST\x00" // UTC-5, standard, abbreviation 0
	loc, err := time.LoadLocationFromTZData("US/Eastern", []byte(header+data+header+data+"\nEST5EDT,M3.2.0,M11.1.0\n"))
	if err != nil {
		t.Fatal(err)
	}
	return loc
}

// A recovery text names the days when the outage ran exactly 24 hours but
// ended on the same calendar day (the clocks went back in between).
func TestZZRecoveryTextNamesTheDayForAFullDayOutage(t *testing.T) {
	loc := zzEastern(t)
	from := time.Date(2026, 11, 1, 0, 30, 0, 0, loc)
	to := from.Add(24 * time.Hour)
	if from.Day() != to.Day() {
		t.Fatalf("setup: %v and %v are different days", from, to)
	}
	got := recoveryText(Outage{From: from, To: to, Missed: 1}, loc)
	if !strings.Contains(got, "from Nov 1 00:30 to Nov 1 23:30.") {
		t.Fatalf("recovery text %q", got)
	}
}

// A waiting outbox poll wakes when a text is queued, and when the line
// recovers with a text to tell the owner.
func TestZZQueueingWakesAWaitingPoll(t *testing.T) {
	clk := &clock{t: time.Date(2026, 10, 5, 13, 5, 0, 0, time.UTC)}
	l := New(Config{Owner: ownerNum, Now: clk.now, SendWait: 5 * time.Second, PollWait: 5 * time.Second})
	call(t, l, bridgeproto.OpState, bridgeproto.State{OwnerLine: bridgeproto.StateOK}, nil)
	got := make(chan bridgeproto.Item, 1)
	go func() {
		var out struct{ Item *bridgeproto.Item }
		call(t, l, bridgeproto.OpOutbox, struct{}{}, &out)
		if out.Item != nil {
			got <- *out.Item
		}
	}()
	time.Sleep(150 * time.Millisecond)
	go l.Send(ownerNum, "wake")
	select {
	case it := <-got:
		if it.Text != "wake" {
			t.Fatalf("polled %+v", it)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("a waiting poll was not woken by a queued text")
	}
}

func TestZZRecoveryWakesAWaitingPoll(t *testing.T) {
	clk := &clock{t: time.Date(2026, 10, 5, 13, 5, 0, 0, time.UTC)}
	l := New(Config{Owner: ownerNum, Now: clk.now, SendWait: 5 * time.Second, PollWait: 5 * time.Second})
	if err := l.Send(ownerNum, "missed"); err == nil { // the line starts down
		t.Fatal("a send on a down line went")
	}
	got := make(chan bridgeproto.Item, 1)
	go func() {
		var out struct{ Item *bridgeproto.Item }
		call(t, l, bridgeproto.OpOutbox, struct{}{}, &out)
		if out.Item != nil {
			got <- *out.Item
		}
	}()
	time.Sleep(150 * time.Millisecond)
	call(t, l, bridgeproto.OpState, bridgeproto.State{OwnerLine: bridgeproto.StateOK}, nil)
	select {
	case it := <-got:
		if !strings.Contains(it.Text, "didn't reach you") {
			t.Fatalf("polled %+v", it)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("a waiting poll was not woken by the recovery text")
	}
}

// Send's wait for the result starts when the bridge takes the text, not
// when it was queued.
func TestZZSendWaitRunsFromTheHandOff(t *testing.T) {
	l := New(Config{Owner: ownerNum, SendWait: 500 * time.Millisecond, PollWait: 50 * time.Millisecond})
	call(t, l, bridgeproto.OpState, bridgeproto.State{OwnerLine: bridgeproto.StateOK}, nil)
	start := time.Now()
	done := sendAsync(l, ownerNum, "slow bridge")
	time.Sleep(300 * time.Millisecond)
	poll(t, l)
	err := <-done
	if err == nil {
		t.Fatal("an unanswered send succeeded")
	}
	if took := time.Since(start); took < 650*time.Millisecond {
		t.Fatalf("send gave up after %v, under SendWait past the hand-off", took)
	}
}

// Whatever the bridge says marks it heard: an inbound text, an outbox poll
// or a result each end the silence.
func TestZZAnyBridgeCallMarksTheLineHeard(t *testing.T) {
	down := "I can't reach my phone modem. Check it's plugged in."
	silent := func() (*Link, *clock) {
		l, clk := rig(t)
		clk.add(Silent + time.Minute)
		if l.OwnerLineNote() != down {
			t.Fatal("setup: the line is not silent")
		}
		return l, clk
	}
	l, _ := silent()
	call(t, l, bridgeproto.OpInbound, bridgeproto.Inbound{Line: bridgeproto.LineOwner, From: ownerNum, Text: "hi"}, nil)
	if n := l.OwnerLineNote(); n != "" {
		t.Fatalf("after an inbound text: %q", n)
	}
	l, _ = silent()
	var out struct{ Item *bridgeproto.Item }
	call(t, l, bridgeproto.OpOutbox, struct{}{}, &out)
	if n := l.OwnerLineNote(); n != "" {
		t.Fatalf("after an outbox poll: %q", n)
	}
	l, _ = silent()
	call(t, l, bridgeproto.OpSent, bridgeproto.Sent{ID: "nothing", Code: bridgeproto.CodeOK}, nil)
	if n := l.OwnerLineNote(); n != "" {
		t.Fatalf("after a result: %q", n)
	}
}

// The inbound rate window forgets texts a minute old without counting the
// ones it keeps twice.
func TestZZInboundWindowCountsEachKeptTextOnce(t *testing.T) {
	l, clk := rig(t)
	in := bridgeproto.Inbound{Line: bridgeproto.LineOwner, From: ownerNum, Text: "hi"}
	take := func(n int) {
		t.Helper()
		for range n {
			if err := call(t, l, bridgeproto.OpInbound, in, nil); err != nil {
				t.Fatal(err)
			}
			<-l.Inbox()
		}
	}
	take(InboundPerMinute / 2)
	clk.add(50 * time.Second)
	take(InboundPerMinute / 2)
	clk.add(20 * time.Second) // the first half is a minute old, the second is not
	take(InboundPerMinute / 2)
	if err := call(t, l, bridgeproto.OpInbound, in, nil); err == nil {
		t.Fatal("a text past the limit was taken")
	}
}

// A state report keeps an adoption under way while it names the same SIM.
func TestZZTheSameSIMReportedAgainKeepsTheAdoption(t *testing.T) {
	clk := &clock{t: time.Date(2026, 10, 5, 13, 5, 0, 0, time.UTC)}
	l := New(Config{Owner: ownerNum, Now: clk.now, Record: func(string) error { return nil }})
	st := bridgeproto.State{OwnerLine: bridgeproto.StateUnbound, ICCID: zzSIM}
	call(t, l, bridgeproto.OpState, st, nil)
	tag, _ := l.SIM()
	if err := l.Adopt(tag); err != nil {
		t.Fatal(err)
	}
	call(t, l, bridgeproto.OpState, st, nil)
	if tag, _ := l.SIM(); tag != "" {
		t.Fatal("the adoption ended on a report of the same SIM")
	}
	if !strings.HasPrefix(l.OwnerLineNote(), "Setting up the SIM") {
		t.Fatalf("note %q", l.OwnerLineNote())
	}
}

// A line the bridge reports as anything but ok is in an outage from that
// report, even when no text fails until later.
func TestZZAStateReportOpensTheOutageAtOnce(t *testing.T) {
	l, clk := rig(t)
	at := clk.now()
	call(t, l, bridgeproto.OpState, bridgeproto.State{OwnerLine: bridgeproto.StateDown}, nil)
	clk.add(time.Hour)
	l.mu.Lock()
	o := l.outage
	l.mu.Unlock()
	if o == nil || !o.From.Equal(at) {
		t.Fatalf("outage %+v, want one from %v", o, at)
	}
	call(t, l, bridgeproto.OpState, bridgeproto.State{OwnerLine: bridgeproto.StateOK}, nil)
	l.mu.Lock()
	o2 := l.outage
	l.mu.Unlock()
	if o2 != nil {
		t.Fatal("an ok report left an outage open")
	}
}

// SetupLine.

func TestZZSetupReadyAtExactlySilent(t *testing.T) {
	clk := &clock{t: time.Date(2026, 10, 5, 13, 5, 0, 0, time.UTC)}
	s := NewSetup(SetupConfig{Now: clk.now})
	zzSetupOK(t, s)
	clk.add(Silent)
	if !s.Ready() {
		t.Fatal("not ready at exactly Silent")
	}
	clk.add(time.Nanosecond)
	if s.Ready() {
		t.Fatal("ready past Silent")
	}
}

func TestZZSetupSendRefusesAtMaxQueued(t *testing.T) {
	s := NewSetup(SetupConfig{SendWait: time.Second})
	zzSetupOK(t, s)
	for range MaxQueued {
		s.queue = append(s.queue, &item{})
	}
	ready := s.ready
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := s.Send(ctx, zzPhone, "x"); !errors.Is(err, ErrNotSent) {
		t.Fatalf("send: %v", err)
	}
	select {
	case <-ready:
		t.Fatal("a text was queued past MaxQueued")
	default:
	}
}

// A setup text that fails leaves nothing behind: not in the queue, not in
// the outbox, and the line is not left locked.
func TestZZSetupFailedSendLeavesNothing(t *testing.T) {
	s := NewSetup(SetupConfig{SendWait: 5 * time.Second, PollWait: 20 * time.Millisecond})
	zzSetupOK(t, s)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.Send(ctx, zzPhone, "never taken") }()
	zzQueued(t, s, 1)
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, ErrNotSent) {
			t.Fatalf("send: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("a cancelled send kept waiting")
	}
	zzWithin(t, 2*time.Second, "Ready after a failed send", func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		if len(s.queue) != 0 || len(s.out) != 0 {
			t.Errorf("queue %d, out %d", len(s.queue), len(s.out))
		}
	})

	// Taken by the bridge, then failed: the outbox forgets it too.
	ctx, cancel = context.WithCancel(context.Background())
	go func() { done <- s.Send(ctx, zzPhone, "taken") }()
	zzQueued(t, s, 1)
	if it := zzSetupPoll(t, s); it == nil || it.Text != "taken" {
		t.Fatalf("polled %+v", it)
	}
	cancel()
	if err := <-done; !errors.Is(err, ErrNotSent) {
		t.Fatalf("send: %v", err)
	}
	zzWithin(t, 2*time.Second, "lock after a failed send", func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		if len(s.out) != 0 {
			t.Errorf("out %d after a failed send", len(s.out))
		}
	})
}

func TestZZSetupQueueingWakesAWaitingPoll(t *testing.T) {
	s := NewSetup(SetupConfig{SendWait: 5 * time.Second, PollWait: 5 * time.Second})
	zzSetupOK(t, s)
	got := make(chan *bridgeproto.Item, 1)
	go func() { got <- zzSetupPoll(t, s) }()
	time.Sleep(150 * time.Millisecond)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.Send(ctx, zzPhone, "wake")
	select {
	case it := <-got:
		if it == nil || it.Text != "wake" {
			t.Fatalf("polled %+v", it)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("a waiting poll was not woken by a queued text")
	}
}

func TestZZPairTextOfNothing(t *testing.T) {
	for _, text := range []string{"", "  ", "\n"} {
		if pairText(text) {
			t.Errorf("%q asks to pair", text)
		}
	}
}

func TestZZSetupInboundRefusesTheSecondLine(t *testing.T) {
	s := NewSetup(SetupConfig{})
	zzSetupOK(t, s)
	_, err := zzSetupCall(s, bridgeproto.OpInbound, bridgeproto.Inbound{Line: bridgeproto.LineSecond, ID: "s", From: zzPhone, Text: "PAIR ABCD"})
	if err == nil {
		t.Fatal("a second-line text was taken")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	if _, _, ok := s.Next(ctx); ok {
		t.Fatal("a second-line text reached the page")
	}
}

// Every bridge call marks the setup line heard.
func TestZZSetupAnyBridgeCallMarksTheLineHeard(t *testing.T) {
	for name, call := range map[string]func(*testing.T, *SetupLine){
		"inbound": func(t *testing.T, s *SetupLine) {
			if _, err := zzSetupCall(s, bridgeproto.OpInbound, bridgeproto.Inbound{Line: bridgeproto.LineOwner, ID: "i", From: zzPhone, Text: "PAIR ABCD"}); err != nil {
				t.Fatal(err)
			}
		},
		"outbox": func(t *testing.T, s *SetupLine) { zzSetupPoll(t, s) },
		"sent": func(t *testing.T, s *SetupLine) {
			if _, err := zzSetupCall(s, bridgeproto.OpSent, bridgeproto.Sent{ID: "none", Code: bridgeproto.CodeOK}); err != nil {
				t.Fatal(err)
			}
		},
	} {
		clk := &clock{t: time.Date(2026, 10, 5, 13, 5, 0, 0, time.UTC)}
		s := NewSetup(SetupConfig{Now: clk.now, PollWait: 10 * time.Millisecond})
		zzSetupOK(t, s)
		clk.add(Silent + time.Minute)
		if s.Ready() {
			t.Fatalf("%s: setup: the line is not silent", name)
		}
		call(t, s)
		if !s.Ready() {
			t.Errorf("%s did not mark the line heard", name)
		}
	}
}

// A taken inbound ID is remembered for IDTTL, and forgotten past it.
func TestZZSetupInboundIDIsRememberedForIDTTL(t *testing.T) {
	clk := &clock{t: time.Date(2026, 10, 5, 13, 5, 0, 0, time.UTC)}
	s := NewSetup(SetupConfig{Now: clk.now})
	zzSetupOK(t, s)
	send := func() int {
		t.Helper()
		if _, err := zzSetupCall(s, bridgeproto.OpInbound, bridgeproto.Inbound{Line: bridgeproto.LineOwner, ID: "same", From: zzPhone, Text: "PAIR ABCD"}); err != nil {
			t.Fatal(err)
		}
		return len(s.inbox)
	}
	if n := send(); n != 1 {
		t.Fatalf("first: %d waiting", n)
	}
	clk.add(IDTTL)
	if n := send(); n != 1 {
		t.Fatalf("a retry at exactly IDTTL: %d waiting", n)
	}
	clk.add(time.Nanosecond)
	if n := send(); n != 2 {
		t.Fatalf("an ID past IDTTL: %d waiting, want it taken again", n)
	}
}

// The setup inbound window forgets old texts without counting the ones it
// keeps twice.
func TestZZSetupInboundWindowCountsEachKeptTextOnce(t *testing.T) {
	clk := &clock{t: time.Date(2026, 10, 5, 13, 5, 0, 0, time.UTC)}
	s := NewSetup(SetupConfig{Now: clk.now})
	zzSetupOK(t, s)
	id := 0
	send := func(n int) {
		t.Helper()
		for range n {
			id++
			if _, err := zzSetupCall(s, bridgeproto.OpInbound, bridgeproto.Inbound{Line: bridgeproto.LineOwner, ID: fmt.Sprint(id), From: zzPhone, Text: "PAIR ABCD"}); err != nil {
				t.Fatal(err)
			}
		}
	}
	send(2)
	clk.add(50 * time.Second)
	send(2)
	clk.add(20 * time.Second)
	send(3)
	if n := len(s.inbox); n != 7 {
		t.Fatalf("%d texts waiting, want 7", n)
	}
}

// An empty outbox poll ends at PollWait, and a hung-up one ends with its
// context's error.
func TestZZSetupPollEnds(t *testing.T) {
	s := NewSetup(SetupConfig{PollWait: 50 * time.Millisecond})
	zzSetupOK(t, s)
	zzWithin(t, 2*time.Second, "an empty poll", func() {
		if it := zzSetupPoll(t, s); it != nil {
			t.Errorf("polled %+v", it)
		}
	})
	s = NewSetup(SetupConfig{PollWait: 10 * time.Second})
	zzSetupOK(t, s)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	zzWithin(t, 2*time.Second, "a hung-up poll", func() {
		_, err := s.Ops()[bridgeproto.OpOutbox](ctx, sockets.Peer{Kind: "owner"}, nil)
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Errorf("hung-up poll: %v", err)
		}
	})
}

// A polled text is handed out once, and a result takes it from the outbox.
func TestZZSetupHandsATextOutOnce(t *testing.T) {
	s := NewSetup(SetupConfig{SendWait: 5 * time.Second, PollWait: 30 * time.Millisecond})
	zzSetupOK(t, s)
	done := make(chan error, 1)
	go func() { done <- s.Send(context.Background(), zzPhone, "once") }()
	zzQueued(t, s, 1)
	it := zzSetupPoll(t, s)
	if it == nil || it.Text != "once" {
		t.Fatalf("polled %+v", it)
	}
	if again := zzSetupPoll(t, s); again != nil {
		t.Fatalf("handed out twice: %+v", again)
	}
	if _, err := zzSetupCall(s, bridgeproto.OpSent, bridgeproto.Sent{ID: it.ID, Code: bridgeproto.CodeOK}); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if len(s.out) != 0 {
		t.Fatalf("%d texts still in the outbox after their result", len(s.out))
	}
}

func TestZZSetupRefusesAnUnknownResultCode(t *testing.T) {
	s := NewSetup(SetupConfig{})
	if _, err := zzSetupCall(s, bridgeproto.OpSent, bridgeproto.Sent{ID: "x", Code: "bogus"}); err == nil {
		t.Fatal("an unknown result code was taken")
	}
}

// A poll that began before the line came back is not handed what is
// queued after; one that began after is.
func TestZZSetupPollBeforeRecoveryGetsNothing(t *testing.T) {
	clk := &clock{t: time.Date(2026, 10, 5, 13, 5, 0, 0, time.UTC)}
	s := NewSetup(SetupConfig{Now: clk.now, SendWait: 5 * time.Second, PollWait: 400 * time.Millisecond})
	got := make(chan *bridgeproto.Item, 1)
	go func() { got <- zzSetupPoll(t, s) }()
	time.Sleep(100 * time.Millisecond)
	clk.add(time.Second)
	zzSetupOK(t, s)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.Send(ctx, zzPhone, "after")
	select {
	case it := <-got:
		if it != nil {
			t.Fatalf("a poll from before the recovery was handed %+v", it)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("poll never ended")
	}
	if it := zzSetupPoll(t, s); it == nil || it.Text != "after" {
		t.Fatalf("a poll after the recovery got %+v", it)
	}
}

// A state report other than ok fails what waits at once, and drops it from
// the queue; an ok report fails nothing.
func TestZZSetupStateReportFailsWhatWaits(t *testing.T) {
	s := NewSetup(SetupConfig{SendWait: 5 * time.Second, PollWait: 30 * time.Millisecond})
	zzSetupOK(t, s)
	done := make(chan error, 1)
	go func() { done <- s.Send(context.Background(), zzPhone, "kept") }()
	zzQueued(t, s, 1)
	zzSetupOK(t, s) // another ok report: the text still waits
	select {
	case err := <-done:
		t.Fatalf("an ok report ended the send: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	if it := zzSetupPoll(t, s); it == nil || it.Text != "kept" {
		t.Fatalf("polled %+v", it)
	}
	if _, err := zzSetupCall(s, bridgeproto.OpSent, bridgeproto.Sent{ID: zzIDOf(s), Code: bridgeproto.CodeOK}); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatalf("send: %v", err)
	}

	go func() { done <- s.Send(context.Background(), zzPhone, "failed") }()
	zzQueued(t, s, 1)
	zzWithin(t, 2*time.Second, "a down report", func() {
		zzSetupCall(s, bridgeproto.OpState, bridgeproto.State{OwnerLine: bridgeproto.StateDown})
	})
	select {
	case err := <-done:
		if !errors.Is(err, ErrNotSent) {
			t.Fatalf("send: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("a down report did not end the waiting send")
	}
	s.mu.Lock()
	n := len(s.queue)
	s.mu.Unlock()
	if n != 0 {
		t.Fatalf("%d texts left queued after a down report", n)
	}
	time.Sleep(5 * time.Millisecond)
	zzSetupOK(t, s)
	if it := zzSetupPoll(t, s); it != nil {
		t.Fatalf("a text from before the outage was handed out: %+v", it)
	}
}

// zzIDOf is the ID of the one item in s.out.
func zzIDOf(s *SetupLine) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id := range s.out {
		return id
	}
	return ""
}

// A report other than ok fails each queued text with the down result and
// empties the queue itself, whoever is waiting on it.
func TestZZSetupStateReportEmptiesTheQueue(t *testing.T) {
	s := NewSetup(SetupConfig{})
	zzSetupOK(t, s)
	its := []*item{{result: make(chan string, 1)}, {result: make(chan string, 1)}}
	s.mu.Lock()
	s.queue = append(s.queue, its...)
	s.mu.Unlock()
	if _, err := zzSetupCall(s, bridgeproto.OpState, bridgeproto.State{OwnerLine: bridgeproto.StateSwapped}); err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	n := len(s.queue)
	s.mu.Unlock()
	if n != 0 {
		t.Fatalf("%d texts left queued", n)
	}
	for i, it := range its {
		select {
		case code := <-it.result:
			if code != bridgeproto.CodeDown {
				t.Fatalf("text %d failed with %q", i, code)
			}
		default:
			t.Fatalf("text %d was not failed", i)
		}
	}
}
