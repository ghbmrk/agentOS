package modemlink

import (
	"errors"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/bridgeproto"
	"github.com/ghbmrk/agentos/broker/modem"
)

// REQ: CH-2, CH-11

func sendFirstAsync(l *Link, to, text string) chan error {
	done := make(chan error, 1)
	go func() { done <- l.SendFirst(to, text) }()
	return done
}

// waitQueued waits until n items are queued for the bridge.
func waitQueued(t *testing.T, l *Link, n int) {
	t.Helper()
	for i := 0; i < 500; i++ {
		l.mu.Lock()
		q := len(l.queue)
		l.mu.Unlock()
		if q >= n {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("fewer than %d items queued", n)
}

// Security R2 on #170 (P2-3w carry): a STOP or STATUS reply goes ahead of
// the texts already waiting for the bridge, so a queue of other texts
// never delays the owner hearing that the box stopped.
func TestP23wR2ReplyGoesAheadOfTheQueue(t *testing.T) {
	l, _ := rig(t)
	var waiting []chan error
	for _, s := range []string{"one", "two", "three"} {
		waiting = append(waiting, sendAsync(l, ownerNum, s))
		waitQueued(t, l, len(waiting))
	}
	first := sendFirstAsync(l, ownerNum, "Stopped. Nothing new will start.")
	waitQueued(t, l, 4)
	it := poll(t, l)
	if it.Text != "Stopped. Nothing new will start." {
		t.Fatalf("first out %q, want the STOP reply", it.Text)
	}
	call(t, l, bridgeproto.OpSent, bridgeproto.Sent{ID: it.ID, Code: bridgeproto.CodeOK}, nil)
	if err := <-first; err != nil {
		t.Fatalf("SendFirst: %v", err)
	}
	for i, want := range []string{"one", "two", "three"} {
		it := poll(t, l)
		if it.Text != want {
			t.Fatalf("out of order: %q, want %q", it.Text, want)
		}
		call(t, l, bridgeproto.OpSent, bridgeproto.Sent{ID: it.ID, Code: bridgeproto.CodeOK}, nil)
		if err := <-waiting[i]; err != nil {
			t.Fatalf("%s: %v", want, err)
		}
	}
	if err := l.SendFirst("+15550200001", "hi"); !errors.Is(err, ErrRecipient) {
		t.Fatalf("SendFirst to another number: %v", err)
	}
}

// A text pushed back by a reply gets one more SendWait before it reads as
// down, so going first never makes another text time out early (L3 on
// #170: SendWait counts the texts ahead).
func TestP23wR2PushedBackTextsKeepTheirWait(t *testing.T) {
	l := New(Config{Owner: ownerNum, SendWait: 300 * time.Millisecond, PollWait: 50 * time.Millisecond})
	call(t, l, bridgeproto.OpState, bridgeproto.State{OwnerLine: bridgeproto.StateOK}, nil)
	behind := sendAsync(l, ownerNum, "behind")
	waitQueued(t, l, 1)
	first := sendFirstAsync(l, ownerNum, "Stopped.")
	waitQueued(t, l, 2)
	// The bridge is slow to poll, then the reply takes a while: "behind"
	// is taken past its own first SendWait, within the one it gained.
	time.Sleep(200 * time.Millisecond)
	it := poll(t, l)
	if it.Text != "Stopped." {
		t.Fatalf("first out %q", it.Text)
	}
	time.Sleep(200 * time.Millisecond)
	call(t, l, bridgeproto.OpSent, bridgeproto.Sent{ID: it.ID, Code: bridgeproto.CodeOK}, nil)
	if err := <-first; err != nil {
		t.Fatalf("SendFirst: %v", err)
	}
	it = poll(t, l)
	if it.Text != "behind" {
		t.Fatalf("next out %q", it.Text)
	}
	call(t, l, bridgeproto.OpSent, bridgeproto.Sent{ID: it.ID, Code: bridgeproto.CodeOK}, nil)
	if err := <-behind; err != nil {
		t.Fatalf("a pushed-back text timed out early: %v", err)
	}
	if n := l.TimedOut(); n != 0 {
		t.Fatalf("timed out %d", n)
	}
}

// A reply still goes with the queue full, within a small slack, and while
// the owner line is down it fails as down and is counted like any text.
func TestP23wR2ReplyPastAFullQueue(t *testing.T) {
	l, _ := rig(t)
	l.mu.Lock()
	for i := 0; i < MaxQueued; i++ {
		l.queue = append(l.queue, &item{Item: bridgeproto.Item{ID: newID(), Line: bridgeproto.LineOwner, To: ownerNum, Text: "filler"}, bump: make(chan struct{}, 1)})
	}
	l.mu.Unlock()
	if err := l.Send(ownerNum, "one more"); !errors.Is(err, modem.ErrDown) {
		t.Fatalf("Send into a full queue: %v", err)
	}
	first := sendFirstAsync(l, ownerNum, "Stopped.")
	waitQueued(t, l, MaxQueued+1)
	if it := poll(t, l); it.Text != "Stopped." {
		t.Fatalf("first out %q", it.Text)
	} else {
		call(t, l, bridgeproto.OpSent, bridgeproto.Sent{ID: it.ID, Code: bridgeproto.CodeOK}, nil)
	}
	if err := <-first; err != nil {
		t.Fatalf("SendFirst past a full queue: %v", err)
	}
	l.mu.Lock()
	for i := 0; i < FirstSlack; i++ {
		l.queue = append([]*item{{Item: bridgeproto.Item{ID: newID(), Line: bridgeproto.LineOwner, To: ownerNum, Text: "reply"}, bump: make(chan struct{}, 1)}}, l.queue...)
	}
	l.mu.Unlock()
	if err := l.SendFirst(ownerNum, "Stopped."); !errors.Is(err, modem.ErrDown) {
		t.Fatalf("SendFirst past the slack: %v", err)
	}
	call(t, l, bridgeproto.OpState, bridgeproto.State{OwnerLine: bridgeproto.StateDown}, nil)
	if err := l.SendFirst(ownerNum, "Stopped."); !errors.Is(err, modem.ErrDown) {
		t.Fatalf("SendFirst while down: %v", err)
	}
}
