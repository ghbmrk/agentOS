package modemlink

import (
	"fmt"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/bridgeproto"
)

// REQ: CH-2, CH-11

func ownerText(text string) bridgeproto.Inbound {
	return bridgeproto.Inbound{Line: bridgeproto.LineOwner, From: ownerNum, Text: text}
}

// Security R1 at bc36b57 (P2-3w carry): an exact STOP from the owner's
// number skips the inbound rate limit, so texts from the owner's number,
// real or spoofed, cannot use up the minute's limit and hold STOP back.
// A STOP is not counted against the limit, and is never a drop.
func TestP23wStopSkipsTheInboundRateLimit(t *testing.T) {
	l, _ := rig(t)
	for i := 0; i < InboundPerMinute; i++ {
		if err := call(t, l, bridgeproto.OpInbound, ownerText("hi"), nil); err != nil {
			t.Fatalf("text %d: %v", i+1, err)
		}
		<-l.Inbox()
	}
	if err := call(t, l, bridgeproto.OpInbound, ownerText("hi"), nil); err == nil {
		t.Fatal("the limit did not hold")
	}
	for _, stop := range []string{"STOP", "stop", " Stop! "} {
		if err := call(t, l, bridgeproto.OpInbound, ownerText(stop), nil); err != nil {
			t.Fatalf("%q past the limit: %v", stop, err)
		}
		if m := <-l.Inbox(); m.Text != stop || m.From != ownerNum {
			t.Fatalf("delivered %+v", m)
		}
	}
	// Not a control word: still under the limit.
	if err := call(t, l, bridgeproto.OpInbound, ownerText("stop everything"), nil); err == nil {
		t.Fatal("a near-miss skipped the limit")
	}
}

// A STOP goes ahead of the owner's texts still waiting in the inbox, so it
// is handled first; the others keep their order.
func TestP23wStopIsHandledFirst(t *testing.T) {
	l, _ := rig(t)
	for i := 0; i < 5; i++ {
		call(t, l, bridgeproto.OpInbound, ownerText(fmt.Sprintf("task %d", i)), nil)
	}
	if err := call(t, l, bridgeproto.OpInbound, ownerText("STOP"), nil); err != nil {
		t.Fatal(err)
	}
	if m := <-l.Inbox(); m.Text != "STOP" {
		t.Fatalf("first out %q, want STOP", m.Text)
	}
	for i := 0; i < 5; i++ {
		if m := <-l.Inbox(); m.Text != fmt.Sprintf("task %d", i) {
			t.Fatalf("out of order: %q", m.Text)
		}
	}
	if l.Dropped() {
		t.Fatal("a drop noted with room in the inbox")
	}
}

// With the inbox full, a STOP still goes in first; the newest waiting text
// gives way and the drop is noted (STATUS's dropped count).
func TestP23wStopGetsInAFullInbox(t *testing.T) {
	l, clk := rig(t)
	n := cap(l.inbox)
	for i := 0; i < n; i++ {
		if i > 0 && i%InboundPerMinute == 0 {
			clk.add(time.Minute)
		}
		if err := call(t, l, bridgeproto.OpInbound, ownerText(fmt.Sprintf("task %d", i)), nil); err != nil {
			t.Fatalf("text %d: %v", i, err)
		}
	}
	if l.Dropped() {
		t.Fatal("dropped before the inbox was full")
	}
	if err := call(t, l, bridgeproto.OpInbound, ownerText("STOP"), nil); err != nil {
		t.Fatalf("STOP into a full inbox: %v", err)
	}
	if m := <-l.Inbox(); m.Text != "STOP" {
		t.Fatalf("first out %q, want STOP", m.Text)
	}
	for i := 0; i < n-1; i++ {
		if m := <-l.Inbox(); m.Text != fmt.Sprintf("task %d", i) {
			t.Fatalf("out of order at %d: %q", i, m.Text)
		}
	}
	select {
	case m := <-l.Inbox():
		t.Fatalf("the newest text did not give way: %q", m.Text)
	default:
	}
	if !l.Dropped() {
		t.Fatal("the drop was not noted")
	}
}

// Strangers' STOPs are still set aside before the limit and the inbox.
func TestP23wStrangerStopIsSetAside(t *testing.T) {
	l, _ := rig(t)
	call(t, l, bridgeproto.OpInbound, bridgeproto.Inbound{Line: bridgeproto.LineOwner, From: "+15550000123", Text: "STOP"}, nil)
	select {
	case m := <-l.Inbox():
		t.Fatalf("a stranger's STOP was delivered: %+v", m)
	default:
	}
	if l.Others() != 1 {
		t.Fatalf("others %d", l.Others())
	}
}
