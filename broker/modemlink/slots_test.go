package modemlink

import (
	"errors"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/bridgeproto"
	"github.com/ghbmrk/agentos/broker/modem"
)

// REQ: CH-2, UX U-B1. #1445: the recovery text has no waiter, so before
// this only a result cleared its outbox slot. A bridge that takes it and
// never answers (it restarts mid-send) kept the slot for the run, and
// after MaxQueued such outages every later text was refused as full. Now
// a waiterless item handed out is forgotten once its result is SendWait
// overdue, as a waiter forgets its own, and a late result for it is stray.
func TestUnansweredRecoveryTextsDoNotFillTheQueue(t *testing.T) {
	l, clk := rig(t)
	outage := func() bridgeproto.Item {
		t.Helper()
		call(t, l, bridgeproto.OpState, bridgeproto.State{OwnerLine: bridgeproto.StateDown}, nil)
		if err := l.Send(ownerNum, "missed"); !errors.Is(err, modem.ErrDown) {
			t.Fatalf("a send while down: %v", err)
		}
		call(t, l, bridgeproto.OpState, bridgeproto.State{OwnerLine: bridgeproto.StateOK}, nil)
		return poll(t, l) // the recovery text, taken and never answered
	}
	first := outage()
	for range MaxQueued + 5 {
		outage()
	}
	// Within SendWait of the last hand-off the slots still hold: the
	// bridge may yet answer.
	clk.add(l.cfg.SendWait)
	if !l.Bridged() {
		t.Fatal("an unanswered recovery text within SendWait reads as no bridge")
	}
	clk.add(time.Nanosecond)
	if l.Bridged() {
		t.Fatal("recovery texts SendWait overdue still read as held by a bridge")
	}
	done := sendAsync(l, ownerNum, "after many outages")
	it := poll(t, l)
	if it.Text != "after many outages" {
		t.Fatalf("polled %+v, want the new text", it)
	}
	call(t, l, bridgeproto.OpSent, bridgeproto.Sent{ID: it.ID, Code: bridgeproto.CodeOK}, nil)
	if err := <-done; err != nil {
		t.Fatalf("a send after %d unanswered recovery texts: %v", MaxQueued+6, err)
	}
	stray := l.Stray()
	call(t, l, bridgeproto.OpSent, bridgeproto.Sent{ID: first.ID, Code: bridgeproto.CodeOK}, nil)
	if l.Stray() != stray+1 {
		t.Fatal("a late result for a forgotten recovery text is not stray")
	}
}

// A recovery text answered in time is cleared by its result, as before,
// and a waiter's item never expires on the recovery text's clock.
func TestAnAnsweredRecoveryTextAndAWaiterKeepTheirSlotRules(t *testing.T) {
	l, clk := rig(t)
	call(t, l, bridgeproto.OpState, bridgeproto.State{OwnerLine: bridgeproto.StateDown}, nil)
	l.Send(ownerNum, "missed")
	call(t, l, bridgeproto.OpState, bridgeproto.State{OwnerLine: bridgeproto.StateOK}, nil)
	rec := poll(t, l)
	call(t, l, bridgeproto.OpSent, bridgeproto.Sent{ID: rec.ID, Code: bridgeproto.CodeOK}, nil)
	if n := len(l.out); n != 0 {
		t.Fatalf("%d items out after the recovery text's result", n)
	}
	done := sendAsync(l, ownerNum, "waited for")
	it := poll(t, l)
	clk.add(time.Hour) // the fake clock: only the waiter's own timer ends it
	l.mu.Lock()
	l.expireLocked(clk.now())
	_, held := l.out[it.ID]
	l.mu.Unlock()
	if !held {
		t.Fatal("a waiter's item expired on the recovery text's deadline")
	}
	call(t, l, bridgeproto.OpSent, bridgeproto.Sent{ID: it.ID, Code: bridgeproto.CodeOK}, nil)
	if err := <-done; err != nil {
		t.Fatalf("send: %v", err)
	}
}
