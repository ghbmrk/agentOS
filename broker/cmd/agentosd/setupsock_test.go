package main

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/localapi"
	"github.com/ghbmrk/agentos/broker/sockets"
)

// REQ: HW-1, ARC-2, ARC-1, CH-7

// HW-1, #1115, #1330: in production the card step runs in
// agentos-localui, so setup mode's card is the page's hold over
// localui.sock: finish answers "card pending" until a finish carries the
// page's report that the card is confirmed, and finishes with it, in one
// call. page_setup_card is not served.
func TestFinishTakesThePageCard(t *testing.T) {
	m := newBareSetupMode(t)
	m.Card = pageCardStep
	done := start(context.Background(), m)
	call := setupCall(t, m)
	var l localapi.EnrollLink
	if err := call(localapi.OpSetupEnroll, nil, &l); err != nil {
		t.Fatal(err)
	}
	var ok localapi.Confirmed
	if err := call(localapi.OpSetupConfirm, localapi.Confirm{Code: "123456"}, &ok); err != nil || !ok.OK {
		t.Fatalf("confirm %v %v", err, ok)
	}
	finish := func(card bool) error {
		return call(localapi.OpSetupFinish, localapi.Finish{Owner: "+15550100100", Card: card}, nil)
	}
	if err := finish(false); err == nil || !strings.Contains(err.Error(), localapi.ErrCardPending) {
		t.Fatalf("finish without the card: %v", err)
	}
	if err := call("page_setup_card", map[string]bool{"confirmed": true}, nil); err == nil || !strings.Contains(err.Error(), string(sockets.ErrUnknownOp)) {
		t.Fatalf("page_setup_card served: %v", err)
	}
	if err := finish(false); err == nil || !strings.Contains(err.Error(), localapi.ErrCardPending) {
		t.Fatalf("finish after the old report op: %v", err)
	}
	finish(true)
	select {
	case r := <-done:
		if r.err != nil || r.owner != "+15550100100" {
			t.Fatalf("run %q %v", r.owner, r.err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("setup did not end at finish")
	}
}

// A card step handed in by a test or another builder takes no report:
// finish's card is ignored and its own hold decides.
func TestOnlyThePagesHoldTakesReports(t *testing.T) {
	m, f := newCardSetup(t)
	done := start(context.Background(), m)
	f.step(t)
	call := setupCall(t, m)
	var l localapi.EnrollLink
	if err := call(localapi.OpSetupEnroll, nil, &l); err != nil {
		t.Fatal(err)
	}
	var ok localapi.Confirmed
	if err := call(localapi.OpSetupConfirm, localapi.Confirm{Code: "123456"}, &ok); err != nil || !ok.OK {
		t.Fatalf("confirm %v %v", err, ok)
	}
	err := call(localapi.OpSetupFinish, localapi.Finish{Owner: "+15550100100", Card: true}, nil)
	if err == nil || !strings.Contains(err.Error(), localapi.ErrCardPending) {
		t.Fatalf("a report was taken for a step the page does not hold: %v", err)
	}
	_ = done
}
