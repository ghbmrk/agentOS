package main

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/localapi"
)

// REQ: HW-1, ARC-2

// HW-1, #1115: in production the card step runs in agentos-localui, so
// setup mode's card is the page's hold over localui.sock: finish answers
// "card pending" until the page reports the card confirmed, and finishes
// after. A report of an unconfirmed card is refused and holds nothing.
func TestThePageReportsTheCardOverTheSocket(t *testing.T) {
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
	finish := func() error {
		return call(localapi.OpSetupFinish, localapi.Finish{Owner: "+15550100100"}, nil)
	}
	if err := finish(); err == nil || !strings.Contains(err.Error(), localapi.ErrCardPending) {
		t.Fatalf("finish before the report: %v", err)
	}
	if err := call(localapi.OpSetupCard, localapi.SetupCard{}, nil); err == nil {
		t.Fatal("an unconfirmed report was taken")
	}
	if err := finish(); err == nil || !strings.Contains(err.Error(), localapi.ErrCardPending) {
		t.Fatalf("finish after an unconfirmed report: %v", err)
	}
	if err := call(localapi.OpSetupCard, localapi.SetupCard{Confirmed: true}, nil); err != nil {
		t.Fatal(err)
	}
	finish()
	select {
	case r := <-done:
		if r.err != nil || r.owner != "+15550100100" {
			t.Fatalf("run %q %v", r.owner, r.err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("setup did not end at finish")
	}
}

// A card step handed in by a test or another builder serves no report op:
// only the page's hold takes reports.
func TestOnlyThePagesHoldTakesReports(t *testing.T) {
	m, f := newCardSetup(t)
	done := start(context.Background(), m)
	f.step(t)
	call := setupCall(t, m)
	if err := call(localapi.OpSetupCard, localapi.SetupCard{Confirmed: true}, nil); err == nil {
		t.Fatal("a report was taken for a step the page does not hold")
	}
	_ = done
}
