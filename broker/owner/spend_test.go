package owner

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/modem"
)

// REQ: CH-15 (#1685)
// Spend checks the hour and counts a request text in one hold of c.mu,
// so a NotifyNow after it sees the hour spent, and the request sent
// later on that spend is not counted again: with an allowance of 1,
// exactly one text goes. Once spent, a paced Spend is refused; an
// unpaced one (an urgent or re-issued request) is not.
func TestSpendChecksAndCountsInOneStep(t *testing.T) {
	r, _, open := raceRig(t, 1)
	open()
	at, ok := r.ch.Spend(true)
	if !ok {
		t.Fatal("Spend refused with the hour's text left")
	}
	if r.ch.checkedIn != r.ch.countedIn {
		t.Fatal("Spend checked and counted in separate holds")
	}
	if err := r.ch.NotifyNow("Q1 asks: which time?"); !errors.Is(err, ErrPaced) {
		t.Fatalf("NotifyNow after a spend: %v, want ErrPaced", err)
	}
	if _, ok := r.ch.Spend(true); ok {
		t.Fatal("paced Spend granted past the hour")
	}
	if _, err := r.ch.Request([]Item{lowItem("m0")}, 0); err != nil {
		t.Fatal(err)
	}
	r.ch.Refund(at) // spent by the request: nothing to return
	if got := r.sentTexts(); len(got) != 1 || strings.Contains(got[0], "Q1 asks") {
		t.Fatalf("sent %q, want only the request", got)
	}
	if n := len(r.ch.codes.st.Sent); n != 1 {
		t.Fatalf("%d texts counted for one request, want 1", n)
	}
	if _, ok := r.ch.Spend(false); !ok {
		t.Fatal("unpaced Spend refused")
	}
}

// REQ: CH-15 (#1685)
// A spend whose text did not go is returned: Refund uncounts a spend no
// request used, and a request that provably did not go uncounts its
// spend as an unspent text is uncounted. Two spends, one request sent:
// one text counted.
func TestRefundReturnsOnlyUnusedSpends(t *testing.T) {
	r, _, open := raceRig(t, 3)
	open()
	a, _ := r.ch.Spend(true)
	b, _ := r.ch.Spend(true)
	if got := r.ch.Allowance(r.clock()); got != 1 {
		t.Fatalf("allowance %d after two spends of 3, want 1", got)
	}
	if _, err := r.ch.Request([]Item{lowItem("m0")}, 0); err != nil {
		t.Fatal(err)
	}
	r.ch.Refund(a)
	r.ch.Refund(b)
	if got := r.ch.Allowance(r.clock()); got != 2 {
		t.Fatalf("allowance %d after one request sent of 3, want 2", got)
	}

	f, g, open2 := raceRig(t, 1)
	open2()
	g.fail = modem.ErrNotSent
	at, _ := f.ch.Spend(true)
	if _, err := f.ch.Request([]Item{lowItem("m1")}, 0); err == nil {
		t.Fatal("request sent through a failing modem")
	}
	f.ch.Refund(at)
	if got := f.ch.Allowance(f.clock()); got != 1 {
		t.Fatalf("allowance %d after an unsent request, want 1", got)
	}
}

// REQ: CH-15 (#1685)
// The restamp variant: an urgent text inside the modem when the gate
// reads its clock is settled to a later time before the gate asks.
// Spend reads the clock under c.mu, so the restamped send is in its hour
// and the request is refused: exactly one text goes.
func TestSpendSeesARestampedSend(t *testing.T) {
	r, g, open := raceRig(t, 1)
	defer open()
	wait := inFlight(t, g, func() error { return r.ch.Post(ClassSecurity, "Security alert.") })
	_ = r.clock() // the gate's clock read
	r.advance(2 * time.Minute)
	open()
	if err := wait(); err != nil {
		t.Fatal(err)
	}
	if _, ok := r.ch.Spend(true); ok {
		t.Fatal("Spend granted beside a restamped send")
	}
	if got := r.sentTexts(); len(got) != 1 {
		t.Fatalf("sent %q, want only the alert", got)
	}
}

// REQ: CH-15 (#1685)
// A send that outlives the hour is still counted when it returns: its
// count was pruned from the hour by another count while it was in the
// modem, so settle counts it again at the time it went.
func TestSendOutlivingTheHourIsCounted(t *testing.T) {
	r, g, open := raceRig(t, 2)
	defer open()
	wait := inFlight(t, g, func() error { return r.ch.Post(ClassSecurity, "Security alert.") })
	r.advance(61 * time.Minute)
	if err := r.ch.Post(ClassSecurity, "Second alert."); err != nil {
		t.Fatal(err)
	}
	open()
	if err := wait(); err != nil {
		t.Fatal(err)
	}
	if a := r.ch.Allowance(r.clock()); a != 0 {
		t.Fatalf("allowance %d after two texts in the hour, want 0", a)
	}
}
