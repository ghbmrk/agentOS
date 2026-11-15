package kernel_test

// REQ: KEY-9, KEY-8, KEY-4

import (
	"errors"
	"testing"

	"github.com/ghbmrk/agentos/broker/clerk/check"
	"github.com/ghbmrk/agentos/broker/kernel"
	"github.com/ghbmrk/agentos/broker/kernel/key"
)

// A new key worth rank 3 (identity, safety or uncapped money) asks the
// hardware key even when it is not big, so its batch needs the co-sign
// (KEY-9, Mark 2026-11-07 in #4999). A rank-1 key the line calls small
// does not; a grant already in the log, or a same-limit renewal of a rank-3
// clerk key, widens nothing and is not priced again.
func TestARankThreeGrantNeedsTheHardwareKey(t *testing.T) {
	r := newRig(t)
	acct := func(serial string) key.Key {
		return key.Issue(r.owner.pass, key.Root{Clerk: "mail", Verbs: []key.Verb{key.ChangeAccount}, Serial: serial})
	}
	first := acct("a1")
	ck, err := key.ClerkKey(first, r.owner.pass, r.holder.pub, 0, 10)
	must(t, err)
	must(t, r.issue(0, first, ck)) // a new verb: big, co-signed
	live := kernel.GrantHold
	second := acct("a2") // the verb is live now, so the line calls it small
	if err := r.k.Issue(live, nil, second); !errors.Is(err, kernel.ErrNeedsCosign) {
		t.Fatalf("a rank-3 root with one tap: %v", err)
	}
	if err := r.issue(live, second); err != nil {
		t.Fatalf("a rank-3 root with the hardware key: %v", err)
	}
	small := key.Issue(r.owner.pass, key.Root{Clerk: "mail", Verbs: []key.Verb{key.Trash}, Serial: "t"})
	if err := r.k.Issue(live, nil, small); err != nil {
		t.Fatalf("a rank-1 root asks only the tap: %v", err)
	}
	if err := r.k.Issue(live, nil, first); err != nil {
		t.Fatalf("a root already granted: %v", err)
	}
	renew, err := key.ClerkKey(first, r.owner.pass, r.holder.pub, live+hour, 10)
	must(t, err)
	if err := r.k.Issue(live+hour, nil, renew); err != nil {
		t.Fatalf("a same-limit renewal of a rank-3 clerk key: %v", err)
	}
	wider, err := key.ClerkKey(first, r.owner.pass, r.holder.pub, live+hour, 20)
	must(t, err)
	if err := r.k.Issue(live+hour, nil, wider); !errors.Is(err, kernel.ErrNeedsCosign) {
		t.Fatalf("a raised rank-3 clerk key with one tap: %v", err)
	}
}

// A held step waits its key's window plus the worth of what that step
// reaches (KEY-8, KEY-9): under one capped key with no hold of its own, an
// unsubscribe (data) runs at once and a buy (capped money) waits an hour.
func TestAHeldStepWaitsItsOwnWorth(t *testing.T) {
	r := newRig(t)
	ck := r.grant(key.Issue(r.owner.pass, key.Root{Clerk: "mail", Verbs: []key.Verb{key.Buy, key.Unsubscribe}, Serial: "w"}), 1<<40)
	r.plan("low", ck, st(key.Unsubscribe, "list-a"))
	buy := st(key.Buy, "shop")
	buy.Args["amount"] = "10"
	r.plan("buy", ck, buy)
	must(t, r.tick(0))
	if n := len(r.mail.Effects()); n != 1 {
		t.Fatalf("at once: %d effects, want the unsubscribe alone", n)
	}
	must(t, r.tick(hour-1))
	if n := len(r.mail.Effects()); n != 1 {
		t.Fatalf("inside the buy's hour: %d effects", n)
	}
	must(t, r.tick(hour))
	if n := len(r.mail.Effects()); n != 2 {
		t.Fatalf("after the buy's hour: %d effects, want 2", n)
	}
}

// The clerk keeps a capped buy's priced hour on its own clock (KEY-9, CLK-2).
func TestClerkKeepsThePricedHoldWhenTheKernelClockRunsAhead(t *testing.T) {
	r := newRig(t)
	ck := r.grant(key.Issue(r.owner.pass, key.Root{Clerk: "mail", Verbs: []key.Verb{key.Buy}, Serial: "pb"}), 1<<40)
	buy := st(key.Buy, "shop")
	buy.Args["amount"] = "10"
	r.plan("p1", ck, buy)
	must(t, r.tick(0))
	r.now = hour / 2
	must(t, r.k.Tick(2*hour))
	if len(r.mail.Effects()) != 0 || r.status("p1") != kernel.SFailed {
		t.Fatalf("status %s, %d effects", r.status("p1"), len(r.mail.Effects()))
	}
	if d := r.k.State().Plans["p1"].Steps[0].Detail; d != check.RHold {
		t.Fatalf("detail %q", d)
	}
}

// An irreversible step whose hold, worth term included, is zero is never
// held: a rank-1 post under a clerk key with no KEY-8 window runs at once
// (KEY-8, KEY-9).
func TestAZeroHoldIsNoHold(t *testing.T) {
	r := newRig(t)
	ck := r.grant(key.Issue(r.owner.pass, key.Root{Clerk: "mail", Verbs: []key.Verb{key.Post}, Serial: "z1"}), 1<<40)
	r.plan("p1", ck, st(key.Post, "alice"))
	if a := kernel.Next(r.k.State(), "p1", hour); a.Kind != kernel.ActDispatch {
		t.Fatalf("a post with no window: act %+v", a)
	}
	must(t, r.tick(hour))
	if s := r.k.State().Plans["p1"].Steps[0]; s.HeldSeq != 0 || len(r.mail.Effects()) != 1 {
		t.Fatalf("a post with no window: %+v, %d effects", s, len(r.mail.Effects()))
	}
}
