package journal

import "testing"

// REQ: RES-1

// PE7 (condition 2): the sleeper never stops the agent while an intent the
// agent submitted is authorized but not dispatched, or in flight. The
// owner's and the broker's intents do not count, nor does a finished one.
func TestGuestActive(t *testing.T) {
	svc := newService()
	e := mustOpen(t, &MemStore{}, newPolicy(), svc)
	if e.GuestActive() {
		t.Fatal("an empty journal is active")
	}
	owner := intent("o", "acct")
	must(e.Submit(owner))
	must(e.Authorize(ctx, "o"))
	if e.GuestActive() {
		t.Fatal("an owner intent counted as the agent's")
	}
	g := intent("g", "acct2")
	g.Origin = "guest:lin-1"
	must(e.Submit(g))
	if e.GuestActive() {
		t.Fatal("a submitted intent not yet authorized counted")
	}
	must(e.Authorize(ctx, "g"))
	if !e.GuestActive() {
		t.Fatal("an authorized guest intent not counted")
	}
	inFlight := false
	svc.onExecute = func(in Intent, _ int) {
		if in.ID == "g" {
			inFlight = e.GuestActive()
		}
	}
	must(e.Dispatch(ctx, "g"))
	if !inFlight {
		t.Fatal("a guest intent in flight not counted")
	}
	if e.GuestActive() {
		t.Fatal("a finished guest intent still counted")
	}
}
