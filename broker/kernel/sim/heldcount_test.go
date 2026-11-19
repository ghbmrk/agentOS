package sim

// REQ: KEY-8

import (
	"math"
	"math/rand/v2"
	"testing"

	"github.com/ghbmrk/agentos/broker/clerk"
	"github.com/ghbmrk/agentos/broker/kernel"
	"github.com/ghbmrk/agentos/broker/kernel/key"
)

// noUses is a ledger with no use under any key.
type noUses struct{}

func (noUses) Uses(key.ID) []key.Use { return nil }

// ledgered is heldView with that ledger, so a key with caps can be checked.
type ledgered struct{ heldView }

func (ledgered) LedgerBefore(uint64) key.Ledger { return noUses{} }

// The world counts a step as held back by the clerk only when the clerk
// refused it for its hold: a refusal for anything else is not one, and
// neither is judged an effect; a step past its hold acts once (#6023).
func TestTheWorldCountsOnlyTheClerksHolds(t *testing.T) {
	rng := rand.New(rand.NewPCG(1, 2))
	owner, holder := gen(rng), gen(rng)
	root := key.Issue(owner.pass, key.Root{Clerk: "mail", Verbs: []key.Verb{key.Post}, Serial: "h1"})
	ck, err := key.ClerkKey(root, owner.pass, holder.pub, 0, 1<<40)
	if err != nil {
		t.Fatal(err)
	}
	hk, err := key.Derive(ck, holder.priv, holder.pub, key.LimitHold(hour, hour))
	if err != nil {
		t.Fatal(err)
	}
	now := 10 * hour
	w := &world{anchors: []key.PublicKey{owner.pk}, now: &now, reads: &[2]int64{math.MaxInt64, math.MinInt64}, done: map[string]bool{}, dead: map[key.ID]bool{}}
	w.mail = clerk.NewMail("mail", w.anchors)
	w.mail.Clock = func() int64 { return now }
	post := func(id, clerkName string) kernel.Request {
		return kernel.Request{Plan: kernel.SignPlan(kernel.Plan{ID: id, Key: hk, Steps: []kernel.PlanStep{{Verb: key.Post, Clerk: clerkName, Args: map[string]string{"to": "alice", "msg": "hi"}}}}, holder.priv)}
	}
	if res := w.do(post("unheld", "mail"), ledgered{}); res.Outcome != "failed" || w.held != 1 {
		t.Fatalf("a step the clerk held back: %+v, held %d", res, w.held)
	}
	if res := w.do(post("elsewhere", "bank"), ledgered{}); res.Outcome != "failed" || w.held != 1 {
		t.Fatalf("a step refused for its clerk: %+v, held %d", res, w.held)
	}
	if len(w.done) != 0 || len(w.bad) != 0 {
		t.Fatalf("refused steps judged as effects: %v %v", w.done, w.bad)
	}
	past := ledgered{heldView{kernel.Dispatch{Held: true, HeldAt: now - 2*hour}}}
	if res := w.do(post("due", "mail"), past); res.Outcome != "ok" || w.held != 1 || len(w.done) != 1 || len(w.bad) != 0 {
		t.Fatalf("a step past its hold: %+v, held %d, judged %v %v", res, w.held, w.done, w.bad)
	}
}
