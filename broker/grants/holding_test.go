package grants

import (
	"testing"

	"github.com/ghbmrk/agentos/broker/owner"
)

// REQ: RES-1

// PE7 (condition 2): the sleeper does not stop the agent while the gate
// holds an effect the agent asked for (waiting on the owner, batched,
// held for its undo window, carried over a restart). The broker's own
// intents do not count.
func TestHoldingCountsTheAgentsHeldEffects(t *testing.T) {
	r := newRig(t, nil)
	r.grant(mailGrant())
	if r.g.Holding() {
		t.Fatal("a grant the owner confirmed is still held")
	}
	r.ver.set("inv-1042", sam())
	r.effect("agent/s1", "invoice.send", map[string]any{"record": "inv-1042", "template": "invoice"}, "sam@example.com")
	if !r.g.Holding() {
		t.Fatal("an effect batched for the owner is not held")
	}
	r.g.Flush()
	if !r.g.Holding() {
		t.Fatal("an effect waiting on the owner's answer is not held")
	}
	r.open() // a restart carries it
	if !r.g.Holding() {
		t.Fatal("an effect carried over a restart is not held")
	}
	r.g.Flush()
	r.decide(false, "no")
	if r.g.Holding() {
		t.Fatal("a declined effect is still held")
	}
}

// PE7 (condition 2, L3 on #149): each place the gate holds an agent's
// effect keeps the agent awake on its own: waiting, batched, carried,
// reissued, held for its undo window, being sent, and approved for the
// local page but not yet confirmed.
func TestHoldingCountsEachPlaceAnEffectWaits(t *testing.T) {
	r := newRig(t, nil)
	r.grant(mailGrant())
	r.ver.set("inv-1042", sam())
	id := r.effect("agent/s1", "invoice.send", map[string]any{"record": "inv-1042", "template": "invoice"}, "sam@example.com").Intent.ID
	g := r.g
	clear := func() {
		g.waiting, g.batch, g.carried, g.reissue = map[string]*wait{}, nil, map[string]bool{}, nil
		g.after, g.sending, g.decided, g.confirmed = map[string]afterRef{}, map[string]pending{}, map[string]decision{}, map[string]bool{}
	}
	for name, put := range map[string]func(){
		"waiting":       func() { g.waiting[id] = &wait{} },
		"batch":         func() { g.batch = []string{id} },
		"carried":       func() { g.carried[id] = true },
		"reissue":       func() { g.reissue = []owner.Carried{{Ref: id}} },
		"after":         func() { g.after[id] = afterRef{} },
		"sending":       func() { g.sending[id] = pending{} },
		"decided local": func() { g.decided[id] = decision{approved: true, local: true} },
	} {
		g.mu.Lock()
		clear()
		put()
		g.mu.Unlock()
		if !g.Holding() {
			t.Errorf("%s: not held", name)
		}
	}
	g.mu.Lock()
	clear()
	g.decided[id] = decision{approved: true, local: true}
	g.confirmed[id] = true
	g.mu.Unlock()
	if g.Holding() {
		t.Error("a confirmed local decision is still held")
	}
}
