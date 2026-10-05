package grants

import "testing"

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
