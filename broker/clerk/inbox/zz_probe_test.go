package inbox

// REQ: KRN-8

// Its own file, named to sort last, keeps mutgate's reach on the tests that
// run before it unchanged.

import (
	"testing"

	"github.com/ghbmrk/agentos/broker/kernel"
	"github.com/ghbmrk/agentos/broker/kernel/key"
)

// Once an organize has been sent MaxChecks times unconfirmed, the clerk's own
// Probe says unknown, not notdone: the cap holds in the clerk, whatever the
// kernel's own count does (inbox.go Probe). Before #6429 the cap was its own
// switch case whose return could be deleted with no effect (an empty case
// also ends the switch); it is now part of the notdone case's condition.
func TestProbeSaysUnknownOnceMaxChecksAreSent(t *testing.T) {
	box := &failingBox{}
	r := newRigOn(t, World{}, []Mail{{ID: "M", Raw: []byte(rawMail("", "a@b.test", "Hi")), Class: "personal"}}, box, 30)
	p := r.step("o", key.Organize, map[string]string{"target": "M", "label": "agentOS/personal"})
	ticks := []int64{}
	for i := int64(1); i <= 2*kernel.MaxChecks; i++ {
		ticks = append(ticks, t0+i*kernel.ProbeEvery)
	}
	r.run(t, p, ticks...)
	if box.calls != kernel.MaxChecks {
		t.Fatalf("%d mailbox calls, want %d", box.calls, kernel.MaxChecks)
	}
	if got := r.acct.Probe(kernel.Request{Plan: p}, r.k.State()).Outcome; got != "unknown" {
		t.Fatalf("probe %q after %d unconfirmed sends, want unknown", got, kernel.MaxChecks)
	}
}
