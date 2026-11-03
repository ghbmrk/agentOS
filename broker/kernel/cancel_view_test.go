package kernel_test

// REQ: KRN-8, LOG-4, PLN-1

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/kernel"
	"github.com/ghbmrk/agentos/broker/kernel/key"
)

// A cancelled plan leaves the spendheld read, by an owner cancel and by an
// erase alike, while a held plan still active stays listed: an ended plan's
// hold waits on no Extend, which answers not-held (#4807). The hold itself
// stays in SpendHeld, so a honey-key Extend naming the plan still pauses its
// scope. The view names each cancel's fixed code and nothing of the erase:
// no subject, item, lineage or time (PLN-1, LOG-4, #4812). Catches a cancel
// that leaves its plan listed as held, a read that drops a live hold, and a
// view that omits the code or carries the cancel's detail.
func TestACancelledPlanLeavesHeldAndItsViewNamesTheCode(t *testing.T) {
	r := newRig(t)
	if _, err := r.k.OpenContent(kernel.NewMemKeys(), map[string]kernel.ContentStore{"mail": kernel.NewMemContent()}, 0); err != nil {
		t.Fatal(err)
	}
	sub, err := r.k.OpenSubject(0)
	must(t, err)
	h, err := r.k.Seal(0, sub, "mail", "message", []byte("lunch on Tuesday"))
	must(t, err)
	if _, err := r.k.ReadFor(1, h, "agent"); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"agent/erased", "owner", "live"} {
		modelPlan(r, id, modelKey(r, "m-"+id, key.LimitSpendTask(100)))
		exhaust(r, id, 100)
	}
	must(t, r.k.Cancel(3, "owner"))
	const erasedAt = 7777
	if _, err := r.k.Erase(erasedAt, sub); err != nil {
		t.Fatal(err)
	}
	s := r.k.State()
	if got := s.Held(); len(got) != 1 || got["live"] != s.SpendHeld["live"] {
		t.Fatalf("held lists %v, want only the live plan", got)
	}
	if len(s.SpendHeld) != 3 {
		t.Fatalf("an ended plan's hold left SpendHeld: %v", s.SpendHeld)
	}
	for id, code := range map[string]string{"agent/erased": kernel.CErased, "owner": "owner"} {
		v := s.PlanView(id)
		if v.Status != kernel.SCancelled || v.Cancel != code {
			t.Errorf("%s: view %+v, want cancelled with code %q", id, v, code)
		}
	}
	b, err := json.Marshal(s.PlanView("agent/erased"))
	must(t, err)
	for _, leak := range []string{sub, hex.EncodeToString(h[:]), "agent", strconv.Itoa(erasedAt), "message"} {
		if strings.Contains(string(b), leak) {
			t.Errorf("the erased plan's view %s names %q", b, leak)
		}
	}
	if v := s.PlanView("live"); v.Status != kernel.SActive || v.Cancel != "" {
		t.Errorf("a live plan's view %+v", v)
	}
	r.replays()
}

// An erase logged between a plan's submission and its decision cancels the
// pending plan in its own fold, and the accept after it then folds to
// nothing and is a divergence, so a plan that may carry what the read gave
// never goes active. The kernel never writes this order (Submit decides at
// once, Boot decides every pending plan before anything else is logged), so
// the log is built by moving the kernel's own erase entry before the accept;
// the branch is the fold's guard on a log the kernel did not write (LOG-4,
// #4807). Catches State.cancel ignoring a pending plan.
func TestAnEraseBeforeTheDecisionCancelsThePendingPlan(t *testing.T) {
	r := newRig(t)
	if _, err := r.k.OpenContent(kernel.NewMemKeys(), map[string]kernel.ContentStore{"mail": kernel.NewMemContent()}, 0); err != nil {
		t.Fatal(err)
	}
	sub, err := r.k.OpenSubject(0)
	must(t, err)
	h, err := r.k.Seal(0, sub, "mail", "message", []byte("x"))
	must(t, err)
	if _, err := r.k.ReadFor(1, h, "agent"); err != nil {
		t.Fatal(err)
	}
	r.plan("agent/p", r.derive(key.LimitHold(hour, hour)), st(key.Unsubscribe, "m1"))
	if _, err := r.k.Erase(2, sub); err != nil {
		t.Fatal(err)
	}
	es := r.k.Log().Entries()
	i := slices.IndexFunc(es, func(e kernel.Entry) bool { return e.Type == kernel.TPlanSubmit })
	if i < 0 || es[i+1].Type != kernel.TPlanAccepted || es[i+2].Type != kernel.TSubjectErased {
		t.Fatal("the log does not run submit, accept, erase")
	}
	moved := append(append(slices.Clone(es[:i+1]), es[i+2]), es[i+1])
	for j := range moved {
		moved[j].Seq = uint64(j + 1)
	}
	s, err := kernel.Replay(r.anchors(), moved)
	must(t, err)
	if p := s.Plans["agent/p"]; p.Status != kernel.SCancelled || p.Cancel != kernel.CErased || len(p.Steps) != 0 {
		t.Fatalf("the plan pending at the erase is %s (%q), %d steps", p.Status, p.Cancel, len(p.Steps))
	}
	var d *kernel.Divergence
	if _, err := kernel.Rederive(r.anchors(), r.k.Box(), moved); !errors.As(err, &d) || d.Seq != uint64(i+3) || d.Type != kernel.TPlanAccepted {
		t.Fatalf("the accept after the erase: %v", err)
	}
}
