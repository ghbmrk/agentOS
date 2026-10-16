package loops

// REQ: OP-7, QCR-4, QCR-5

import (
	"testing"

	"github.com/ghbmrk/agentos/broker/change"
	"github.com/ghbmrk/agentos/broker/journal"
)

// spyCases is the real pipeline's suite, with each case Harvest added and
// what the pipeline answered.
type spyCases struct {
	p    *change.Pipeline
	got  []change.Case
	errs []error
}

func (s *spyCases) AddTaskCase(c change.Case) error {
	err := s.p.AddTaskCase(c)
	s.got, s.errs = append(s.got, c), append(s.errs, err)
	return err
}

func (s *spyCases) Dev(cl change.Class) []change.Case { return s.p.Dev(cl) }

// explicit counts the owner's own cases in the evidence, held out or dev.
func explicit(t *testing.T, h *Harvester) int {
	t.Helper()
	ev, err := h.Evidence()
	must(t, err)
	return ev.Explicit + len(ev.Dev)
}

// QCR-4: a later owner action on the same intent (UNDO after YES) reaches
// the suite and wakes the scheduler; a restated one does nothing; an
// owner's case replacing a silent acceptance counts in full.
func TestHarvestAppliesALaterOwnerAction(t *testing.T) {
	r := newRig(t)
	cs := &spyCases{p: r.p}
	wakes := 0
	h := &Harvester{J: r.eng, Pipeline: cs, Store: &change.MemStore{}, Wake: func() { wakes++ }}
	r.task("t1", "g1", "mail", "send", "private")
	out := Outcome{Intent: "t1", Action: Approved, Input: []byte("reply to Sam"), Output: []byte("ok")}
	must(t, h.Harvest(out))
	out.Action = Undone
	must(t, h.Harvest(out))
	if n := len(cs.got); n != 2 || cs.errs[1] != nil || cs.got[1].Outcome != change.Rejected {
		t.Fatalf("UNDO after YES not applied: %d cases, %v", n, cs.errs)
	}
	if wakes != 2 {
		t.Fatalf("wakes = %d, want 2", wakes)
	}
	must(t, h.Harvest(out))
	if wakes != 2 {
		t.Fatal("a restated action woke the scheduler")
	}

	r.task("t2", "g2", "mail", "send", "private")
	must(t, h.Harvest(Outcome{Intent: "t2", Action: Implicit, Input: []byte("task"), Output: []byte("reply")}))
	before := explicit(t, h)
	must(t, h.Harvest(Outcome{Intent: "t2", Action: Approved, Input: []byte("task"), Output: []byte("reply")}))
	if got := explicit(t, h); got != before+1 {
		t.Fatalf("owner case over an implicit one: explicit %d -> %d", before, got)
	}
}

// QCR-5: silence never revises an owner's verdict: an implicit acceptance
// on an intent the owner already answered records nothing and adds no
// case.
func TestImplicitNeverSupersedesOwnerCase(t *testing.T) {
	r := newRig(t)
	cs := &spyCases{p: r.p}
	h := &Harvester{J: r.eng, Pipeline: cs, Store: &change.MemStore{}}
	r.task("t1", "g1", "mail", "send", "private")
	must(t, h.Harvest(Outcome{Intent: "t1", Action: Denied, Input: []byte("task"), Output: []byte("reply")}))
	must(t, h.Harvest(Outcome{Intent: "t1", Action: Implicit, Input: []byte("task"), Output: []byte("reply")}))
	st, err := r.eng.Get("t1")
	must(t, err)
	if st.Quality.Verdict != journal.VerdictWrong || st.Quality.Source != "owner" {
		t.Fatalf("silence revised the owner's verdict: %+v", st.Quality)
	}
	if len(cs.got) != 1 {
		t.Fatalf("implicit case offered over the owner's: %+v", cs.got)
	}
}
