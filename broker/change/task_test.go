package change

import (
	"testing"

	"github.com/ghbmrk/agentos/broker/journal"
)

// REQ: CHG-1
//
// A task case (ClassTask, Loop 1's harvest of owner outcomes) is evidence
// for every change to how tasks are done, and for none that is not.

func TestTaskCasesAreEvidenceForEveryTaskClass(t *testing.T) {
	e := newEnv(t, nil)
	// The split key is random: add cases until both sides have some.
	n := 0
	for n < 12 || len(e.p.Dev(ClassTask)) == 0 || n-len(e.p.Dev(ClassTask)) < 3 {
		e.taskCase(ClassTask, "procedures/file", "v2", Corrected)
		n++
	}
	dev := len(e.p.Dev(ClassTask))
	for _, c := range []Class{ClassProcedure, ClassSkill, ClassRouting, ClassContext, ClassConfig} {
		if got := len(e.p.Dev(c)); got != dev {
			t.Fatalf("Dev(%s) has %d task cases, Dev(task) %d", c, got, dev)
		}
	}
	// A procedure change is evaluated on the held-out task cases.
	rep := e.propose(Candidate{Files: Tree{"procedures/file": []byte("v2")}})
	if rep.HeldOut != n-dev || rep.State != StateAdopted || rep.Passed != rep.HeldOut || rep.BaselinePassed != 0 {
		t.Fatalf("report %+v with %d held-out task cases", rep, n-dev)
	}
	st, err := e.eng.Get("task-1")
	if err != nil || st.Quality.Verdict != journal.VerdictWrong {
		t.Fatalf("task quality %+v, %v", st.Quality, err)
	}
}
