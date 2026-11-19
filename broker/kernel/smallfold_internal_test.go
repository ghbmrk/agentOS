package kernel

// Guards of the code-approval, line and suite and task folds (#6256): each
// test fails when its one check is dropped or moved by one, and reaches
// only the fold it pins, so mutgate's reach scope stays on these files.
// REQ: CH-4, KEY-4, KRN-1

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"testing"

	"github.com/ghbmrk/agentos/broker/kernel/key"
)

// Every fold of a code approval, a security-suite entry or a task entry
// refuses a body it cannot read, so a replay stops at a corrupt entry
// rather than folding it as an empty one (KRN-1).
func TestASmallFoldRefusesABodyItCannotRead(t *testing.T) {
	folds := map[string]func(*State, Entry) error{
		TCodeApproved: (*State).applyCode,
		TSecurityCase: (*State).applySecurity, TSecurityDrop: (*State).applySecurity, TSecurityKept: (*State).applySecurity,
		TTaskOpened: (*State).applyTask, TTaskApproved: (*State).applyTask, TTaskEnded: (*State).applyTask,
	}
	for typ, fold := range folds {
		err := fold(NewState(nil), Entry{Seq: 1, Type: typ, Body: json.RawMessage(`"x"`)})
		if !errors.Is(err, ErrCorrupt) {
			t.Fatalf("%s with an unreadable body: %v", typ, err)
		}
	}
}

// A code approval names one to MaxCodeSteps held steps: the checker's
// signature over none approves nothing, one over exactly MaxCodeSteps
// passes, and one over a step more does not (CH-4).
func TestACodeApprovalNamesOneToMaxCodeSteps(t *testing.T) {
	checker := seedKey(40)
	s := NewState(nil)
	var steps []CodeStep
	for i := range MaxCodeSteps + 1 {
		p := Plan{ID: fmt.Sprintf("p%d", i), Steps: []PlanStep{{Verb: key.Unsubscribe, Clerk: "mail", Args: map[string]string{"list": fmt.Sprint(i)}}}}
		s.Plans[p.ID] = &PlanState{Plan: p, Status: SActive, Steps: []StepState{{Phase: PHeld}}}
		steps = append(steps, CodeStepOf(p, 0))
	}
	for _, c := range []struct {
		n    int
		want bool
	}{{0, false}, {1, true}, {MaxCodeSteps, true}, {MaxCodeSteps + 1, false}} {
		if got := s.codeOK(SignCode(checker, steps[:c.n])); got != c.want {
			t.Fatalf("an approval naming %d steps: %v, want %v", c.n, got, c.want)
		}
	}
}

// The line is at least 100%: exactly 100% passes with no passkey, and so
// does the line it already is, which raises nothing (KEY-4).
func TestTheLineTakesItsBoundsWithoutAPasskey(t *testing.T) {
	s := NewState(nil)
	for _, c := range []struct {
		pct  int64
		want error
	}{{99, ErrLine}, {100, nil}, {DefaultLine, nil}, {DefaultLine + 1, ErrNeedsCosign}} {
		if err := s.lineOK(lineSet{Percent: c.pct}); !errors.Is(err, c.want) {
			t.Fatalf("a line of %d%%: %v, want %v", c.pct, err, c.want)
		}
	}
}

// A one-off's line is the largest daily cap times the line, and a cap too
// large for that product saturates at MaxInt64 instead of wrapping; the
// largest cap that fits is multiplied exactly (KEY-4).
func TestAOneOffLineSaturatesOnlyPastWhatFits(t *testing.T) {
	fits := int64(math.MaxInt64 / DefaultLine)
	root := key.Key{Root: key.Root{Clerk: "mail", Verbs: []key.Verb{key.Buy}, Serial: "b"}}
	for _, c := range []struct{ day, want int64 }{
		{fits, fits * DefaultLine / 100},
		{fits + 1, math.MaxInt64},
	} {
		s := NewState(nil)
		k := key.Key{Root: root.Root, Links: []key.Link{{Caveats: []key.Caveat{{Kind: key.KExpires, N: 10}, {Kind: key.KSpendDay, N: c.day}}}}}
		s.Grants[k.Tip()] = Grant{Key: k}
		if got := s.oneOffLine(root.Tip(), Reading{}); got != c.want {
			t.Fatalf("a %d/day cap: one-off line %d, want %d", c.day, got, c.want)
		}
	}
}
