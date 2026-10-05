package compile

// REQ: CAP-5, CHG-1

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/change"
	"github.com/ghbmrk/agentos/broker/journal"
)

// implicit journals a weekly task the owner let go (source owner-implicit,
// loops L6) in the dev split.
func (r *rig) implicit(goal, to string, week int) string {
	id := r.task(goal, "private", 30*time.Second, weekly(to, week)...)
	r.judge(id, journal.VerdictGood, "owner"+change.ImplicitSuffix)
	r.dev[id] = true
	return id
}

// Arbitrator ruling on W3 PW3 part B ("count, not content"): implicit runs
// count toward MinRuns only beside an explicit-good run of the same shape,
// and never supply a skill's content: its literals come only from explicit
// runs. An implicit run whose value differs makes that value an input,
// never a literal of its own.
func TestImplicitRunsCountButNeverTeach(t *testing.T) {
	r := newRig(t)
	r.implicit("g1", "ann@example.test", 40)
	r.implicit("g2", "bo@example.test", 41)
	r.implicit("g3", "cy@example.test", 42)
	c := r.compiler()
	if cs := c.Candidates(change.Tree{}); len(cs) != 0 {
		t.Fatalf("implicit runs alone made %d candidates", len(cs))
	}
	if _, err := c.BuildSkill(r.eng.List()); !errors.Is(err, ErrNoSkill) {
		t.Fatalf("implicit runs alone built a skill: %v", err)
	}

	// One explicit run anchors the shape: 1 explicit + 3 implicit runs
	// reach MinRuns (3). Every value in the skill is the explicit run's or
	// an input; the implicit runs' "CANARY-" subject never appears.
	r.accepted("g4", "dee@example.test", 43)
	r.implicit("g5", "eve@example.test", 44)
	r.task("g6", "private", 30*time.Second, []step{
		{"mail", "draft.create", map[string]any{"subject": "CANARY-implicit", "to": "fay@example.test", "meta": map[string]any{"week": 45}}, nil},
		{"mail", "message.send", nil, []string{"fay@example.test"}},
	}...)
	r.judge("guest-a/g6-1", journal.VerdictGood, "owner"+change.ImplicitSuffix)
	r.dev["guest-a/g6-1"] = true
	for _, build := range []func() (change.Candidate, error){
		func() (change.Candidate, error) {
			cs := c.Candidates(change.Tree{})
			if len(cs) != 1 {
				return change.Candidate{}, errors.New("not one candidate")
			}
			return cs[0], nil
		},
		func() (change.Candidate, error) { return c.BuildSkill(r.eng.List()) },
	} {
		cand, err := build()
		if err != nil {
			t.Fatal(err)
		}
		_, sk, _ := only(t, []change.Candidate{cand})
		if sk.Kind != "skill" {
			t.Fatalf("kind %s", sk.Kind)
		}
		for _, b := range cand.Files {
			if strings.Contains(string(b), "CANARY-") || strings.Contains(string(b), "ann@") || strings.Contains(string(b), "fay@") {
				t.Fatalf("an implicit run's value reached the skill: %s", b)
			}
		}
		if sk.Steps[0].Params["subject"].Slot == "" {
			t.Fatalf("a value implicit runs vary must be an input: %+v", sk.Steps[0].Params["subject"])
		}
		// The recipient, which only implicit runs vary, stays the explicit
		// run's literal (arbitrator on #109).
		if string(sk.Steps[0].Params["to"].Lit) != `"dee@example.test"` || string(sk.Steps[1].Recipients[0].Lit) != `"dee@example.test"` {
			t.Fatalf("an implicit run widened a recipient: %+v", sk.Steps)
		}
	}
}
