package compile

// REQ: CAP-5, CHG-1

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/change"
	"github.com/ghbmrk/agentos/broker/journal"
	"github.com/ghbmrk/agentos/broker/skill"
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

// hashed is how the box keeps an implicit run's values (agentosd W3-values
// V4): each string and number leaf, and each data-shaped map key, a keyed
// hash. A stand-in for the box's HMAC.
func hashed(v any) any {
	h := func(s string) string {
		sum := sha256.Sum256([]byte("box-key|" + s))
		return "h" + hex.EncodeToString(sum[:16])
	}
	switch t := v.(type) {
	case map[string]any:
		out := map[string]any{}
		for k, c := range t {
			out[k] = hashed(c)
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, c := range t {
			out[i] = hashed(c)
		}
		return out
	case []string:
		out := make([]string, len(t))
		for i, c := range t {
			out[i] = h(c)
		}
		return out
	case string:
		return h(t)
	case int:
		return h(fmt.Sprint(t))
	case float64, json.Number:
		return h(fmt.Sprint(t))
	}
	return v
}

// implicitHashed journals an implicit run as the box keeps it: hashed.
func (r *rig) implicitHashed(goal string, steps []step) {
	for i := range steps {
		if steps[i].params != nil {
			steps[i].params = hashed(steps[i].params).(map[string]any)
		}
		steps[i].recips = hashed(steps[i].recips).([]string)
	}
	id := r.task(goal, "private", 30*time.Second, steps...)
	r.judge(id, journal.VerdictGood, "owner"+change.ImplicitSuffix)
	r.dev[id] = true
}

// Potency on #119 (BOARD W3-values-mix): implicit runs are kept as keyed
// hashes, so with the box's hash the compiler hashes the explicit run's
// values to compare: a hashed implicit run of the same shape counts, a
// content value equal across runs stays the explicit run's literal, and
// one an implicit run changes is an input. Never an implicit value.
func TestHashedImplicitRunsKeepConstants(t *testing.T) {
	r := newRig(t)
	r.accepted("g1", "dee@example.test", 40)
	r.implicitHashed("g2", weekly("dee@example.test", 41))
	r.implicitHashed("g3", weekly("dee@example.test", 42))
	if _, err := r.compiler().BuildSkill(r.eng.List()); !errors.Is(err, ErrNoSkill) {
		t.Fatalf("without the hash, hashed runs matched: %v", err)
	}
	c, err := New(Config{Journal: r.eng, Cases: r, Hash: hashed})
	if err != nil {
		t.Fatal(err)
	}
	subject := func() skill.Node {
		t.Helper()
		cand, err := c.BuildSkill(r.eng.List())
		if err != nil {
			t.Fatal(err)
		}
		_, sk, _ := only(t, []change.Candidate{cand})
		if sk.Runs != 3 && sk.Runs != 4 {
			t.Fatalf("runs %d", sk.Runs)
		}
		for _, b := range cand.Files {
			if strings.Contains(string(b), `"h`) {
				t.Fatalf("a hash reached the skill: %s", b)
			}
		}
		if string(sk.Steps[0].Params["to"].Lit) != `"dee@example.test"` {
			t.Fatalf("recipient %+v", sk.Steps[0].Params["to"])
		}
		return sk.Steps[0].Params["subject"]
	}
	if n := subject(); string(n.Lit) != `"Weekly report"` {
		t.Fatalf("a constant became an input: %+v", n)
	}
	other := weekly("dee@example.test", 43)
	other[0].params["subject"] = "Monthly report"
	r.implicitHashed("g4", other)
	if n := subject(); n.Slot == "" {
		t.Fatalf("a subject an implicit run changes stayed literal: %+v", n)
	}
}
