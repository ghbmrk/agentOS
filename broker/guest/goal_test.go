package guest

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"testing"
	"time"
)

// REQ: OP-1, OP-7, OP-8

// fetch hands machine id's next owner message to its guest and returns its
// ID, as the bridge does.
func (r *rig) fetch(id string) string {
	r.t.Helper()
	code, body := r.do(id, "GET", "/owner/next", "")
	if code != 200 {
		r.t.Fatalf("owner/next: %d %s", code, body)
	}
	var m struct{ ID string }
	json.Unmarshal([]byte(body), &m)
	return m.ID
}

func (r *rig) reply(id, msg string) {
	r.t.Helper()
	if code, body := r.do(id, "POST", "/owner/reply", fmt.Sprintf(`{"id":%q,"text":"ok"}`, msg)); code != 204 {
		r.t.Fatalf("owner/reply: %d %s", code, body)
	}
}

func (r *rig) goalOf(intentID string) string {
	r.t.Helper()
	s, err := r.eng.Get(intentID)
	if err != nil {
		r.t.Fatal(err)
	}
	return s.Intent.GoalID
}

func (r *rig) deliver(id, text string) string {
	r.t.Helper()
	msg, err := r.p.DeliverOwner(id, text, true)
	if err != nil {
		r.t.Fatal(err)
	}
	return msg
}

// TestOP1EffectsCarryTheOwnerMessageTheyServe: an effect request is
// stamped with the owner message its lineage was handed, and the stamp is
// fixed per request ID: a repeat during a later message is the same
// intent, runs once, and keeps its first goal.
func TestOP1EffectsCarryTheOwnerMessageTheyServe(t *testing.T) {
	r := newRig(t, nil)
	r.ms.lineage["f1"] = "m1"
	r.client("m1")
	if st, e := r.tool("m1", "effect_request", send("r0")); st.State != "succeeded" {
		t.Fatalf("r0: %+v %s", st, e)
	}
	if g := r.goalOf("m1/r0"); g != "" {
		t.Fatalf("no owner message yet, goal %q", g)
	}
	a := r.deliver("m1", "book the dentist")
	if st, _ := r.tool("m1", "effect_request", send("r-before")); st.State != "succeeded" || r.goalOf("m1/r-before") != "" {
		t.Fatalf("a message not yet handed out is not served: goal %q", r.goalOf("m1/r-before"))
	}
	if got := r.fetch("m1"); got != a {
		t.Fatalf("fetched %s, want %s", got, a)
	}
	r.tool("m1", "effect_request", send("r1"))
	if g := r.goalOf("m1/r1"); g != GoalID(a) {
		t.Fatalf("r1 goal %q, want %q", g, GoalID(a))
	}
	r.reply("m1", a)
	b := r.deliver("m1", "renew the passport")
	r.fetch("m1")
	if st, e := r.tool("m1", "effect_request", send("r1")); st.State != "succeeded" || e != "" {
		t.Fatalf("repeat of r1 during b: %+v %s", st, e)
	}
	if g := r.goalOf("m1/r1"); g != GoalID(a) || r.ex.runs["m1/r1"] != 1 {
		t.Fatalf("repeat moved r1 to %q or ran it again (%d)", g, r.ex.runs["m1/r1"])
	}
	r.tool("f1", "effect_request", send("r2"))
	if g := r.goalOf("m1/r2"); g != GoalID(b) {
		t.Fatalf("a fork's request serves its lineage's message: %q, want %q", g, GoalID(b))
	}
	r.reply("m1", b)
	r.tool("m1", "effect_request", send("r3"))
	if g := r.goalOf("m1/r3"); g != GoalID(b) {
		t.Fatalf("after the answer, work still serves the last message: %q", g)
	}
	r.client("m2")
	r.tool("m2", "effect_request", send("r4"))
	if g := r.goalOf("m2/r4"); g != "" {
		t.Fatalf("another lineage took m1's goal: %q", g)
	}
}

// TestOP1TwoOpenMessagesStampNoGoal: when the lineage holds more than one
// unanswered message, the broker cannot tell which one a request serves,
// so it stamps none rather than guess.
func TestOP1TwoOpenMessagesStampNoGoal(t *testing.T) {
	r := newRig(t, nil)
	r.client("m1")
	a := r.deliver("m1", "one")
	b := r.deliver("m1", "two")
	r.fetch("m1")
	r.fetch("m1")
	r.tool("m1", "effect_request", send("r1"))
	if g := r.goalOf("m1/r1"); g != "" {
		t.Fatalf("ambiguous goal stamped %q", g)
	}
	r.reply("m1", a)
	r.tool("m1", "effect_request", send("r2"))
	if g := r.goalOf("m1/r2"); g != GoalID(b) {
		t.Fatalf("one open message left, goal %q", g)
	}
}

// TestOP1GoalSurvivesABrokerRestart: the last message a lineage was handed
// is kept with the inbox, so work after a restart still serves it.
func TestOP1GoalSurvivesABrokerRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "inbox.json")
	r := newRig(t, func(c *Config) { c.InboxPath = path })
	r.client("m1")
	a := r.deliver("m1", "book the dentist")
	r.fetch("m1")
	r.reply("m1", a)
	r.p.Shutdown()
	r2 := newRig(t, func(c *Config) { c.InboxPath = path; c.Dir = r.p.cfg.Dir })
	r2.client("m1")
	r2.tool("m1", "effect_request", send("r1"))
	if g := r2.goalOf("m1/r1"); g != GoalID(a) {
		t.Fatalf("after restart, goal %q, want %q", g, GoalID(a))
	}
	r2.p.Close("m1") // destroyed: its lineage's goal goes with it
	r2.p.Shutdown()
	r3 := newRig(t, func(c *Config) { c.InboxPath = path; c.Dir = r.p.cfg.Dir })
	r3.client("m1")
	r3.tool("m1", "effect_request", send("r1"))
	if g := r3.goalOf("m1/r1"); g != "" {
		t.Fatalf("a destroyed machine's goal came back: %q", g)
	}
}

// TestOP8ModelUseIsChargedToTheGoal: model calls made while a lineage
// serves an owner message are counted against that goal too.
func TestOP8ModelUseIsChargedToTheGoal(t *testing.T) {
	r := newRig(t, nil)
	r.ms.lineage["f1"] = "m1"
	r.client("m1")
	a := r.deliver("m1", "book the dentist")
	r.fetch("m1")
	if code, _ := r.do("m1", "POST", "/model/openai/v1/chat/completions", `{"messages":[]}`); code != 200 {
		t.Fatal(code)
	}
	if code, _ := r.do("f1", "POST", "/model/openai/v1/chat/completions", `{"messages":[]}`); code != 200 {
		t.Fatal(code)
	}
	u := r.meter.GoalUsage(GoalID(a))
	if u.Calls != 2 || u.Tokens <= 0 {
		t.Fatalf("goal usage %+v", u)
	}
	if u := r.meter.GoalUsage(""); u.Calls != 0 {
		t.Fatalf("unattributed calls counted under the empty goal: %+v", u)
	}
}

// TestOP1LastGoalEndsOnDeliveryOrQuiet: after its answer, a message stays
// the lineage's goal only until another message is delivered or GoalQuiet
// has passed since it was handed out; guest requests do not extend it.
// Later requests are unattributed rather than merged into an unrelated
// task (potency PG1; arbitrator on #55).
func TestOP1LastGoalEndsOnDeliveryOrQuiet(t *testing.T) {
	now := time.Date(2026, 10, 5, 9, 0, 0, 0, time.UTC)
	r := newRig(t, func(c *Config) {
		c.GoalQuiet = 30 * time.Minute
		c.Now = func() time.Time { return now }
	})
	r.client("m1")
	a := r.deliver("m1", "book the dentist")
	r.fetch("m1")
	r.reply("m1", a)
	now = now.Add(20 * time.Minute)
	r.tool("m1", "effect_request", send("r1"))
	if g := r.goalOf("m1/r1"); g != GoalID(a) {
		t.Fatalf("inside the window: %q", g)
	}
	now = now.Add(11 * time.Minute) // 31 min after the hand-out, 11 after r1
	r.tool("m1", "effect_request", send("r3"))
	if g := r.goalOf("m1/r3"); g != "" {
		t.Fatalf("a guest request extended the window: %q", g)
	}
	b := r.deliver("m1", "renew the passport")
	r.fetch("m1")
	r.reply("m1", b)
	r.deliver("m1", "something new") // delivered, not yet fetched
	r.tool("m1", "effect_request", send("r4"))
	if g := r.goalOf("m1/r4"); g != "" {
		t.Fatalf("a new delivery did not end the last goal: %q", g)
	}
}

// TestOP1GuestCannotNameAGoal: a goal the guest supplies, at the top level
// or in params, is ignored; the broker's stamp stands.
func TestOP1GuestCannotNameAGoal(t *testing.T) {
	r := newRig(t, nil)
	r.client("m1")
	a := r.deliver("m1", "book the dentist")
	r.fetch("m1")
	args := send("r1")
	args["goal_id"] = "owner:forged"
	args["GoalID"] = "owner:forged"
	args["params"] = map[string]any{"text": "hello", "goal_id": "owner:forged", "GoalID": "owner:forged"}
	if st, e := r.tool("m1", "effect_request", args); st.State != "succeeded" {
		t.Fatalf("%+v %s", st, e)
	}
	if g := r.goalOf("m1/r1"); g != GoalID(a) {
		t.Fatalf("goal %q, want the broker's %q", g, GoalID(a))
	}
}

// TestOpenDoesNotCallBackIntoTheManager: the machine manager calls Open
// holding its own lock, so Open must not ask it for the lineage (that
// deadlocked the OpenClaw integration run).
func TestOpenDoesNotCallBackIntoTheManager(t *testing.T) {
	r := newRig(t, nil)
	r.ms.mu.Lock()
	r.ms.locked = true
	r.ms.mu.Unlock()
	if _, err := r.p.Open("m1"); err != nil {
		t.Fatal(err)
	}
	r.ms.mu.Lock()
	r.ms.locked = false
	n := r.ms.misuse
	r.ms.mu.Unlock()
	if n != 0 {
		t.Fatalf("Open asked the manager for a lineage %d times", n)
	}
}
