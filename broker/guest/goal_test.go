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

// goalNow is the goal machine id's lineage serves now, as the plane names
// it to the model route on a model call (G14).
func (r *rig) goalNow(id string) string {
	r.t.Helper()
	if code, body := r.do(id, "POST", "/model/openai/v1/chat/completions", `{"messages":[]}`); code != 200 {
		r.t.Fatalf("model call: %d %s", code, body)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.goals[len(r.goals)-1]
}

func (r *rig) deliver(id, text string) string {
	r.t.Helper()
	msg, err := r.p.DeliverOwner(id, text, true)
	if err != nil {
		r.t.Fatal(err)
	}
	return msg
}

// TestOP1WorkServesTheOwnerMessageItWasHanded: the lineage's goal is the
// owner message it was handed, and a fork serves its lineage's goal.
func TestOP1WorkServesTheOwnerMessageItWasHanded(t *testing.T) {
	r := newRig(t, nil)
	r.ms.lineage["f1"] = "m1"
	r.client("m1")
	if g := r.goalNow("m1"); g != "" {
		t.Fatalf("no owner message yet, goal %q", g)
	}
	a := r.deliver("m1", "book the dentist")
	if g := r.goalNow("m1"); g != "" {
		t.Fatalf("a message not yet handed out is not served: goal %q", g)
	}
	if got := r.fetch("m1"); got != a {
		t.Fatalf("fetched %s, want %s", got, a)
	}
	if g := r.goalNow("m1"); g != GoalID(a) {
		t.Fatalf("goal %q, want %q", g, GoalID(a))
	}
	r.reply("m1", a)
	b := r.deliver("m1", "renew the passport")
	r.fetch("m1")
	if g := r.goalNow("f1"); g != GoalID(b) {
		t.Fatalf("a fork serves its lineage's message: %q, want %q", g, GoalID(b))
	}
	r.reply("m1", b)
	if g := r.goalNow("m1"); g != GoalID(b) {
		t.Fatalf("after the answer, work still serves the last message: %q", g)
	}
	r.client("m2")
	if g := r.goalNow("m2"); g != "" {
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
	if g := r.goalNow("m1"); g != "" {
		t.Fatalf("ambiguous goal stamped %q", g)
	}
	r.reply("m1", a)
	if g := r.goalNow("m1"); g != GoalID(b) {
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
	if g := r2.goalNow("m1"); g != GoalID(a) {
		t.Fatalf("after restart, goal %q, want %q", g, GoalID(a))
	}
	r2.p.Close("m1") // destroyed: its lineage's goal goes with it
	r2.p.Shutdown()
	r3 := newRig(t, func(c *Config) { c.InboxPath = path; c.Dir = r.p.cfg.Dir })
	r3.client("m1")
	if g := r3.goalNow("m1"); g != "" {
		t.Fatalf("a destroyed machine's goal came back: %q", g)
	}
}

// TestOP8ModelUseIsChargedToTheGoal: every model call names the goal its
// lineage serves when it arrives, a fork's included, so the wiring's meter
// charges it there (OP-8, G14).
func TestOP8ModelUseIsChargedToTheGoal(t *testing.T) {
	r := newRig(t, nil)
	r.ms.lineage["f1"] = "m1"
	r.client("m1")
	a := r.deliver("m1", "book the dentist")
	r.fetch("m1")
	if g, h := r.goalNow("m1"), r.goalNow("f1"); g != GoalID(a) || h != GoalID(a) {
		t.Fatalf("goals %q and %q, want %q", g, h, GoalID(a))
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
	if g := r.goalNow("m1"); g != GoalID(a) {
		t.Fatalf("inside the window: %q", g)
	}
	now = now.Add(11 * time.Minute) // 31 min after the hand-out, 11 after r1
	if g := r.goalNow("m1"); g != "" {
		t.Fatalf("a guest request extended the window: %q", g)
	}
	b := r.deliver("m1", "renew the passport")
	r.fetch("m1")
	r.reply("m1", b)
	r.deliver("m1", "something new") // delivered, not yet fetched
	if g := r.goalNow("m1"); g != "" {
		t.Fatalf("a new delivery did not end the last goal: %q", g)
	}
}

// TestOP1GuestCannotNameAGoal: a goal the guest sends with a model call is
// ignored; the broker's stands.
func TestOP1GuestCannotNameAGoal(t *testing.T) {
	r := newRig(t, nil)
	r.client("m1")
	a := r.deliver("m1", "book the dentist")
	r.fetch("m1")
	if code, _ := r.do("m1", "POST", "/model/openai/v1/chat/completions", `{"goal_id":"owner:forged"}`, "X-Goal", "owner:forged"); code != 200 {
		t.Fatal(code)
	}
	r.mu.Lock()
	g := r.goals[len(r.goals)-1]
	r.mu.Unlock()
	if g != GoalID(a) {
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
