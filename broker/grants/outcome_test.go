package grants

import (
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/journal"
	"github.com/ghbmrk/agentos/broker/owner"
	"github.com/ghbmrk/agentos/broker/reversible"
)

// REQ: OP-7, CHG-1, ADP-11, CH-16

type outcomes struct {
	mu  sync.Mutex
	got []string
}

func (o *outcomes) add(x OwnerOutcome) {
	o.mu.Lock()
	o.got = append(o.got, x.Intent.ID+" "+string(x.Verdict))
	o.mu.Unlock()
}

func (o *outcomes) take() string {
	o.mu.Lock()
	defer o.mu.Unlock()
	s := strings.Join(o.got, ", ")
	o.got = nil
	return s
}

// W3 (potency PW3 on #90): the owner's verdict on an agent's effect is
// reported once, when it is final, for Loop 1's harvesting. YES and NO are
// reported as decided; a held effect only when its undo window ends (its
// release) or on UNDO, so YES then UNDO is an undo, never an acceptance; a
// pre-allowed auto-reply the owner let go is an implicit acceptance.
// Closings that are not the owner's answer (expiry) report nothing.
func TestOwnerOutcomesAreReportedOnceFinal(t *testing.T) {
	var o outcomes
	r := newRig(t, func(c *Config) {
		withForms(map[string]reversible.Form{"invoice.send": {}})(c)
		c.Isolated = func(m string) bool { return m == "reply-1" }
		c.Outcome = o.add
	})
	r.grant(mailGrant())
	r.grant(Spec{Account: "mail", Rule: &Rule{Action: "message.send", PerRecord: 5, PerDay: 20, Reply: true}})
	r.ver.set("inv-1042", sam())

	r.effect("agent/yes", "invoice.send", map[string]any{"record": "inv-1042"}, "sam@example.com")
	r.g.Flush()
	r.approveHeld()
	if got := o.take(); got != "" {
		t.Fatalf("reported at YES, before the undo window: %q", got)
	}
	r.advance(reversible.DefaultWindow)
	r.g.Tick()
	r.g.Wait()
	if got := o.take(); got != "agent/yes accepted" {
		t.Fatalf("release: %q", got)
	}

	r.effect("agent/undo", "invoice.send", map[string]any{"record": "inv-1042"}, "sam@example.com")
	r.g.Flush()
	h := r.approveHeld()
	r.g.Decide(owner.Decision{Request: h[0], Item: 1, Ref: "agent/undo", Why: "undo"})
	r.g.Wait()
	r.g.Decide(owner.Decision{Request: h[0], Item: 1, Ref: "agent/undo", Why: "undo"})
	r.g.Wait()
	if got := o.take(); got != "agent/undo undone" {
		t.Fatalf("YES then UNDO: %q", got)
	}

	r.effect("agent/no", "invoice.send", map[string]any{"record": "inv-1042"}, "sam@example.com")
	r.g.Flush()
	r.decide(false, "owner")
	r.decide(false, "owner")
	if got := o.take(); got != "agent/no declined" {
		t.Fatalf("NO: %q", got)
	}

	r.effect("agent/late", "invoice.send", map[string]any{"record": "inv-1042"}, "sam@example.com")
	r.g.Flush()
	r.decide(false, "expired")
	if got := o.take(); got != "" {
		t.Fatalf("expiry reported as a verdict: %q", got)
	}

	thread := Verified{Item: owner.Item{Object: "reply in thread", Recipient: "sam@example.com",
		Facts: owner.Facts{RecipientChecked: true, RecipientExists: true, RecipientByOwner: true}},
		Recipients: []string{"sam@example.com"}, Record: "thr-1", ThreadVerified: true}
	r.ver.set("thr-1", thread)
	reply := func(id string) {
		r.submit(journal.Intent{ID: id, Origin: "guest:reply-1", Machine: "reply-1", Account: "mail", Action: "message.send",
			Params: map[string]any{"record": "thr-1", "body": "Thanks, got it."}, Recipients: []string{"sam@example.com"}, Executor: "mail"})
	}
	reply("reply-1/r1")
	r.advance(11 * time.Minute)
	r.g.Tick()
	r.g.Wait()
	if got := o.take(); got != "reply-1/r1 accepted-implicitly" {
		t.Fatalf("auto-reply let go: %q", got)
	}
	reply("reply-1/r2")
	q := r.own.due[len(r.own.due)-1]
	r.g.Decide(owner.Decision{Request: q.ID, Item: 1, Ref: "reply-1/r2", Why: "undo"})
	r.g.Wait()
	if got := o.take(); got != "reply-1/r2 undone" {
		t.Fatalf("auto-reply undone: %q", got)
	}
}

// Security A1, A2 on PW3: a failing learning hook never fails the owner's
// answer, and an intent is reported at most once, even if it is asked
// again after its approval was spent.
func TestOwnerOutcomeHookCannotFailTheAnswer(t *testing.T) {
	calls := 0
	r := newRig(t, func(c *Config) {
		c.Outcome = func(OwnerOutcome) { calls++; panic("learning plane down") }
	})
	r.grant(mailGrant())
	r.ver.set("inv-1042", sam())
	r.effect("agent/1", "invoice.send", map[string]any{"record": "inv-1042"}, "sam@example.com")
	r.g.Flush()
	r.decide(true, "owner")
	if st := r.state("agent/1"); st.State != journal.Succeeded || calls != 1 {
		t.Fatalf("after a panicking hook: %s, %d calls", st.State, calls)
	}
	if r.g.reportOnce("agent/1") {
		t.Fatal("an intent could be reported twice")
	}
}
