package grants

import (
	"context"
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
	if got := o.take(); got != "" {
		t.Fatalf("auto-reply reported before a late UNDO could come: %q", got)
	}
	r.advance(owner.LateRelease)
	r.g.Tick()
	r.g.Wait()
	if got := o.take(); got != "reply-1/r1 accepted-implicitly" {
		t.Fatalf("auto-reply let go: %q", got)
	}

	// L3 MUST-4 on #109: an UNDO just after the release was too late to
	// stop the reply, but the owner did not let it go: no verdict.
	reply("reply-1/r3")
	q3 := r.own.due[len(r.own.due)-1]
	r.advance(11 * time.Minute)
	r.g.Tick()
	r.g.Wait()
	r.own.mu.Lock()
	r.own.lateUndo = map[string]bool{q3.ID: true}
	r.own.mu.Unlock()
	r.advance(owner.LateRelease)
	r.g.Tick()
	r.g.Wait()
	if got := o.take(); got != "" {
		t.Fatalf("an UNDO after the release left a verdict: %q", got)
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

// L3 MUST-1 on #101: an acceptance is reported only once the effect is
// sent. A YES that STOP holds is reported after RESUME, when the send
// ends: not if it fails or its draft changed after the YES.
func TestAcceptanceWaitsForTheSend(t *testing.T) {
	var o outcomes
	r := newRig(t, func(c *Config) { c.Outcome = o.add })
	r.grant(mailGrant())
	ctx := context.Background()

	r.approveStopped("agent/f1", "inv-f1")
	if got := o.take(); got != "" {
		t.Fatalf("reported before the send: %q", got)
	}
	r.exec.fail = map[string]bool{"agent/f1": true}
	if st, _ := r.g.Dispatch(ctx, "agent/f1"); st.State != journal.NotApplied {
		t.Fatalf("failed send: %s", st.State)
	}
	r.g.Wait()
	r.g.Tick()
	r.g.Wait()
	if got := o.take(); got != "" {
		t.Fatalf("a failed send was reported: %q", got)
	}

	r.approveStopped("agent/s1", "inv-s1")
	if st, _ := r.g.Dispatch(ctx, "agent/s1"); st.State != journal.Succeeded {
		t.Fatalf("send: %s", st.State)
	}
	r.g.Wait()
	if got := o.take(); got != "agent/s1 accepted" {
		t.Fatalf("sent after RESUME: %q", got)
	}
}

// The same for a held effect released under STOP whose draft changed.
func TestAnEditedDraftIsNotAnAcceptance(t *testing.T) {
	var o outcomes
	form := reversible.Form{Stage: "draft.save", Inverse: "draft.discard"}
	r := newRig(t, func(c *Config) {
		withForms(map[string]reversible.Form{"invoice.send": form})(c)
		c.Outcome = o.add
	})
	r.grant(mailGrant())
	r.ver.set("inv-1042", sam())
	r.effect("agent/e1", "invoice.send", map[string]any{"record": "inv-1042"}, "sam@example.com")
	r.g.Flush()
	r.approveHeld()
	r.exec.fail = map[string]bool{"agent/e1": true}
	r.exec.evidence = map[string]string{"agent/e1": reversible.EvidenceEdited}
	if _, err := r.eng.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}
	r.advance(reversible.DefaultWindow)
	r.g.Tick()
	r.g.Wait()
	if err := r.eng.Resume(); err != nil {
		t.Fatal(err)
	}
	if st, _ := r.g.Dispatch(context.Background(), "agent/e1"); st.State != journal.NotApplied {
		t.Fatalf("after RESUME: %s", st.State)
	}
	r.g.Wait()
	if got := o.take(); got != "" {
		t.Fatalf("an edited draft was reported: %q", got)
	}
}

// L3 MUST-2 on #101: each guard on what counts as the owner's verdict.
func TestOnlyTheOwnersAnswersAreVerdicts(t *testing.T) {
	guest := journal.Intent{ID: "agent/1", Origin: "guest:agent", Account: "mail"}
	yes := decision{approved: true, why: "owner", asked: true}
	no := decision{why: "owner", asked: true}
	at := func(in journal.Intent, s journal.State) journal.Status { return journal.Status{Intent: in, State: s} }
	broker := guest
	broker.Account = journal.BrokerAccount
	local := guest
	local.Origin = "owner"
	for _, c := range []struct {
		name string
		d    decision
		st   journal.Status
		want OwnerVerdict
	}{
		{"YES sent", yes, at(guest, journal.Succeeded), OwnerAccepted},
		{"YES unknown", yes, at(guest, journal.OutcomeUnknown), OwnerAccepted},
		{"NO", no, at(guest, journal.Denied), OwnerDeclined},
		{"UNDO", decision{why: "undo", asked: true}, at(guest, journal.Denied), OwnerUndone},
		{"YES not applied", yes, at(guest, journal.NotApplied), ""},
		{"YES refused at the recheck", yes, at(guest, journal.Denied), ""},
		{"not a guest's", yes, at(local, journal.Succeeded), ""},
		{"the broker's", no, at(broker, journal.Denied), ""},
		{"never asked this run", decision{why: "owner"}, at(guest, journal.Denied), ""},
		{"released late", decision{approved: true, why: whyReleasedLate, asked: true, late: true}, at(guest, journal.Succeeded), ""},
	} {
		if got := ownerVerdict(c.d, c.st); got != c.want {
			t.Errorf("%s: %q, want %q", c.name, got, c.want)
		}
	}
}

// Security B1(a) on PW3: an auto-reply released late, or after its alert's
// line failed, is still sent, but its silence is not reported as the
// owner's acceptance, nor as an explicit one.
func TestALateReleaseIsNoVerdict(t *testing.T) {
	var o outcomes
	quiet := new(func(time.Time) bool)
	*quiet = func(time.Time) bool { return false }
	r := newRig(t, func(c *Config) {
		c.Isolated = func(m string) bool { return m == "reply-1" }
		c.Outcome = o.add
		c.Quiet = func(t time.Time) bool { return (*quiet)(t) }
	})
	r.grant(mailGrant())
	r.grant(Spec{Account: "mail", Rule: &Rule{Action: "message.send", PerRecord: 5, PerDay: 20, Reply: true}})
	r.ver.set("thr-1", Verified{Item: owner.Item{Object: "reply in thread", Recipient: "sam@example.com",
		Facts: owner.Facts{RecipientChecked: true, RecipientExists: true, RecipientByOwner: true}},
		Recipients: []string{"sam@example.com"}, Record: "thr-1", ThreadVerified: true})
	r.submit(journal.Intent{ID: "reply-1/late", Origin: "guest:reply-1", Machine: "reply-1", Account: "mail", Action: "message.send",
		Params: map[string]any{"record": "thr-1", "body": "Thanks, got it."}, Recipients: []string{"sam@example.com"}, Executor: "mail"})
	r.own.mu.Lock()
	r.own.due[len(r.own.due)-1].Late = true
	r.own.mu.Unlock()
	r.advance(11 * time.Minute)
	r.g.Tick()
	r.g.Wait()
	if st := r.state("reply-1/late"); st.State != journal.Succeeded {
		t.Fatalf("a late release was not sent: %s", st.State)
	}
	if got := o.take(); got != "" {
		t.Fatalf("a late release was reported: %q", got)
	}

	// Security F1 on #109: quiet hours at the alert or the release make
	// the silence not the owner's either.
	for _, at := range []string{"alert", "release"} {
		id := "reply-1/quiet-" + at
		r.submit(journal.Intent{ID: id, Origin: "guest:reply-1", Machine: "reply-1", Account: "mail", Action: "message.send",
			Params: map[string]any{"record": "thr-1", "body": "Thanks, got it."}, Recipients: []string{"sam@example.com"}, Executor: "mail"})
		r.own.mu.Lock()
		alerted := r.now()
		r.own.due[len(r.own.due)-1].Alerted = alerted
		r.own.mu.Unlock()
		quietAt := alerted
		if at == "release" {
			quietAt = alerted.Add(11 * time.Minute)
		}
		*quiet = func(t time.Time) bool { return t.Equal(quietAt) }
		r.advance(11 * time.Minute)
		r.g.Tick()
		r.g.Wait()
		if got := o.take(); got != "" {
			t.Fatalf("silence in quiet hours at the %s was reported: %q", at, got)
		}
	}
	*quiet = func(time.Time) bool { return false }
	r.submit(journal.Intent{ID: "reply-1/awake", Origin: "guest:reply-1", Machine: "reply-1", Account: "mail", Action: "message.send",
		Params: map[string]any{"record": "thr-1", "body": "Thanks, got it."}, Recipients: []string{"sam@example.com"}, Executor: "mail"})
	r.own.mu.Lock()
	r.own.due[len(r.own.due)-1].Alerted = r.now()
	r.own.mu.Unlock()
	r.advance(11 * time.Minute)
	r.g.Tick()
	r.g.Wait()
	r.advance(owner.LateRelease)
	r.g.Tick()
	r.g.Wait()
	if got := o.take(); got != "reply-1/awake accepted-implicitly" {
		t.Fatalf("on time, outside quiet hours: %q", got)
	}
}

// Security on #101 (BOARD follow-up on #109): an unsent acceptance whose
// intent the journal no longer has is dropped, never reported, so the
// held set cannot fill with verdicts nothing will end.
func TestAnUnsentVerdictForAMissingIntentIsDropped(t *testing.T) {
	var got []OwnerOutcome
	r := newRig(t, func(c *Config) { c.Outcome = func(o OwnerOutcome) { got = append(got, o) } })
	r.g.mu.Lock()
	r.g.sending["gone/1"] = pending{v: OwnerAccepted}
	r.g.mu.Unlock()
	r.g.Tick()
	r.g.Wait()
	r.g.mu.Lock()
	_, kept := r.g.sending["gone/1"]
	r.g.mu.Unlock()
	if kept || len(got) != 0 {
		t.Fatalf("missing intent: kept %v, reported %+v", kept, got)
	}
}

// REQ: LOOP-4, CAP-5
// W3-values, security V1: Observe sees a guest intent as written once the
// policy authorized it, as a deep copy, never before the owner's YES, never
// a refused one, and a panic in it changes nothing.
func TestObserveSeesAuthorizedIntentsOnly(t *testing.T) {
	var seen []journal.Intent
	r := newRig(t, func(c *Config) {
		c.Observe = func(in journal.Intent) {
			seen = append(seen, in)
			in.Params["record"] = "changed by the observer"
			panic("learning plane down")
		}
	})
	r.grant(mailGrant())
	r.ver.set("inv-1042", sam())
	r.effect("agent/1", "invoice.send", map[string]any{"record": "inv-1042"}, "sam@example.com")
	r.g.Flush()
	if len(seen) != 0 {
		t.Fatalf("observed before the owner's YES: %+v", seen)
	}
	r.decide(true, "owner")
	if st := r.state("agent/1"); st.State != journal.Succeeded || st.Intent.Params["record"] != "inv-1042" {
		t.Fatalf("after an observer that panics and edits: %s %+v", st.State, st.Intent.Params)
	}
	if len(seen) != 1 || seen[0].ID != "agent/1" || seen[0].Recipients[0] != "sam@example.com" {
		t.Fatalf("observed %+v", seen)
	}
	r.submit(journal.Intent{ID: "agent/2", Origin: "guest:agent", Account: "bank", Action: "transfer",
		Params: map[string]any{"amount": 5}, Executor: "mail", Machine: "agent", Label: "private"})
	if len(seen) != 1 {
		t.Fatalf("a refused intent was observed: %+v", seen)
	}
}
