package kernel_test

// REQ: KRN-1, EVL-1

import (
	"encoding/json"
	"errors"
	"fmt"
	"testing"

	"github.com/ghbmrk/agentos/broker/kernel"
	"github.com/ghbmrk/agentos/broker/kernel/key"
)

// mixed runs one of each kernel decision: an accept, a reject, a hold, a
// dispatch, a cancel for a revoke during the hold, a cancel for a clerk the
// kernel lacks, and a send refused after a STOP.
func mixed(t *testing.T) *rig {
	r := newRig(t)
	bank := r.grant(key.Issue(r.owner.pass, key.Root{Clerk: "bank", Verbs: []key.Verb{key.Trash}, Serial: "b1"}), 1<<40)
	held := r.derive(key.LimitHold(hour, 4*hour))
	r.plan("held", held, st(key.Unsubscribe, "list-a"))
	r.plan("now", r.ck, st(key.Trash, "m1"))
	one := int64(1)
	r.plan("bad", r.derive(key.LimitArg(key.ArgBound{Name: "msg", Min: &one})), st(key.Draft, "5"))
	must(t, r.tick(1))
	must(t, r.tick(4*hour))
	revoked := r.derive(key.LimitHold(hour, hour))
	r.plan("revoked", revoked, st(key.Unsubscribe, "list-b"))
	must(t, r.tick(4*hour+1))
	must(t, r.k.Revoke(4*hour+2, revoked.Tip()))
	must(t, r.tick(4*hour+3))
	far := st(key.Trash, "m2")
	far.Clerk = "bank"
	r.plan("noclerk", bank, far)
	must(t, r.tick(4*hour+4))
	r.plan("stopped", r.ck, st(key.Trash, "m3"))
	c := r.calls(4*hour+5, 1)[0]
	must(t, r.k.Stop(4*hour+6))
	ok, err := r.k.Send(4*hour+6, c)
	must(t, err)
	if ok {
		t.Fatal("a dispatch was sent after STOP")
	}
	return r
}

func rederives(t *testing.T, r *rig) kernel.Rederived {
	t.Helper()
	got, err := kernel.Rederive(r.anchors(), r.k.Box(), r.k.Log().Entries())
	must(t, err)
	return got
}

// Every decision the kernel logged is re-derived from the entries before it
// at its own time, byte for byte, so a log prefix reproduces what the kernel
// did (KRN-1, EVL-1).
func TestRederiveReproducesEveryDecision(t *testing.T) {
	r := mixed(t)
	got := rederives(t, r)
	for _, typ := range []string{kernel.TPlanAccepted, kernel.TPlanRejected, kernel.TStepHeld, kernel.TStepDispatch, kernel.TPlanCancel} {
		if got.Checked[typ] == 0 {
			t.Errorf("no %s re-derived: %+v", typ, got)
		}
	}
	codes := map[string]bool{}
	for _, e := range r.k.Log().Entries() {
		if e.Type == kernel.TPlanCancel {
			var b struct{ Code string }
			must(t, json.Unmarshal(e.Body, &b))
			codes[b.Code] = true
		}
	}
	for _, c := range []string{key.RRevoked, kernel.CClerk, key.RStopped} {
		if !codes[c] {
			t.Errorf("the run logged no %q cancel: %v", c, codes)
		}
	}
}

// A decision the entries before it do not give fails at its own seq,
// whatever the rest of the log holds.
func TestRederiveFindsATamperedDecision(t *testing.T) {
	r := mixed(t)
	es := r.k.Log().Entries()
	find := func(typ, plan string) int {
		for i, e := range es {
			var b struct{ Plan string }
			if e.Type == typ && json.Unmarshal(e.Body, &b) == nil && b.Plan == plan {
				return i
			}
		}
		t.Fatalf("no %s for %s", typ, plan)
		return 0
	}
	set := func(e kernel.Entry, field string, v any) kernel.Entry {
		var m map[string]any
		must(t, json.Unmarshal(e.Body, &m))
		m[field] = v
		b, err := json.Marshal(m)
		must(t, err)
		e.Body = b
		return e
	}
	retype := func(e kernel.Entry, typ string, body any) kernel.Entry {
		b, err := json.Marshal(body)
		must(t, err)
		e.Type, e.Body = typ, b
		return e
	}
	for name, tc := range map[string]struct {
		i  int
		to func(kernel.Entry) kernel.Entry
	}{
		"a hold's novelty flipped": {find(kernel.TStepHeld, "held"), func(e kernel.Entry) kernel.Entry { return set(e, "novel", false) }},
		"a reject's code changed":  {find(kernel.TPlanRejected, "bad"), func(e kernel.Entry) kernel.Entry { return set(e, "code", kernel.CKey) }},
		"an accept's scopes cut":   {find(kernel.TPlanAccepted, "now"), func(e kernel.Entry) kernel.Entry { return set(e, "scopes", []string{}) }},
		"a reject made an accept": {find(kernel.TPlanRejected, "bad"), func(e kernel.Entry) kernel.Entry {
			return retype(e, kernel.TPlanAccepted, map[string]any{"plan": "bad", "cause": e.Seq - 1, "root": r.ck.Root, "scopes": []string{}})
		}},
		"a dispatch where Next holds": {find(kernel.TStepHeld, "held"), func(e kernel.Entry) kernel.Entry {
			return retype(e, kernel.TStepDispatch, map[string]any{"plan": "held", "index": 0, "attempt": 1, "idem": kernel.Idem("held", 0)})
		}},
		"a dispatch's attempt changed": {find(kernel.TStepDispatch, "now"), func(e kernel.Entry) kernel.Entry { return set(e, "attempt", 2) }},
		"a cancel's code changed":      {find(kernel.TPlanCancel, "revoked"), func(e kernel.Entry) kernel.Entry { return set(e, "code", key.RExpired) }},
		"a send's cancel reworded":     {find(kernel.TPlanCancel, "stopped"), func(e kernel.Entry) kernel.Entry { return set(e, "detail", "other") }},
		"a dispatch made a cancel": {find(kernel.TStepDispatch, "now"), func(e kernel.Entry) kernel.Entry {
			return retype(e, kernel.TPlanCancel, map[string]any{"plan": "now", "code": key.RRevoked})
		}},
	} {
		t.Run(name, func(t *testing.T) {
			bad := append([]kernel.Entry(nil), es...)
			bad[tc.i] = tc.to(bad[tc.i])
			_, err := kernel.Rederive(r.anchors(), r.k.Box(), bad)
			var d *kernel.Divergence
			if !errors.As(err, &d) || d.Seq != es[tc.i].Seq {
				t.Fatalf("want a divergence at seq %d, got %v", es[tc.i].Seq, err)
			}
		})
	}
}

// An owner's cancel is an input, not a decision: it is recorded and folded,
// never re-derived.
func TestRederiveRecordsInputs(t *testing.T) {
	r := newRig(t)
	k := r.derive(key.LimitHold(hour, hour))
	r.plan("p1", k, st(key.Unsubscribe, "list-a"))
	must(t, r.tick(1))
	must(t, r.k.Cancel(2, "p1"))
	got := rederives(t, r)
	if got.Checked[kernel.TPlanCancel] != 0 || got.Recorded[kernel.TPlanCancel] != 1 || got.Recorded[kernel.TPlanSubmit] != 1 {
		t.Fatalf("%+v", got)
	}
}

// A restart's decisions are re-derived too: a plan submitted but undecided
// before a crash is decided at boot, at the boot's time.
func TestRederiveCoversBoot(t *testing.T) {
	r := newRig(t)
	r.plan("p1", r.ck, st(key.Trash, "m1"))
	cutLast(t, r.store, 1) // decision lost
	r.boot(9)
	if got := rederives(t, r); got.Checked[kernel.TPlanAccepted] != 1 {
		t.Fatalf("%+v", got)
	}
}

// The probe from #5147: a key that expires at 1 h. A plan at 2 h is
// rejected; one submitted after the clock stepped back to 0.5 h is rejected
// too, since the kernel's time is floored at its last entry, and the log's
// times stay ordered, so Rederive passes it.
//
// REQ: TIM-1, KEY-7
func TestTIM1ClockStepBackRevivesNoKey(t *testing.T) {
	r := newRig(t)
	k := r.derive(key.LimitExpires(hour))
	submit := func(at int64, id string) {
		t.Helper()
		must(t, r.k.Submit(at, r.sign(kernel.Plan{ID: id, Key: k, Steps: []kernel.PlanStep{st(key.Organize, id)}})))
		must(t, r.tick(at))
	}
	submit(2*hour, "late")
	submit(hour/2, "stepped-back")
	for _, id := range []string{"late", "stepped-back"} {
		if r.status(id) != kernel.SRejected {
			t.Fatalf("%s: %s under a key that expired at 1 h, want rejected", id, r.status(id))
		}
	}
	if n := len(r.mail.Effects()); n != 0 {
		t.Fatalf("%d effects under an expired key", n)
	}
	es := r.k.Log().Entries()
	for i := 1; i < len(es); i++ {
		if es[i].Late != nil { // an exact reading logs no Late
			t.Fatalf("entry %d at an exact reading carries Late %d", es[i].Seq, *es[i].Late)
		}
		if es[i].At < es[i-1].At {
			t.Fatalf("entry %d at %d is before entry %d at %d", es[i].Seq, es[i].At, es[i-1].Seq, es[i-1].At)
		}
	}
	if last := es[len(es)-1]; last.At != 2*hour {
		t.Fatalf("the stepped-back entry is at %d, want the floor %d", last.At, 2*hour)
	}
	if _, err := kernel.Rederive(r.anchors(), r.k.Box(), es); err != nil {
		t.Fatal(err)
	}
	// A log whose times decrease is not one the kernel wrote.
	bad := append([]kernel.Entry(nil), es...)
	bad[len(bad)-1].At = hour / 2
	var d *kernel.Divergence
	if _, err := kernel.Rederive(r.anchors(), r.k.Box(), bad); !errors.As(err, &d) || d.Seq != bad[len(bad)-1].Seq ||
		d.Derived != fmt.Sprintf("a time no earlier than %d", es[len(es)-2].At) {
		t.Fatalf("a log whose times decrease: want a divergence on its time at its last entry, got %v", err)
	}
	if _, err := r.k.Log().Append(hour, kernel.TStop, 1, struct{}{}); !errors.Is(err, kernel.ErrBackward) {
		t.Fatalf("an append before the last entry: %v, want ErrBackward", err)
	}
}

// The kernel decides on the TIM-1 guard's interval: a key expires once the
// latest credible time passes its expiry, though the earliest has not, and
// a hold ends only once the earliest credible time reaches its due, though
// the latest is past it. Each entry carries the reading it used, so Rederive
// checks both moves from the log alone and refuses a log that claims either
// on a reading that does not allow it.
//
// REQ: TIM-1, KEY-7, KEY-8
func TestTIM1ReadingDecidesBothWays(t *testing.T) {
	r := newRig(t)
	buy := r.grant(key.Issue(r.owner.pass, key.Root{Clerk: "mail", Verbs: []key.Verb{key.Buy}, Serial: "r2"}), 1<<40)
	var now kernel.Reading
	r.k.UseClock(func() kernel.Reading { return now })
	at := func(e, l int64) int64 { now = kernel.Reading{Earliest: e, Latest: l}; return e }

	// Expiry by Latest.
	k := r.derive(key.LimitExpires(hour))
	must(t, r.k.Submit(at(0, hour), r.sign(kernel.Plan{ID: "expired", Key: k, Steps: []kernel.PlanStep{st(key.Organize, "a")}})))
	if r.status("expired") != kernel.SRejected {
		t.Fatalf("a plan when the latest credible time is the key's expiry: %s, want rejected", r.status("expired"))
	}

	// A hold waits for Earliest.
	s := st(key.Buy, "shop")
	s.Args["amount"] = "10"
	must(t, r.k.Submit(at(0, 0), r.sign(kernel.Plan{ID: "held", Key: buy, Steps: []kernel.PlanStep{s}})))
	must(t, r.tick(at(0, 0)))
	if p := r.k.State().Plans["held"]; p.Steps[0].Phase != kernel.PHeld {
		t.Fatalf("a capped buy: phase %s, want held", p.Steps[0].Phase)
	}
	must(t, r.tick(at(hour-1, 5*hour)))
	if p := r.k.State().Plans["held"]; p.Steps[0].Phase != kernel.PHeld || len(r.mail.Effects()) != 0 {
		t.Fatalf("a hold ended on a reading whose earliest time is before its due: phase %s", p.Steps[0].Phase)
	}
	must(t, r.tick(at(hour, hour)))
	if len(r.mail.Effects()) != 1 {
		t.Fatalf("the hold's due: %d effects, want 1", len(r.mail.Effects()))
	}

	es := r.k.Log().Entries()
	if _, err := kernel.Rederive(r.anchors(), r.k.Box(), es); err != nil {
		t.Fatal(err)
	}
	find := func(typ, plan string) int {
		for i, e := range es {
			var b struct{ Plan string }
			if e.Type == typ && json.Unmarshal(e.Body, &b) == nil && b.Plan == plan {
				return i
			}
		}
		t.Fatalf("no %s for %s", typ, plan)
		return 0
	}
	if e := es[find(kernel.TPlanRejected, "expired")]; e.At != 0 || e.Late == nil || *e.Late != hour {
		t.Fatalf("the rejection carries reading %d, %v, want [0, %d]", e.At, e.Late, hour)
	}
	for name, tc := range map[string]struct {
		i  int
		to func(*kernel.Entry)
	}{
		// The accept the kernel would log at [0, 0], claimed at [0, 1 h].
		"an admission past the key's expiry by Latest": {find(kernel.TPlanRejected, "expired"), func(e *kernel.Entry) {
			acc := es[find(kernel.TPlanAccepted, "held")]
			*e = acc
			var b map[string]any
			must(t, json.Unmarshal(acc.Body, &b))
			b["plan"], b["cause"] = "expired", es[find(kernel.TPlanSubmit, "")].Seq
			e.Body, _ = json.Marshal(b)
			e.Seq, e.At, e.Late = es[find(kernel.TPlanRejected, "expired")].Seq, 0, &[]int64{hour}[0]
		}},
		"a dispatch from a hold whose Earliest is before its due": {find(kernel.TStepDispatch, "held"), func(e *kernel.Entry) {
			e.At, e.Late = hour-1, &[]int64{5 * hour}[0]
		}},
	} {
		t.Run(name, func(t *testing.T) {
			bad := append([]kernel.Entry(nil), es...)
			tc.to(&bad[tc.i])
			_, err := kernel.Rederive(r.anchors(), r.k.Box(), bad)
			var d *kernel.Divergence
			if !errors.As(err, &d) || d.Seq != es[tc.i].Seq {
				t.Fatalf("want a divergence at seq %d, got %v", es[tc.i].Seq, err)
			}
		})
	}
}

// A widening window starts at the latest credible time and ends on the
// earliest, so it runs its full length of true time however wide the
// reading: a hold started on [0, 1 h - 1 ms] is not over at [1 h, 1 h], and
// a grant issued on [0, GrantHold - 1 ms] is not live at GrantHold. Rederive
// fails a log that dispatched the hold at 1 h (TIM-1, KEY-4, KEY-8).
//
// REQ: TIM-1, KEY-4, KEY-8
func TestTIM1AWideningWindowStartsAtLatest(t *testing.T) {
	r := newRig(t)
	buy := r.grant(key.Issue(r.owner.pass, key.Root{Clerk: "mail", Verbs: []key.Verb{key.Buy}, Serial: "w1"}), 1<<40)
	var now kernel.Reading
	r.k.UseClock(func() kernel.Reading { return now })
	at := func(e, l int64) int64 { now = kernel.Reading{Earliest: e, Latest: l}; return e }
	s := st(key.Buy, "shop")
	s.Args["amount"] = "10"
	must(t, r.k.Submit(at(0, hour-1), r.sign(kernel.Plan{ID: "held", Key: buy, Steps: []kernel.PlanStep{s}})))
	must(t, r.tick(at(0, hour-1)))
	must(t, r.tick(at(hour, hour)))
	if p := r.k.State().Plans["held"]; p.Steps[0].Phase != kernel.PHeld || len(r.mail.Effects()) != 0 {
		t.Fatalf("a hold started at Latest 1 h - 1 ms ended at 1 h: phase %s", p.Steps[0].Phase)
	}
	must(t, r.tick(at(2*hour-1, 2*hour-1)))
	if len(r.mail.Effects()) != 1 {
		t.Fatalf("the hold's due from Latest: %d effects, want 1", len(r.mail.Effects()))
	}
	es := r.k.Log().Entries()
	if _, err := kernel.Rederive(r.anchors(), r.k.Box(), es); err != nil {
		t.Fatal(err)
	}
	bad := append([]kernel.Entry(nil), es...)
	i := len(bad) - 1
	for bad[i].Type != kernel.TStepDispatch {
		i--
	}
	bad[i].At = hour
	var d *kernel.Divergence
	if _, err := kernel.Rederive(r.anchors(), r.k.Box(), bad); !errors.As(err, &d) || d.Seq != bad[i].Seq {
		t.Fatalf("a dispatch at 1 h from a hold started at Latest 1 h - 1 ms: want a divergence at seq %d, got %v", bad[i].Seq, err)
	}

	k := key.Issue(r.owner.pass, key.Root{Clerk: "mail", Verbs: []key.Verb{key.Trash}, Serial: "w2"})
	must(t, r.issue(at(2*hour, 2*hour+kernel.GrantHold-1), k))
	if from, _ := r.k.State().Granted(k.Tip()); from != 2*hour+2*kernel.GrantHold-1 {
		t.Fatalf("a grant issued on [2 h, 2 h + GrantHold - 1 ms] is live from %d, want a hold after Latest", from)
	}
}

// Rederive judges each decision at its entry's reading: a tick and a send
// whose Latest passes a key's expiry cancel the plan, and Rederive agrees;
// a dispatch whose logged Latest had passed it is a divergence (TIM-1).
//
// REQ: TIM-1, KEY-7, KRN-1
func TestTIM1ARederiveReadsEachEntrysLatest(t *testing.T) {
	r := newRig(t)
	var now kernel.Reading
	r.k.UseClock(func() kernel.Reading { return now })
	at := func(e, l int64) int64 { now = kernel.Reading{Earliest: e, Latest: l}; return e }
	at(0, 0)
	r.plan("a", r.derive(key.LimitExpires(hour)), st(key.Organize, "a"))
	must(t, r.tick(at(0, hour)))
	at(hour, hour)
	r.plan("b", r.derive(key.LimitExpires(2*hour)), st(key.Organize, "b"))
	cs, err := r.k.Calls(0)
	must(t, err)
	at(hour, 2*hour)
	if ok, err := r.k.Send(0, cs[0]); err != nil || ok {
		t.Fatalf("a send whose Latest passed the key's expiry: sent %v, %v", ok, err)
	}
	for _, id := range []string{"a", "b"} {
		if p := r.k.State().Plans[id]; p.Status != kernel.SCancelled || p.Cancel != key.RExpired {
			t.Fatalf("%s: %s %s, want cancelled as expired by Latest", id, p.Status, p.Cancel)
		}
	}
	at(3*hour-1, 3*hour-1)
	r.plan("c", r.derive(key.LimitExpires(3*hour)), st(key.Organize, "c"))
	must(t, r.tick(3*hour-1))
	if r.status("c") != kernel.SDone {
		t.Fatalf("c: %s", r.status("c"))
	}
	r.replays()
	bad := append([]kernel.Entry(nil), r.k.Log().Entries()...)
	i := len(bad) - 1
	for bad[i].Type != kernel.TStepDispatch {
		i--
	}
	late := 3 * hour
	bad[i].Late = &late
	var d *kernel.Divergence
	if _, err := kernel.Rederive(r.anchors(), r.k.Box(), bad); !errors.As(err, &d) || d.Seq != bad[i].Seq {
		t.Fatalf("a dispatch logged with a Latest past its key's expiry: want a divergence at seq %d, got %v", bad[i].Seq, err)
	}
}

// A grant is live once Earliest is past its hold: a plan under it at a
// reading whose Latest alone is past the hold is refused (TIM-1, D-146).
//
// REQ: TIM-1, KEY-4
func TestTIM1AGrantLiveOnEarliest(t *testing.T) {
	r := newRig(t)
	root := key.Issue(r.owner.pass, key.Root{Clerk: "mail", Verbs: []key.Verb{key.Organize}, Serial: "g"})
	k, err := key.ClerkKey(root, r.owner.pass, r.holder.pub, 0, 1<<40)
	must(t, err)
	must(t, r.issue(0, root, k))
	wide(r, kernel.GrantHold-1)
	r.plan("p", k, st(key.Organize, "a"))
	if r.status("p") != kernel.SRejected {
		t.Fatalf("a plan under a grant live only by Latest: %s", r.status("p"))
	}
}

// Send takes a fresh reading: a dispatch whose key expires while an earlier
// call in the same tick hangs is answered unsent, and its plan cancelled,
// though the tick began before the expiry.
//
// REQ: TIM-1, KEY-7, KRN-5
func TestTIM1SendReadsTheClockAfresh(t *testing.T) {
	r := newRig(t)
	var now int64
	r.k.UseClock(func() kernel.Reading { return kernel.At(now) })
	r.plan("first", r.ck, st(key.Organize, "a"))
	r.plan("second", r.derive(key.LimitExpires(hour/2)), st(key.Organize, "b"))
	cs, err := r.k.Calls(0)
	must(t, err)
	if len(cs) != 2 {
		t.Fatalf("%d calls at 0, want both dispatches", len(cs))
	}
	ok, err := r.k.Send(0, cs[0])
	must(t, err)
	if !ok {
		t.Fatal("the first dispatch was not sent")
	}
	now = hour // the first clerk call hung for an hour
	must(t, r.k.Answer(0, cs[0], r.mail.Do(cs[0].Req, r.k.State())))
	ok, err = r.k.Send(0, cs[1])
	must(t, err)
	if ok {
		t.Fatal("a dispatch was sent under a key that expired while the call before it hung")
	}
	if p := r.k.State().Plans["second"]; p.Status != kernel.SCancelled || p.Cancel != key.RExpired {
		t.Fatalf("second: %s %s, want cancelled as expired", p.Status, p.Cancel)
	}
	if _, err := kernel.Rederive(r.anchors(), r.k.Box(), r.k.Log().Entries()); err != nil {
		t.Fatal(err)
	}
}
