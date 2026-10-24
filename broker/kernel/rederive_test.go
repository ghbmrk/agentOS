package kernel_test

// REQ: KRN-1, EVL-1

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/ghbmrk/agentos/broker/kernel"
	"github.com/ghbmrk/agentos/broker/kernel/key"
)

// mixed runs one of each kernel decision: an accept, a reject, a hold, a
// dispatch, a cancel for a revoke during the hold, a cancel for a clerk the
// kernel lacks, and a send refused after a STOP.
func mixed(t *testing.T) *rig {
	r := newRig(t)
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
	bank := r.grant(key.Issue(r.owner.priv, key.Root{Clerk: "bank", Verbs: []key.Verb{key.Trash}, Serial: "b1"}), 1<<40)
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
	got, err := kernel.Rederive(r.anchors(), r.k.Log().Entries())
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
			_, err := kernel.Rederive(r.anchors(), bad)
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
