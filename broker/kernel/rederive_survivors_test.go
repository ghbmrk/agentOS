package kernel_test

// REQ: KRN-1, EVL-1

import (
	"bytes"
	"errors"
	"testing"

	"github.com/ghbmrk/agentos/broker/kernel"
	"github.com/ghbmrk/agentos/broker/kernel/key"
)

// divergenceAt fails t unless Rederive over es returns a *Divergence at seq,
// and gives it.
func divergenceAt(t *testing.T, r *rig, es []kernel.Entry, seq uint64) *kernel.Divergence {
	t.Helper()
	_, err := kernel.Rederive(r.anchors(), r.k.Box(), es)
	var d *kernel.Divergence
	if !errors.As(err, &d) || d.Seq != seq {
		t.Fatalf("want a divergence at seq %d, got %v", seq, err)
	}
	return d
}

// A divergence names what the entries before it give in the logged
// decision's place: a reject logged as an accept reports the reject the
// kernel derives, byte for byte, not "nothing".
func TestRederiveDivergenceNamesTheDerivedDecision(t *testing.T) {
	r := mixed(t)
	es := append([]kernel.Entry(nil), r.k.Log().Entries()...)
	for i, e := range es {
		if e.Type != kernel.TPlanRejected {
			continue
		}
		want := e.Type + " " + string(e.Body)
		es[i].Type = kernel.TPlanAccepted
		d := divergenceAt(t, r, es, e.Seq)
		if d.Derived != want {
			t.Fatalf("derived %q, want %q", d.Derived, want)
		}
		return
	}
	t.Fatal("the run logged no reject")
}

// A plan is decided once: the same accept logged again, when the plan is
// already active, is a decision the entries before it do not give.
func TestRederiveRefusesASecondDecisionForOnePlan(t *testing.T) {
	r := mixed(t)
	all := r.k.Log().Entries()
	for i, e := range all {
		if e.Type != kernel.TPlanAccepted {
			continue
		}
		again := e
		again.Seq = e.Seq + 1
		es := append(append(append([]kernel.Entry(nil), all[:i+1]...), again), all[i+1:]...)
		if d := divergenceAt(t, r, es, again.Seq); d.Derived != "nothing" {
			t.Fatalf("derived %q for a decided plan, want nothing", d.Derived)
		}
		return
	}
	t.Fatal("the run logged no accept")
}

// Only an unsent answer can be followed by the send check's cancel: an
// answer the clerk gave, to a step whose key was revoked after it was sent,
// allows no cancel after it, though the send check would refuse that step now.
func TestRederiveAllowsNoSendCancelAfterAnAnsweredStep(t *testing.T) {
	r := newRig(t)
	k := r.derive(key.LimitExpires(100 * hour))
	r.plan("a", k, st(key.Trash, "m1"))
	r.plan("b", k, st(key.Trash, "m2"))
	cs := r.calls(1, 2)
	ca, cb := cs[0], cs[1]
	if ca.Req.Plan.ID != "a" {
		ca, cb = cb, ca
	}
	ok, err := r.k.Send(1, ca)
	must(t, err)
	if !ok {
		t.Fatal("a was not sent")
	}
	must(t, r.k.Revoke(2, k.Tip()))
	ok, err = r.k.Send(3, cb)
	must(t, err)
	if ok {
		t.Fatal("b was sent under a revoked key")
	}
	es := r.k.Log().Entries()
	var cancelB []byte
	for _, e := range es {
		if e.Type == kernel.TPlanCancel && bytes.Contains(e.Body, []byte(`"plan":"b"`)) {
			cancelB = e.Body
		}
	}
	if !bytes.Contains(cancelB, []byte(`"code":"`+key.RRevoked.String()+`"`)) {
		t.Fatalf("b's cancel %s, want it revoked", cancelB)
	}
	must(t, r.k.Answer(4, ca, r.mail.Do(ca.Req, r.k.State())))
	es = r.k.Log().Entries()
	if last := es[len(es)-1]; last.Type != kernel.TStepResult || bytes.Contains(last.Body, []byte(kernel.OUnsent)) {
		t.Fatalf("last entry %s %s, want a's answered result", last.Type, last.Body)
	}
	if _, err := kernel.Rederive(r.anchors(), r.k.Box(), es); err != nil {
		t.Fatal(err)
	}
	last := es[len(es)-1]
	forged := kernel.Entry{Seq: last.Seq + 1, At: last.At, Type: kernel.TPlanCancel,
		Body: bytes.Replace(cancelB, []byte(`"plan":"b"`), []byte(`"plan":"a"`), 1)}
	divergenceAt(t, r, append(es, forged), forged.Seq)
}

// An unsent answer naming no step of a plan the log holds is folded as
// given: no send check runs on a step that is not there.
func TestRederiveFoldsAnUnsentAnswerForNoStep(t *testing.T) {
	r := mixed(t)
	es := r.k.Log().Entries()
	before := rederives(t, r).Recorded[kernel.TStepResult]
	last := es[len(es)-1]
	for _, body := range []string{
		`{"plan":"ghost","index":0,"outcome":"unsent"}`,
		`{"plan":"now","index":7,"outcome":"unsent"}`,
		`{"plan":"now","index":-1,"outcome":"unsent"}`,
	} {
		bad := append(append([]kernel.Entry(nil), es...), kernel.Entry{Seq: last.Seq + 1, At: last.At, Type: kernel.TStepResult, Body: []byte(body)})
		got, err := kernel.Rederive(r.anchors(), r.k.Box(), bad)
		if err != nil || got.Recorded[kernel.TStepResult] != before+1 {
			t.Fatalf("%s: %v, recorded %v, want it folded as given", body, err, got.Recorded)
		}
	}
}

// The send check's cancel may follow only an unsent answer to a step in
// flight on an active plan: after a plan is cancelled for its revoked key, an
// unsent answer to its step allows no cancel for the STOP in force, though
// the send check would refuse that step for it.
func TestRederiveAllowsNoSendCancelForAnEndedPlan(t *testing.T) {
	r := mixed(t)
	es := r.k.Log().Entries()
	var revoked, stopped []byte
	for _, e := range es {
		if e.Type == kernel.TPlanCancel && bytes.Contains(e.Body, []byte(`"plan":"revoked"`)) {
			revoked = e.Body
		}
		if e.Type == kernel.TPlanCancel && bytes.Contains(e.Body, []byte(`"plan":"stopped"`)) {
			stopped = e.Body
		}
	}
	if !bytes.Contains(revoked, []byte(`"code":"`+key.RRevoked.String()+`"`)) || !bytes.Contains(stopped, []byte(`"code":"`+key.RStopped.String()+`"`)) {
		t.Fatalf("cancels %s and %s, want revoked and stopped", revoked, stopped)
	}
	last := es[len(es)-1]
	unsent := kernel.Entry{Seq: last.Seq + 1, At: last.At, Type: kernel.TStepResult,
		Body: []byte(`{"plan":"revoked","index":0,"idem":"` + kernel.Idem("revoked", 0) + `","outcome":"unsent"}`)}
	again := kernel.Entry{Seq: last.Seq + 2, At: last.At, Type: kernel.TPlanCancel,
		Body: bytes.Replace(stopped, []byte(`"plan":"stopped"`), []byte(`"plan":"revoked"`), 1)}
	divergenceAt(t, r, append(append([]kernel.Entry(nil), es...), unsent, again), again.Seq)
}
