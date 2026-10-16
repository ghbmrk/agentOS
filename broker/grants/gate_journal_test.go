package grants

// REQ: OP-11, OP-12, CH-10, SM-AJ-1, SM-AJ-2, SM-AJ-3
//
// The owner's answer is journaled before the gate acts on it, and the
// gate's decided, confirmed and waiting state is rebuilt from the journal
// at a restart (SM-approval-journal, R3 of the state machine audit).

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/journal"
	"github.com/ghbmrk/agentos/broker/owner"
)

// failStore is the rig's journal with appends of one record type failing,
// as a full disk or a crash at that write would: the line never lands.
type failStore struct {
	*journal.MemStore
	mu     sync.Mutex
	failOn string // a record type; "" fails nothing
}

func (s *failStore) Append(line []byte) error {
	s.mu.Lock()
	t := s.failOn
	s.mu.Unlock()
	if t != "" && strings.Contains(string(line), `"type":"`+t+`"`) {
		return errors.New("disk full")
	}
	return s.MemStore.Append(line)
}

func (s *failStore) fail(t string) {
	s.mu.Lock()
	s.failOn = t
	s.mu.Unlock()
}

// openFailing restarts the rig's gate and engine on its journal behind a
// failStore, as openWith does on the journal itself.
func (r *rig) openFailing() *failStore {
	r.t.Helper()
	fs := &failStore{MemStore: r.store}
	r.own = &fakeOwner{limits: owner.Limits{AmountLimit: 50000}, now: r.now, reqs: map[string][]owner.Item{}}
	r.g = New(r.cfg)
	eng, err := journal.Open(fs, r.g, map[string]journal.Executor{"mail": r.exec, ExecutorName: r.g},
		func(s string) string { return s }, journal.WithClock(r.now))
	if err != nil {
		r.t.Fatal(err)
	}
	r.eng = eng
	r.g.Attach(eng, r.own)
	r.g.Reissue(nil)
	return fs
}

// invoice puts one invoice send to sam up for the owner's approval.
func (r *rig) invoice(id, rec string) {
	r.t.Helper()
	x := sam()
	x.Record = rec
	r.ver.set(rec, x)
	r.effect(id, "invoice.send", map[string]any{"record": rec}, "sam@example.com")
	r.g.Flush()
	if st := r.state(id); st.State != journal.Pending {
		r.t.Fatalf("%s: %s %q, want pending", id, st.State, st.Permission.Reason)
	}
}

// answers returns the journaled owner answers for id.
func answers(eng *journal.Engine, id string) []journal.Record {
	var out []journal.Record
	for _, r := range eng.Trail() {
		if r.Type == journal.RecAnswer && r.ID == id {
			out = append(out, r)
		}
	}
	return out
}

func seqOf(eng *journal.Engine, id string, t journal.RecordType) uint64 {
	for _, r := range eng.Trail() {
		if r.Type == t && r.ID == id {
			return r.Seq
		}
	}
	return 0
}

// TestAnswerIsJournaledBeforeAuthorize (SM-AJ-1, OP-12): the owner's
// answer is journaled before the intent is authorized, and carries no
// code. An answer that cannot be journaled is not acted on.
func TestAnswerIsJournaledBeforeAuthorize(t *testing.T) {
	r := newRig(t, nil)
	r.grant(mailGrant())
	r.invoice("agent/a", "inv-a")
	_, items := r.own.last(t)
	r.decide(true, "owner")
	if st := r.state("agent/a"); st.State != journal.Succeeded {
		t.Fatalf("agent/a: %s %q", st.State, st.Permission.Reason)
	}
	as := answers(r.eng, "agent/a")
	if len(as) != 1 {
		t.Fatalf("answers journaled = %d, want 1", len(as))
	}
	a := as[0]
	if auth := seqOf(r.eng, "agent/a", journal.RecAuthorized); auth == 0 || a.Seq > auth {
		t.Fatalf("answer at seq %d, authorized at %d: the answer must come first", a.Seq, auth)
	}
	if a.Answer == nil || !a.Answer.Approved || !a.Answer.Asked || a.Answer.Sum != owner.ItemSum(items[0]) {
		t.Fatalf("answer note = %+v", a.Answer)
	}

	// A denial is journaled too.
	r.invoice("agent/b", "inv-b")
	r.decide(false, "owner")
	if as := answers(r.eng, "agent/b"); len(as) != 1 || as[0].Answer.Approved {
		t.Fatalf("denial journaled as %+v", as)
	}

	// An approval the journal cannot take is not acted on.
	fs := r.openFailing()
	r.invoice("agent/c", "inv-c")
	fs.fail(string(journal.RecAnswer))
	r.decide(true, "owner")
	if n := r.exec.runs("agent/c"); n != 0 {
		t.Fatalf("an approval that was not journaled ran %d times", n)
	}
	if st := r.state("agent/c"); st.State != journal.Pending {
		t.Fatalf("agent/c: %s, want still pending", st.State)
	}
}

// approveThenCrash asks the owner about id, journals the approval, and
// crashes at the authorize record, so only the answer is durable.
func (r *rig) approveThenCrash(id, rec string) owner.Item {
	r.t.Helper()
	fs := r.openFailing()
	r.invoice(id, rec)
	_, items := r.own.last(r.t)
	fs.fail(string(journal.RecAuthorized))
	r.decide(true, "owner")
	if n := r.exec.runs(id); n != 0 {
		r.t.Fatalf("%s ran %d times through a failed authorize", id, n)
	}
	if len(answers(r.eng, id)) != 1 {
		r.t.Fatalf("%s: answer not journaled", id)
	}
	return items[0]
}

// TestDecidedSurvivesRestart (SM-AJ-2, OP-11): an approval journaled
// before a restart is honoured after it, without asking the owner again:
// one held by STOP dispatches on RESUME, and one whose authorize never
// landed is settled at boot.
func TestDecidedSurvivesRestart(t *testing.T) {
	ctx := context.Background()
	t.Run("held by STOP", func(t *testing.T) {
		r := newRig(t, nil)
		r.grant(mailGrant())
		if _, err := r.eng.Stop(ctx); err != nil {
			t.Fatal(err)
		}
		r.invoice("agent/a", "inv-a")
		r.decide(true, "owner")
		if st := r.state("agent/a"); st.State != journal.Authorized {
			t.Fatalf("agent/a should be held by STOP: %s", st.State)
		}
		r.advance(10 * time.Minute)
		r.open()
		if err := r.eng.Resume(); err != nil {
			t.Fatal(err)
		}
		st, _ := r.g.Dispatch(ctx, "agent/a")
		if st.State != journal.Succeeded || r.exec.runs("agent/a") != 1 {
			t.Fatalf("after restart: %s %q, runs %d", st.State, st.Permission.Reason, r.exec.runs("agent/a"))
		}
		if n := r.own.count(); n != 0 {
			t.Fatalf("the owner was asked %d more times", n)
		}
	})
	t.Run("crash before authorize", func(t *testing.T) {
		r := newRig(t, nil)
		r.grant(mailGrant())
		r.approveThenCrash("agent/a", "inv-a")
		r.open()
		r.g.Wait()
		if st := r.state("agent/a"); st.State != journal.Succeeded || r.exec.runs("agent/a") != 1 {
			t.Fatalf("after restart: %s %q, runs %d", st.State, st.Permission.Reason, r.exec.runs("agent/a"))
		}
		if n := r.own.count(); n != 0 {
			t.Fatalf("the owner was asked %d more times", n)
		}
	})
	t.Run("denial before authorize", func(t *testing.T) {
		r := newRig(t, nil)
		r.grant(mailGrant())
		fs := r.openFailing()
		r.invoice("agent/a", "inv-a")
		fs.fail(string(journal.RecDenied))
		r.decide(false, "owner")
		r.open()
		r.g.Wait()
		if st := r.state("agent/a"); st.State != journal.Denied || r.exec.runs("agent/a") != 0 {
			t.Fatalf("after restart: %s %q, runs %d", st.State, st.Permission.Reason, r.exec.runs("agent/a"))
		}
		if n := r.own.count(); n != 0 {
			t.Fatalf("a denied intent was asked again %d times", n)
		}
	})
	t.Run("local confirmation", func(t *testing.T) {
		r := newRig(t, nil)
		fs := r.openFailing()
		id := "local/grant/0"
		st := r.submit(journal.Intent{ID: id, Origin: "local", Account: journal.BrokerAccount,
			Action: journal.ActionGrantChange, Params: specParams(mailGrant()), Executor: ExecutorName})
		if st.State != journal.Pending {
			t.Fatalf("grant: %s %q", st.State, st.Permission.Reason)
		}
		r.g.Flush()
		fs.fail(string(journal.RecAuthorized))
		r.pageDecide("")
		r.open()
		r.g.Wait()
		if st := r.state(id); st.State != journal.Succeeded {
			t.Fatalf("grant after restart: %s %q", st.State, st.Permission.Reason)
		}
		if n := r.own.count(); n != 0 {
			t.Fatalf("the owner was asked %d more times", n)
		}
	})
}

// TestStaleDecisionRefusedAfterRestart (SM-AJ-2, OP-3): Fresh runs from
// the journaled answer, not from the restart, so an approval older than
// Fresh is refused at dispatch after a restart.
func TestStaleDecisionRefusedAfterRestart(t *testing.T) {
	ctx := context.Background()
	r := newRig(t, nil)
	r.grant(mailGrant())
	if _, err := r.eng.Stop(ctx); err != nil {
		t.Fatal(err)
	}
	r.invoice("agent/a", "inv-a")
	r.decide(true, "owner")
	r.advance(DefaultFresh + time.Minute)
	r.open()
	if err := r.eng.Resume(); err != nil {
		t.Fatal(err)
	}
	st, _ := r.g.Dispatch(ctx, "agent/a")
	if st.State != journal.Denied || !strings.Contains(st.Permission.Reason, "older") || r.exec.runs("agent/a") != 0 {
		t.Fatalf("stale approval after restart: %s %q, runs %d", st.State, st.Permission.Reason, r.exec.runs("agent/a"))
	}
}

// TestWaitingRebuiltAfterRestart (SM-AJ-3, CH-10): an intent the owner
// answered is not asked again at boot, even when the owner channel
// carries its request (its retire did not save); one never answered is
// asked exactly once.
func TestWaitingRebuiltAfterRestart(t *testing.T) {
	r := newRig(t, nil)
	r.grant(mailGrant())
	fs := r.openFailing()
	r.invoice("agent/a", "inv-a")
	ra, ia := r.own.last(t)
	r.invoice("agent/b", "inv-b")
	rb, ib := r.own.last(t)
	fs.fail(string(journal.RecAuthorized))
	r.g.Decide(owner.Decision{Request: ra, Item: 1, Ref: "agent/a", Approved: true, Why: "owner"})
	r.g.Wait()
	if n := r.exec.runs("agent/a"); n != 0 {
		t.Fatalf("agent/a ran %d times through a failed authorize", n)
	}
	exp := r.now().Add(time.Hour)
	r.boot = []owner.Carried{
		{Ref: "agent/a", Request: ra, Asked: r.now(), Expires: exp, Sum: owner.ItemSum(ia[0])},
		{Ref: "agent/b", Request: rb, Asked: r.now(), Expires: exp, Sum: owner.ItemSum(ib[0])},
	}
	r.open()
	r.g.Wait()
	r.g.Flush()
	if st := r.state("agent/a"); st.State != journal.Succeeded || r.exec.runs("agent/a") != 1 {
		t.Fatalf("answered agent/a: %s %q, runs %d", st.State, st.Permission.Reason, r.exec.runs("agent/a"))
	}
	if n := r.own.count(); n != 1 {
		t.Fatalf("owner asked %d times after restart, want 1 (agent/b only)", n)
	}
	if _, got := r.own.last(t); len(got) != 1 || got[0].Ref != "agent/b" {
		t.Fatalf("re-asked %+v, want agent/b", got)
	}
}
