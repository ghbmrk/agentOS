package grants

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"

	"github.com/ghbmrk/agentos/broker/journal"
)

// REQ: OP-3, OP-4, REV-3

// approveStopped asks for and approves an invoice send while STOP holds
// it, so the approval stays held for a dispatch after RESUME.
func (r *rig) approveStopped(id, rec string) {
	r.t.Helper()
	r.ver.set(rec, func() Verified { v := sam(); v.Record = rec; return v }())
	if _, err := r.eng.Stop(context.Background()); err != nil {
		r.t.Fatal(err)
	}
	r.effect(id, "invoice.send", map[string]any{"record": rec}, "sam@example.com")
	r.g.Flush()
	r.decide(true, "owner")
	if st := r.state(id); st.State != journal.Authorized {
		r.t.Fatalf("%s should be authorized and held by STOP: %s", id, st.State)
	}
	if err := r.eng.Resume(); err != nil {
		r.t.Fatal(err)
	}
}

// TestApprovalUsedUpByTheDispatchCommit (GR8, Security ruling on #76): an
// owner's YES covers one attempt. The approval is used up by the journal's
// dispatch record itself, so a second dispatch that slips in before the
// gate's bookkeeping runs is refused at the recheck, not sent.
func TestApprovalUsedUpByTheDispatchCommit(t *testing.T) {
	r := newRig(t, nil)
	r.grant(mailGrant())
	r.approveStopped("agent/s1", "inv-s1")
	r.exec.fail = map[string]bool{"agent/s1": true}

	// The engine directly: no gate wrapper runs between the two dispatches.
	ctx := context.Background()
	if st, err := r.eng.Dispatch(ctx, "agent/s1"); err != nil || st.State != journal.NotApplied {
		t.Fatalf("first attempt: %s %v", st.State, err)
	}
	r.exec.fail = map[string]bool{}
	st, err := r.eng.Dispatch(ctx, "agent/s1")
	if !errors.Is(err, journal.ErrRecheck) || r.exec.runs("agent/s1") != 1 {
		t.Fatalf("second attempt on the same YES: %s %v, ran %d", st.State, err, r.exec.runs("agent/s1"))
	}
}

// TestConcurrentDispatchStartsOneAttempt (GR8): N rounds of many
// concurrent Dispatch calls on one approved intent whose attempts are not
// applied start exactly one attempt each round. Run under -race.
func TestConcurrentDispatchStartsOneAttempt(t *testing.T) {
	const rounds, callers, calls = 50, 8, 20
	r := newRig(t, nil)
	r.grant(mailGrant())
	r.exec.mu.Lock()
	r.exec.fail = map[string]bool{}
	r.exec.mu.Unlock()
	double := 0
	for i := 0; i < rounds; i++ {
		id := fmt.Sprintf("agent/c%d", i)
		r.approveStopped(id, "inv-"+id)
		r.exec.mu.Lock()
		r.exec.fail[id] = true
		r.exec.mu.Unlock()
		var wg sync.WaitGroup
		for c := 0; c < callers; c++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for k := 0; k < calls; k++ {
					r.g.Dispatch(context.Background(), id)
				}
			}()
		}
		wg.Wait()
		r.g.Wait()
		if n := r.exec.runs(id); n != 1 {
			double++
			t.Errorf("%s: %d attempts on one approval", id, n)
		}
	}
	if double != 0 {
		t.Fatalf("%d of %d rounds started a second attempt", double, rounds)
	}
}
