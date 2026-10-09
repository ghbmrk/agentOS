package journal

// SR2-3j: a denial's reason reaches the guest only as text the policy
// wrote for it (guesterr.Safe, by its own method set); anything else is
// kept for the owner and the log, never marked for the guest.
//
// REQ: RES-4, CAP-8

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/ghbmrk/agentos/broker/guesterr"
)

// safeRefusal is a policy refusal with separate owner and guest texts.
type safeRefusal struct{}

func (safeRefusal) Error() string     { return "denied: key " + canary }
func (safeRefusal) GuestText() string { return "not granted" }

// phasePolicy refuses the intent named by its ID, at the phase named.
type phasePolicy struct {
	deny  map[string]error
	phase Phase
}

func (p *phasePolicy) Check(_ context.Context, phase Phase, in Intent) error {
	if phase != p.phase {
		return nil
	}
	return p.deny[in.ID]
}

func TestOnlyASafeRefusalIsMarkedForTheGuest(t *testing.T) {
	for _, phase := range []Phase{PhaseAuthorize, PhaseDispatch} {
		t.Run(string(phase), func(t *testing.T) {
			p := &phasePolicy{phase: phase, deny: map[string]error{
				"safe":    safeRefusal{},
				"plain":   errors.New("open /var/lib/" + canary + ": denied"),
				"wrapped": fmt.Errorf("gate: %w", safeRefusal{}),
				"text":    guesterr.New("needs the owner's approval"),
			}}
			st := &MemStore{}
			e := mustOpen(t, st, p, newService())
			want := map[string]string{"safe": "not granted", "plain": "", "wrapped": "", "text": "needs the owner's approval"}
			for id := range want {
				must(e.Submit(intent(id, "acct")))
				must(e.Authorize(ctx, id))
				if phase == PhaseDispatch {
					e.Dispatch(ctx, id)
				}
			}
			check := func(e *Engine) {
				t.Helper()
				for id, g := range want {
					s := must(e.Get(id))
					if s.State != Denied || s.Permission.Phase != phase {
						t.Fatalf("%s: %s at %s", id, s.State, s.Permission.Phase)
					}
					if s.Permission.GuestReason != g {
						t.Errorf("%s: guest reason %q, want %q", id, s.Permission.GuestReason, g)
					}
					if s.Permission.Reason == "" {
						t.Errorf("%s: the owner's reason is gone", id)
					}
				}
			}
			check(e)
			// Replay keeps it: the guest's text is journaled with the denial.
			check(mustOpen(t, &MemStore{data: must(st.ReadAll())}, p, newService()))
		})
	}
}
