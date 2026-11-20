package clerk_test

import (
	"testing"

	"github.com/ghbmrk/agentos/broker/clerk"
	"github.com/ghbmrk/agentos/broker/kernel"
	"github.com/ghbmrk/agentos/broker/kernel/key"
)

// Each injected fault answers as it names: fail refuses before acting, drop
// answers nothing and acts not, and a lost ack acts but answers nothing, so
// the kernel's unknown-outcome path sees the effect the remote really had
// (KRN-8).
func TestMailFaultsAnswerAsTheyName(t *testing.T) {
	f := setup(t, key.Trash)
	for i, c := range []struct {
		fault, outcome, detail string
		effects                int
	}{
		{clerk.FaultFail, "failed", "fault", 0},
		{clerk.FaultDrop, "unknown", "no answer", 0},
		{clerk.FaultLostAck, "unknown", "no answer", 1},
	} {
		f.mail.Fault = func(string, kernel.Request) string { return c.fault }
		r := f.mail.Do(f.request(c.fault, f.root, stepOf(key.Trash)), f.view())
		if r.Outcome != c.outcome || r.Detail != c.detail {
			t.Errorf("fault %q: %+v, want %s %q", c.fault, r, c.outcome, c.detail)
		}
		if n := len(f.mail.Effects()); n != c.effects {
			t.Errorf("fault %q: %d effects after case %d, want %d", c.fault, n, i, c.effects)
		}
	}
}
