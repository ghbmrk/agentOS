package grants

import (
	"context"
	"testing"

	"github.com/ghbmrk/agentos/broker/journal"
)

// REQ: LOOP-9, ADP-9

// W5a, loops K-S2: Loop 2's containment pauses a grant from the broker's
// own origin, during STOP too. It can pause and nothing else: revoke stays
// the owner's (resuming is a grant change, with its code and local
// confirmation), and a guest cannot use the origin, since guest
// intents carry "guest:<lineage>" (guest/mcp.go), never a broker origin.
func TestLoop2PausesAGrantAndNothingElse(t *testing.T) {
	r := newRig(t, nil)
	r.grant(mailGrant())
	rule := r.grant(Spec{Account: "mail", Rule: &Rule{Action: "invoice.send", AmountCap: 15000, PerRecord: 5, PerDay: 50}})
	in := func(id, origin, action string) journal.Intent {
		return journal.Intent{ID: id, Origin: origin, Account: journal.BrokerAccount, Action: action, GrantRef: rule, Executor: ExecutorName}
	}
	for _, x := range []journal.Intent{
		in("loop2/revoke", OriginLoop2, journal.ActionGrantRevoke),
		in("agent/pause", "guest:"+OriginLoop2, journal.ActionGrantPause),
		in("agent/pause2", "guest:agent", journal.ActionGrantPause),
	} {
		if st := r.submit(x); st.State != journal.Denied {
			t.Fatalf("%s from %s: %s", x.Action, x.Origin, st.State)
		}
	}
	if _, err := r.eng.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}
	if st := r.submit(in("loop2/pause", OriginLoop2, journal.ActionGrantPause)); st.State != journal.Succeeded {
		t.Fatalf("Loop 2's pause during STOP: %s", st.State)
	}
	r.eng.Resume()
	x := sam()
	x.Record = "inv-1"
	r.ver.set("inv-1", x)
	if st := r.effect("agent/s1", "invoice.send", map[string]any{"record": "inv-1"}, "sam@example.com"); st.State != journal.Pending {
		t.Fatalf("paused rule still ran: %s", st.State)
	}
}

// Loop 2 lists a paused grant until the owner ends the pause: resuming or
// revoking it tells Config.Unpaused (W5a, loops S4).
func TestEndingAPauseIsReported(t *testing.T) {
	var got []string
	r := newRig(t, func(c *Config) { c.Unpaused = func(id string) { got = append(got, id) } })
	r.grant(mailGrant())
	rule := r.grant(Spec{Account: "mail", Rule: &Rule{Action: "invoice.send", AmountCap: 15000, PerRecord: 5, PerDay: 50}})
	if st := r.submit(journal.Intent{ID: "loop2/p", Origin: OriginLoop2, Account: journal.BrokerAccount,
		Action: journal.ActionGrantPause, GrantRef: rule, Executor: ExecutorName}); st.State != journal.Succeeded {
		t.Fatalf("pause: %s", st.State)
	}
	if len(got) != 0 {
		t.Fatalf("a pause reported as ended: %v", got)
	}
	r.grant(Spec{Resume: rule})
	if len(got) != 1 || got[0] != rule {
		t.Fatalf("after RESUME: %v", got)
	}
	if out := r.g.Narrow("REVOKE", rule); out == "" {
		t.Fatal("no reply to REVOKE")
	}
	if len(got) != 2 || got[1] != rule {
		t.Fatalf("after REVOKE: %v", got)
	}
}
