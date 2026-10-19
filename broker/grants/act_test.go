package grants

import (
	"testing"

	"github.com/ghbmrk/agentos/broker/journal"
)

// REQ: CH-10

// The act over the exact request bytes comes from the account's Verifier:
// the item the owner is asked to approve carries it unchanged, so the
// owner's code approves those bytes and no others (SIM-split-wire part 4).
func TestApprovalItemCarriesTheVerifiedAct(t *testing.T) {
	r := newRig(t, nil)
	r.grant(mailGrant())
	v := sam()
	v.Item.Act = "act-inv-1042"
	r.ver.set("inv-1042", v)
	st := r.effect("agent/act", "invoice.send", map[string]any{"template": "invoice", "record": "inv-1042"}, "sam@example.com")
	if st.State != journal.Pending {
		t.Fatalf("send: %s %q", st.State, st.Permission.Reason)
	}
	r.g.Flush()
	_, items := r.own.last(t)
	if len(items) != 1 || items[0].Act != "act-inv-1042" {
		t.Fatalf("asked items: %+v", items)
	}
}
