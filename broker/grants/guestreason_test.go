package grants

// SR2-3j: the gate's refusals carry fixed text for the guest, apart from
// the owner's reason, which may echo a parse error, a pipeline's refusal
// or the owner's own words.
//
// REQ: RES-4, CAP-8

import (
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/change"
	"github.com/ghbmrk/agentos/broker/journal"
)

// guestCanary is a synthetic host path; it is no real path on any box.
const guestCanary = "/var/lib/agentos-canary-7f3a/owner.db"

// checkGuestReasons fails t if a denied or explained intent in the rig's
// journal has no text for the guest, or text naming a path; newRigExecs
// runs it as every grants test ends.
func (r *rig) checkGuestReasons(t *testing.T) {
	if r.g == nil {
		return
	}
	for _, st := range r.g.List() {
		g := st.Permission.GuestReason
		if st.State == journal.Denied && g == "" {
			t.Errorf("%s denied with no guest text (owner's: %q)", st.Intent.ID, st.Permission.Reason)
		}
		if strings.Contains(g, "/") || strings.Contains(g, "canary") {
			t.Errorf("%s: guest text names a path: %q", st.Intent.ID, g)
		}
	}
}

func TestRefusalsShowTheGuestOnlyFixedText(t *testing.T) {
	r, _ := changeRig(t)
	// A pipeline refusal is the owner's detail; the guest sees fixed words.
	st := r.submit(journal.Intent{ID: "chg:c77:revert:n1:owner", Origin: change.OriginOwner, Account: journal.BrokerAccount,
		Action: change.ActionRevert, Executor: change.Executor, Params: map[string]any{"adoption": "c77", "why": "owner"}})
	if st.State != journal.Denied || !strings.Contains(st.Permission.Reason, "no active adoption") {
		t.Fatalf("%s %q", st.State, st.Permission.Reason)
	}
	if g := st.Permission.GuestReason; g != "the change pipeline refused it" {
		t.Fatalf("pipeline refusal shown to the guest as %q", g)
	}
	// A literal refusal is the same text for both.
	st = r.submit(journal.Intent{ID: "chg:policy:n1:auto_adopt:off", Origin: "guest:agent", Account: journal.BrokerAccount,
		Action: change.ActionPolicyOff, Executor: change.Executor, Params: map[string]any{"setting": "auto_adopt", "value": "off"}})
	if st.Permission.GuestReason != st.Permission.Reason || st.Permission.Reason != "broker actions are not available to agents" {
		t.Fatalf("%q %q", st.Permission.Reason, st.Permission.GuestReason)
	}
}

func TestTheOwnersWordsAndChannelErrorsStayOffTheGuest(t *testing.T) {
	r := newRig(t, nil)
	r.grant(mailGrant())
	r.ver.set("inv-1042", sam())
	r.effect("agent/s1", "invoice.send", map[string]any{"record": "inv-1042"}, "sam@example.com")
	r.g.Flush()
	r.decide(false, "see "+guestCanary)
	st := r.state("agent/s1")
	if st.State != journal.Denied || !strings.Contains(st.Permission.Reason, guestCanary) {
		t.Fatalf("%s %q", st.State, st.Permission.Reason)
	}
	if g := st.Permission.GuestReason; g != "not approved by the owner" {
		t.Fatalf("owner's decline shown to the guest as %q", g)
	}

	// An ask the owner's channel refused: its error is the owner's.
	r.own.down = true
	r.effect("agent/s2", "invoice.send", map[string]any{"record": "inv-1042"}, "sam@example.com")
	r.g.Flush()
	st = r.state("agent/s2")
	if st.State != journal.Pending || !strings.Contains(st.Permission.Reason, "no modem") {
		t.Fatalf("%s %q", st.State, st.Permission.Reason)
	}
	if g := st.Permission.GuestReason; g != "could not ask the owner; retry later" {
		t.Fatalf("channel error shown to the guest as %q", g)
	}
}
