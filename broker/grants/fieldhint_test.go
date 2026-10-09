package grants

// SR2-3o: a malformed grant change or destination change tells the guest
// which field or cause to fix, in fixed words: no value it sent, no path,
// no owner or host text. The owner's reason keeps the detail.
//
// REQ: RES-4, CAP-8

import (
	"fmt"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/journal"
)

func TestMalformedGrantChangesNameTheFieldInFixedWords(t *testing.T) {
	r := newRig(t, nil)
	r.grant(mailGrant())
	bad := guestCanary
	cases := []struct {
		name   string
		params map[string]any
		guest  string
	}{
		{"extra param", map[string]any{"grant": map[string]any{"account": "cal"}, bad: "x"},
			"the grant change is malformed: a grant change carries exactly one param, grant"},
		{"unknown field", map[string]any{"grant": map[string]any{"account": "cal", bad: "x"}},
			"the grant change is malformed: the grant spec has a field it does not define"},
		{"grant not an object", map[string]any{"grant": bad},
			"the grant change is malformed: grant is an object"},
		{"account type", map[string]any{"grant": map[string]any{"account": 7}},
			"the grant change is malformed: account is a string"},
		{"ops value type", map[string]any{"grant": map[string]any{"account": "cal", "executor": "cal", "ops": map[string]any{bad: 1}}},
			"the grant change is malformed: ops maps each operation to a verb, both strings"},
		{"per_day type", map[string]any{"grant": map[string]any{"account": "mail", "rule": map[string]any{"action": "invoice.send", "per_day": bad}}},
			"the grant change is malformed: rule per_day is a whole number"},
		{"executor", specParams(Spec{Account: "cal", Executor: bad, Ops: map[string]string{"event.add": "draft"}}),
			"the grant change is not valid: the executor is not a connected adapter"},
		{"undeclared op", specParams(Spec{Account: "cal", Executor: "cal", Ops: map[string]string{bad: "draft"}}),
			"the grant change is not valid: an operation in ops is not one the adapter declares"},
		{"weak verb", specParams(Spec{Account: "cal", Executor: "cal", Ops: map[string]string{"event.add": bad}}),
			"the grant change is not valid: an operation's verb is weaker than the adapter's or not on the list"},
		{"no ops", specParams(Spec{Account: "cal", Executor: "cal"}),
			"the grant change is not valid: an adapter grant chooses at least one operation"},
		{"account taken", specParams(mailGrant()),
			"the grant change is not valid: another grant already connects this account; revoke it first"},
		{"no account", specParams(Spec{Executor: "cal", Ops: map[string]string{"event.add": "draft"}}),
			"the grant change is not valid: a grant names an external account"},
		{"rule account", specParams(Spec{Account: bad, Rule: &Rule{Action: "invoice.send", PerRecord: 1, PerDay: 1}}),
			"the grant change is not valid: no adapter grant connects the rule's account"},
		{"rule action", specParams(Spec{Account: "mail", Rule: &Rule{Action: bad, PerRecord: 1, PerDay: 1}}),
			"the grant change is not valid: the rule's action is not an operation granted on its account"},
		{"reversible action", specParams(Spec{Account: "mail", Rule: &Rule{Action: "draft.save", PerRecord: 1, PerDay: 1}}),
			"the grant change is not valid: the rule's action is reversible and needs no pre-allowance"},
		{"scope", specParams(Spec{Account: "mail", Rule: &Rule{Action: "invoice.send"}}),
			"the grant change is not valid: every rule has scope bounds: per_record and per_day of at least 1 (ADP-9)"},
		{"per-run param", specParams(Spec{Account: "mail", Rule: &Rule{Action: "invoice.send", PerRecord: 1, PerDay: 1, Params: map[string]string{ParamRecord: bad}}}),
			"the grant change is not valid: rule params may not fix record or body"},
		{"resume", specParams(Spec{Resume: bad, Pause: "p1"}),
			"the grant change is not valid: resume names no paused grant, and no account"},
		{"pause alone", specParams(Spec{Account: "cal", Executor: "cal", Ops: map[string]string{"event.add": "draft"}, Pause: bad}),
			"the grant change is not valid: only a resume names a pause"},
	}
	for i, c := range cases {
		id := fmt.Sprintf("local/bad/%d", i)
		st := r.submit(journal.Intent{ID: id, Origin: "local", Account: journal.BrokerAccount,
			Action: journal.ActionGrantChange, Params: c.params, Executor: ExecutorName})
		if st.State != journal.Denied {
			t.Errorf("%s: %s %q", c.name, st.State, st.Permission.Reason)
			continue
		}
		if g := st.Permission.GuestReason; g != c.guest {
			t.Errorf("%s: guest sees %q, want %q", c.name, g, c.guest)
		}
		if strings.Contains(st.Permission.GuestReason, "canary") {
			t.Errorf("%s: guest text echoes the request: %q", c.name, st.Permission.GuestReason)
		}
	}
}

func TestMalformedDestinationChangesNameTheCauseInFixedWords(t *testing.T) {
	r, _ := evidenceRig(t, nil)
	cases := []struct {
		name   string
		params map[string]any
		guest  string
	}{
		{"extra param", map[string]any{ParamEvidenceAddress: ownAddr, ParamEvidenceAccount: "mail", guestCanary: "x"},
			"malformed request to change where private replies go: it carries exactly an address and an account, both strings"},
		{"address type", map[string]any{ParamEvidenceAddress: 7, ParamEvidenceAccount: "mail"},
			"malformed request to change where private replies go: it carries exactly an address and an account, both strings"},
		{"clear names account", map[string]any{ParamEvidenceAddress: "", ParamEvidenceAccount: guestCanary},
			"malformed request to change where private replies go: clearing the destination names no account"},
		{"not bare", map[string]any{ParamEvidenceAddress: "Owner <" + guestCanary + ">", ParamEvidenceAccount: "mail"},
			"malformed request to change where private replies go: the destination must be one bare, lower-case address"},
		{"no account", map[string]any{ParamEvidenceAddress: ownAddr, ParamEvidenceAccount: ""},
			"malformed request to change where private replies go: setting the destination names its account"},
	}
	for i, c := range cases {
		in := EvidenceIntent(fmt.Sprintf("owner/evidence/bad/%d", i), OriginOwner, ownAddr, "mail")
		in.Params = c.params
		st := r.submit(in)
		if st.State != journal.Denied {
			t.Errorf("%s: %s %q", c.name, st.State, st.Permission.Reason)
			continue
		}
		if g := st.Permission.GuestReason; g != c.guest {
			t.Errorf("%s: guest sees %q, want %q", c.name, g, c.guest)
		}
		if strings.Contains(st.Permission.GuestReason, "canary") {
			t.Errorf("%s: guest text echoes the request: %q", c.name, st.Permission.GuestReason)
		}
	}
}

// The owner's reason keeps the value the guest's text leaves out.
func TestTheOwnerKeepsTheMalformedValue(t *testing.T) {
	r := newRig(t, nil)
	st := r.submit(journal.Intent{ID: "local/bad/x", Origin: "local", Account: journal.BrokerAccount, Action: journal.ActionGrantChange,
		Params: specParams(Spec{Account: "cal", Executor: guestCanary, Ops: map[string]string{"event.add": "draft"}}), Executor: ExecutorName})
	if st.State != journal.Denied || !strings.Contains(st.Permission.Reason, "canary") {
		t.Fatalf("%s %q", st.State, st.Permission.Reason)
	}
}
