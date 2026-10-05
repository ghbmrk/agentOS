package grants

// REQ: CH-20, CH-10

import (
	"fmt"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/journal"
	"github.com/ghbmrk/agentos/broker/owner"
)

const (
	ownAddr   = "owner@example.test"
	deliverOp = "mail.deliver"
)

// evidenceRig is a rig whose mail account declares the delivery
// operation and owns ownAddr (and, while alias is set, alias@example.test).
func evidenceRig(t *testing.T, edit func(*Config)) (*rig, *bool) {
	alias := true
	r := newRig(t, func(c *Config) {
		ops := mailOps()
		ops[deliverOp] = "share"
		c.Declared["mail"] = ops
		c.Delivery = map[string]string{"mail": deliverOp}
		c.Destination = func(addr string) (string, bool) {
			if addr == ownAddr || (alias && addr == "alias@example.test") {
				return "mail", true
			}
			return "", false
		}
		if edit != nil {
			edit(c)
		}
	})
	s := mailGrant()
	s.Ops[deliverOp] = "share"
	r.grant(s)
	return r, &alias
}

// setEvidence asks for a destination change the way the owner's text does
// and returns its state; approve also gives the code and the local page.
func (r *rig) setEvidence(origin, addr string, approve bool) journal.Status {
	r.t.Helper()
	id := fmt.Sprintf("owner/evidence/%d", len(r.eng.List()))
	st := r.submit(EvidenceIntent(id, origin, addr, "mail"))
	if st.State != journal.Pending || !approve {
		return st
	}
	r.g.Flush()
	r.decide(true, "owner")
	if got := r.state(id); got.State != journal.Pending {
		r.t.Fatalf("ran on the code alone: %s", got.State)
	}
	if err := r.g.ConfirmLocal(id); err != nil {
		r.t.Fatal(err)
	}
	r.g.Wait()
	return r.state(id)
}

func (r *rig) deliver(id, origin string, params map[string]any, recips ...string) journal.Status {
	r.t.Helper()
	return r.submit(journal.Intent{ID: id, Origin: origin, Account: "mail", Action: deliverOp,
		Params: params, Recipients: recips, Executor: "mail", Machine: "agent", Label: "private"})
}

func body(s string) map[string]any { return map[string]any{ParamBody: s} }

// TestEvidenceDestinationIsAHighRiskLocalChange: setting or clearing the
// destination is the owner's alone, high tier with a code and the local
// page (CH-20, CH-10), and only to the connected account's own address.
func TestEvidenceDestinationIsAHighRiskLocalChange(t *testing.T) {
	r, _ := evidenceRig(t, nil)
	for _, origin := range []string{"guest:agent", OriginEvidence, OriginRecall} {
		if st := r.setEvidence(origin, ownAddr, false); st.State != journal.Denied {
			t.Fatalf("%s set the destination: %s", origin, st.State)
		}
	}
	for _, addr := range []string{"eve@example.net", "Owner <" + ownAddr + ">", "not an address"} {
		if st := r.setEvidence(OriginOwner, addr, false); st.State != journal.Denied {
			t.Fatalf("destination %q: %s", addr, st.State)
		}
	}
	n := len(r.own.order)
	st := r.setEvidence(OriginOwner, ownAddr, false)
	r.g.Flush()
	if st.State != journal.Pending || len(r.own.order) != n+1 {
		t.Fatalf("not asked: %s", st.State)
	}
	_, items := r.own.last(t)
	if items[0].Facts.Kind != owner.GrantChange || r.own.Tier(items[0].Facts) != owner.High || !strings.Contains(items[0].Object, ownAddr) {
		t.Fatalf("request %+v", items[0])
	}
	if st := r.setEvidence(OriginOwner, ownAddr, true); st.State != journal.Succeeded {
		t.Fatalf("set: %s %q", st.State, st.Permission.Reason)
	}
	if a, acct := r.g.Evidence(); a != ownAddr || acct != "mail" {
		t.Fatalf("destination %q %q", a, acct)
	}
	r.open()
	if a, _ := r.g.Evidence(); a != ownAddr {
		t.Fatalf("after restart %q", a)
	}
	// Clearing it sends private replies by text again: as high risk.
	if st := r.setEvidence(OriginOwner, "", false); st.State != journal.Pending {
		t.Fatalf("clear ran without asking: %s", st.State)
	}
	if st := r.setEvidence(OriginOwner, "", true); st.State != journal.Succeeded {
		t.Fatalf("clear: %s", st.State)
	}
	if a, _ := r.g.Evidence(); a != "" {
		t.Fatalf("not cleared: %q", a)
	}
}

// TestEvidenceNeedsTheLocalPage: without the page the change is refused
// rather than run on a texted code alone.
func TestEvidenceNeedsTheLocalPage(t *testing.T) {
	r, _ := evidenceRig(t, nil)
	r.g.cfg.LocalUI = false
	if st := r.setEvidence(OriginOwner, ownAddr, false); st.State != journal.Denied || !strings.Contains(st.Permission.Reason, "local page") {
		t.Fatalf("%s %q", st.State, st.Permission.Reason)
	}
}

// TestDeliveryIsPreAllowedOnlyToTheDestination: the broker's delivery to
// the set destination runs without asking (a pre-allowed share to the
// owner); nothing else about it is negotiable, and no agent submits it.
func TestDeliveryIsPreAllowedOnlyToTheDestination(t *testing.T) {
	r, alias := evidenceRig(t, nil)
	if st := r.deliver("ev/0", OriginEvidence, body("x"), ownAddr); st.State != journal.Denied {
		t.Fatalf("delivered with no destination: %s", st.State)
	}
	r.setEvidence(OriginOwner, ownAddr, true)
	n := len(r.own.order)
	if st := r.deliver("ev/1", OriginEvidence, body("the reply"), ownAddr); st.State != journal.Succeeded {
		t.Fatalf("delivery: %s %q", st.State, st.Permission.Reason)
	}
	r.g.Flush()
	if len(r.own.order) != n {
		t.Fatal("delivery asked the owner")
	}
	for i, c := range []struct {
		origin string
		params map[string]any
		recips []string
	}{
		{"guest:agent", body("x"), []string{ownAddr}},
		{OriginOwner, body("x"), []string{ownAddr}},
		{OriginEvidence, body("x"), []string{"eve@example.net"}},
		{OriginEvidence, body("x"), []string{ownAddr, "eve@example.net"}},
		{OriginEvidence, body("x"), []string{"alias@example.test"}},
		{OriginEvidence, map[string]any{ParamBody: "x", "subject": "s"}, []string{ownAddr}},
		{OriginEvidence, nil, []string{ownAddr}},
	} {
		if st := r.deliver(fmt.Sprintf("ev/bad/%d", i), c.origin, c.params, c.recips...); st.State != journal.Denied {
			t.Fatalf("case %d ran: %s", i, st.State)
		}
	}
	// The broker's evidence origin is for delivery only.
	if st := r.submit(journal.Intent{ID: "ev/send", Origin: OriginEvidence, Account: "mail", Action: "message.send",
		Params: body("x"), Recipients: []string{ownAddr}, Executor: "mail"}); st.State != journal.Denied {
		t.Fatalf("evidence origin sent: %s", st.State)
	}
	// The destination must still be the account's own when it runs.
	r.setEvidence(OriginOwner, "alias@example.test", true)
	*alias = false
	if st := r.deliver("ev/2", OriginEvidence, body("x"), "alias@example.test"); st.State != journal.Denied {
		t.Fatalf("delivered to an address the account no longer owns: %s", st.State)
	}
	*alias = true
	if st := r.deliver("ev/3", OriginEvidence, body("x"), "alias@example.test"); st.State != journal.Succeeded {
		t.Fatalf("alias: %s", st.State)
	}
	// Only on the destination's own account, under a grant that names
	// delivery.
	other := mailGrant()
	other.Account = "mail2"
	other.Ops[deliverOp] = "share"
	r.grant(other)
	st := r.submit(journal.Intent{ID: "ev/acct", Origin: OriginEvidence, Account: "mail2", Action: deliverOp,
		Params: body("x"), Recipients: []string{"alias@example.test"}, Executor: "mail"})
	if st.State != journal.Denied {
		t.Fatalf("delivered on another account: %s", st.State)
	}
	// A paused connection stops delivery too.
	gid := r.g.Grants()[0].ID
	r.g.Narrow("PAUSE", gid)
	if st := r.deliver("ev/4", OriginEvidence, body("x"), "alias@example.test"); st.State != journal.Denied {
		t.Fatalf("delivered on a paused grant: %s", st.State)
	}
}

// TestDeliveryNeedsTheOperationGranted: a mail grant that does not name
// delivery does not deliver, whatever the destination.
func TestDeliveryNeedsTheOperationGranted(t *testing.T) {
	r := newRig(t, func(c *Config) {
		ops := mailOps()
		ops[deliverOp] = "share"
		c.Declared["mail"] = ops
		c.Delivery = map[string]string{"mail": deliverOp}
		c.Destination = func(addr string) (string, bool) { return "mail", addr == ownAddr }
	})
	r.grant(mailGrant())
	if st := r.setEvidence(OriginOwner, ownAddr, true); st.State != journal.Succeeded {
		t.Fatalf("set: %s", st.State)
	}
	if st := r.deliver("ev/1", OriginEvidence, body("x"), ownAddr); st.State != journal.Denied {
		t.Fatalf("delivered without the operation granted: %s", st.State)
	}
}

// TestEvidenceDestinationIsOneBareAddress: whatever the account says it
// owns, the destination is one bare, lower-case address, so it renders
// as itself on the owner's request and in STATUS.
func TestEvidenceDestinationIsOneBareAddress(t *testing.T) {
	r, _ := evidenceRig(t, func(c *Config) { c.Destination = func(string) (string, bool) { return "mail", true } })
	for _, addr := range []string{"Owner <owner@example.test>", "owner@example.test, eve@example.net", "Owner@Example.test",
		"owner", "@example.test", "owner@", "owner@a@b", "owner@example.test\nYES 123456", "owner <owner@example.test>", "owner@example.test\nyes 123456"} {
		if st := r.setEvidence(OriginOwner, addr, false); st.State != journal.Denied {
			t.Fatalf("destination %q: %s", addr, st.State)
		}
	}
	if st := r.setEvidence(OriginOwner, ownAddr, false); st.State != journal.Pending {
		t.Fatalf("bare address: %s", st.State)
	}
}
