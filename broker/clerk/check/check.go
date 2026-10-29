// Package check is the clerk check path (CLK-2): a clerk's own authorization
// of a request against its anchors and the log's view. It links no network
// code, so a process that may not dial (agentosd) can host a clerk with it.
package check

import (
	"strconv"

	"github.com/ghbmrk/agentos/broker/kernel"
	"github.com/ghbmrk/agentos/broker/kernel/key"
)

// Facts is a clerk's own reading of what a step carries: the content class,
// flow labels and amount it computes from the arguments and the account it
// guards. The planner only claims these, and every clerk has facts: a claim
// that differs is refused, and so is every step at a clerk without them
// (KEY-2, CLK-2).
type Facts func(key.Step) (content string, labels []string, amount int64)

// Clerk refusal codes, beside the key package's and the kernel's.
const (
	RClaim    = "claim"    // a claim the clerk's facts contradict, or no facts to judge it
	RDispatch = "dispatch" // the log has no such step in flight
	RHold     = "hold"
)

// Check is the clerk's own authorization of a request at now, on the clerk's
// own clock. It trusts nothing the kernel or the transport says: the chain
// and its last holder's signature on the plan, verified against the clerk's own
// anchors (D-146), the step taken from that signed plan, the key's grants live
// in the log on the clerk's clock, the log's record that this very plan's
// step is in flight, the key's limits as of that step's first dispatch, and
// for an irreversible verb the hold the log recorded (CLK-2).
func Check(anchors []key.PublicKey, name string, facts Facts, now int64, r kernel.Request, v kernel.View) *key.Refusal {
	_, rf := Verify(anchors, name, facts, now, r, v)
	return rf
}

// Verify is Check that also returns the plan key's verified chain when the
// request passes, for a clerk that asks more of the key, such as an owner's
// approval (Verified.ByOwner). A refused request returns no chain, whichever
// check refused it: this is the one place that holds.
func Verify(anchors []key.PublicKey, name string, facts Facts, now int64, r kernel.Request, v kernel.View) (*key.Verified, *key.Refusal) {
	ver, rf := verify(anchors, name, facts, now, r, v)
	if rf != nil {
		return nil, rf
	}
	return ver, nil
}

func verify(anchors []key.PublicKey, name string, facts Facts, now int64, r kernel.Request, v kernel.View) (*key.Verified, *key.Refusal) {
	st := r.Step()
	if st.Clerk != name {
		return nil, &key.Refusal{Code: key.RClerk, Detail: st.Clerk}
	}
	// The recipient a key's caveats judge is the verb's first argument, the
	// object the request acts on; a step claiming another is refused here.
	if a := st.Args[key.RecipientArg(st.Verb)]; st.Recipient != a.Value {
		return nil, &key.Refusal{Code: RClaim, Detail: "step recipient differs from its object argument"}
	}
	if facts == nil {
		return nil, &key.Refusal{Code: RClaim, Detail: "clerk has no facts to judge the step's claims"}
	}
	if content, labels, amount := facts(st); content != st.Content || amount != st.Amount || !sameSet(labels, st.Labels) {
		return nil, &key.Refusal{Code: RClaim, Detail: "step claims differ from the clerk's facts"}
	}
	owners := kernel.PlanOwners(v, anchors, r.Plan.Key)
	ver, err := kernel.VerifyPlan(r.Plan, owners)
	if err != nil {
		return nil, &key.Refusal{Code: kernel.CKey, Detail: err.Error()}
	}
	if rf := kernel.Live(v, ver, now); rf != nil {
		return ver, rf
	}
	if rf := kernel.OneOff(v, owners, anchors, r.Plan, now); rf != nil {
		return ver, rf
	}
	d, ok := v.Dispatched(r)
	if !ok {
		return ver, &key.Refusal{Code: RDispatch, Detail: "the log has no such step in flight"}
	}
	ctx := key.Context{Now: now, Changes: v.ChangesView(), Ledger: v.LedgerBefore(d.Seq)}
	if rf := ver.Authorize(st, ctx); rf != nil {
		return ver, rf
	}
	if c, ok := key.ClassOf(st.Verb); ok && c.Irreversible() && max(ver.Limits.Window(false), ver.Limits.Window(true)) > 0 {
		if !d.Held {
			return ver, &key.Refusal{Code: RHold, Detail: "step was not held"}
		}
		if !d.Approved && now < ver.Limits.Due(d.HeldAt, d.Novel) {
			return ver, &key.Refusal{Code: RHold, Detail: "window not over"}
		}
	}
	return ver, nil
}

// Amount is a clerk's own reading of the amount argument: its one canonical
// spelling, any other unreadable and so -1; 0 when the verb has none.
func Amount(s key.Step) int64 {
	a, ok := s.Args[key.ArgAmount]
	if !ok {
		return 0
	}
	n, err := strconv.ParseInt(a.Value, 10, 64)
	if err != nil || n < 0 || strconv.FormatInt(n, 10) != a.Value {
		return -1
	}
	return n
}

func sameSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	m := map[string]int{}
	for _, x := range a {
		m[x]++
	}
	for _, x := range b {
		m[x]--
	}
	for _, n := range m {
		if n != 0 {
			return false
		}
	}
	return true
}
