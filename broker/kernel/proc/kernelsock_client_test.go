package proc

import (
	"crypto/ed25519"

	"github.com/ghbmrk/agentos/broker/kernel"
	"github.com/ghbmrk/agentos/broker/kernel/key"
)

// ownerClient is the part of the owner seam's client that no binary links
// and only a few tests call: it sits outside the trusted core (KRN-2, D-310,
// #5732), on a type of the tests' own, so that mutgate counts a change here
// against only the tests that name it (D-319).
type ownerClient struct{ Owner }

func (o ownerClient) Cancel(plan string) error { return o.Call("cancel", stepArgs{Plan: plan}, nil) }

func (o ownerClient) Undo(plan string, index int) error {
	return o.Call("undo", stepArgs{plan, index}, nil)
}

func (o ownerClient) Unenroll(u key.Unenrollment) error {
	return o.Call("unenroll", u, nil)
}

func (o ownerClient) Extend(ext key.Key, plan string) error {
	return o.Call("extend", extendArgs{ext, plan}, nil)
}

// Reserve sets what is kept of pool for the owner. A lowering needs a live
// passkey's cosign over kernel.ReserveHash, else kernel.ErrReserveSig, and a
// big one a second, one an anchor, else kernel.ErrNeedsCosign (RES-5a).
func (o ownerClient) Reserve(pool string, reserve int64, cos ...key.Cosign) error {
	return o.Call("reserve", poolArgs{Pool: pool, Reserve: reserve, Cosigns: cos}, nil)
}

func (o ownerClient) ApproveTask(id string, a kernel.TaskApproval) error {
	return o.Call("approvetask", approveArgs{id, a}, nil)
}

func (o ownerClient) Revoke(id key.ID) error { return o.Call("revoke", id, nil) }

func (o ownerClient) Pause(id key.ID) error { return o.Call("pause", id, nil) }

func (o ownerClient) Unpause(id key.ID) error { return o.Call("unpause", id, nil) }

// Resume lifts the STOP whose count it names (Changes's stops).
func (o ownerClient) Resume(stops uint64) error { return o.Call("resume", resumeArgs{stops}, nil) }

func (o ownerClient) SpendHeld() (m map[string]kernel.SpendHold, err error) {
	err = o.Call("spendheld", nil, &m)
	return
}

// Pools is every pool as it stands now: its windows, the live reserve, a
// lowering still in its hold and when it goes live, and the change count a
// lowering signs.
func (o ownerClient) Pools() (m map[string]kernel.Pool, err error) {
	err = o.Call("pools", nil, &m)
	return
}

// Spent is metered spend per route since a time, for the last two days only.
func (o ownerClient) Spent(since int64) (m map[string]int64, err error) {
	err = o.Call("spent", spentArgs{since}, &m)
	return
}

// Anchors is the owner's hardware keys as setup logged them, in order: the
// owner side lists them and finds which one signed an enrollment (#2779a).
func (o ownerClient) Anchors() (a []key.PublicKey, err error) {
	err = o.Call("anchors", nil, &a)
	return
}

// EdgeEnroll makes edge, the candidate the link port logged, the live edge
// on a hardware key's signature c over kernel.EdgeEnrollHash.
func (o ownerClient) EdgeEnroll(edge ed25519.PublicKey, c key.Cosign) error {
	return o.Call("edgeenroll", edgeEnrollArgs{edge, c}, nil)
}

// EdgeRevoke cuts edge for good, with no replacement.
func (o ownerClient) EdgeRevoke(edge ed25519.PublicKey) error {
	return o.Call("edgerevoke", edgeArgs{edge}, nil)
}

// Certify signs the page's serving key, PKIX DER (Kernel.Certify).
func (o ownerClient) Certify(pub []byte) (c Certified, err error) {
	err = o.Call("certify", certifyArgs{pub}, &c)
	return
}
