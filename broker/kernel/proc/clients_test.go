package proc

// The owner and content clients of the kernel process's sockets (KEY-9-reach-inbound-offset,
// #5732): no binary links them, so they live with the tests that speak the wire through them,
// outside the trusted core's lines (KRN-2, D-310). agentosd's client is owner/kernelsock.

import (
	"crypto/ed25519"
	"unicode/utf8"

	"github.com/ghbmrk/agentos/broker/kernel"
	"github.com/ghbmrk/agentos/broker/kernel/key"
)

func (o Owner) Submit(p kernel.Plan) error { return o.Call("submit", p, nil) }
func (o Owner) Retry(plan string, index, attempt int) error {
	return o.Call("retry", retryArgs{plan, index, attempt}, nil)
}
func (o Owner) Cancel(plan string) error { return o.Call("cancel", stepArgs{Plan: plan}, nil) }
func (o Owner) Undo(plan string, index int) error {
	return o.Call("undo", stepArgs{plan, index}, nil)
}
func (o Owner) Enroll(e key.Enrollment) error { return o.Call("enroll", e, nil) }
func (o Owner) Unenroll(u key.Unenrollment) error {
	return o.Call("unenroll", u, nil)
}
func (o Owner) Extend(ext key.Key, plan string) error {
	return o.Call("extend", extendArgs{ext, plan}, nil)
}

// Reserve sets what is kept of pool for the owner. A lowering needs a live
// passkey's cosign over kernel.ReserveHash, else kernel.ErrReserveSig, and a
// big one a second, one an anchor, else kernel.ErrNeedsCosign (RES-5a).
func (o Owner) Reserve(pool string, reserve int64, cos ...key.Cosign) error {
	return o.Call("reserve", poolArgs{Pool: pool, Reserve: reserve, Cosigns: cos}, nil)
}
func (o Owner) Issue(cos []key.Cosign, keys ...key.Key) error {
	return o.Call("issue", issueArgs{cos, keys}, nil)
}
func (o Owner) ApproveTask(id string, a kernel.TaskApproval) error {
	return o.Call("approvetask", approveArgs{id, a}, nil)
}
func (o Owner) ApproveCode(a kernel.CodeApproval) error { return o.Call("approvecode", a, nil) }
func (o Owner) Revoke(id key.ID) error                  { return o.Call("revoke", id, nil) }
func (o Owner) Pause(id key.ID) error                   { return o.Call("pause", id, nil) }
func (o Owner) Unpause(id key.ID) error                 { return o.Call("unpause", id, nil) }

// Resume lifts the STOP whose count it names (Changes's stops).
func (o Owner) Resume(stops uint64) error { return o.Call("resume", resumeArgs{stops}, nil) }

func (o Owner) SpendHeld() (m map[string]kernel.SpendHold, err error) {
	err = o.Call("spendheld", nil, &m)
	return
}

// Pools is every pool as it stands now: its windows, the live reserve, a
// lowering still in its hold and when it goes live, and the change count a
// lowering signs.
func (o Owner) Pools() (m map[string]kernel.Pool, err error) { err = o.Call("pools", nil, &m); return }

// Spent is metered spend per route since a time, for the last two days only.
func (o Owner) Spent(since int64) (m map[string]int64, err error) {
	err = o.Call("spent", spentArgs{since}, &m)
	return
}

// Anchors is the owner's hardware keys as setup logged them, in order: the
// owner side lists them and finds which one signed an enrollment (#2779a).
func (o Owner) Anchors() (a []key.PublicKey, err error) { err = o.Call("anchors", nil, &a); return }

func (o Owner) Enrollments() ([]key.Enrollment, []key.PublicKey, error) {
	var e enrolled
	err := o.Call("enrollments", nil, &e)
	return e.Enrolled, e.Unenrolled, err
}

// Plan is plan id's view: its status, a rejection's code and its steps'
// results (kernel.PlanView); ok is false when the log has no such plan.
func (o Owner) Plan(id string) (v kernel.PlanView, ok bool, err error) {
	err = o.Call("plan", id, &v)
	return v, v.Status != "", err
}

// Granted is when key id's grant is live from, if it is granted.
func (o Owner) Granted(id key.ID) (from int64, ok bool, err error) {
	var r grantRead
	err = o.Call("granted", id, &r)
	return r.From, r.OK, err
}

// Task is task id while it is live on the kernel's clock.
func (o Owner) Task(id string) (kernel.Task, bool, error) {
	var t taskRead
	if err := o.Call("task", id, &t); err != nil || t.Task == nil {
		return kernel.Task{}, false, err
	}
	return *t.Task, true, nil
}

// BackupTarget adds a backup destination on an anchor's signature over
// kernel.BackupTargetHash.
func (o Owner) BackupTarget(t kernel.BackupTarget, c key.Cosign) error {
	return o.Call("backuptarget", targetArgs{t, c}, nil)
}

// EdgeEnroll makes edge, the candidate the link port logged, the live edge
// on a hardware key's signature c over kernel.EdgeEnrollHash.
func (o Owner) EdgeEnroll(edge ed25519.PublicKey, c key.Cosign) error {
	return o.Call("edgeenroll", edgeEnrollArgs{edge, c}, nil)
}

// EdgeRevoke cuts edge for good, with no replacement.
func (o Owner) EdgeRevoke(edge ed25519.PublicKey) error {
	return o.Call("edgerevoke", edgeArgs{edge}, nil)
}

// Untarget stops new backups to a destination; its backups keep their
// erase reach.
func (o Owner) Untarget(name string) error { return o.Call("untarget", untargetArgs{name}, nil) }

// DeclareReach and DeclReach write and read the log's decl.reach (KEY-9).
func (o Owner) DeclareReach(d kernel.DeclReach) error      { return o.Call("declreach", d, nil) }
func (o Owner) DeclReach() (d kernel.DeclReach, err error) { err = o.Call("declared", nil, &d); return }

// Backup takes one backup now to every current destination.
func (o Owner) Backup() (t []Taken, err error) { err = o.Call("backup", nil, &t); return }

// RecoveryRotate asks for a recovery-key approval on an anchor's signature
// c over kernel.RecoveryRotateHash(old, next), old the recipient the
// kernel holds (Backups' Recipient): next is the new key's recipient ID,
// or "" when the card is lost. The approval is handoff.Approval's form.
func (o Owner) RecoveryRotate(next string, c key.Cosign) ([]byte, error) {
	var r approvalRead
	err := o.Call("recoveryrotate", rotateArgs{next, c}, &r)
	return r.Approval, err
}

// SwitchRecipient makes r, in its wire form, the backup recipient, on the
// card-route approval RecoveryRotate gave for it.
func (o Owner) SwitchRecipient(r, approval []byte) error {
	return o.Call("recipient", recipientArgs{r, approval}, nil)
}

// Certify signs the page's serving key, PKIX DER (Kernel.Certify).
func (o Owner) Certify(pub []byte) (c Certified, err error) {
	err = o.Call("certify", certifyArgs{pub}, &c)
	return
}

// Named is the live subjects a label reads as (kernel.Named): those found,
// and those whose labels could not be read. A blank label is
// kernel.ErrLabel. Invalid UTF-8 is ErrArgs here, since JSON would carry it
// as U+FFFD and match a label the owner did not type (LOG-4).
func (o Owner) Named(label string) (found, unread []string, err error) {
	if !utf8.ValidString(label) {
		return nil, nil, ErrArgs
	}
	var r namedRead
	err = o.Call("named", labelArgs{label}, &r)
	return r.Found, r.Unread, err
}

// Recall is what the box knows of subject; ok is false when it has none.
func (o Owner) Recall(subject string) (kernel.Recall, bool, error) {
	var r recallRead
	if err := o.Call("recall", subject, &r); err != nil || r.Recall == nil {
		return kernel.Recall{}, false, err
	}
	return *r.Recall, true, nil
}

// Erase erases subject. A Confirmation with its Subject set means the
// erase is logged, even with an error: a step after it failed, and Tick
// retries it.
func (o Owner) Erase(subject string) (kernel.Confirmation, error) {
	var r eraseRead
	if err := o.Call("erase", subject, &r); err != nil {
		return kernel.Confirmation{}, err
	}
	if r.Err == "" {
		return r.Confirmation, nil
	}
	return r.Confirmation, fromWire(r.Err, r.Is)
}

// Unerased is every erase a store or the key table has not confirmed.
func (o Owner) Unerased() (u []kernel.Unerased, err error) { err = o.Call("unerased", nil, &u); return }

// ErasedReads is each lineage that read an erased subject's item, at its
// first read: what agentosd rewinds (D-169).
func (o Owner) ErasedReads() (r []kernel.ErasedRead, err error) {
	err = o.Call("erasedreads", nil, &r)
	return
}

// Content is a content clerk's seam over its content socket (ContentSide).
type Content struct{ Conn }

// OpenSubject opens a new subject and returns its ID.
func (c Content) OpenSubject() (sub string, err error) {
	err = c.Call("opensubject", nil, &sub)
	return
}

// Seal seals data as an item of subject, of class, in the clerk's own
// store, and returns its hash.
func (c Content) Seal(subject, class string, data []byte) (h kernel.Hash, err error) {
	if len(data) > MaxItem {
		return h, ErrArgs
	}
	err = c.Call("seal", sealArgs{subject, class, data}, &h)
	return
}

// ReadFor opens the item named h, of the clerk's own store, for the agent
// session of lineage; the kernel logs the read first.
func (c Content) ReadFor(h kernel.Hash, lineage string) (data []byte, err error) {
	err = c.Call("readfor", readForArgs{h, lineage}, &data)
	return
}
