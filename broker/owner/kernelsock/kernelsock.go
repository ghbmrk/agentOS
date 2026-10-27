// Package kernelsock is agentosd's client of the kernel's owner socket
// (MIG-4-run start-up slice, #2682; D-154 rules 1 and 2). The kernel's
// process serves the owner seam there to the owner side's uid alone
// (agentos-kernel -owner-uid), which is never root, and agentosd runs as
// root: every call is made on a thread of its own whose effective uid is
// the owner side's (asUID), so the peer the kernel reads is the one the
// deployment names, and no frame carries a uid.
//
// This is the wire kernel/proc's Owner speaks, written out here rather
// than imported, as localsrv/accountsock writes out the mail clerk's:
// kernel/proc is the kernel process's own host, which agentosd's control
// path does not link (daemon TestARC2ControlPathCannotReachInference).
// TestSpeaksTheKernelsWire serves the real OwnerSide to keep the two the
// same. Only the calls agentosd makes are here; #2783 adds the seam's
// actions as it moves the owner channel onto them. The plan types are the
// kernel package's own (pure data and its key check, no process), so a plan
// agentosd signs is the bytes the kernel verifies.
package kernelsock

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/ghbmrk/agentos/broker/kernel"
	"github.com/ghbmrk/agentos/broker/kernel/key"
	"github.com/ghbmrk/agentos/broker/sockets"
)

// callFor bounds one call, as kernel/proc's Conn does by default.
const callFor = time.Minute

// maxAnswer bounds an answer (kernel/proc maxKernelAnswer).
const maxAnswer = 4 << 20

// Owner is the owner seam on the kernel's owner socket.
type Owner struct {
	Socket string
	UID    int // the kernel's uid: the only peer called
	As     int // the owner side's uid, which every call is made as
}

// ErrUnreachable is a call that was never sent: no process listens on the
// socket, another uid holds it, or the owner side's uid was not taken.
var ErrUnreachable = errors.New("kernelsock: the kernel's owner socket could not be reached; nothing was sent")

// ErrLost is a call whose answer never came: it may or may not have taken
// effect (kernel/proc ErrLost).
var ErrLost = errors.New("kernelsock: the kernel's answer was lost; it may or may not have taken effect")

// errNoSeat: the owner side's uid could not be taken.
var errNoSeat = errors.New("kernelsock: I could not take the owner side's uid")

// Refused is the kernel's refusal or error, in its own words.
type Refused struct{ Text string }

func (r Refused) Error() string { return "kernelsock: the kernel refused: " + r.Text }

// call makes one call as the owner side: one {"op","args"} line, one
// {"result"}, {"error"} or {"refusal"} answer (kernel/proc ServeOne).
func (o Owner) call(ctx context.Context, op string, args, out any) error {
	if args == nil {
		args = struct{}{} // as kernel/proc's mustRaw sends no arguments
	}
	raw, err := json.Marshal(args)
	if err != nil {
		return err
	}
	b, err := json.Marshal(wireCall{op, raw})
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, callFor)
	defer cancel()
	var a wireAnswer
	err = asUID(o.As, func() error {
		conn, err := (&net.Dialer{}).DialContext(ctx, "unix", o.Socket)
		if err != nil {
			return ErrUnreachable
		}
		defer conn.Close()
		if uid, ok := sockets.PeerUID(conn); !ok || uid != o.UID {
			return ErrUnreachable
		}
		if dl, ok := ctx.Deadline(); ok {
			conn.SetDeadline(dl)
		}
		if _, err := conn.Write(append(b, '\n')); err != nil {
			return ErrLost
		}
		if json.NewDecoder(io.LimitReader(conn, maxAnswer)).Decode(&a) != nil {
			return ErrLost
		}
		return nil
	})
	switch {
	case errors.Is(err, errNoSeat):
		return fmt.Errorf("%w (%v)", ErrUnreachable, err)
	case err != nil:
		return err
	case a.Refusal != nil:
		return Refused{a.Refusal.Code + ": " + a.Refusal.Detail}
	case a.Error != "":
		return Refused{a.Error}
	case out != nil:
		if json.Unmarshal(a.Result, out) != nil {
			return ErrLost
		}
	}
	return nil
}

type wireCall struct {
	Op   string          `json:"op"`
	Args json.RawMessage `json:"args"`
}

type wireAnswer struct {
	Result  json.RawMessage `json:"result"`
	Error   string          `json:"error"`
	Refusal *wireRefusal    `json:"refusal"`
}

// wireRefusal is a key.Refusal's code and detail.
type wireRefusal struct {
	Code   string `json:"code"`
	Detail string `json:"detail"`
}

// setupInfo is kernel/proc SetupInfo's frame; the box key is not read here.
type setupInfo struct {
	Open bool `json:"open"`
}

// SetupOpen reads whether the kernel is waiting for setup (only the
// owner's two hardware keys) or running; a setup-only kernel serves it.
func (o Owner) SetupOpen(ctx context.Context) (bool, error) {
	var i setupInfo
	err := o.call(ctx, "setupinfo", nil, &i)
	return i.Open, err
}

// Stop logs a STOP on the kernel and anchors it (KRN-7): nothing the
// kernel holds runs again until a RESUME. A setup-only kernel refuses it.
func (o Owner) Stop(ctx context.Context) error { return o.call(ctx, "stop", nil, nil) }

// Resume logs a RESUME on the kernel and anchors it. It names the count
// of STOPs it lifts, as Stopped read it: the kernel refuses it once a later
// STOP is logged, so a RESUME abandoned here never lifts that STOP (#3078).
func (o Owner) Resume(ctx context.Context, stops uint64) error {
	return o.call(ctx, "resume", resume{stops}, nil)
}

// resume is kernel/proc's resumeArgs.
type resume struct {
	Stops uint64 `json:"stops"`
}

// changes is the part of kernel/proc's changes read used here.
type changes struct {
	Stopped bool
	Stops   uint64 `json:"stops"`
}

// Stopped reads whether a STOP is in force on the kernel (its log's
// Changes view) and how many STOPs it has logged, which a RESUME names. A
// setup-only kernel refuses it.
func (o Owner) Stopped(ctx context.Context) (bool, uint64, error) {
	var c changes
	err := o.call(ctx, "changes", nil, &c)
	return c.Stopped, c.Stops, err
}

// Step is a step the kernel's log has not settled (kernel.Unsettled, the
// owner seam's status read): its outcome is unknown, it is parked for the
// owner's RETRY, or its clerk was not reached. The fields agentosd shows
// or judges a RETRY on; the rest of the frame is not read here.
type Step struct {
	Plan   string
	Index  int
	Verb   string
	Clerk  string
	Phase  string // PhaseUnknown, PhaseParked or PhaseUnsent
	Detail string // the clerk's last answer, which the kernel bounds
	Retry  bool   // the owner may RETRY it
	SentAt int64  // when it was first sent (unix ms), which RETRY names
	// What the owner's RETRY tier is judged on (CH-10, CH-11): the step's
	// spend in minor units, whether its verb moves money, its recipient.
	Amount    int64
	Money     bool
	Recipient string
	// PlanStatus is the plan's: a cancelled plan's step stays listed while
	// it may have acted, but nothing more is tried.
	PlanStatus string
}

// The phases and plan status Step carries (kernel PUnknown, PParked,
// PUnsent, SActive).
const (
	PhaseUnknown = "unknown"
	PhaseParked  = "parked"
	PhaseUnsent  = "unsent"
	PlanActive   = "active"
)

// Status lists the steps the kernel's log has not settled, in submission
// order. A setup-only kernel holds none.
func (o Owner) Status(ctx context.Context) ([]Step, error) {
	var s []Step
	err := o.call(ctx, "status", nil, &s)
	return s, err
}

// stepArgs is kernel/proc's stepArgs.
type stepArgs struct {
	Plan  string `json:"plan"`
	Index int    `json:"index"`
}

// Retry logs the owner's RETRY of a parked step and anchors it (KRN-7): the
// kernel sends it again on a later tick, under every check it would make
// now. It refuses a step that is not parked, or one it would not send now.
func (o Owner) Retry(ctx context.Context, plan string, index int) error {
	return o.call(ctx, "retry", stepArgs{plan, index}, nil)
}

// Submit logs a guest's plan on the kernel, which decides it at once (PLN-5
// (b)): its authority is its key and the signature of the key's last holder,
// not this channel. A plan the key check rejects is logged all the same
// (PLN-4); Plan reads its status.
func (o Owner) Submit(ctx context.Context, p kernel.Plan) error {
	return o.call(ctx, "submit", p, nil)
}

// Plan reads plan id's view (kernel.PlanView): its status, a rejected
// plan's failing check and each step's result. Its Status is empty when the
// kernel's log holds no such plan.
func (o Owner) Plan(ctx context.Context, id string) (v kernel.PlanView, err error) {
	err = o.call(ctx, "plan", id, &v)
	return v, err
}

// ErrAnchor is the kernel's refusal to cut off one of the owner's hardware
// keys (kernel.ErrAnchor): only recovery replaces one (REC-3, #2740). The
// kernel's text is matched here and never passed on.
var ErrAnchor = errors.New("kernelsock: the kernel refused: that key is an anchor")

// ErrSetupOnly is a setup-only kernel's refusal of every call but setup's
// (kernel/proc ErrSetupOnly, matched by its text).
var ErrSetupOnly = errors.New("kernelsock: the kernel is waiting for setup")

// setupOnlyText is kernel/proc ErrSetupOnly's text; TestASetupOnlyKernelRefusesPasskeyOps
// keeps the two the same.
const setupOnlyText = "run: I am waiting for setup; I take only your two hardware keys until then"

// The kernel's refusals of a backup destination change, matched by its
// words (kernel.ErrTargetSig, ErrTargetExists, ErrNoTarget). Each still
// wraps the Refused, so errors.As finds the kernel's own words too.
var (
	ErrTargetSig    = errors.New("kernelsock: the kernel refused: no hardware key signed that destination")
	ErrTargetExists = errors.New("kernelsock: the kernel refused: that destination name is taken")
	ErrNoTarget     = errors.New("kernelsock: the kernel refused: no such current destination")
)

// typed is err as ErrAnchor, ErrSetupOnly or a destination refusal when
// the kernel's words are exactly that refusal's, else err.
func typed(err error) error {
	var r Refused
	if !errors.As(err, &r) {
		return err
	}
	switch r.Text {
	case kernel.ErrAnchor.Error():
		return ErrAnchor
	case setupOnlyText:
		return ErrSetupOnly
	case noAuthorityText:
		return ErrNoAuthority
	case pageRestoreText:
		return ErrPageRestore
	case kernel.ErrTargetSig.Error():
		return fmt.Errorf("%w (%w)", ErrTargetSig, r)
	case kernel.ErrTargetExists.Error():
		return fmt.Errorf("%w (%w)", ErrTargetExists, r)
	case kernel.ErrNoTarget.Error():
		return fmt.Errorf("%w (%w)", ErrNoTarget, r)
	}
	return err
}

// Enroll logs an anchor-signed enrollment of a passkey, such as a new
// phone's (D-146); the kernel checks By against its anchors and Sig
// against EnrollMsg(Passkey), and refuses with ErrNotEnrolled's text
// otherwise. A setup-only kernel refuses it (ErrSetupOnly).
func (o Owner) Enroll(ctx context.Context, e key.Enrollment) error {
	return typed(o.call(ctx, "enroll", e, nil))
}

// Unenroll cuts a passkey off for good on a hardware key's signature over
// key.UnenrollMsg (#3209); the kernel refuses one no anchor signed with
// kernel.ErrNotUnenrolled's text. It refuses an anchor (ErrAnchor) and a
// setup-only kernel refuses it (ErrSetupOnly).
func (o Owner) Unenroll(ctx context.Context, u key.Unenrollment) error {
	return typed(o.call(ctx, "unenroll", u, nil))
}

// enrolled is kernel/proc's enrollments frame.
type enrolled struct {
	Enrolled   []key.Enrollment `json:"enrolled"`
	Unenrolled []key.PublicKey  `json:"unenrolled"`
}

// Enrollments reads the log's enrollments and the passkeys cut off, as the
// kernel's Passkeys reads them.
func (o Owner) Enrollments(ctx context.Context) ([]key.Enrollment, []key.PublicKey, error) {
	var e enrolled
	err := typed(o.call(ctx, "enrollments", nil, &e))
	return e.Enrolled, e.Unenrolled, err
}

// Anchors reads the owner's hardware keys as setup logged them, in order.
func (o Owner) Anchors(ctx context.Context) ([]key.PublicKey, error) {
	var a []key.PublicKey
	err := typed(o.call(ctx, "anchors", nil, &a))
	return a, err
}

// Backups (BAK-1, MIG-4-recovery-e3): the kernel holds the destinations and
// writes, reads back and verifies each backup itself; the owner side
// triggers, chooses and tells. The frames are kernel/proc's.

// BackupView is a kept backup: its recipient only by ID, and whether the
// kernel read it back whole.
type BackupView struct {
	Target     string `json:"target"`
	BackupID   string `json:"backup_id"`
	Recipient  string `json:"recipient"`
	Created    int64  `json:"created"`
	Generation uint64 `json:"generation"`
	Verified   bool   `json:"verified"`
	Pending    bool   `json:"pending,omitempty"` // its table may be out, but it never finished
}

// TargetView is a destination; Rewritable is false for an append-only one,
// where an erase cannot drop a key table.
type TargetView struct {
	Name       string `json:"name"`
	Kind       string `json:"kind"`
	Locator    string `json:"locator"`
	AppendOnly bool   `json:"append_only"`
	Removed    bool   `json:"removed"`
	Rewritable bool   `json:"rewritable"`
}

// BackupsView is the current recipient's ID ("" when the store holds none,
// so no backup can be taken), every destination and every kept backup.
type BackupsView struct {
	Recipient string       `json:"recipient"`
	Targets   []TargetView `json:"targets"`
	Backups   []BackupView `json:"backups"`
}

// Taken is one destination's outcome of a backup: the backup kept for it
// (Reused when the last one was recent and verified), or why none was
// written.
type Taken struct {
	Target string      `json:"target"`
	Backup *BackupView `json:"backup,omitempty"`
	Reused bool        `json:"reused,omitempty"`
	Error  string      `json:"error,omitempty"`
}

// Target is a destination as the owner adds it, so the owner side builds
// one without linking the kernel (ARC-2's control path).
type Target = kernel.BackupTarget

// KindDir is a mounted directory, such as a second local drive.
const KindDir = kernel.KindDir

// TargetMsg is the message a hardware key signs to add t as destination n,
// n the destinations added so far, removed ones included:
// key.CosignMsg(kernel.BackupTargetHash(n, t)).
func TargetMsg(n int, t Target) []byte { return key.CosignMsg(kernel.BackupTargetHash(n, t)) }

// BackupTarget adds a destination on a hardware key's signature over
// kernel.BackupTargetHash(n, t), n the destinations added so far. A
// signature over another add is ErrTargetSig, a name used before
// ErrTargetExists; the kernel's other refusals are of the place.
func (o Owner) BackupTarget(ctx context.Context, t kernel.BackupTarget, c key.Cosign) error {
	return typed(o.call(ctx, "backuptarget", struct {
		Target kernel.BackupTarget `json:"target"`
		Cosign key.Cosign          `json:"cosign"`
	}{t, c}, nil))
}

// Untarget stops new backups to a destination; its backups keep their
// erase reach. One not current is ErrNoTarget.
func (o Owner) Untarget(ctx context.Context, name string) error {
	return typed(o.call(ctx, "untarget", struct {
		Name string `json:"name"`
	}{name}, nil))
}

// Backup takes one backup now to every current destination.
func (o Owner) Backup(ctx context.Context) ([]Taken, error) {
	var t []Taken
	err := typed(o.call(ctx, "backup", nil, &t))
	return t, err
}

// Backups reads the recipient's ID, the destinations and the kept backups.
func (o Owner) Backups(ctx context.Context) (BackupsView, error) {
	var v BackupsView
	err := typed(o.call(ctx, "backups", nil, &v))
	return v, err
}

// The page's serving certificate (CH-9, MIG-4-recovery-f1): the kernel
// holds the page authority and signs the page's serving key for the page
// name only; the authority's key never leaves the kernel's process.

// ErrNoAuthority: the kernel holds no page authority, so the page serves
// HTTP only.
var ErrNoAuthority = errors.New("kernelsock: the kernel holds no page authority")

// ErrPageRestore: the box is claimed but its kernel holds no page
// authority; it must be restored, never given a new one.
var ErrPageRestore = errors.New("kernelsock: the claimed box has no page authority; restore it")

// noAuthorityText and pageRestoreText are kernel/proc ErrNoAuthority's and
// ErrPageRestore's texts; TestCertifyReachesTheKernel keeps them the same.
const (
	noAuthorityText = "run: my store holds no page authority, so I certify no page key"
	pageRestoreText = "run: I am claimed but hold no page authority; restore me from a backup"
)

// Certify asks the kernel to sign pub, the page's serving public key in
// PKIX DER (ECDSA P-256 only), and returns the leaf and the authority's
// certificate, both DER. A setup-only kernel serves it, since setup's
// passkeys are made on the page.
func (o Owner) Certify(ctx context.Context, pub []byte) (leaf, authority []byte, err error) {
	var c struct {
		Leaf      []byte `json:"leaf"`
		Authority []byte `json:"authority"`
	}
	err = typed(o.call(ctx, "certify", struct {
		Key []byte `json:"key"`
	}{pub}, &c))
	return c.Leaf, c.Authority, err
}
