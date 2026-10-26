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

// typed is err as ErrAnchor or ErrSetupOnly when the kernel's words are
// exactly that refusal's, else err.
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
