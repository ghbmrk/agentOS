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
// actions as it moves the owner channel onto them.
package kernelsock

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

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

// Resume logs a RESUME on the kernel and anchors it.
func (o Owner) Resume(ctx context.Context) error { return o.call(ctx, "resume", nil, nil) }

// changes is the part of kernel/key Changes read here.
type changes struct {
	Stopped bool
}

// Stopped reads whether a STOP is in force on the kernel (its log's
// Changes view). A setup-only kernel refuses it.
func (o Owner) Stopped(ctx context.Context) (bool, error) {
	var c changes
	err := o.call(ctx, "changes", nil, &c)
	return c.Stopped, err
}
