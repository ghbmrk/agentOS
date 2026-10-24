// Package accountsock is agentosd's client of the mail clerk's owner socket
// for the Connect page's Gmail sign-in (#3006, D-150, D-154 rule 1). The
// local UI's two frames, checked against the session on localui.sock
// (localsrv), go on to the mail clerk's process (clerk/run MailOwnerSide),
// which holds the verifier, the client and the grant; agentosd keeps
// nothing of either frame. It lives apart from localsrv so agentosd's
// control path links no network client (ARC-2), as bridgeclient does.
//
// This is the wire run.MailOwner speaks over kernel/proc, written out here
// rather than imported: clerk/run links the mail clerk's credential clients
// (clerk/inbox/imapsmtp), which agentosd never links
// (TestDaemonLinksNoCredentialCustody), and kernel/proc the kernel
// process's own host. TestGmailSpeaksTheMailProcesssWire serves the real
// MailOwnerSide to keep the two the same.
package accountsock

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"time"

	"github.com/ghbmrk/agentos/broker/localapi"
	"github.com/ghbmrk/agentos/broker/sockets"
)

// callFor bounds one call: Finish redeems the code at Google and reads
// the address.
const callFor = time.Minute

// maxAnswer bounds an answer: a consent address or a detail.
const maxAnswer = 64 << 10

// Gmail is the Gmail sign-in on the mail process's owner socket, called
// only on a peer under uid (localsrv.AccountSignIn).
type Gmail struct {
	Socket string
	UID    int
}

// ErrNoAnswer is every failed call: it carries nothing the clerk said.
var ErrNoAnswer = errors.New("accountsock: the mail clerk did not answer")

// call makes one call: one {"op","args"} line, one {"result"} or {"error"}
// answer (kernel/proc ServeOne).
func (g Gmail) call(ctx context.Context, op string, args, out any) error {
	ctx, cancel := context.WithTimeout(ctx, callFor)
	defer cancel()
	raw, err := json.Marshal(args)
	if err != nil {
		return err
	}
	b, err := json.Marshal(wireCall{op, raw})
	if err != nil {
		return err
	}
	conn, err := (&net.Dialer{}).DialContext(ctx, "unix", g.Socket)
	if err != nil {
		return ErrNoAnswer
	}
	defer conn.Close()
	if uid, ok := sockets.PeerUID(conn); !ok || uid != g.UID {
		return ErrNoAnswer
	}
	if dl, ok := ctx.Deadline(); ok {
		conn.SetDeadline(dl)
	}
	if _, err := conn.Write(append(b, '\n')); err != nil {
		return ErrNoAnswer
	}
	var a wireAnswer
	if json.NewDecoder(io.LimitReader(conn, maxAnswer)).Decode(&a) != nil || a.Error != "" || json.Unmarshal(a.Result, out) != nil {
		return ErrNoAnswer
	}
	return nil
}

type wireCall struct {
	Op   string          `json:"op"`
	Args json.RawMessage `json:"args"`
}

type wireAnswer struct {
	Result json.RawMessage `json:"result"`
	Error  string          `json:"error"`
}

// The frames of gmailbegin and gmailfinish (clerk/run gmailBeginArgs,
// gmailBegun, gmailFinishArgs).
type beginArgs struct {
	Use          string        `json:"use"`
	Registration *registration `json:"registration,omitempty"`
}

type registration struct {
	ID     string `json:"id"`
	Secret string `json:"secret"`
}

type begun struct {
	Consent string `json:"consent,omitempty"`
	Detail  string `json:"detail,omitempty"`
}

type finishArgs struct {
	Use    string `json:"use"`
	Pasted string `json:"pasted"`
}

// Begin starts a sign-in for use and returns the consent address, or the
// clerk's detail.
func (g Gmail) Begin(ctx context.Context, use string, reg *localapi.AccountRegistration) (consent, detail string, err error) {
	a := beginArgs{Use: use}
	if reg != nil {
		a.Registration = &registration{reg.ID, reg.Secret}
	}
	var b begun
	err = g.call(ctx, "gmailbegin", a, &b)
	return b.Consent, b.Detail, err
}

// Finish hands the clerk the pasted address and the use the owner
// confirmed, and returns its detail.
func (g Gmail) Finish(ctx context.Context, use, pasted string) (detail string, err error) {
	err = g.call(ctx, "gmailfinish", finishArgs{use, pasted}, &detail)
	return detail, err
}
