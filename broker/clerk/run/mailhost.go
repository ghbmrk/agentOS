package run

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"sync"

	"github.com/ghbmrk/agentos/broker/clerk"
	"github.com/ghbmrk/agentos/broker/clerk/inbox"
	"github.com/ghbmrk/agentos/broker/kernel"
)

// MailHost is the mail clerk's process around its clerk (MIG-4-run slice 3b):
// the clerk the kernel calls over ServeClerk, opened again after each change
// of account and on the planner's re-read, and the two sockets besides the
// kernel's. The owner's socket sets up and removes the account and reads
// what the clerk tells the owner; the planner's socket reads the listing.
// The password reaches this process only, never the kernel's (CLK-1).
type MailHost struct {
	ctx context.Context
	dir string
	sec *clerk.Secrets
	cfg MailConfig

	mu      sync.Mutex
	cur     *Mail // nil: no account, or it did not open
	why     string
	notices []string
}

// Fixed owner notices when the account changes, the old setup's (CH-11).
const (
	noteMailReplaced = "The mail account was replaced on my Wi-Fi page."
	noteMailRemoved  = "The mail account was removed on my Wi-Fi page."
)

// DNoAccount is the clerk's detail for a step while no account is open.
const DNoAccount = "no-account"

// NewMailHost opens the account in dir, if there is one.
func NewMailHost(ctx context.Context, dir string, sec *clerk.Secrets, cfg MailConfig) *MailHost {
	h := &MailHost{ctx: ctx, dir: dir, sec: sec, cfg: cfg}
	h.mu.Lock()
	h.open()
	h.mu.Unlock()
	return h
}

// open opens the account again; h.mu is held. Its notices are kept until
// the owner reads them.
func (h *MailHost) open() {
	m, err := OpenMail(h.ctx, h.dir, h.sec, h.cfg)
	h.cur, h.why = m, ""
	switch {
	case errors.Is(err, ErrNoMailAccount):
	case err != nil:
		h.why = "The mail clerk could not open your mailbox (" + detail(err.Error()) + "). It tries again at the next read."
	default:
		h.notices = append(h.notices, m.Status.Notices...)
	}
}

func (h *MailHost) clerk() *Mail {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.cur
}

// Do runs r on the open clerk; with none, nothing is sent.
func (h *MailHost) Do(r kernel.Request, v kernel.View) kernel.Result {
	m := h.clerk()
	if m == nil {
		return kernel.Result{Outcome: "failed", Detail: DNoAccount}
	}
	return m.Do(r, v)
}

// Probe asks the open clerk; with none, the step's effect cannot be checked.
func (h *MailHost) Probe(r kernel.Request, v kernel.View) string {
	m := h.clerk()
	if m == nil {
		return "unknown"
	}
	return m.Probe(r, v)
}

// status is the owner's read: the lines that hold now, and the
// notices not yet read, which this read hands over once.
func (h *MailHost) status() MailStatus {
	h.mu.Lock()
	defer h.mu.Unlock()
	var st MailStatus
	switch {
	case h.why != "":
		st.Lines = []string{h.why}
	case h.cur != nil:
		st.Lines = append(st.Lines, h.cur.Status.Lines...)
	}
	st.Notices, h.notices = h.notices, nil
	return st
}

type setMailArgs struct {
	Settings MailSettings `json:"settings"`
	Password string       `json:"password"`
}

// mailOp is one call on a mail socket.
type mailOp func(h *MailHost, args json.RawMessage) (any, error)

// MailSide is one caller's closed table of the mail process's calls.
type MailSide struct {
	name string
	ops  map[string]mailOp
}

// MailOwnerSide is the owner side's table: set up, remove, and read status.
var MailOwnerSide = MailSide{"mail owner", map[string]mailOp{
	"setmail": func(h *MailHost, raw json.RawMessage) (any, error) {
		var a setMailArgs
		if json.Unmarshal(raw, &a) != nil {
			return nil, errArgs
		}
		h.mu.Lock()
		defer h.mu.Unlock()
		_, err := readMail(h.dir)
		replacing := err == nil
		if err := SetMail(h.dir, h.sec, a.Settings, a.Password); err != nil {
			return nil, err
		}
		if replacing {
			h.notices = append(h.notices, noteMailReplaced)
		}
		h.open()
		return nil, nil
	},
	"removemail": func(h *MailHost, _ json.RawMessage) (any, error) {
		h.mu.Lock()
		defer h.mu.Unlock()
		_, err := readMail(h.dir)
		removing := err == nil
		if err := RemoveMail(h.dir, h.sec); err != nil {
			return nil, err
		}
		if removing {
			h.notices = append(h.notices, noteMailRemoved)
		}
		h.cur, h.why = nil, ""
		return nil, nil
	},
	"status": func(h *MailHost, _ json.RawMessage) (any, error) { return h.status(), nil },
}}

// MailPlannerSide is the planner's table: the listing, as last read or read
// again now.
var MailPlannerSide = MailSide{"mail planner", map[string]mailOp{
	"listing": func(h *MailHost, _ json.RawMessage) (any, error) { return h.listing(false) },
	"reread":  func(h *MailHost, _ json.RawMessage) (any, error) { return h.listing(true) },
}}

func (h *MailHost) listing(again bool) ([]inbox.Item, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if again || (h.cur == nil && h.why != "") {
		h.open()
	}
	if h.cur == nil {
		return nil, ErrNoMailAccount
	}
	return h.cur.Listing(), nil
}

// ListenMail opens one of the mail process's sockets besides the kernel's,
// admitting only that side's uid.
func ListenMail(path string, uid int) (net.Listener, error) { return ListenKernel(path, uid) }

// ServeMail answers side's calls to h on ln until ln closes.
func ServeMail(ln net.Listener, h *MailHost, side MailSide) error {
	for {
		conn, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		go serveOne(conn, func(name string, args json.RawMessage) (json.RawMessage, error) {
			f, ok := side.ops[name]
			if !ok {
				return nil, errors.New("run: the " + side.name + " socket has no call " + name)
			}
			res, err := f(h, args)
			if err != nil || res == nil {
				return nil, err
			}
			return json.Marshal(res)
		})
	}
}

// MailOwner is the owner side's caller of the mail process.
type MailOwner struct{ Conn }

func (o MailOwner) SetMail(s MailSettings, password string) error {
	return o.call("setmail", setMailArgs{s, password}, nil)
}
func (o MailOwner) RemoveMail() error { return o.call("removemail", nil, nil) }
func (o MailOwner) Status() (st MailStatus, err error) {
	err = o.call("status", nil, &st)
	return
}

// MailPlanner is the planner's caller of the mail process.
type MailPlanner struct{ Conn }

func (p MailPlanner) Listing() (ls []inbox.Item, err error) {
	err = p.call("listing", nil, &ls)
	return
}
func (p MailPlanner) Reread() (ls []inbox.Item, err error) { err = p.call("reread", nil, &ls); return }
