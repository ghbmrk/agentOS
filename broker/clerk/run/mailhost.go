package run

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"slices"
	"sync"

	"github.com/ghbmrk/agentos/broker/clerk"
	"github.com/ghbmrk/agentos/broker/clerk/inbox"
	"github.com/ghbmrk/agentos/broker/clerk/inbox/imapsmtp"
	"github.com/ghbmrk/agentos/broker/kernel"
)

// MailHost is the mail clerk's process around its clerk (MIG-4-run slice 3b):
// the clerk the kernel calls over ServeClerk, opened again after each change
// of account and on the planner's re-read, and the two sockets besides the
// kernel's. The owner's socket sets up and removes the account and reads
// what the clerk tells the owner; the planner's socket reads the listing.
// The password reaches this process only, never the kernel's (CLK-1).
//
// A read of the mailbox runs outside mu, so the kernel's steps and the
// owner's reads never wait on it, and reads that overlap share one. Setup,
// removal and the record's writes wait for the read in flight to end, so a
// read never mixes two accounts' files.
type MailHost struct {
	ctx context.Context
	dir string
	sec *clerk.Secrets
	cfg MailConfig

	mu      sync.Mutex
	cur     *Mail         // the last clerk this account opened; nil: none
	why     string        // why the last read failed; "" if it did not
	stop    error         // a sign-in failure only setup clears (stops): no sign-in until setup
	reading chan struct{} // the read in flight; setup and removal wait for it
	changes int64         // account changes so far (changed)
	seq     int64
	notices []notice
}

// notice is one thing the owner is told until the owner has read it. Seq
// orders them; a newer notice of the same kind replaces an unread one.
type notice struct {
	seq  int64
	warm bool // the end of the warm-up, for the account as it is now
	text string
}

// Fixed owner notices when the account changes, the old setup's (CH-11).
const (
	noteMailReplaced = "The mail account was replaced on my Wi-Fi page."
	noteMailRemoved  = "The mail account was removed on my Wi-Fi page."
)

// DNoAccount is the clerk's detail for a step while no account is open.
const DNoAccount = "no-account"

// DSignInRefused is a step's detail while the server refuses the sign-in:
// nothing is sent until the owner sets the account up again, so no plan can
// drive failed sign-ins toward a provider's lockout (#2737 combined 4). It
// is inbox's own word for a step the server refused that way.
const DSignInRefused = "sign-in-refused"

// DNoSignIn is a step's detail while the server offers no sign-in the clerk
// can make with these settings (imapsmtp.ErrNoSignIn): as with a refusal,
// nothing is sent until the owner sets the account up again, since no retry
// can change what the server offers (#2698 item 32). It is inbox's word too.
const DNoSignIn = "no-sign-in"

// ErrSignInRefused is the planner's answer while the server refuses the
// clerk's sign-in: nothing is read again until the owner sets the account
// up again, so the planner cannot drive repeated failed sign-ins toward the
// provider's lockout (#2698 item 5).
var ErrSignInRefused = errors.New("run: the mail server refused the sign-in; the owner must set the account up again")

// ErrNoPasswordSignIn is the planner's answer while the server offers no
// sign-in the clerk can make with these settings: nothing is read again
// until the owner sets the account up again.
var ErrNoPasswordSignIn = errors.New("run: the mail server offers no sign-in with these settings; the owner must set the account up again")

// stops reports whether err is a sign-in failure only a change of setup
// clears, and so stops every sign-in until then.
func stops(err error) bool {
	return errors.Is(err, imapsmtp.ErrLoginRefused) || errors.Is(err, imapsmtp.ErrNoSignIn)
}

// stopped is what a step, and the planner, get while stop holds.
func stopped(stop error) (detail string, planner error) {
	if errors.Is(stop, imapsmtp.ErrNoSignIn) {
		return DNoSignIn, ErrNoPasswordSignIn
	}
	return DSignInRefused, ErrSignInRefused
}

// NewMailHost opens the account in dir, if there is one.
func NewMailHost(ctx context.Context, dir string, sec *clerk.Secrets, cfg MailConfig) *MailHost {
	h := &MailHost{ctx: ctx, dir: dir, sec: sec, cfg: cfg}
	h.mu.Lock()
	h.refresh()
	h.mu.Unlock()
	return h
}

// refresh reads the account again and waits for the read; h.mu is held, and
// released while the mailbox is read. A read in flight is shared, not
// started again: it is of the account as it is now, since setup and removal
// wait for it before they change the account (idle).
func (h *MailHost) refresh() {
	if h.reading != nil {
		h.wait()
		return
	}
	done := make(chan struct{})
	h.reading = done
	h.mu.Unlock()
	m, err := OpenMail(h.ctx, h.dir, h.sec, h.cfg)
	h.mu.Lock()
	h.reading = nil
	close(done)
	h.why, h.stop = "", nil
	switch {
	case errors.Is(err, ErrNoMailAccount):
		h.cur = nil
	case err != nil:
		// The last clerk this account opened goes on serving the kernel's
		// steps: each signs in afresh, and judges the kernel's view.
		why, next := trouble(err)
		h.why = "I could not read your mailbox: " + why + ". " + next
		if stops(err) {
			h.stop = err
		}
	default:
		h.cur = m
		if m.Status.WarmedUp != "" {
			h.notify(true, m.Status.WarmedUp)
		}
	}
}

// wait waits, with h.mu released, for the read in flight to end.
func (h *MailHost) wait() {
	done := h.reading
	h.mu.Unlock()
	<-done
	h.mu.Lock()
}

// idle waits until no read is in flight; h.mu is held. While the caller
// keeps h.mu, none starts.
func (h *MailHost) idle() {
	for h.reading != nil {
		h.wait()
	}
}

// changed follows a change of account: the old clerk stops serving, and an
// unread warm-up notice, which was about it, is dropped.
func (h *MailHost) changed() {
	h.changes++
	h.cur, h.why, h.stop = nil, "", nil
	h.notices = slices.DeleteFunc(h.notices, func(n notice) bool { return n.warm })
}

// notify adds a notice. A warm-up notice already waiting keeps its place
// with the newer text, so the owner side's Told for it still covers it.
func (h *MailHost) notify(warm bool, text string) {
	if i := slices.IndexFunc(h.notices, func(n notice) bool { return n.warm }); warm && i >= 0 {
		h.notices[i].text = text
		return
	}
	h.seq++
	h.notices = slices.DeleteFunc(h.notices, func(n notice) bool { return n.warm == warm && (warm || n.text == text) })
	h.notices = append(h.notices, notice{h.seq, warm, text})
}

func (h *MailHost) clerk() (m *Mail, stop error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.cur, h.stop
}

// Do runs r on the open clerk; with none, or while a sign-in failure only
// setup clears holds, nothing is sent.
func (h *MailHost) Do(r kernel.Request, v kernel.View) kernel.Result {
	m, stop := h.clerk()
	switch {
	case stop != nil:
		detail, _ := stopped(stop)
		return kernel.Result{Outcome: "failed", Detail: detail}
	case m == nil:
		return kernel.Result{Outcome: "failed", Detail: DNoAccount}
	}
	res := m.Do(r, v)
	if stop := map[string]error{DSignInRefused: imapsmtp.ErrLoginRefused, DNoSignIn: imapsmtp.ErrNoSignIn}[res.Detail]; res.Outcome == "failed" && stop != nil {
		// The step's own sign-in failed that way, before any effect: no
		// step, probe or read signs in again until the owner sets the account
		// up again, and STATUS says so (#2708 item 2, #2698 item 32). The
		// step's detail carries no side (#2698 item 37), so the line names
		// none.
		h.mu.Lock()
		if h.cur == m {
			why, next := trouble(stop)
			h.why, h.stop = "I stopped working in your mailbox: "+why+". "+next, stop
		}
		h.mu.Unlock()
	}
	return res
}

// Probe asks the open clerk; with none, or while the server refuses the
// sign-in, the step's effect cannot be checked.
func (h *MailHost) Probe(r kernel.Request, v kernel.View) kernel.Result {
	m, stop := h.clerk()
	if m == nil || stop != nil {
		return kernel.Result{Outcome: "unknown"}
	}
	return m.Probe(r, v)
}

// OwnerStatus is the owner's read of the mail clerk: the lines that hold
// now, and the notices not yet read. Reading them does not use them up: the
// owner's side passes Through to Told once it has shown them, so a lost
// answer, or a setup page that polls, loses none.
type OwnerStatus struct {
	Lines   []string `json:"lines"`
	Notices []string `json:"notices"`
	Through int64    `json:"through"`
}

func (h *MailHost) status() OwnerStatus {
	h.mu.Lock()
	defer h.mu.Unlock()
	var st OwnerStatus
	if h.why != "" {
		st.Lines = append(st.Lines, h.why)
	}
	if h.cur != nil {
		st.Lines = append(st.Lines, h.cur.Status.Lines...)
	}
	for _, n := range h.notices {
		st.Notices = append(st.Notices, n.text)
		st.Through = max(st.Through, n.seq)
	}
	return st
}

// told drops the notices up to through. Once the owner has read the end of
// the warm-up, the record keeps that, and a warm-up notice a later read gave
// (a re-read between the owner side's read and this call) is the same news,
// so it goes too: the end is told once.
func (h *MailHost) told(through int64) {
	h.mu.Lock()
	defer h.mu.Unlock()
	warm := false
	h.notices = slices.DeleteFunc(h.notices, func(n notice) bool {
		warm = warm || (n.warm && n.seq <= through)
		return n.seq <= through
	})
	if !warm {
		return
	}
	shown := h.changes
	h.idle() // a read in flight may add the notice again; it ends first
	// The owner was shown the warm-up end of the account as it was: if a setup
	// changed it while the read ended, even back to the same settings, the
	// account's record began again and its end is not yet told (#2742 item 14).
	if h.changes != shown {
		return
	}
	h.notices = slices.DeleteFunc(h.notices, func(n notice) bool { return n.warm })
	if s, err := readMail(h.dir); err == nil {
		// A record that cannot be saved tells the warm-up's end again.
		_ = markTold(h.dir, h.cfg.Sealer, slotOf(s))
	}
}

// MailAccount is whether an account is set up, and its settings (never its
// password): what the owner's setup page shows.
type MailAccount struct {
	Set      bool         `json:"set"`
	Settings MailSettings `json:"settings"`
}

func (h *MailHost) account() (MailAccount, error) {
	s, err := readMail(h.dir)
	switch {
	case errors.Is(err, ErrNoMailAccount):
		return MailAccount{}, nil
	case err != nil:
		return MailAccount{}, errMailUnreadable
	}
	return MailAccount{true, s}, nil
}

var errMailUnreadable = errors.New("run: the mail settings could not be read")

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

// MailOwnerSide is the owner side's table: set up, remove, and read what the
// clerk tells the owner.
var MailOwnerSide = MailSide{"mail owner", map[string]mailOp{
	"setmail": func(h *MailHost, raw json.RawMessage) (any, error) {
		var a setMailArgs
		if json.Unmarshal(raw, &a) != nil {
			return nil, errArgs
		}
		h.mu.Lock()
		defer h.mu.Unlock()
		h.idle()
		_, err := readMail(h.dir)
		replacing := err == nil
		if err := SetMail(h.dir, h.sec, a.Settings, a.Password); err != nil {
			return nil, err
		}
		h.changed()
		if replacing {
			h.notify(false, noteMailReplaced)
		}
		h.refresh()
		return nil, nil
	},
	"removemail": func(h *MailHost, _ json.RawMessage) (any, error) {
		h.mu.Lock()
		defer h.mu.Unlock()
		h.idle()
		_, err := readMail(h.dir)
		removing := err == nil
		if err := RemoveMail(h.dir, h.sec); err != nil {
			return nil, err
		}
		h.changed()
		if removing {
			h.notify(false, noteMailRemoved)
		}
		return nil, nil
	},
	"status":  func(h *MailHost, _ json.RawMessage) (any, error) { return h.status(), nil },
	"account": func(h *MailHost, _ json.RawMessage) (any, error) { return h.account() },
	"told": func(h *MailHost, raw json.RawMessage) (any, error) {
		var through int64
		if json.Unmarshal(raw, &through) != nil {
			return nil, errArgs
		}
		h.told(through)
		return nil, nil
	},
}}

// MailPlannerSide is the planner's table: the listing, as last read or read
// again now.
var MailPlannerSide = MailSide{"mail planner", map[string]mailOp{
	"listing": func(h *MailHost, _ json.RawMessage) (any, error) { return h.listing(false) },
	"reread":  func(h *MailHost, _ json.RawMessage) (any, error) { return h.listing(true) },
}}

// listing is the planner's view. A re-read, or a listing while the last read
// failed, reads the mailbox again, except while the server refuses the
// sign-in.
func (h *MailHost) listing(again bool) ([]inbox.Item, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.stop == nil && (again || h.why != "") {
		h.refresh()
	}
	switch {
	case h.stop != nil:
		_, err := stopped(h.stop)
		return nil, err
	case h.cur == nil:
		return nil, ErrNoMailAccount
	}
	return h.cur.Listing(), nil
}

// ListenMail opens one of the mail process's sockets besides the kernel's,
// admitting only that side's uid.
func ListenMail(path string, uid int) (net.Listener, error) { return ListenKernel(path, uid) }

// ServeMail answers side's calls to h on ln until ln closes.
func ServeMail(ln net.Listener, h *MailHost, side MailSide) error {
	return serveConns(ln, maxConns, func(conn net.Conn) {
		serveOne(conn, func(name string, args json.RawMessage) (json.RawMessage, error) {
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
	})
}

// MailOwner is the owner side's caller of the mail process.
type MailOwner struct{ Conn }

func (o MailOwner) SetMail(s MailSettings, password string) error {
	return o.call("setmail", setMailArgs{s, password}, nil)
}
func (o MailOwner) RemoveMail() error { return o.call("removemail", nil, nil) }
func (o MailOwner) Status() (st OwnerStatus, err error) {
	err = o.call("status", nil, &st)
	return
}

// Told drops the notices up to through, a Status answer's Through, once
// they have been shown to the owner.
func (o MailOwner) Told(through int64) error { return o.call("told", through, nil) }

// Account is whether an account is set up, and its settings.
func (o MailOwner) Account() (a MailAccount, err error) {
	err = o.call("account", nil, &a)
	return
}

// MailPlanner is the planner's caller of the mail process.
type MailPlanner struct{ Conn }

func (p MailPlanner) Listing() (ls []inbox.Item, err error) {
	err = p.call("listing", nil, &ls)
	return
}
func (p MailPlanner) Reread() (ls []inbox.Item, err error) { err = p.call("reread", nil, &ls); return }
