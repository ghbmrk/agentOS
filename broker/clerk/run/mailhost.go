package run

import (
	"cmp"
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
	"github.com/ghbmrk/agentos/broker/kernel/proc"
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

	mu       sync.Mutex
	cur      *Mail         // the last clerk this account opened; nil: none
	why      string        // why the last read failed; "" if it did not
	checkWhy string        // why the last change check failed, since the last read; "" if it did not
	stop     error         // a sign-in failure only setup clears (stops): no sign-in until setup
	reading  chan struct{} // the read in flight; setup and removal wait for it
	mark     inbox.Mark    // the mailbox's Mark from just before the last read; nil: none
	day      string        // the last read's day (MailConfig.day); "": none since the account changed
	fails    int           // failed reads in a row within day under mark; 0 after a good read
	changes  int64         // account changes so far (changed)
	seq      int64
	notices  []notice

	signMu  sync.Mutex
	signing *gmailSignIn // the Gmail sign-in waiting for its paste; nil: none

	planned planState // setup's account plan (accountPlan)

	stepping chan struct{}  // the worker's step in flight (planSenders); setup and removal wait for it
	kick     chan struct{}  // wakes the worker; buffered, sent to without blocking
	ws       worldState     // the host's own world's sources (world.go)
	srec     *sealedSenders // the senders record of the account at srecAt, between steps (senders.go)
	srecAt   int64
	own      bool // the world is the host's own: each read's clerk is bound to its account (worldAt)
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

// DReconnect is a step's detail while Gmail refuses the clerk's grant
// (inbox.ErrReconnect): nothing is sent until the owner signs in again. It
// is inbox's word for a step refused that way.
const DReconnect = "reconnect"

// ErrReconnect is the planner's answer while Gmail refuses the grant.
var ErrReconnect = errors.New("run: Gmail refused the clerk's sign-in; the owner must sign in again")

// ErrNoPasswordSignIn is the planner's answer while the server offers no
// sign-in the clerk can make with these settings: nothing is read again
// until the owner sets the account up again.
var ErrNoPasswordSignIn = errors.New("run: the mail server offers no sign-in with these settings; the owner must set the account up again")

// stops reports whether err is a sign-in failure only a change of setup
// clears, and so stops every sign-in until then.
func stops(err error) bool {
	return errors.Is(err, imapsmtp.ErrLoginRefused) || errors.Is(err, imapsmtp.ErrNoSignIn) || errors.Is(err, inbox.ErrReconnect)
}

// stopped is what a step, and the planner, get while stop holds.
func stopped(stop error) (detail string, planner error) {
	switch {
	case errors.Is(stop, imapsmtp.ErrNoSignIn):
		return DNoSignIn, ErrNoPasswordSignIn
	case errors.Is(stop, inbox.ErrReconnect):
		return DReconnect, ErrReconnect
	}
	return DSignInRefused, ErrSignInRefused
}

// NewMailHost opens the account in dir, if there is one.
// With no cfg.World the host builds its own (world.go) and starts the
// worker that reads its alert senders; a given World is used unchanged.
func NewMailHost(ctx context.Context, dir string, sec *clerk.Secrets, cfg MailConfig) *MailHost {
	h := &MailHost{ctx: ctx, dir: dir, sec: sec, cfg: cfg, kick: make(chan struct{}, 1)}
	h.own = cfg.World == nil
	if h.own {
		h.cfg.World = h.world
	}
	h.mu.Lock()
	h.refresh()
	h.mu.Unlock()
	if h.own {
		go h.work()
	}
	return h
}

// wake kicks the worker without blocking; h.mu may be held.
func (h *MailHost) wake() {
	select {
	case h.kick <- struct{}{}:
	default:
	}
}

// refresh reads the account again and waits for the read; h.mu is held, and
// released while the mailbox is read. A read in flight is shared, not
// started again: it is of the account as it is now, since setup and removal
// wait for it before they change the account (idle). Once a read is done,
// the mailbox is read again only when recheck says so (#2742 item 1): a
// first failure gets one more try under any Mark, and a failure that
// repeats under an unchanged Mark within the day waits for the Mark to move
// or the next day (#2742, #2768 review).
func (h *MailHost) refresh() {
	if h.reading != nil {
		h.wait()
		return
	}
	done := make(chan struct{})
	h.reading = done
	last, day, fails, today := h.mark, h.day, h.fails, h.cfg.day()
	c := h.cfg
	if h.own {
		// The clerk judges in the world of the account it is opened for:
		// a step it runs after a change of account has the guard off.
		at := h.changes
		c.World = func() inbox.World { return h.worldAt(at) }
	}
	h.mu.Unlock()
	var m *Mail
	var mark inbox.Mark
	read, err := true, error(nil)
	if day != "" {
		read, mark, err = recheck(h.ctx, last, day, fails == 1, h.dir, h.sec, h.cfg)
	}
	if read && err == nil {
		m, mark, err = openMail(h.ctx, h.dir, h.sec, c, mark)
	}
	h.mu.Lock()
	h.reading = nil
	close(done)
	h.wake() // a senders read that failed retries at the next refresh
	if !read {
		// The last read stands. A change check that failed, for any
		// reason but a refused sign-in (which reads), is told until a
		// check or a read works: otherwise STATUS would say nothing until
		// the server answers or the next day (#2742, #2768 review).
		h.checkWhy = ""
		if err != nil {
			why, next := trouble(err, last)
			h.checkWhy = "I could not check your mailbox for new mail: " + why + ". " + next
		}
		return
	}
	h.mark, h.day = mark, today
	h.why, h.checkWhy, h.stop, h.fails = "", "", nil, 0
	switch {
	case errors.Is(err, ErrNoMailAccount):
		h.cur = nil
	case err != nil:
		h.fails = 1
		if fails > 0 && day == today && last.Same(mark) {
			h.fails = fails + 1
		}
		// The last clerk this account opened goes on serving the kernel's
		// steps: each signs in afresh, and judges the kernel's view.
		why, next := trouble(err, mark)
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

// wait waits, with h.mu released, for the read in flight to end, or the
// worker's step when no read is in flight.
func (h *MailHost) wait() {
	done := h.reading
	if done == nil {
		done = h.stepping
	}
	h.mu.Unlock()
	<-done
	h.mu.Lock()
}

// idle waits until no read and no worker step is in flight; h.mu is held.
// While the caller keeps h.mu, none starts.
func (h *MailHost) idle() {
	for h.reading != nil || h.stepping != nil {
		h.wait()
	}
}

// changed follows a change of account: the old clerk stops serving, and an
// unread warm-up notice, which was about it, is dropped.
func (h *MailHost) changed() {
	h.changes++
	h.ws.reset(h.changes)
	h.srec = nil
	h.wake()
	h.cur, h.why, h.checkWhy, h.stop = nil, "", "", nil
	h.mark, h.day = nil, ""
	h.notices = slices.DeleteFunc(h.notices, func(n notice) bool { return n.warm })
}

// wrote is the test seam right after a setter's write (MailConfig.wrote).
func (h *MailHost) wrote() {
	if h.cfg.wrote != nil {
		h.cfg.wrote()
	}
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
	if stop := map[string]error{DSignInRefused: imapsmtp.ErrLoginRefused, DNoSignIn: imapsmtp.ErrNoSignIn, DReconnect: inbox.ErrReconnect}[res.Detail]; res.Outcome == "failed" && stop != nil {
		// The step's own sign-in failed that way, before any effect: no
		// step, probe or read signs in again until the owner sets the account
		// up again, and STATUS says so (#2708 item 2, #2698 item 32). The
		// step's detail carries no side (#2698 item 37), so the line names
		// none.
		h.mu.Lock()
		if h.cur == m {
			why, next := trouble(stop, nil)
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
	// A failed read's line already says the mailbox is not read; a change
	// check failing since is told only after a good read.
	why := cmp.Or(h.why, h.checkWhy)
	if why != "" {
		st.Lines = append(st.Lines, why)
	}
	if l := sendersLine(h.ws.sendersNow()); h.own && h.cur != nil && l != "" {
		st.Lines = append(st.Lines, l)
	}
	if h.cur != nil && len(h.cur.Status.Lines) > 0 {
		if why != "" {
			// The clerk's lines are of the last read that worked, not of
			// the one that just failed (#2742 item 3).
			st.Lines = append(st.Lines, "From my last good read of your mailbox:")
		}
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
		// A record that cannot be saved tells the warm-up's end again, at
		// the next read.
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

// MailOwnerSide is the owner side's table: set up, remove, sign in to Gmail
// and give its sign-in back, and read what the clerk tells the owner.
var MailOwnerSide = MailSide{"mail owner", map[string]mailOp{
	"setmail": func(h *MailHost, raw json.RawMessage) (any, error) {
		var a setMailArgs
		if json.Unmarshal(raw, &a) != nil {
			return nil, proc.ErrArgs
		}
		// Refused before a Gmail grant is given back for nothing.
		if err := checkSetup(a.Settings, a.Password); err != nil {
			return nil, err
		}
		h.mu.Lock()
		defer h.mu.Unlock()
		h.idle()
		prev, err := readMail(h.dir)
		replacing := err == nil
		release := func() {}
		if replacing {
			release = h.holdGmail(prev) // a Gmail account's grant, given back once SetMail drops it (A22)
		}
		end := h.ws.writing() // until the change is told (#3538)
		err = SetMail(h.dir, h.sec, a.Settings, a.Password)
		h.wrote()
		release()
		if !h.setUp(slotOf(a.Settings)) {
			end()
			return nil, err // the account before, and its grant, stand
		}
		h.changed()
		end()
		if replacing {
			h.notify(false, noteMailReplaced)
		}
		h.refresh()
		return nil, err
	},
	"removemail": func(h *MailHost, _ json.RawMessage) (any, error) {
		h.mu.Lock()
		defer h.mu.Unlock()
		h.idle()
		prev, err := readMail(h.dir)
		removing := err == nil
		release := func() {}
		if removing {
			release = h.holdGmail(prev) // a Gmail account's grant, given back once RemoveMail drops it (A22)
		}
		end := h.ws.writing()
		err = RemoveMail(h.dir, h.sec)
		h.wrote()
		release()
		if err != nil {
			end()
			return nil, err
		}
		h.changed()
		end()
		if removing {
			h.notify(false, noteMailRemoved)
		}
		return nil, nil
	},
	"gmailbegin": func(h *MailHost, raw json.RawMessage) (any, error) {
		var a gmailBeginArgs
		if json.Unmarshal(raw, &a) != nil {
			return nil, proc.ErrArgs
		}
		var reg *clerk.Registration
		if a.Registration != nil {
			reg = &clerk.Registration{ID: a.Registration.ID, Secret: a.Registration.Secret}
		}
		return h.gmailBegin(a.Use, reg), nil
	},
	"gmailfinish": func(h *MailHost, raw json.RawMessage) (any, error) {
		var a gmailFinishArgs
		if json.Unmarshal(raw, &a) != nil {
			return nil, proc.ErrArgs
		}
		return h.gmailFinish(a.Use, a.Pasted)
	},
	"gmailrevoke": func(h *MailHost, _ json.RawMessage) (any, error) { return h.gmailRevoke() },
	"accountplan": func(h *MailHost, _ json.RawMessage) (any, error) { return h.accountPlan() },
	"status":      func(h *MailHost, _ json.RawMessage) (any, error) { return h.status(), nil },
	"account":     func(h *MailHost, _ json.RawMessage) (any, error) { return h.account() },
	"told": func(h *MailHost, raw json.RawMessage) (any, error) {
		var through int64
		if json.Unmarshal(raw, &through) != nil {
			return nil, proc.ErrArgs
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
func ListenMail(path string, uid int) (net.Listener, error) {
	return proc.ListenKernel(path, uid)
}

// ServeMail answers side's calls to h on ln until ln closes.
func ServeMail(ln net.Listener, h *MailHost, side MailSide) error {
	return proc.ServeConns(ln, proc.MaxConns, func(conn net.Conn) {
		proc.ServeOne(conn, func(name string, args json.RawMessage) (json.RawMessage, error) {
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
type MailOwner struct{ proc.Conn }

func (o MailOwner) SetMail(s MailSettings, password string) error {
	return o.Call("setmail", setMailArgs{s, password}, nil)
}
func (o MailOwner) RemoveMail() error { return o.Call("removemail", nil, nil) }

// GmailBegin starts a Gmail sign-in for one declared use (inbox.GmailUses)
// and returns the consent address, or a typed detail (clerk.D*). reg is
// the household's client at the first sign-in; nil signs in again with the
// Gmail account's own.
func (o MailOwner) GmailBegin(use string, reg *clerk.Registration) (consent, detail string, err error) {
	a := gmailBeginArgs{Use: use}
	if reg != nil {
		a.Registration = &gmailRegistration{reg.ID, reg.Secret}
	}
	var b gmailBegun
	err = o.Call("gmailbegin", a, &b)
	return b.Consent, b.Detail, err
}

// GmailFinish hands the mail process the address the owner pasted and the
// use the owner confirmed: "signedin <use>" once the account is set up,
// or a typed detail (clerk.D*, DGmailAddress).
func (o MailOwner) GmailFinish(use, pasted string) (detail string, err error) {
	err = o.Call("gmailfinish", gmailFinishArgs{use, pasted}, &detail)
	return
}

// GmailRevoke gives the Gmail account's sign-in back to Google and removes
// the account: clerk.DRevoked, or a typed detail with the account kept.
func (o MailOwner) GmailRevoke() (detail string, err error) {
	err = o.Call("gmailrevoke", nil, &detail)
	return
}

// AccountPlan is setup's account plan (TN-account-plan): its items, or
// the typed reason the mailbox could not be read for them.
func (o MailOwner) AccountPlan() (p AccountPlanned, err error) {
	err = o.Call("accountplan", nil, &p)
	return
}
func (o MailOwner) Status() (st OwnerStatus, err error) {
	err = o.Call("status", nil, &st)
	return
}

// Told drops the notices up to through, a Status answer's Through, once
// they have been shown to the owner.
func (o MailOwner) Told(through int64) error { return o.Call("told", through, nil) }

// Account is whether an account is set up, and its settings.
func (o MailOwner) Account() (a MailAccount, err error) {
	err = o.Call("account", nil, &a)
	return
}

// MailPlanner is the planner's caller of the mail process.
type MailPlanner struct{ proc.Conn }

func (p MailPlanner) Listing() (ls []inbox.Item, err error) {
	err = p.Call("listing", nil, &ls)
	return
}
func (p MailPlanner) Reread() (ls []inbox.Item, err error) { err = p.Call("reread", nil, &ls); return }
