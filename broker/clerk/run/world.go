package run

import (
	"cmp"
	"context"
	"errors"
	"net"
	"sync"
	"time"

	"github.com/ghbmrk/agentos/broker/clerk/accounts"
	"github.com/ghbmrk/agentos/broker/clerk/inbox"
)

// The host's own VRB-2 world (MAIL-world-a, D-154 rule 5). With no
// MailConfig.World, the host builds each world from what the clerk reads
// itself: the day from its own clock, the provider table, authserv-id and
// security senders from the tables shipped in its binary (inbox.Shipped),
// keyed by the account as its settings are now, and the domains of its own
// PlanSenders read, which the worker runs, that the accounts table matches.
// A read's clerk judges in the world of the account it was opened for. DKIM keys are the read's own
// (MailConfig.DKIM), and LastOpened the clerk's record, as before. History,
// KnownSenders and Contacts come from the worker's senders read (senders.go,
// MAIL-world-b2): until it is through once, while it is past a bound, and
// after a step fails they are empty, so VRB-2 stops at no-history.

// sendersEvery is how often the worker reads the alert senders again,
// besides after start and each change of account. A var for tests.
var sendersEvery = 24 * time.Hour

// worldState is what the host's own world is built from. Its mu is taken
// after h.mu, never before, and the world function takes only it, so a
// world never waits on h.mu, a read or a step.
type worldState struct {
	mu      sync.Mutex
	changes int64         // h.changes as last told (reset)
	read    bool          // settings were read at changes
	set     *MailSettings // those settings; nil: no account
	domains []string      // the PlanSenders domains read for changes
	got     bool          // domains were read for changes
	writes  int           // settings writes in flight (writing)
	gen     int64         // moves at each write's start and end, so a read that spans one is not kept

	sread    sendersState     // how far the senders read is for changes
	hist     []inbox.Delivery // its History, KnownSenders and Contacts once full
	known    []string
	contacts []string

	load func(dir string) (MailSettings, error) // readMail; tests may wrap it
}

// reset follows a change of account to changes: nothing read for the
// account before stands; h.mu is held.
func (ws *worldState) reset(changes int64) {
	ws.mu.Lock()
	defer ws.mu.Unlock()
	ws.changes, ws.read, ws.set, ws.domains, ws.got = changes, false, nil, nil, false
	ws.sread, ws.hist, ws.known, ws.contacts = sendersReading, nil, nil, nil
}

// writing marks a settings write in flight until the end it returns is
// called, after the change of account (changed) or its failure: a setter
// calls it, with h.mu held, before it writes the settings file (#3538).
// Meanwhile the file may already be the next account's while h.changes is
// still the old one's, so no snapshot reads the file: one with the settings
// cached keeps them, and one without has no account (the guard is off).
// A read that began before and ends after is not kept either.
func (ws *worldState) writing() (end func()) {
	ws.mu.Lock()
	ws.writes++
	ws.gen++
	ws.mu.Unlock()
	return func() {
		ws.mu.Lock()
		ws.writes--
		ws.gen++
		ws.mu.Unlock()
	}
}

// snapshot is what the world for the account at changes at is built from,
// taken under one ws.mu, so settings and senders are of the same account:
// its settings, cached until the next change (a read that a change overtook
// is not kept, and a file that does not load is read again each time and
// gives no account meanwhile), and the domains of its last completed
// senders read (got false until one has), and the senders read's fields
// (full false until it gives them). With at < 0 it is the account as it is
// now. ok is false with no account, or once a change has overtaken at, so a
// world bound to an old account carries none of the new one's.
func (ws *worldState) snapshot(dir string, at int64) (sn snap, ok bool) {
	ws.mu.Lock()
	defer ws.mu.Unlock()
	for {
		now := ws.changes
		if at >= 0 && at != now {
			return snap{}, false
		}
		if !ws.read {
			if ws.writes > 0 {
				return snap{}, false
			}
			load, gen := ws.load, ws.gen
			if load == nil {
				load = readMail
			}
			ws.mu.Unlock()
			r, err := load(dir)
			ws.mu.Lock()
			if ws.changes != now {
				continue // a change overtook the read: not kept, nor used
			}
			if ws.gen != gen {
				return snap{}, false // a write spanned the read
			}
			if err != nil && !errors.Is(err, ErrNoMailAccount) {
				return snap{}, false
			}
			ws.read, ws.set = true, nil
			if err == nil {
				ws.set = &r
			}
		}
		if ws.set == nil {
			return snap{}, false
		}
		return snap{set: *ws.set, domains: append([]string(nil), ws.domains...), got: ws.got,
			full: ws.sread == sendersFull, hist: ws.hist, known: ws.known, contacts: ws.contacts}, true
	}
}

// snap is one snapshot's sources: the settings, the PlanSenders domains,
// and the senders read's fields, shared and never written once kept.
type snap struct {
	set      MailSettings
	domains  []string
	got      bool
	full     bool
	hist     []inbox.Delivery
	known    []string
	contacts []string
}

// keep records the domains a senders read gave for the account at changes.
func (ws *worldState) keep(changes int64, domains []string) {
	ws.mu.Lock()
	defer ws.mu.Unlock()
	if ws.changes == changes {
		ws.domains, ws.got = append([]string{}, domains...), true
	}
}

// keepSenders records a senders step's state for the account at changes,
// and its fields when full.
func (ws *worldState) keepSenders(changes int64, st sendersState, hist []inbox.Delivery, known, contacts []string) {
	ws.mu.Lock()
	defer ws.mu.Unlock()
	if ws.changes == changes {
		ws.sread, ws.hist, ws.known, ws.contacts = st, hist, known, contacts
	}
}

// sendersNow is how far the senders read is for the account as it is now.
func (ws *worldState) sendersNow() sendersState {
	ws.mu.Lock()
	defer ws.mu.Unlock()
	return ws.sread
}

// senders is the domains of the last completed senders read for the
// account as it is now; ok is false until one has completed.
func (ws *worldState) senders() (domains []string, ok bool) {
	ws.mu.Lock()
	defer ws.mu.Unlock()
	return append([]string(nil), ws.domains...), ws.got
}

// world is the host's own world for the account as it is now, for
// MailConfig.World; worldAt is the one a read binds its clerk to.
func (h *MailHost) world() inbox.World { return h.worldAt(-1) }

// worldAt is the host's own world for the account at changes at (now with
// at < 0), from one snapshot. It reads no mailbox and takes no lock but
// ws.mu. With no account, or once a change has overtaken at, it holds only
// the day, so the guard is off (guardOff): a clerk opened for the old
// account never judges with the new one's values. AlertSenders stays empty
// until the senders read has completed for the account, so after every
// start and change the guard is off until then too.
func (h *MailHost) worldAt(at int64) inbox.World {
	now := time.Now
	if h.cfg.now != nil {
		now = h.cfg.now
	}
	w := inbox.World{Today: now().UTC().Format(time.DateOnly)}
	sn, ok := h.ws.snapshot(h.dir, at)
	if !ok {
		return w
	}
	s := sn.set
	tables := inbox.Shipped
	if h.cfg.tables != nil {
		tables = h.cfg.tables
	}
	w.ProviderTable = tables.Table()
	auth, security := tables.For(s.API, imapHost(s))
	w.AuthServ = auth
	if sn.got && auth != "" {
		w.AlertSenders = append(security, sn.domains...)
	}
	if sn.full {
		w.History, w.KnownSenders, w.Contacts = sn.hist, sn.known, sn.contacts
	}
	return w
}

// held is the senders read's domains that the accounts table matches to a
// service (accounts.Table.Held): VRB-2's alert senders are those of
// accounts the owner holds, never any sender the provider passed DKIM for.
// A table that does not load gives none, so the guard stays off.
func (h *MailHost) held(domains []string) []string {
	t := h.cfg.accounts
	if t == nil {
		var err error
		if t, err = accounts.Known(); err != nil {
			return nil
		}
	}
	return t.Held(domains)
}

// imapHost is the host of an IMAP account's server, "" for an API account.
func imapHost(s MailSettings) string {
	if s.API != "" {
		return ""
	}
	host, _, err := net.SplitHostPort(s.IMAP)
	if err != nil {
		return ""
	}
	return host
}

// work is the host's one background worker, until h.ctx ends: it runs the
// senders read after start and after each change of account (a kick from
// changed or refresh, which also retries a read that failed), and again
// every sendersEvery. Beside it, it steps the senders read (readSenders):
// after each kick, so once the first read is through it reads what arrived
// at each mail read, and every sendersPause while a step leaves more to read;
// a kick while a pause runs waits for it, so steps stay that far apart. It
// pauses while a sign-in failure stops the clerk.
func (h *MailHost) work() {
	tick := time.NewTicker(sendersEvery)
	defer tick.Stop()
	var step <-chan time.Time // the pause before the next step; nil: none
	for {
		again, plan := false, true
		select {
		case <-h.ctx.Done():
			return
		case <-h.kick:
		case <-tick.C:
			again = true
		case <-step:
			plan, step = false, nil
		}
		h.mu.Lock()
		more := false
		if h.ctx.Err() == nil && h.stop == nil {
			if _, err := readMail(h.dir); err == nil {
				if plan {
					_, _ = h.planSenders(again)
				}
				if step == nil {
					more = h.readSenders()
				}
			}
		}
		h.mu.Unlock()
		if more {
			step = time.After(cmp.Or(h.cfg.pause, sendersPause))
		}
	}
}

// planSenders is the PlanSenders read for the account as it is now, run as
// the worker's step, and shared: unless again, a completed read for the
// account is answered from memory, and a step in flight is waited for, so
// setup's plan and the worker read the mailbox once between them. h.mu is
// held, and released while the mailbox is read: under h.mu the step records
// h.changes and sets h.stepping, which idle waits for, so setup, removal,
// the Gmail sign-in's finish and revocation never change the account under
// a step. Retaking h.mu, it keeps the domains only if the account is
// unchanged, and only then does a sign-in failure stop the clerk, as a
// step's does (Do). The domains come back even across a change, as the
// plan reads them, but are not kept.
func (h *MailHost) planSenders(again bool) ([]string, error) {
	for h.stepping != nil {
		h.wait()
	}
	changes := h.changes
	if d, ok := h.ws.senders(); ok && !again {
		return d, nil
	}
	if h.stop != nil {
		return nil, h.stop
	}
	s, err := readMail(h.dir)
	if err != nil {
		return nil, err
	}
	auth := h.authServ()
	done := make(chan struct{})
	h.stepping = done
	h.mu.Unlock()
	var domains []string
	box, err := boxFor(s, h.sec, h.cfg)
	if err == nil {
		read := func(ctx context.Context) ([]string, error) { return box.PlanSenders(ctx, auth) }
		if h.cfg.senders != nil {
			domains, err = h.cfg.senders(h.ctx, read)
		} else {
			domains, err = read(h.ctx)
		}
	}
	h.mu.Lock()
	h.stepping = nil
	close(done)
	if h.changes == changes {
		switch {
		case stops(err):
			// As a step refused this way (Do): nothing is sent until the
			// owner signs in again, and STATUS says so (#2708 item 2).
			why, next := trouble(err, nil)
			h.why, h.stop = "I stopped working in your mailbox: "+why+". "+next, err
		case err == nil:
			h.ws.keep(changes, h.held(domains))
		}
	}
	return domains, err
}
