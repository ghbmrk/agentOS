package run

import (
	"context"
	"errors"
	"net"
	"sync"
	"time"

	"github.com/ghbmrk/agentos/broker/clerk/inbox"
)

// The host's own VRB-2 world (MAIL-world-a, D-154 rule 5). With no
// MailConfig.World, the host builds each world from what the clerk reads
// itself: the day from its own clock, the provider table, authserv-id and
// security senders from the tables shipped in its binary (inbox.Shipped),
// keyed by the account as its settings are now, and the domains of its own
// PlanSenders read, which the worker runs. DKIM keys are the read's own
// (MailConfig.DKIM), and LastOpened the clerk's record, as before. History,
// KnownSenders and Contacts are slice b2's; until then they are empty, so
// VRB-2 stops at no-history.

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
}

// reset follows a change of account to changes: nothing read for the
// account before stands; h.mu is held.
func (ws *worldState) reset(changes int64) {
	ws.mu.Lock()
	defer ws.mu.Unlock()
	ws.changes, ws.read, ws.set, ws.domains, ws.got = changes, false, nil, nil, false
}

// settings is the account's settings as they are now, cached until the
// next change: a read that a change overtook is not kept. A file that does
// not load is read again each time, and gives no account meanwhile.
func (ws *worldState) settings(dir string) (MailSettings, bool) {
	ws.mu.Lock()
	if ws.read {
		s := ws.set
		ws.mu.Unlock()
		if s == nil {
			return MailSettings{}, false
		}
		return *s, true
	}
	at := ws.changes
	ws.mu.Unlock()
	s, err := readMail(dir)
	ws.mu.Lock()
	defer ws.mu.Unlock()
	if ws.changes == at && (err == nil || errors.Is(err, ErrNoMailAccount)) {
		ws.read, ws.set = true, nil
		if err == nil {
			ws.set = &s
		}
	}
	return s, err == nil
}

// keep records the domains a senders read gave for the account at changes.
func (ws *worldState) keep(changes int64, domains []string) {
	ws.mu.Lock()
	defer ws.mu.Unlock()
	if ws.changes == changes {
		ws.domains, ws.got = append([]string{}, domains...), true
	}
}

// senders is the domains of the last completed senders read for the
// account as it is now; ok is false until one has completed.
func (ws *worldState) senders() (domains []string, ok bool) {
	ws.mu.Lock()
	defer ws.mu.Unlock()
	return append([]string(nil), ws.domains...), ws.got
}

// world is the host's own world, for MailConfig.World. It reads no mailbox
// and takes no lock but ws.mu. With no account it holds only the day.
// AlertSenders stays empty until the senders read has completed for the
// account as it is now, so after every start and change the guard is off
// (guardOff) until then.
func (h *MailHost) world() inbox.World {
	now := time.Now
	if h.cfg.now != nil {
		now = h.cfg.now
	}
	w := inbox.World{Today: now().UTC().Format(time.DateOnly)}
	s, ok := h.ws.settings(h.dir)
	if !ok {
		return w
	}
	tables := inbox.Shipped
	if h.cfg.tables != nil {
		tables = h.cfg.tables
	}
	w.ProviderTable = tables.Table()
	auth, security := tables.For(s.API, imapHost(s))
	w.AuthServ = auth
	if d, ok := h.ws.senders(); ok && auth != "" {
		w.AlertSenders = append(security, d...)
	}
	return w
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
// every sendersEvery. It pauses while a sign-in failure stops the clerk.
func (h *MailHost) work() {
	tick := time.NewTicker(sendersEvery)
	defer tick.Stop()
	for {
		again := false
		select {
		case <-h.ctx.Done():
			return
		case <-h.kick:
		case <-tick.C:
			again = true
		}
		h.mu.Lock()
		if h.ctx.Err() == nil && h.stop == nil {
			if _, err := readMail(h.dir); err == nil {
				_, _ = h.planSenders(again)
			}
		}
		h.mu.Unlock()
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
			h.ws.keep(changes, domains)
		}
	}
	return domains, err
}
