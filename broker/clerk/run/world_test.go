package run

// REQ: VRB-2, D-141, D-154, DEV-2

import (
	"context"
	"errors"
	"os"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/clerk"
	"github.com/ghbmrk/agentos/broker/clerk/accounts"
	"github.com/ghbmrk/agentos/broker/clerk/inbox"
	"github.com/ghbmrk/agentos/broker/clerk/inbox/gmailtest"
	"github.com/ghbmrk/agentos/broker/clerk/inbox/imapsmtp/imaptest"
	"github.com/ghbmrk/agentos/broker/kernel"
	"github.com/ghbmrk/agentos/broker/kernel/key"
	"github.com/ghbmrk/agentos/broker/kernel/proc"
)

// testTables is a test-only provider table: the loopback server's host and
// two made-up providers. None of it is in the shipped file.
var testTables = func() *inbox.Providers {
	p, err := inbox.ParseProviders([]byte("esp mailhub.test -- test\n" +
		"authserv 127.0.0.1 mx.loopback.test -- test\nsecurity 127.0.0.1 security@loopback.test -- test\n" +
		"authserv mailhub.test mx.mailhub.test -- test\nsecurity mailhub.test security@mailhub.test -- test\n" +
		"authserv other.test mx.other.test -- test\nsecurity other.test alerts.other.test -- test\n"))
	if err != nil {
		panic(err)
	}
	return p
}()

// testAccounts is a test-only accounts table: Gmail's entry, and services
// at the made-up domains the senders gates give. spam.test is in none.
var testAccounts = func() *accounts.Table {
	t, err := accounts.Load([]byte(`[
  {"id": "payment-card", "name": "Card", "kind": "money", "group": "payment", "route": "none"},
  {"id": "payment-wallet", "name": "Wallet", "kind": "money", "group": "payment", "route": "none"},
  {"id": "mailbox", "name": "Mailbox", "kind": "mail", "group": "mailbox", "route": "none"},
  {"id": "gmail", "name": "Gmail", "kind": "mail", "group": "account", "domains": ["google.com"], "route": "oauth"},
  {"id": "bank", "name": "Bank", "kind": "money", "group": "account", "domains": ["bank.test"], "route": "none"},
  {"id": "old", "name": "Old", "kind": "mail", "group": "account", "domains": ["old.test"], "route": "none"}
]`))
	if err != nil {
		panic(err)
	}
	return t
}()

// testDay is the host's clock in these tests.
var testDay = time.Date(2026, 10, 21, 9, 0, 0, 0, time.UTC)

// ownConfig is c with the host's own world over the test tables and clock.
func ownConfig(c MailConfig) MailConfig {
	c.World, c.tables, c.accounts, c.now = nil, testTables, testAccounts, func() time.Time { return testDay }
	return c
}

// eventually fails unless ok holds within a few seconds (more under the
// race detector: raceScale).
func eventually(t *testing.T, what string, ok func() bool) {
	t.Helper()
	within := raceScale * 5 * time.Second
	for end := time.Now().Add(within); time.Now().Before(end); time.Sleep(5 * time.Millisecond) {
		if ok() {
			return
		}
	}
	t.Fatalf("%s: not within %v", what, within)
}

// gate is a senders wrap whose first read waits for open; later reads fail
// unless pass is set. It counts the reads.
type gate struct {
	started chan struct{}
	open    chan struct{}
	once    sync.Once
	reads   atomic.Int64
	domains []string
	pass    atomic.Bool
}

func newGate(domains ...string) *gate {
	return &gate{started: make(chan struct{}), open: make(chan struct{}), domains: domains}
}

func (g *gate) wrap(ctx context.Context, read func(context.Context) ([]string, error)) ([]string, error) {
	if g.reads.Add(1) == 1 {
		g.once.Do(func() { close(g.started) })
		select {
		case <-g.open:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		if g.domains != nil {
			return g.domains, nil
		}
		return read(ctx)
	}
	if g.pass.Load() {
		return read(ctx)
	}
	return nil, errors.New("test: the senders read fails")
}

// For a Gmail account (the shipped table) and an IMAP account (a test
// table), the world has the table's fields, Today from the host's clock,
// and, once the senders read has completed, its domains in AlertSenders;
// DKIMKeys and LastOpened are the read's own, not the host world's.
func TestWorldFromOwnSources(t *testing.T) {
	check := func(t *testing.T, h *MailHost, auth string, security string) {
		t.Helper()
		eventually(t, "the senders read", func() bool { return len(h.world().AlertSenders) > 0 })
		w := h.world()
		if w.Today != "2026-10-21" || w.AuthServ != auth {
			t.Fatalf("world %+v: want today 2026-10-21 and authserv %q", w, auth)
		}
		if !slices.Contains(w.AlertSenders, security) || !slices.Contains(w.AlertSenders, "accounts.google.com") {
			t.Fatalf("alert senders %q: want %q and the read's accounts.google.com", w.AlertSenders, security)
		}
		if w.DKIMKeys != nil || w.LastOpened != nil {
			t.Fatalf("world %+v carries fields the host's world does not source", w)
		}
	}
	t.Run("gmail", func(t *testing.T) {
		srv, dir, sec := newGmailAccount(t)
		srv.Deliver(googleMail("mx.google.com"))
		c := ownConfig(gmailConfig(srv))
		c.tables = nil // the shipped table
		h := NewMailHost(t.Context(), dir, sec, c)
		check(t, h, "mx.google.com", "accounts.google.com")
		if !slices.Equal(h.world().ProviderTable, inbox.Shipped.Table()) {
			t.Fatalf("provider table %q, want the shipped one", h.world().ProviderTable)
		}
	})
	t.Run("imap", func(t *testing.T) {
		srv := imaptest.Start(t)
		srv.Deliver("INBOX", imapMail(googleMail("mx.loopback.test")))
		dir := shortDir(t)
		sec, err := OpenSecrets(dir, testSealer())
		if err != nil {
			t.Fatal(err)
		}
		if err := SetMail(dir, sec, MailSettings{Address: imaptest.User, IMAP: srv.IMAP, SMTP: srv.SMTP}, imaptest.Password); err != nil {
			t.Fatal(err)
		}
		h := NewMailHost(t.Context(), dir, sec, ownConfig(mailConfig()))
		check(t, h, "mx.loopback.test", "security@loopback.test")
		if !slices.Equal(h.world().ProviderTable, []string{"mailhub.test"}) {
			t.Fatalf("provider table %q", h.world().ProviderTable)
		}
	})
}

// The world follows the account's settings as they are now: none at start,
// the IMAP provider's after setup, and after a replacement the new
// provider's values or "", never the old ones.
func TestWorldFollowsTheAccount(t *testing.T) {
	dir := shortDir(t)
	sec, err := OpenSecrets(dir, testSealer())
	if err != nil {
		t.Fatal(err)
	}
	c := ownConfig(mailConfig())
	c.plain = false // these servers are not the loopback's
	g := newGate("old.test")
	close(g.open)
	c.senders = g.wrap
	h := NewMailHost(t.Context(), dir, sec, c)
	owner := MailOwner{serveMail(t, h, MailOwnerSide)}
	if w := h.world(); w.AuthServ != "" || w.AlertSenders != nil || w.ProviderTable != nil || w.Today != "2026-10-21" {
		t.Fatalf("with no account: %+v", w)
	}
	set := func(imap string) {
		t.Helper()
		if err := owner.SetMail(MailSettings{Address: "owner@mailhub.test", IMAP: imap, SMTP: "smtp.mailhub.test:465"}, imaptest.Password); err != nil {
			t.Fatal(err)
		}
	}
	set("imap.mailhub.test:993")
	eventually(t, "the first senders read", func() bool { return slices.Contains(h.world().AlertSenders, "old.test") })
	if w := h.world(); w.AuthServ != "mx.mailhub.test" || !slices.Equal(w.AlertSenders, []string{"security@mailhub.test", "old.test"}) {
		t.Fatalf("after setup: %+v", w)
	}
	set("imap.other.test:993")
	if w := h.world(); w.AuthServ != "mx.other.test" || len(w.AlertSenders) != 0 {
		t.Fatalf("after replacing with another provider (its senders read failing): %+v", w)
	}
	set("imap.unknown.test:993")
	if w := h.world(); w.AuthServ != "" || len(w.AlertSenders) != 0 {
		t.Fatalf("after replacing with an unknown provider: %+v", w)
	}
	if err := owner.RemoveMail(); err != nil {
		t.Fatal(err)
	}
	if w := h.world(); w.AuthServ != "" || w.ProviderTable != nil {
		t.Fatalf("after removal: %+v", w)
	}
}

// guardRig is a host over a loopback account whose reader calls every mail
// spam, served to a kernel that may trash.
type guardRig struct {
	h  *MailHost
	b  *box
	id string // the spam mail's clerk id
}

func newGuardRig(t *testing.T, g *gate) *guardRig {
	t.Helper()
	srv := imaptest.Start(t)
	srv.Deliver("INBOX", mailFrom("deals@spam.test", "<s1@spam.test>"))
	dir := shortDir(t)
	sec, err := OpenSecrets(dir, testSealer())
	if err != nil {
		t.Fatal(err)
	}
	if err := SetMail(dir, sec, MailSettings{Address: imaptest.User, IMAP: srv.IMAP, SMTP: srv.SMTP}, imaptest.Password); err != nil {
		t.Fatal(err)
	}
	c := ownConfig(mailConfig())
	c.Ask = func(context.Context, string) (string, error) { return "spam", nil }
	c.senders = g.wrap
	h := NewMailHost(t.Context(), dir, sec, c)
	ls, err := h.listing(false)
	if err != nil || len(ls) != 1 {
		t.Fatalf("the listing: %v, %v", ls, err)
	}
	r := &guardRig{h: h, id: ls[0].Mail}
	sock := shortDir(t) + "/mail.sock"
	ln, err := proc.ListenClerk(sock, os.Getuid())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go proc.ServeClerk(ln, h, anchors)
	r.b = newBoxFor(t, sock, inbox.Name, key.Trash)
	return r
}

// trash runs a trash step on the spam mail and returns its state.
func (r *guardRig) trash() kernel.StepState {
	id := r.b.submitStep(kernel.PlanStep{Verb: key.Trash, Clerk: inbox.Name, Args: map[string]string{"target": r.id}})
	r.b.tick(r.b.now)
	return r.b.step(id)
}

// After a start, until the senders read completes, AlertSenders is empty and
// a spam mail is not trashed (no-alert-guard); after it, the mail is. A
// failing read keeps the guard off.
func TestGuardStaysOffUntilTheSendersRead(t *testing.T) {
	g := newGate("bank.test")
	r := newGuardRig(t, g)
	<-g.started
	if w := r.h.world(); len(w.AlertSenders) != 0 {
		t.Fatalf("alert senders %q before the read completed", w.AlertSenders)
	}
	if st := r.trash(); st.Phase == kernel.PDone || st.Detail != "no-alert-guard" {
		t.Fatalf("trash before the senders read: %s %q, want no-alert-guard", st.Phase, st.Detail)
	}
	close(g.open)
	eventually(t, "the senders read", func() bool { return len(r.h.world().AlertSenders) > 0 })
	if st := r.trash(); st.Phase != kernel.PDone {
		t.Fatalf("trash after the senders read: %s %q", st.Phase, st.Detail)
	}

	failing := newGate()
	failing.reads.Store(1) // every read fails
	r = newGuardRig(t, failing)
	eventually(t, "a failed senders read", func() bool { return failing.reads.Load() > 1 })
	r.h.listing(true) // a refresh retries the read, which fails again
	if st := r.trash(); st.Phase == kernel.PDone || st.Detail != "no-alert-guard" {
		t.Fatalf("trash after a failed senders read: %s %q, want no-alert-guard", st.Phase, st.Detail)
	}
}

// Each change of account that runs during a slow worker step waits for the
// step, the step's result is not kept for the changed account, and the
// account stays as changed; status answers while the step runs. Cancelling
// the host's context ends the worker.
func TestTheWorkerStopsForRemoval(t *testing.T) {
	for _, c := range []struct {
		name   string
		change func(t *testing.T, srv *gmailtest.Server, owner MailOwner) func() error
		set    bool // an account is set up after the change
	}{
		{"setmail", func(t *testing.T, _ *gmailtest.Server, owner MailOwner) func() error {
			return func() error {
				return owner.SetMail(MailSettings{Address: "owner@mailhub.test", IMAP: "imap.mailhub.test:993", SMTP: "smtp.mailhub.test:465"}, imaptest.Password)
			}
		}, true},
		{"removemail", func(*testing.T, *gmailtest.Server, MailOwner) func() error { return nil }, false},
		{"gmail sign-in finish", func(t *testing.T, srv *gmailtest.Server, owner MailOwner) func() error {
			consent, d, err := owner.GmailBegin("watch", fakeClient)
			if err != nil || d != "" {
				t.Fatalf("GmailBegin = %q, %v", d, err)
			}
			landing, ok := srv.Approve(consent)
			if !ok {
				t.Fatal("the fake refused the consent address")
			}
			return func() error {
				d, err := owner.GmailFinish("watch", landing)
				if err == nil && d != clerk.DSignedIn+" watch" {
					err = errors.New("GmailFinish = " + d)
				}
				return err
			}
		}, true},
		{"gmail revoke", func(*testing.T, *gmailtest.Server, MailOwner) func() error { return nil }, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			srv, dir, sec := newGmailAccount(t)
			cfg := ownConfig(signInConfig(srv))
			g := newGate("old.test")
			cfg.senders = g.wrap
			h := NewMailHost(t.Context(), dir, sec, cfg)
			owner := MailOwner{serveMail(t, h, MailOwnerSide)}
			change := c.change(t, srv, owner)
			switch c.name {
			case "removemail":
				change = owner.RemoveMail
			case "gmail revoke":
				change = func() error {
					d, err := owner.GmailRevoke()
					if err == nil && d != clerk.DRevoked {
						err = errors.New("GmailRevoke = " + d)
					}
					return err
				}
			}
			<-g.started
			done := make(chan error, 1)
			go func() { done <- change() }()
			select {
			case err := <-done:
				t.Fatalf("the change did not wait for the step: %v", err)
			case <-time.After(150 * time.Millisecond):
			}
			if _, err := owner.Status(); err != nil {
				t.Fatalf("status during a step: %v", err)
			}
			close(g.open)
			if err := <-done; err != nil {
				t.Fatal(err)
			}
			if slices.Contains(h.world().AlertSenders, "old.test") {
				t.Fatalf("the step's result was kept across the change: %q", h.world().AlertSenders)
			}
			if a, err := owner.Account(); err != nil || a.Set != c.set {
				t.Fatalf("account after the change: %+v, %v; want set %v", a, err, c.set)
			}
		})
	}
	t.Run("the worker ends with the host", func(t *testing.T) {
		dir := shortDir(t)
		sec, err := OpenSecrets(dir, testSealer())
		if err != nil {
			t.Fatal(err)
		}
		runtime.GC()
		n := runtime.NumGoroutine()
		ctx, cancel := context.WithCancel(context.Background())
		NewMailHost(ctx, dir, sec, ownConfig(mailConfig()))
		if runtime.NumGoroutine() <= n {
			t.Fatal("no worker started")
		}
		cancel()
		eventually(t, "the worker's end", func() bool { return runtime.NumGoroutine() <= n })
	})
}

// accountplan and a read run at once, under -race, with no deadlock, and
// the plan and the worker read the senders once between them.
func TestWorldDoesNotWaitOnThePlan(t *testing.T) {
	srv, dir, sec := newGmailAccount(t)
	srv.Deliver(googleMail("mx.google.com"))
	cfg := ownConfig(gmailConfig(srv))
	cfg.tables = nil
	g := newGate()
	cfg.senders = g.wrap
	h := NewMailHost(t.Context(), dir, sec, cfg)
	owner := MailOwner{serveMail(t, h, MailOwnerSide)}
	planner := MailPlanner{serveMail(t, h, MailPlannerSide)}
	<-g.started
	plan := make(chan AccountPlanned, 1)
	go func() {
		p, err := owner.AccountPlan()
		if err != nil {
			t.Error(err)
		}
		plan <- p
	}()
	if ls, err := planner.Reread(); err != nil || len(ls) != 1 {
		t.Fatalf("a read while the senders read runs: %v, %v", ls, err)
	}
	close(g.open)
	select {
	case p := <-plan:
		if !slices.Contains(planIDs(p), "gmail") {
			t.Fatalf("plan %v lacks the read's Gmail entry", planIDs(p))
		}
	case <-time.After(10 * time.Second):
		t.Fatal("accountplan did not finish")
	}
	if n := g.reads.Load(); n != 1 {
		t.Fatalf("%d senders reads; want one shared by the plan and the worker", n)
	}
	eventually(t, "the world's alert senders", func() bool { return slices.Contains(h.world().AlertSenders, "accounts.google.com") })
}

// A sender the provider passed DKIM for is an alert sender only when the
// accounts table matches it to a service: with the shipped tables, a
// spammer's domains in the senders read stay out of AlertSenders while
// Google's sign-in sender is kept (Security 6455968499 point 1; probe
// builds/2026-10-27-pr3523-security-probes_test.go).
func TestAlertSendersOnlyFromTheAccountsTable(t *testing.T) {
	srv, dir, sec := newGmailAccount(t)
	srv.Deliver(googleMail("mx.google.com"))
	c := ownConfig(gmailConfig(srv))
	c.tables, c.accounts = nil, nil // the shipped tables
	g := newGate("spam.test", "accounts.google.com", "mail.spam.test", "google.com.spam.test")
	close(g.open)
	c.senders = g.wrap
	h := NewMailHost(t.Context(), dir, sec, c)
	eventually(t, "the senders read", func() bool { return slices.Contains(h.world().AlertSenders, "accounts.google.com") })
	for _, d := range h.world().AlertSenders {
		if strings.Contains(d, "spam.test") {
			t.Fatalf("alert senders %q keep a sender outside the accounts table", h.world().AlertSenders)
		}
	}
}

// A read's clerk judges in the world of the account it was opened for:
// once a change of account overtakes it, its world holds only the day, so
// the guard is off and none of the new account's values reach it, while
// the host's world is the new account's (L3 6455930789 point 1).
func TestTheClerkJudgesInItsOwnAccountsWorld(t *testing.T) {
	srv := imaptest.Start(t)
	srv.Deliver("INBOX", mailFrom("deals@spam.test", "<s1@spam.test>"))
	dir := shortDir(t)
	sec, err := OpenSecrets(dir, testSealer())
	if err != nil {
		t.Fatal(err)
	}
	if err := SetMail(dir, sec, MailSettings{Address: imaptest.User, IMAP: srv.IMAP, SMTP: srv.SMTP}, imaptest.Password); err != nil {
		t.Fatal(err)
	}
	c := ownConfig(mailConfig())
	g := newGate("bank.test", "spam.test")
	close(g.open)
	c.senders = g.wrap
	h := NewMailHost(t.Context(), dir, sec, c)
	owner := MailOwner{serveMail(t, h, MailOwnerSide)}
	h.mu.Lock()
	m := h.cur
	h.mu.Unlock()
	if m == nil {
		t.Fatal("no clerk opened")
	}
	eventually(t, "the senders read", func() bool { return len(m.world().AlertSenders) > 0 })
	if w := m.world(); w.AuthServ != "mx.loopback.test" || !slices.Equal(w.AlertSenders, []string{"security@loopback.test", "bank.test"}) {
		t.Fatalf("the clerk's world before the change: %+v", w)
	}
	if err := owner.SetMail(MailSettings{Address: "owner@mailhub.test", IMAP: "imap.mailhub.test:993", SMTP: "smtp.mailhub.test:465"}, imaptest.Password); err != nil {
		t.Fatal(err)
	}
	if w := m.world(); w.Today != "2026-10-21" || w.AuthServ != "" || w.AlertSenders != nil || w.ProviderTable != nil {
		t.Fatalf("the old clerk's world after the change: %+v", w)
	}
	if w := h.world(); w.AuthServ != "mx.mailhub.test" {
		t.Fatalf("the host's world after the change: %+v", w)
	}
}

// worldRig is a host with its own world over an IMAP account at a made-up
// provider, its senders read answered by a gate, and the owner's socket,
// returned once the worker's start-up step has ended.
func worldRig(t *testing.T, edit func(*MailConfig)) (*MailHost, MailOwner, string) {
	t.Helper()
	dir := shortDir(t)
	sec, err := OpenSecrets(dir, testSealer())
	if err != nil {
		t.Fatal(err)
	}
	if err := SetMail(dir, sec, mailhub("imap.mailhub.test:993"), imaptest.Password); err != nil {
		t.Fatal(err)
	}
	c := ownConfig(mailConfig())
	c.plain = false
	g := newGate("old.test")
	close(g.open)
	c.senders = g.wrap
	if edit != nil {
		edit(&c)
	}
	h := NewMailHost(t.Context(), dir, sec, c)
	// The worker's start-up step reads the world (planSenders' authServ),
	// which caches the settings: it settles before a test resets them.
	eventually(t, "the start-up senders read", func() bool { _, ok := h.ws.senders(); return ok })
	h.mu.Lock()
	h.idle()
	h.mu.Unlock()
	return h, MailOwner{serveMail(t, h, MailOwnerSide)}, dir
}

func mailhub(imap string) MailSettings {
	return MailSettings{Address: "owner@mailhub.test", IMAP: imap, SMTP: "smtp.mailhub.test:465"}
}

// A settings read that a change of account overtook is neither kept nor
// returned for the old count (#3538 item 1): the read waits while the file
// is rewritten and the change is counted, with no setter's write window
// around it, so only the overtaken-read check stands between the old
// account's clerk and the new account's settings.
func TestAnOvertakenSettingsReadIsNotKept(t *testing.T) {
	h, _, dir := worldRig(t, nil)
	started, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	h.mu.Lock()
	at := h.changes
	h.ws.reset(at) // nothing cached: the next world reads the file
	h.mu.Unlock()
	h.ws.mu.Lock()
	h.ws.load = func(dir string) (MailSettings, error) {
		once.Do(func() { close(started); <-release })
		return readMail(dir)
	}
	h.ws.mu.Unlock()
	got := make(chan inbox.World)
	go func() { got <- h.worldAt(at) }()
	<-started
	if err := SetMail(dir, h.sec, mailhub("imap.other.test:993"), imaptest.Password); err != nil {
		t.Fatal(err)
	}
	h.mu.Lock()
	h.changed()
	h.mu.Unlock()
	close(release)
	if w := <-got; w.AuthServ != "" {
		t.Fatalf("the old count's world after an overtaken read: authserv %q, want none", w.AuthServ)
	}
	// The worker, kicked by the change, may cache the settings itself, read
	// under the new count: whatever is cached is the new account's.
	h.ws.mu.Lock()
	cached := h.ws.read && h.ws.set != nil && h.ws.set.IMAP != "imap.other.test:993"
	h.ws.mu.Unlock()
	if cached {
		t.Fatal("the overtaken read was kept")
	}
	if w := h.world(); w.AuthServ != "mx.other.test" {
		t.Fatalf("the world now: authserv %q", w.AuthServ)
	}
}

// The senders record's plaintext, which names who writes to the owner and
// to whom the owner writes, is wiped once saveSenders has sealed it and
// once loadSenders has decoded it (#5325, senders.go's two clears).
func TestTheSendersRecordsPlaintextIsWiped(t *testing.T) {
	dir := shortDir(t)
	k := &gmailtest.Kept{Sealer: testSealer()}
	rec := sealedSenders{Rec: inbox.SendersRecord{Senders: map[string]int64{"a@one.test": 1}, Sent: map[string]bool{"b@two.test": true}}}
	if err := saveSenders(dir, k, "slot", rec, nil); err != nil {
		t.Fatal(err)
	}
	if n, wiped := k.Wiped(); n != 1 || !wiped {
		t.Fatalf("saveSenders left %d plaintexts, wiped %v", n, wiped)
	}
	if got := loadSenders(dir, k, "slot"); got.Rec.Senders["a@one.test"] != 1 || !got.Rec.Sent["b@two.test"] {
		t.Fatalf("loadSenders = %+v", got)
	}
	if n, wiped := k.Wiped(); n != 2 || !wiped {
		t.Fatalf("loadSenders left %d plaintexts, wiped %v", n, wiped)
	}
}

// A sealer that fails after it decrypted loads no senders record:
// loadSenders trusts no plaintext handed back with an error and wipes it
// (#5325, #5740, senders.go's Open check).
func TestAFailedOpenLoadsNoSendersRecord(t *testing.T) {
	dir := shortDir(t)
	rec := sealedSenders{Rec: inbox.SendersRecord{Senders: map[string]int64{"a@one.test": 1}}}
	if err := saveSenders(dir, testSealer(), "slot", rec, nil); err != nil {
		t.Fatal(err)
	}
	k := &gmailtest.Kept{Sealer: testSealer(), OpenErr: os.ErrClosed} // any error
	if got := loadSenders(dir, k, "slot"); got.Over || got.Rec.Senders != nil {
		t.Fatalf("loadSenders with a failing open = %+v; want an empty record", got)
	}
	if n, wiped := k.Wiped(); n != 1 || !wiped {
		t.Fatalf("a failed open left %d plaintexts, wiped %v", n, wiped)
	}
}

// A seal that fails saves no senders record: saveSenders returns the
// sealer's error, wipes the plaintext, and the record before it still
// loads (#5325, senders.go's Seal check).
func TestAFailedSealSavesNoSendersRecord(t *testing.T) {
	dir := shortDir(t)
	rec := sealedSenders{Rec: inbox.SendersRecord{Senders: map[string]int64{"a@one.test": 1}}}
	if err := saveSenders(dir, testSealer(), "slot", rec, nil); err != nil {
		t.Fatal(err)
	}
	k := &gmailtest.Kept{Sealer: testSealer(), SealErr: os.ErrClosed} // any error
	next := sealedSenders{Rec: inbox.SendersRecord{Senders: map[string]int64{"b@two.test": 2}}}
	if err := saveSenders(dir, k, "slot", next, nil); err != os.ErrClosed {
		t.Fatalf("saveSenders with a failing sealer = %v; want %v", err, os.ErrClosed)
	}
	if n, wiped := k.Wiped(); n != 1 || !wiped {
		t.Fatalf("a failed seal left %d plaintexts, wiped %v", n, wiped)
	}
	if got := loadSenders(dir, testSealer(), "slot"); got.Rec.Senders["a@one.test"] != 1 || len(got.Rec.Senders) != 1 {
		t.Fatalf("after a failed seal the record is %+v; want the one before", got)
	}
}

// A snapshot reads the settings once per account and keeps them; a file
// that does not load is not kept and is read again at the next snapshot;
// no account is kept as none; and a read that a settings write spanned is
// not kept (#5325, world.go's snapshot).
func TestASnapshotKeepsOnlyAWholeSettingsRead(t *testing.T) {
	var ws worldState
	var loads int
	answer := func() (MailSettings, error) { return MailSettings{Address: "owner@one.test"}, nil }
	ws.load = func(string) (MailSettings, error) {
		loads++
		return answer()
	}
	for i := range 3 {
		if sn, ok := ws.snapshot("dir", -1); !ok || sn.set.Address != "owner@one.test" {
			t.Fatalf("snapshot %d: %+v, %v", i, sn, ok)
		}
	}
	if loads != 1 {
		t.Fatalf("three snapshots read the settings %d times; want once", loads)
	}

	ws.reset(1)
	loads = 0
	answer = func() (MailSettings, error) { return MailSettings{}, errors.New("a damaged settings file") }
	if _, ok := ws.snapshot("dir", -1); ok {
		t.Fatal("a snapshot with settings that do not load has an account")
	}
	answer = func() (MailSettings, error) { return MailSettings{Address: "owner@two.test"}, nil }
	if sn, ok := ws.snapshot("dir", -1); !ok || sn.set.Address != "owner@two.test" || loads != 2 {
		t.Fatalf("after a failed read: %+v, %v, %d reads; want the settings read again", sn, ok, loads)
	}

	ws.reset(2)
	loads = 0
	answer = func() (MailSettings, error) { return MailSettings{}, ErrNoMailAccount }
	for range 2 {
		if _, ok := ws.snapshot("dir", -1); ok {
			t.Fatal("a snapshot with no account has one")
		}
	}
	if loads != 1 {
		t.Fatalf("no account was read %d times; want once, then kept", loads)
	}

	ws.reset(3)
	loads = 0
	answer = func() (MailSettings, error) {
		end := ws.writing() // a setter's write begins and ends during the read
		end()
		return MailSettings{Address: "owner@three.test"}, nil
	}
	if _, ok := ws.snapshot("dir", -1); ok {
		t.Fatal("a read that a write spanned gave an account")
	}
	answer = func() (MailSettings, error) { return MailSettings{Address: "owner@four.test"}, nil }
	if sn, ok := ws.snapshot("dir", -1); !ok || sn.set.Address != "owner@four.test" || loads != 2 {
		t.Fatalf("after a spanned read: %+v, %v, %d reads; want the settings read again", sn, ok, loads)
	}
}

// With no accounts table in its config, the host matches the senders
// read's domains against the shipped one (#5325, world.go's held).
func TestHeldFallsBackToTheShippedTable(t *testing.T) {
	h := &MailHost{}
	if got := h.held([]string{"spam.test", "accounts.google.com"}); !slices.Equal(got, []string{"accounts.google.com"}) {
		t.Fatalf("held with the shipped table = %q; want only accounts.google.com", got)
	}
}

// imapHost is the IMAP server's host, and none for an API account even
// with an IMAP server named (#5325, world.go's imapHost).
func TestImapHostIsNoneForAnAPIAccount(t *testing.T) {
	for _, c := range []struct {
		s    MailSettings
		want string
	}{
		{MailSettings{IMAP: "imap.one.test:993"}, "imap.one.test"},
		{MailSettings{API: "gmail", IMAP: "imap.one.test:993"}, ""},
		{MailSettings{IMAP: "imap.one.test"}, ""},
	} {
		if got := imapHost(c.s); got != c.want {
			t.Errorf("imapHost(%+v) = %q; want %q", c.s, got, c.want)
		}
	}
}

// A senders step waits for the step in flight before it reads (#5325,
// senders.go's wait for h.stepping): while another step is marked in
// flight, it reads nothing and tells nothing, and once that one ends it
// runs.
func TestASendersStepWaitsForTheStepInFlight(t *testing.T) {
	srv := imaptest.Start(t)
	srv.DeliverAt("INBOX", time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC), mailFrom("a@one.test", "<a1@one.test>"))
	dir := shortDir(t)
	sec, err := OpenSecrets(dir, testSealer())
	if err != nil {
		t.Fatal(err)
	}
	if err := SetMail(dir, sec, MailSettings{Address: imaptest.User, IMAP: srv.IMAP, SMTP: srv.SMTP}, imaptest.Password); err != nil {
		t.Fatal(err)
	}
	var steps atomic.Int32
	c := mailConfig() // World set: no worker, the test runs the step
	c.stepped = func(bool, bool) { steps.Add(1) }
	h := &MailHost{ctx: t.Context(), dir: dir, sec: sec, cfg: c, kick: make(chan struct{}, 1)}
	other := make(chan struct{})
	h.mu.Lock()
	h.stepping = other
	h.mu.Unlock()
	done := make(chan bool)
	go func() {
		h.mu.Lock()
		defer h.mu.Unlock()
		done <- h.readSenders()
	}()
	eventually(t, "the step waiting for the one in flight", func() bool {
		select {
		case <-done:
			t.Fatal("the step ran while another was in flight")
		default:
		}
		return gmailtest.Waiting("(*MailHost).wait", "chan receive")
	})
	if n := steps.Load(); n != 0 || len(srv.Logins()) != 0 {
		t.Fatalf("while another step was in flight: %d steps told, logins %v", n, srv.Logins())
	}
	h.mu.Lock()
	h.stepping = nil
	close(other)
	h.mu.Unlock()
	<-done
	if n := steps.Load(); n != 1 || len(srv.Logins()) == 0 {
		t.Fatalf("after the other step ended: %d steps told, logins %v; want it run", n, srv.Logins())
	}
}

// The PlanSenders read reads no mailbox while a sign-in failure stops the
// clerk, giving the stop, nor with no account, giving that (#5325,
// world.go's planSenders).
func TestThePlanSendersReadNeedsAnAccountAndNoStop(t *testing.T) {
	srv := imaptest.Start(t)
	dir := shortDir(t)
	sec, err := OpenSecrets(dir, testSealer())
	if err != nil {
		t.Fatal(err)
	}
	c := mailConfig() // World set: no worker, the test runs the read
	h := &MailHost{ctx: t.Context(), dir: dir, sec: sec, cfg: c, kick: make(chan struct{}, 1)}
	plan := func() ([]string, error) {
		h.mu.Lock()
		defer h.mu.Unlock()
		return h.planSenders(true)
	}
	if d, err := plan(); !errors.Is(err, ErrNoMailAccount) || d != nil {
		t.Fatalf("with no account: %q, %v; want %v", d, err, ErrNoMailAccount)
	}
	if err := SetMail(dir, sec, MailSettings{Address: imaptest.User, IMAP: srv.IMAP, SMTP: srv.SMTP}, imaptest.Password); err != nil {
		t.Fatal(err)
	}
	stop := errors.New("synthetic: stopped until setup")
	h.stop = stop
	if d, err := plan(); err != stop || d != nil || len(srv.Logins()) != 0 {
		t.Fatalf("while stopped: %q, %v, logins %v; want the stop and no read", d, err, srv.Logins())
	}
	h.stop = nil
	if _, err := plan(); err != nil || len(srv.Logins()) == 0 {
		t.Fatalf("with the stop cleared: %v, logins %v; want a read", err, srv.Logins())
	}
}

// A host with no world of its config's has no authserv-id to match its
// senders read against, rather than calling a world it does not have
// (#5325; accountplan.go's authServ, a line #5326 lists, reached by the
// senders step's tests).
func TestAHostWithoutAWorldHasNoAuthServ(t *testing.T) {
	if got := (&MailHost{}).authServ(); got != "" {
		t.Fatalf("authServ with no world = %q; want none", got)
	}
	h := &MailHost{cfg: MailConfig{World: func() inbox.World { return inbox.World{AuthServ: "mx.one.test"} }}}
	if got := h.authServ(); got != "mx.one.test" {
		t.Fatalf("authServ = %q; want the world's", got)
	}
}

// Each setter writes the settings inside its change (#3538 item 2): a world
// for the old count, built between the write and the change being counted
// with no settings cached, has no account, never the new one's.
func TestASettingsWriteIsInsideTheChange(t *testing.T) {
	for _, c := range []struct {
		name   string
		change func(MailOwner) error
	}{
		{"setmail", func(o MailOwner) error { return o.SetMail(mailhub("imap.other.test:993"), imaptest.Password) }},
		{"removemail", func(o MailOwner) error { return o.RemoveMail() }},
		{"gmail sign-in finish", nil},
	} {
		t.Run(c.name, func(t *testing.T) {
			var h *MailHost
			var at int64
			var mid atomic.Value
			srv := gmailtest.New()
			t.Cleanup(srv.Close)
			h, owner, _ := worldRig(t, func(cfg *MailConfig) {
				cfg.wrote = func() { mid.Store(h.worldAt(at)) }
				g := signInConfig(srv)
				cfg.gmail, cfg.Guard, cfg.TLS = g.gmail, g.Guard, g.TLS
			})
			if c.change == nil {
				c.change = func(o MailOwner) error {
					if d := signIn(t, srv, o, "watch", fakeClient); d != clerk.DSignedIn+" watch" {
						return errors.New("GmailFinish = " + d)
					}
					return nil
				}
			}
			h.mu.Lock()
			at = h.changes
			h.ws.reset(at)
			h.mu.Unlock()
			if err := c.change(owner); err != nil {
				t.Fatal(err)
			}
			w, ok := mid.Load().(inbox.World)
			if !ok {
				t.Fatal("the setter did not write")
			}
			if w.AuthServ != "" || w.ProviderTable != nil {
				t.Fatalf("the old count's world between the write and the change: %+v", w)
			}
		})
	}
}
