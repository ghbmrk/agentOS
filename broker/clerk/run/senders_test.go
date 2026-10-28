package run

// REQ: VRB-2, D-141, D-154

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/emersion/go-imap"

	"github.com/ghbmrk/agentos/broker/clerk"
	"github.com/ghbmrk/agentos/broker/clerk/inbox"
	"github.com/ghbmrk/agentos/broker/clerk/inbox/imapsmtp/imaptest"
	"github.com/ghbmrk/agentos/broker/kernel/privfile"
)

// sendersRig is a host with its own world over a loopback account, each
// step of its senders read counted.
type sendersRig struct {
	h     *MailHost
	dir   string
	sec   *clerk.Secrets
	cfg   MailConfig
	steps atomic.Int64
	more  atomic.Bool // the last step's answer
	whole atomic.Bool // whether the last step left the world with history
}

// newSendersRig sets up srv's account in a fresh directory and opens a host
// over it; edit, if given, changes the config first.
func newSendersRig(t *testing.T, srv *imaptest.Server, edit func(*MailConfig)) *sendersRig {
	t.Helper()
	dir := shortDir(t)
	sec, err := OpenSecrets(dir, testSealer())
	if err != nil {
		t.Fatal(err)
	}
	if err := SetMail(dir, sec, MailSettings{Address: imaptest.User, IMAP: srv.IMAP, SMTP: srv.SMTP}, imaptest.Password); err != nil {
		t.Fatal(err)
	}
	r := &sendersRig{dir: dir, sec: sec}
	r.cfg = ownConfig(mailConfig())
	r.cfg.pause = time.Millisecond
	if edit != nil {
		edit(&r.cfg)
	}
	r.open(t)
	return r
}

// open opens a host over the rig's directory, until ctx ends.
func (r *sendersRig) open(t *testing.T) {
	r.openCtx(t, t.Context())
}

func (r *sendersRig) openCtx(t *testing.T, ctx context.Context) {
	c := r.cfg
	c.stepped = func(more, full bool) {
		if r.cfg.stepped != nil {
			r.cfg.stepped(more, full)
		}
		r.more.Store(more)
		r.whole.Store(full)
		r.steps.Add(1)
	}
	r.h = NewMailHost(ctx, r.dir, r.sec, c)
}

// full waits until the world gives history.
func (r *sendersRig) full(t *testing.T) inbox.World {
	t.Helper()
	eventually(t, "the senders read through", func() bool { return r.h.world().History != nil })
	return r.h.world()
}

// blank fails unless the world has none of the three fields.
func blank(t *testing.T, what string, w inbox.World) {
	t.Helper()
	if w.History != nil || w.KnownSenders != nil || w.Contacts != nil {
		t.Fatalf("%s: history %v, known %v, contacts %v; want none", what, w.History, w.KnownSenders, w.Contacts)
	}
}

func day(n int) time.Time { return time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC).AddDate(0, 0, n) }

// Only the Inbox and Archive roles are history, each sender at its earliest
// arrival. Junk, the All folder (which also shows junk), an unflagged Spam
// folder, Trash and a folder the owner made never are.
func TestHistoryFromTheMailbox(t *testing.T) {
	srv := imaptest.Start(t)
	srv.AddFolder("All Mail", imap.AllAttr)
	srv.AddFolder("Spam", "")
	srv.AddFolder("Projects", "")
	srv.DeliverAt("INBOX", day(5), mailFrom("Ann <ann@inbox.test>", "<a2@inbox.test>"))
	srv.DeliverAt("INBOX", day(0), mailFrom("ANN@Inbox.test", "<a1@inbox.test>"))
	srv.DeliverAt("Archive", day(1), mailFrom("bo@archive.test", "<b1@archive.test>"))
	srv.DeliverAt("Archive", day(-1), mailFrom("ann@inbox.test", "<a0@inbox.test>"), `\Seen`)
	srv.DeliverAt("Junk", day(2), mailFrom("cy@junk.test", "<c1@junk.test>"))
	srv.DeliverAt("All Mail", day(2), mailFrom("cy@junk.test", "<c1@junk.test>"))
	srv.DeliverAt("All Mail", day(3), mailFrom("di@all.test", "<d1@all.test>"))
	srv.DeliverAt("Spam", day(3), mailFrom("ed@spam.test", "<e1@spam.test>"))
	srv.DeliverAt("Trash", day(3), mailFrom("fi@trash.test", "<f1@trash.test>"))
	srv.DeliverAt("Projects", day(3), mailFrom("gu@projects.test", "<g1@projects.test>"))
	srv.DeliverAt("Drafts", day(3), mailFrom("ha@drafts.test", "<h1@drafts.test>"))
	srv.DeliverAt("Sent", day(3), mailFrom(imaptest.User, "<s1@loopback.test>"))
	srv.DeliverAt("INBOX", day(3), "From: x@two.test\n"+mailFrom("y@two.test", "<t1@two.test>")) // two From fields
	w := newSendersRig(t, srv, nil).full(t)
	want := []inbox.Delivery{{From: "ann@inbox.test", Folder: "inbox", Date: "2026-05-31"}, {From: "bo@archive.test", Folder: "inbox", Date: "2026-06-02"}}
	if !slices.Equal(w.History, want) {
		t.Fatalf("history %v, want %v", w.History, want)
	}
	if !slices.Equal(w.KnownSenders, []string{"ann@inbox.test", "bo@archive.test"}) {
		t.Fatalf("known senders %v", w.KnownSenders)
	}
}

// The To and Cc of sent mail are Contacts, and a sender whose domain looks
// like a contact's gives lookalike.
func TestContactsAreSentRecipients(t *testing.T) {
	srv := imaptest.Start(t)
	srv.DeliverAt("INBOX", day(0), mailFrom("news@shop.test", "<n1@shop.test>"))
	srv.Deliver("Sent", "From: "+imaptest.User+"\nTo: \"Pal, Old\" <Pal@Friends.test>, kim@sh0p.test\nCc: lee@work.test\n"+
		"Bcc: hidden@bcc.test\nSubject: Hi\nMessage-ID: <s1@loopback.test>\n\nsynthetic body\n")
	srv.Deliver("Sent", "From: "+imaptest.User+"\nTo: broken list <a@b.test>;; ,,mo@club.test\nSubject: Hi\nMessage-ID: <s2@loopback.test>\n\nsynthetic body\n")
	w := newSendersRig(t, srv, nil).full(t)
	want := []string{"a@b.test", "kim@sh0p.test", "lee@work.test", "mo@club.test", "pal@friends.test"}
	if !slices.Equal(w.Contacts, want) {
		t.Fatalf("contacts %v, want %v", w.Contacts, want)
	}
	fw, raw := fixtureWorld(t)
	fw.History, fw.KnownSenders, fw.Contacts = w.History, w.KnownSenders, w.Contacts
	if r, _ := inbox.Evaluate(raw, fw); r != inbox.RLookalike {
		t.Fatalf("with a contact at sh0p.test: %s, want lookalike", r)
	}
	fw.Contacts = slices.DeleteFunc(slices.Clone(w.Contacts), func(a string) bool { return strings.HasSuffix(a, "@sh0p.test") })
	if r, _ := inbox.Evaluate(raw, fw); r == inbox.RLookalike || r == inbox.RNoHistory {
		t.Fatalf("without it: %s", r)
	}
}

// fixtureFrom is the fixture's one-click bulk mail's sender, delivered long
// enough ago that only history stands between it and ok.
func fixtureFrom(srv *imaptest.Server) {
	srv.DeliverAt("INBOX", day(0), mailFrom("News <news@shop.test>", "<n0@shop.test>"))
}

// noHistory fails unless the fixture's mail gets no-history in w's fields.
func noHistory(t *testing.T, what string, w inbox.World) {
	t.Helper()
	blank(t, what, w)
	fw, raw := fixtureWorld(t)
	fw.History, fw.KnownSenders, fw.Contacts = w.History, w.KnownSenders, w.Contacts
	if r, _ := inbox.Evaluate(raw, fw); r != inbox.RNoHistory {
		t.Fatalf("%s: %s, want no-history", what, r)
	}
}

// A folder failing, a bound passed, and a first read not yet through each
// leave all three fields empty, so an otherwise eligible mail gets
// no-history.
func TestIncompleteReadBlanksAll(t *testing.T) {
	fw, raw := fixtureWorld(t)
	if r, _ := inbox.Evaluate(raw, fw); r != inbox.ROK {
		t.Fatalf("the fixture: %s, want ok", r)
	}
	t.Run("a folder fails", func(t *testing.T) {
		srv := imaptest.Start(t)
		fixtureFrom(srv)
		r := newSendersRig(t, srv, nil)
		w := r.full(t)
		fw.History, fw.KnownSenders, fw.Contacts = w.History, w.KnownSenders, w.Contacts
		if res, _ := inbox.Evaluate(raw, fw); res != inbox.ROK {
			t.Fatalf("with the read's history: %s, want ok", res)
		}
		srv.FailList("Archive", true)
		n := r.steps.Load()
		r.h.listing(true) // a mail read: the worker steps
		eventually(t, "a failed step", func() bool { return r.steps.Load() > n })
		noHistory(t, "after a folder failed", r.h.world())
		if !has(r.h.status().Lines, "could not finish reading who writes to you") {
			t.Fatalf("status %q", r.h.status().Lines)
		}
		r.h.mu.Lock()
		r.h.stop = errors.New("test: a sign-in the server refused")
		r.h.mu.Unlock()
		if has(r.h.status().Lines, "who writes to you") {
			t.Fatalf("while a sign-in failure stops the worker, status promises a retry: %q", r.h.status().Lines)
		}
		r.h.mu.Lock()
		r.h.stop = nil
		r.h.mu.Unlock()
		srv.FailList("Archive", false)
		r.h.listing(true)
		r.full(t)
	})
	t.Run("a bound passed", func(t *testing.T) {
		srv := imaptest.Start(t)
		fixtureFrom(srv)
		for m := range 11 {
			var to []string
			for i := range 500 {
				to = append(to, fmt.Sprintf("p%d@c.test", m*500+i))
			}
			srv.Deliver("Sent", "From: "+imaptest.User+"\nTo: "+strings.Join(to, ",")+"\nSubject: Hi\nMessage-ID: <"+fmt.Sprint(m)+"@loopback.test>\n\nsynthetic body\n")
		}
		r := newSendersRig(t, srv, nil)
		eventually(t, "the read past its bound", func() bool { return r.h.ws.sendersNow() == sendersOver })
		noHistory(t, "past the contacts bound", r.h.world())
		if rec := loadSenders(r.dir, testSealer(), slotOf(mustRead(t, r.dir))); !rec.Over || len(rec.Rec.Sent) != 0 {
			t.Fatalf("the record past its bound: over %v, %d contacts kept", rec.Over, len(rec.Rec.Sent))
		}
		if !has(r.h.status().Lines, "than I can keep track of") {
			t.Fatalf("status %q", r.h.status().Lines)
		}
	})
	t.Run("the first read not yet through", func(t *testing.T) {
		srv := imaptest.Start(t)
		fixtureFrom(srv)
		srv.Deliver("INBOX", mailFrom("x@later.test", "<x1@later.test>"))
		r := newSendersRig(t, srv, func(c *MailConfig) { c.stepMax, c.pause = 1, time.Hour })
		eventually(t, "the first step", func() bool { return r.steps.Load() > 0 })
		if !r.more.Load() {
			t.Fatal("one mail a step: the first step left none")
		}
		noHistory(t, "before the read is through", r.h.world())
		if !has(r.h.status().Lines, "read through your mailbox once") {
			t.Fatalf("status %q", r.h.status().Lines)
		}
	})
}

func mustRead(t *testing.T, dir string) MailSettings {
	t.Helper()
	s, err := readMail(dir)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// 9,000 mails complete in five steps of 2,000, and history is given only
// after the fifth.
func TestALargeMailboxCompletes(t *testing.T) {
	srv := imaptest.Start(t)
	for i := range 9000 {
		srv.DeliverAt("INBOX", day(0).Add(time.Duration(i)*time.Second), mailFrom(fmt.Sprintf("s%d@bulk.test", i%50), fmt.Sprintf("<m%d@bulk.test>", i)))
	}
	var early atomic.Bool
	r := newSendersRig(t, srv, func(c *MailConfig) {
		c.stepped = func(more, full bool) { early.Store(early.Load() || more && full) }
	})
	if w := r.full(t); len(w.History) != 50 {
		t.Fatalf("%d senders in history, want 50", len(w.History))
	}
	if early.Load() {
		t.Fatal("history was given before the read was through")
	}
	if n := r.steps.Load(); n != 5 {
		t.Fatalf("%d steps, want 5", n)
	}
}

// A second read reads only the mail that arrived since, and a changed UID
// validity reads the folder again. A record sealed under another account or
// key, too large, or damaged starts over; an intact one gives history at the
// first step after a start.
func TestSenderRecordIsSealedAndIncremental(t *testing.T) {
	srv := imaptest.Start(t)
	for i := range 3 {
		srv.DeliverAt("INBOX", day(i), mailFrom(fmt.Sprintf("s%d@old.test", i), fmt.Sprintf("<o%d@old.test>", i)))
	}
	ctx, cancel := context.WithCancel(t.Context())
	r := newSendersRig(t, srv, func(c *MailConfig) { c.stepMax = 1 })
	r.h = nil
	r.openCtx(t, ctx) // a host this test stops
	r.full(t)
	n := r.steps.Load()
	srv.DeliverAt("INBOX", day(9), mailFrom("new@new.test", "<n1@new.test>"))
	r.h.listing(true) // a mail read
	eventually(t, "the new sender", func() bool { return slices.Contains(r.h.world().KnownSenders, "new@new.test") })
	if got := r.steps.Load(); got != n+1 || r.more.Load() {
		t.Fatalf("one new mail at one mail a step: %d steps, more %v; want 1 step and none left", got-n, r.more.Load())
	}

	srv.Renumber("INBOX")
	r.h.listing(true)
	eventually(t, "the renumbered folder read again", func() bool {
		rec := loadSenders(r.dir, testSealer(), slotOf(mustRead(t, r.dir)))
		return rec.Rec.Sources["INBOX"].Validity == 101 && rec.Rec.Complete()
	})
	if w := r.full(t); len(w.KnownSenders) != 4 {
		t.Fatalf("after the folder was read again: %v", w.KnownSenders)
	}
	cancel()
	r.h.mu.Lock()
	r.h.idle()
	r.h.mu.Unlock()

	path := filepath.Join(r.dir, sendersFile)
	good, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	slot := slotOf(mustRead(t, r.dir))
	rec := loadSenders(r.dir, testSealer(), slot)
	other, err := clerk.NewAESSealer([]byte("another key, 32 bytes long......"))
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		name  string
		write func() error
		full  bool
	}{
		{"intact", func() error { return privfile.WriteAtomic(r.dir, sendersFile, good, nil) }, true},
		{"damaged", func() error {
			bad := slices.Clone(good)
			bad[len(bad)/2] ^= 1
			return privfile.WriteAtomic(r.dir, sendersFile, bad, nil)
		}, false},
		{"too large", func() error { return privfile.WriteAtomic(r.dir, sendersFile, make([]byte, maxSendersRec+1), nil) }, false},
		{"another account's", func() error { return saveSenders(r.dir, testSealer(), slot+"x", rec) }, false},
		{"another key's", func() error { return saveSenders(r.dir, other, slot, rec) }, false},
		{"past a bound, not marked", func() error {
			big := sealedSenders{Rec: inbox.SendersRecord{Sources: rec.Rec.Sources, Senders: rec.Rec.Senders, Sent: map[string]bool{}}}
			for i := range inbox.ContactsMax + 1 {
				big.Rec.Sent[fmt.Sprintf("c%d@many.test", i)] = true
			}
			return saveSenders(r.dir, testSealer(), slot, big)
		}, false},
	} {
		if err := c.write(); err != nil {
			t.Fatal(err)
		}
		r.cfg.pause = time.Hour
		ctx, cancel := context.WithCancel(t.Context())
		n := r.steps.Load()
		r.openCtx(t, ctx)
		eventually(t, c.name+": the first step", func() bool { return r.steps.Load() > n })
		if r.whole.Load() != c.full {
			t.Errorf("%s: history after the first step %v, want %v", c.name, r.whole.Load(), c.full)
		}
		cancel()
		r.h.mu.Lock()
		r.h.idle()
		r.h.mu.Unlock()
		if loadSenders(r.dir, testSealer(), slot).Over {
			t.Errorf("%s: the record started over is marked past its bound", c.name)
		}
	}
}

// Over the loopback server, the senders read changes no mail's \Seen flag.
func TestSendersReadKeepsReadState(t *testing.T) {
	srv := imaptest.Start(t)
	srv.DeliverAt("INBOX", day(0), mailFrom("a@unread.test", "<u1@unread.test>"))
	srv.DeliverAt("INBOX", day(1), mailFrom("b@read.test", "<r1@read.test>"), `\Seen`)
	srv.DeliverAt("Archive", day(2), mailFrom("c@unread.test", "<u2@unread.test>"))
	srv.Deliver("Sent", "From: "+imaptest.User+"\nTo: d@friends.test\nSubject: Hi\nMessage-ID: <s1@loopback.test>\n\nsynthetic body\n")
	before := map[string][]imaptest.Message{}
	for _, f := range []string{"INBOX", "Archive", "Sent"} {
		before[f] = srv.Messages(f)
	}
	r := newSendersRig(t, srv, nil)
	if w := r.full(t); len(w.KnownSenders) != 3 || len(w.Contacts) != 1 {
		t.Fatalf("world %+v", w)
	}
	for f, ms := range before {
		after := srv.Messages(f)
		for i, m := range ms {
			if !slices.Equal(m.Flags, after[i].Flags) {
				t.Fatalf("%s %s: flags %v became %v", f, m.ID, m.Flags, after[i].Flags)
			}
		}
	}
}

// Mails whose From passes the header bound are passed over without ending
// the step, up to 16 a folder (inbox's longPerStep); past that the step ends at the
// next and the folder goes on at the next step. They count for no one.
func TestPaddedMailsDoNotStopTheRead(t *testing.T) {
	padded := func(i int) string {
		return mailFrom(strings.Repeat("x", 9000)+"@pad.test", fmt.Sprintf("<p%d@pad.test>", i))
	}
	for _, c := range []struct {
		name  string
		pads  int
		steps int64
	}{{"a few", 3, 1}, {"more than a step passes over (inbox passes 16)", 20, 2}} {
		t.Run(c.name, func(t *testing.T) {
			srv := imaptest.Start(t)
			srv.DeliverAt("INBOX", day(0), mailFrom("a@one.test", "<a1@one.test>"))
			for i := range c.pads {
				srv.DeliverAt("INBOX", day(1), padded(i))
				if i == c.pads/2 {
					srv.DeliverAt("INBOX", day(2), mailFrom("b@two.test", "<b1@two.test>"))
				}
			}
			srv.DeliverAt("INBOX", day(3), mailFrom("c@three.test", "<c1@three.test>"))
			r := newSendersRig(t, srv, nil)
			w := r.full(t)
			if !slices.Equal(w.KnownSenders, []string{"a@one.test", "b@two.test", "c@three.test"}) {
				t.Fatalf("known senders %v", w.KnownSenders)
			}
			if n := r.steps.Load(); n != c.steps {
				t.Fatalf("%d steps, want %d", n, c.steps)
			}
		})
	}
}
