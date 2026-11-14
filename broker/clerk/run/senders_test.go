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
	return newSendersRigCtx(t, t.Context(), srv, edit)
}

// newSendersRigCtx is newSendersRig with a host that runs until ctx ends.
// It opens only that host, so no other worker's steps are counted.
func newSendersRigCtx(t *testing.T, ctx context.Context, srv *imaptest.Server, edit func(*MailConfig)) *sendersRig {
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
	r.openCtx(t, ctx)
	return r
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

// full waits until the world gives history, then until the host is idle.
func (r *sendersRig) full(t *testing.T) inbox.World {
	t.Helper()
	eventually(t, "the senders read through", func() bool { return r.h.world().History != nil })
	r.idle()
	return r.h.world()
}

// idle waits until no read or step of the host is in flight. A step keeps
// its result in the world before it is counted, both under h.mu, and the
// world takes no h.mu: so once the world shows a step's result, the step
// is counted only after h.mu is taken.
func (r *sendersRig) idle() {
	r.h.mu.Lock()
	r.h.idle()
	r.h.mu.Unlock()
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
	r := newSendersRigCtx(t, ctx, srv, func(c *MailConfig) { c.stepMax = 1 }) // a host this test stops
	r.full(t)
	n := r.steps.Load()
	srv.DeliverAt("INBOX", day(9), mailFrom("new@new.test", "<n1@new.test>"))
	r.h.listing(true) // a mail read
	eventually(t, "the new sender", func() bool { return slices.Contains(r.h.world().KnownSenders, "new@new.test") })
	r.idle()
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
		{"another account's", func() error { return saveSenders(r.dir, testSealer(), slot+"x", rec, nil) }, false},
		{"another key's", func() error { return saveSenders(r.dir, other, slot, rec, nil) }, false},
		{"past a bound, not marked", func() error {
			big := sealedSenders{Rec: inbox.SendersRecord{Sources: rec.Rec.Sources, Senders: rec.Rec.Senders, Sent: map[string]bool{}}}
			for i := range inbox.ContactsMax + 1 {
				big.Rec.Sent[fmt.Sprintf("c%d@many.test", i)] = true
			}
			return saveSenders(r.dir, testSealer(), slot, big, nil)
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

// loadSenders closes the record's file once read (#5325, senders.go's
// deferred Close): each fd still open on it right after a load is one the
// load left, read from /proc/self/fd as TestLoadingTheSeenRecordClosesItsFile
// reads it, so the GC finalizing a leaked file cannot hide the leak.
func TestLoadingTheSendersRecordClosesItsFile(t *testing.T) {
	dir := shortDir(t)
	rec := sealedSenders{Rec: inbox.SendersRecord{Senders: map[string]int64{"a@one.test": day(0).Unix()}}}
	if err := saveSenders(dir, testSealer(), "slot", rec, nil); err != nil {
		t.Fatal(err)
	}
	path, err := filepath.EvalSymlinks(filepath.Join(dir, sendersFile))
	if err != nil {
		t.Fatal(err)
	}
	held := func() bool {
		fds, err := os.ReadDir("/proc/self/fd")
		if err != nil {
			t.Fatal(err)
		}
		for _, fd := range fds {
			if to, err := os.Readlink(filepath.Join("/proc/self/fd", fd.Name())); err == nil && to == path {
				return true
			}
		}
		return false
	}
	for range 64 {
		if got := loadSenders(dir, testSealer(), "slot"); got.Rec.Senders["a@one.test"] != day(0).Unix() {
			t.Fatalf("loadSenders = %+v", got)
		}
		if held() {
			t.Fatalf("loadSenders left %s open", path)
		}
	}
}

// A record another uid could read or write is not the clerk's own and
// loads as an empty one (#5325, senders.go's privfile check), however well
// it is sealed; made the clerk's own again, it loads.
func TestASendersRecordOthersCanReachDoesNotLoad(t *testing.T) {
	dir := shortDir(t)
	rec := sealedSenders{Rec: inbox.SendersRecord{Senders: map[string]int64{"a@one.test": day(0).Unix()}}}
	if err := saveSenders(dir, testSealer(), "slot", rec, nil); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, sendersFile)
	for _, c := range []struct {
		mode os.FileMode
		load bool
	}{{0o640, false}, {0o606, false}, {0o600, true}} {
		if err := os.Chmod(path, c.mode); err != nil {
			t.Fatal(err)
		}
		if got := loadSenders(dir, testSealer(), "slot"); (got.Rec.Senders != nil) != c.load {
			t.Fatalf("mode %v: loaded %+v; want loaded %v", c.mode, got, c.load)
		}
	}
}

// A sealed record past maxSendersRec is not saved, and the one saved
// before stays (#5325, senders.go's size bound on save).
func TestASendersRecordPastItsSizeIsNotSaved(t *testing.T) {
	dir := shortDir(t)
	small := sealedSenders{Rec: inbox.SendersRecord{Senders: map[string]int64{"a@one.test": day(0).Unix()}}}
	if err := saveSenders(dir, testSealer(), "slot", small, nil); err != nil {
		t.Fatal(err)
	}
	big := sealedSenders{Over: true, Rec: inbox.SendersRecord{Senders: map[string]int64{}}}
	for i := 0; i*48 < maxSendersRec+maxSendersRec/4; i++ {
		big.Rec.Senders[fmt.Sprintf("%040d@big.test", i)] = int64(i)
	}
	if err := saveSenders(dir, testSealer(), "slot", big, nil); err == nil {
		t.Fatal("a record past its bound was saved")
	}
	fi, err := os.Stat(filepath.Join(dir, sendersFile))
	if err != nil || fi.Size() > maxSendersRec {
		t.Fatalf("the record on disk: %v, %v", fi, err)
	}
	if got := loadSenders(dir, testSealer(), "slot"); got.Over || got.Rec.Senders["a@one.test"] != day(0).Unix() {
		t.Fatalf("after a refused save the record is %+v; want the one before", got)
	}
}

// history gives one Delivery per sender, sorted by sender like the
// senders and contacts it gives beside it (#5325, senders.go's sort of h),
// whatever order the record's map gives them in.
func TestHistoryIsSortedBySender(t *testing.T) {
	r := inbox.SendersRecord{Senders: map[string]int64{}, Sent: map[string]bool{}}
	for i := range 32 {
		r.Senders[fmt.Sprintf("s%02d@many.test", 31-i)] = day(i).Unix()
		r.Sent[fmt.Sprintf("c%02d@many.test", i)] = true
	}
	h, known, contacts := history(r)
	if len(h) != 32 || len(known) != 32 || len(contacts) != 32 {
		t.Fatalf("history %d, known %d, contacts %d; want 32 each", len(h), len(known), len(contacts))
	}
	for i, d := range h {
		if d.From != known[i] || d.Folder != "inbox" || d.Date != time.Unix(r.Senders[d.From], 0).UTC().Format(time.DateOnly) {
			t.Fatalf("history[%d] = %+v; want %s's earliest arrival in inbox", i, d, known[i])
		}
	}
	if !slices.IsSorted(known) || !slices.IsSorted(contacts) {
		t.Fatalf("known %v, contacts %v; want each sorted", known, contacts)
	}
}

// One step of the senders read, run as the worker runs it (h.mu held, no
// worker beside it): it keeps its record and the world's fields for the
// account it read, says why a step failed until one reads, stops the clerk
// on a refused sign-in, marks itself in flight while it reads, and reads
// nothing while the clerk is stopped or there is no account (#5325,
// senders.go's readSenders).
func TestASendersStepKeepsWhatItRead(t *testing.T) {
	type told struct{ more, full bool }
	host := func(t *testing.T, srv *imaptest.Server, password string) (*MailHost, *[]told) {
		dir := shortDir(t)
		sec, err := OpenSecrets(dir, testSealer())
		if err != nil {
			t.Fatal(err)
		}
		if srv != nil {
			if err := SetMail(dir, sec, MailSettings{Address: imaptest.User, IMAP: srv.IMAP, SMTP: srv.SMTP}, password); err != nil {
				t.Fatal(err)
			}
		}
		var steps []told
		c := mailConfig()
		c.stepped = func(more, full bool) { steps = append(steps, told{more, full}) }
		// No worker: World is set, so the test runs each step itself.
		return &MailHost{ctx: t.Context(), dir: dir, sec: sec, cfg: c, kick: make(chan struct{}, 1)}, &steps
	}
	step := func(h *MailHost) bool {
		h.mu.Lock()
		defer h.mu.Unlock()
		return h.readSenders()
	}
	noRecord := func(t *testing.T, h *MailHost) {
		t.Helper()
		if _, err := os.Stat(filepath.Join(h.dir, sendersFile)); !os.IsNotExist(err) {
			t.Fatalf("a senders record was written: %v", err)
		}
	}

	t.Run("a step that reads", func(t *testing.T) {
		srv := imaptest.Start(t)
		srv.DeliverAt("INBOX", day(0), mailFrom("a@one.test", "<a1@one.test>"))
		h, steps := host(t, srv, imaptest.Password)
		var during []bool
		srv.AfterFetch(func(string) {
			h.mu.Lock()
			during = append(during, h.stepping != nil)
			h.mu.Unlock()
		})
		if step(h) {
			t.Fatal("a one-mail mailbox has more to read")
		}
		srv.AfterFetch(nil)
		if len(during) == 0 || slices.Contains(during, false) {
			t.Fatalf("in flight while it read: %v; want marked at every fetch", during)
		}
		if !slices.Equal(*steps, []told{{false, true}}) {
			t.Fatalf("steps told %v", *steps)
		}
		if h.ws.sendersNow() != sendersFull || h.srec == nil || h.srec.Rec.Senders["a@one.test"] == 0 || h.stepping != nil {
			t.Fatalf("after the step: state %v, record %+v, stepping %v", h.ws.sendersNow(), h.srec, h.stepping)
		}
		if w := h.worldAt(-1); !slices.Equal(w.KnownSenders, []string{"a@one.test"}) {
			t.Fatalf("the world's senders after the step: %v", w.KnownSenders)
		}
	})

	t.Run("a step that fails, then one that reads", func(t *testing.T) {
		srv := imaptest.Start(t)
		srv.DeliverAt("INBOX", day(0), mailFrom("a@one.test", "<a1@one.test>"))
		h, steps := host(t, srv, imaptest.Password)
		srv.FailList("INBOX", true)
		step(h)
		if h.sendersWhy == "" || h.ws.sendersNow() != sendersFailed || h.stop != nil {
			t.Fatalf("after a failed step: why %q, state %v, stop %v", h.sendersWhy, h.ws.sendersNow(), h.stop)
		}
		srv.FailList("INBOX", false)
		step(h)
		if h.sendersWhy != "" || h.ws.sendersNow() != sendersFull {
			t.Fatalf("after a good step: why %q, state %v; want none and full", h.sendersWhy, h.ws.sendersNow())
		}
		if len(*steps) != 2 {
			t.Fatalf("steps told %v", *steps)
		}
	})

	t.Run("a refused sign-in stops the clerk", func(t *testing.T) {
		srv := imaptest.Start(t)
		h, _ := host(t, srv, imaptest.Password+"-not")
		step(h)
		if !stops(h.stop) || !strings.HasPrefix(h.why, "I stopped working in your mailbox: ") {
			t.Fatalf("after a refused sign-in: stop %v, why %q", h.stop, h.why)
		}
	})

	t.Run("a stopped clerk reads nothing", func(t *testing.T) {
		srv := imaptest.Start(t)
		srv.DeliverAt("INBOX", day(0), mailFrom("a@one.test", "<a1@one.test>"))
		h, steps := host(t, srv, imaptest.Password)
		h.stop = errors.New("synthetic: stopped until setup")
		if step(h) || len(*steps) != 0 || len(srv.Logins()) != 0 {
			t.Fatalf("a stopped clerk stepped: told %v, logins %v", *steps, srv.Logins())
		}
		noRecord(t, h)
	})

	t.Run("no account reads nothing", func(t *testing.T) {
		h, steps := host(t, nil, "")
		if step(h) || len(*steps) != 0 || h.sendersWhy != "" || h.ws.sendersNow() != sendersReading {
			t.Fatalf("with no account: told %v, why %q, state %v", *steps, h.sendersWhy, h.ws.sendersNow())
		}
		noRecord(t, h)
	})
}
