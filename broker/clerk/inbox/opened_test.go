package inbox

// REQ: VRB-2 (assumption MIG-4-mail-reader-5)

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"reflect"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/clerk/inbox/imapsmtp"
	"github.com/ghbmrk/agentos/broker/clerk/inbox/imapsmtp/imaptest"
)

// arrived is the INTERNALDATE the tests deliver logged mail at.
var arrived = time.Date(2026, 1, 2, 9, 0, 0, 0, time.UTC)

// liveStore is a transport to the test server.
func liveStore(t *testing.T, srv *imaptest.Server) *imapsmtp.Store {
	t.Helper()
	st, err := imapsmtp.New(imapsmtp.Config{IMAP: srv.IMAP, SMTP: srv.SMTP, IMAPSec: imapsmtp.Plain, SMTPSec: imapsmtp.Plain, From: imaptest.User,
		Credential: func(context.Context) (imapsmtp.Login, error) {
			return imapsmtp.Login{User: imaptest.User, Secret: imaptest.Password}, nil
		}})
	if err != nil {
		t.Fatal(err)
	}
	return st
}

// A sign-in the server refuses, reading or sending, says so, so the host can
// stop signing in until the owner sets the account up again.
func TestARefusedLoginSaysSo(t *testing.T) {
	srv := imaptest.Start(t)
	st, err := imapsmtp.New(imapsmtp.Config{IMAP: srv.IMAP, SMTP: srv.SMTP, IMAPSec: imapsmtp.Plain, SMTPSec: imapsmtp.Plain, From: imaptest.User,
		Credential: func(context.Context) (imapsmtp.Login, error) {
			return imapsmtp.Login{User: imaptest.User, Secret: "canary-wrong"}, nil
		}})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := NewLive(st).Opened(context.Background(), "2026-10-19", SeenLog{}); !errors.Is(err, imapsmtp.ErrLoginRefused) {
		t.Fatalf("read: err %v, want ErrLoginRefused", err)
	}
	if err := st.Submit(context.Background(), []string{"a@example.test"}, []byte("x")); !errors.Is(err, imapsmtp.ErrLoginRefused) {
		t.Fatalf("send: err %v, want ErrLoginRefused", err)
	}
}

// #2618: every sender with a read mail, in any folder, is opened today, keyed
// by lower-cased address as Evaluate looks it up; a sender with only unread
// mail is not; and every message keeps its flags. Only seen mail is fetched,
// so this cannot show BODY.PEEK at work; it shows nothing else changed.
func TestOpenedCountsEverySeenSenderAsOpenedToday(t *testing.T) {
	srv := imaptest.Start(t)
	srv.Deliver("INBOX", rawMail("<a@shop.test>", "News <News@Shop.Test>", "Sale"), `\Seen`)
	srv.Deliver("INBOX", rawMail("<b@spam.test>", "x@spam.test", "Win"))
	srv.Deliver("Archive", rawMail("<c@example.test>", "pat@example.test", "Hi"), `\Seen`, `\Flagged`)
	srv.Deliver("Trash", rawMail("<d@list.test>", "old@list.test", "Digest"), `\Seen`)
	srv.Deliver("Junk", rawMail("<e@junk.test>", "j@junk.test", "Offer"))
	got, _, err := NewLive(liveStore(t, srv)).Opened(context.Background(), "2026-10-19", SeenLog{})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"news@shop.test": "2026-10-19", "pat@example.test": "2026-10-19", "old@list.test": "2026-10-19"}
	if !maps.Equal(got, want) {
		t.Fatalf("opened %v, want %v", got, want)
	}
	for id, flags := range map[string][]string{"<b@spam.test>": nil, "<e@junk.test>": nil, "<c@example.test>": {`\Flagged`, `\Seen`}} {
		_, f, _ := srv.Find(id)
		if slices.Sort(f); !slices.Equal(f, flags) {
			t.Fatalf("%s flags %v, want %v", id, f, flags)
		}
	}
}

// A sender the owner reads is never unsubscribed: with the fixture's
// eligible M01 read once, however long ago, VRB-2 refuses it.
func TestASenderWithAReadMailIsNotUnsubscribed(t *testing.T) {
	w, _, raw := loadFixture(t)
	if r, _ := Evaluate(raw["M01"], w); r != ROK {
		t.Fatalf("control: M01 is %s", r)
	}
	srv := imaptest.Start(t)
	srv.Deliver("Archive", strings.ReplaceAll(string(raw["M01"]), "\r\n", "\n"), `\Seen`)
	opened, _, err := NewLive(liveStore(t, srv)).Opened(context.Background(), w.Today, SeenLog{})
	if err != nil {
		t.Fatal(err)
	}
	w.LastOpened = opened
	if r, _ := Evaluate(raw["M01"], w); r != RRecentlyOpened {
		t.Fatalf("M01 read once is %s, want %s", r, RRecentlyOpened)
	}
}

// A folder that cannot be read fails the whole answer and hands back no
// LastOpened: a partial list would make the senders it missed look never
// opened. The log it hands back keeps every entry it began with and adds
// only read mail it found (#2841); one that found none hands back none.
func TestOpenedFailsWhenAFolderCannotBeRead(t *testing.T) {
	srv := imaptest.Start(t)
	srv.DeliverAt("Drafts", arrived, rawMail("<o@shop.test>", "old@shop.test", "Old"), `\Seen`)
	l := NewLive(liveStore(t, srv))
	_, first, err := l.Opened(context.Background(), "2026-01-02", SeenLog{})
	if err != nil || len(first.Seen) != 1 {
		t.Fatalf("first read: log %+v, err %v", first, err)
	}
	srv.Remove("Drafts", "<o@shop.test>")
	srv.Deliver("INBOX", rawMail("<a@shop.test>", "news@shop.test", "Sale"), `\Seen`)
	srv.Deliver("Archive", rawMail("<c@example.test>", "pat@example.test", "Hi"), `\Seen`)
	srv.FailList("Archive", true)
	got, log, err := l.Opened(context.Background(), "2026-10-19", first)
	if err == nil || got != nil {
		t.Fatalf("opened %v, err %v; want an error", got, err)
	}
	froms := map[string]bool{}
	for _, e := range log.Seen {
		froms[e.From] = true
	}
	if log.Seen != nil && (!froms["old@shop.test"] || !froms["news@shop.test"] || froms["pat@example.test"] || log.Since != "2026-01-02") {
		t.Fatalf("log %+v: want the entry it began with and the read mail it found", log)
	}
	srv.Remove("INBOX", "<a@shop.test>")
	if _, log, err := l.Opened(context.Background(), "2026-10-19", first); err == nil || log.Seen != nil {
		t.Fatalf("a failed read that found no read mail handed back log %+v (err %v)", log, err)
	}
}

// #2684: each read mail the log lacks is logged once, with only its sender, a
// digest of its Message-ID and today; and a logged sender stays opened after
// its mail is gone for good.
func TestTheSeenLogKeepsADeletedReadMailOpened(t *testing.T) {
	srv := imaptest.Start(t)
	srv.DeliverAt("INBOX", arrived, rawMail("<a@shop.test>", "news@shop.test", "Sale"), `\Seen`)
	srv.Deliver("INBOX", rawMail("<b@spam.test>", "x@spam.test", "Win"))
	l := NewLive(liveStore(t, srv))
	_, log, err := l.Opened(context.Background(), "2026-07-01", SeenLog{})
	id := seenID("news@shop.test", "<a@shop.test>", arrived)
	want := SeenLog{Since: "2026-07-01", Seen: []Seen{{From: "news@shop.test", ID: hex.EncodeToString(id[:]), Date: "2026-07-01"}}}
	if err != nil || !reflect.DeepEqual(log, want) {
		t.Fatalf("log %+v, err %v; want %+v", log, err, want)
	}
	if b, _ := json.Marshal(log); strings.Contains(string(b), "a@shop.test>") || strings.Contains(string(b), "Sale") {
		t.Fatalf("the log keeps more than sender, digest and date: %s", b)
	}
	if _, again, _ := l.Opened(context.Background(), "2026-07-02", log); !reflect.DeepEqual(again, want) {
		t.Fatalf("logged again: %+v", again)
	}
	srv.Remove("INBOX", "<a@shop.test>")
	got, kept, err := l.Opened(context.Background(), "2026-08-01", log)
	if err != nil || !maps.Equal(got, map[string]string{"news@shop.test": "2026-07-01"}) || !reflect.DeepEqual(kept, want) {
		t.Fatalf("opened %v, log %+v, err %v", got, kept, err)
	}
}

// Once the log has watched for unopenedDays its dates replace the guess: a
// read mail first seen long ago leaves its sender eligible, a mail read since
// is opened on its day, and a read mail with no Message-ID, or any read mail
// before then, is still opened today. An entry older than unopenedDays whose
// mail is gone opens nothing and is dropped.
func TestTheSeenLogsDatesReplaceTheGuessAfterNinetyDays(t *testing.T) {
	srv := imaptest.Start(t)
	srv.DeliverAt("INBOX", arrived, rawMail("<a@shop.test>", "news@shop.test", "Sale"), `\Seen`)
	srv.Deliver("INBOX", rawMail("<c@list.test>", "new@list.test", "Digest"), `\Seen`)
	srv.Deliver("INBOX", "From: bare@none.test\nSubject: x\n\nbody\n", `\Seen`)
	a, gone := seenID("news@shop.test", "<a@shop.test>", arrived), seenID("gone@old.test", "<g@old.test>", arrived)
	log := SeenLog{Since: "2026-01-02", Seen: []Seen{
		{From: "news@shop.test", ID: hex.EncodeToString(a[:]), Date: "2026-01-02"},
		{From: "gone@old.test", ID: hex.EncodeToString(gone[:]), Date: "2026-01-02"},
	}}
	l := NewLive(liveStore(t, srv))
	for _, c := range []struct {
		today string
		want  map[string]string
		kept  int
	}{
		{"2026-03-01", map[string]string{"news@shop.test": "2026-03-01", "new@list.test": "2026-03-01", "bare@none.test": "2026-03-01", "gone@old.test": "2026-01-02"}, 3},
		{"2026-04-02", map[string]string{"news@shop.test": "2026-01-02", "new@list.test": "2026-04-02", "bare@none.test": "2026-04-02", "gone@old.test": "2026-01-02"}, 2},
	} {
		got, kept, err := l.Opened(context.Background(), c.today, log)
		if err != nil || !maps.Equal(got, c.want) || len(kept.Seen) != c.kept || kept.Since != "2026-01-02" {
			t.Fatalf("%s: opened %v, log %+v, err %v; want %v and %d entries", c.today, got, kept, err, c.want, c.kept)
		}
	}
}

// A new mail that reuses an earlier read mail's Message-ID is a new entry,
// dated the day it is read, so a sender cannot keep one old read standing in
// for every later mail; and a read mail the server gives no INTERNALDATE is
// opened today and logged under no name.
func TestAReusedMessageIDIsANewRead(t *testing.T) {
	srv := imaptest.Start(t)
	srv.DeliverAt("INBOX", arrived.Add(30*24*time.Hour), rawMail("<a@shop.test>", "news@shop.test", "Sale again"), `\Seen`)
	a := seenID("news@shop.test", "<a@shop.test>", arrived)
	log := SeenLog{Since: "2026-01-02", Seen: []Seen{{From: "news@shop.test", ID: hex.EncodeToString(a[:]), Date: "2026-01-02"}}}
	got, kept, err := NewLive(liveStore(t, srv)).Opened(context.Background(), "2026-06-01", log)
	if err != nil || got["news@shop.test"] != "2026-06-01" || len(kept.Seen) != 1 || kept.Seen[0].Date != "2026-06-01" {
		t.Fatalf("opened %v, log %+v, err %v; want the reused ID read today", got, kept, err)
	}
	o, _ := newOpened("2026-06-01", log)
	if err := o.header([]byte("From: news@shop.test\r\nMessage-Id: <a@shop.test>\r\n\r\n"), time.Time{}); err != nil {
		t.Fatal(err)
	}
	if got, kept := o.result(); got["news@shop.test"] != "2026-06-01" || len(kept.Seen) != 0 {
		t.Fatalf("no INTERNALDATE: opened %v, log %+v; want opened today, nothing logged", got, kept)
	}
}

// A read mail whose headers are too long fails the answer, and the error
// names it so the owner can find and remove it: its folder and arrival in
// the text, and its subject, decoded and only as a field, since it is the
// mail's content; a subject past subjectMax is cut and marked.
func TestOpenedNamesAMailWhoseHeadersAreTooLong(t *testing.T) {
	long := "news@shop.test (" + strings.Repeat("x", 9<<10) + ")"
	for subject, want := range map[string]string{
		"=?UTF-8?Q?Gro=C3=9Fer_Sale?=": "Großer Sale",
		strings.Repeat("y", 2<<10):     strings.Repeat("y", 1<<10-len("Subject: ")) + "…",
	} {
		srv := imaptest.Start(t)
		srv.DeliverAt("Archive", arrived, rawMail("<a@shop.test>", long, subject), `\Seen`)
		_, _, err := NewLive(liveStore(t, srv)).Opened(context.Background(), "2026-06-01", SeenLog{})
		var lh *imapsmtp.LongHeaderError
		if !errors.As(err, &lh) || !errors.Is(err, imapsmtp.ErrLongHeader) || lh.Subject != want ||
			!strings.Contains(err.Error(), "the mail in Archive that arrived 2026-01-02 09:00") || strings.Contains(err.Error(), want[:4]) {
			t.Fatalf("err %v (%+v); want ErrLongHeader naming Archive and 2026-01-02 09:00, subject %q kept out of the text", err, lh, want)
		}
	}
}

// An entry the clerk did not write is dated today even in a log whose start
// is valid and old: its day is not trusted, so it cannot leave its sender
// eligible.
func TestAnEntryTheClerkDidNotWriteIsDatedToday(t *testing.T) {
	o, err := newOpened("2026-06-01", SeenLog{Since: "2026-01-01", Seen: []Seen{{From: "forged@x.test", ID: "not-hex", Date: "2026-02-01"}}})
	if err != nil {
		t.Fatal(err)
	}
	id := seenID("forged@x.test", "not-hex", time.Time{})
	want := SeenLog{Since: "2026-01-01", Seen: []Seen{{From: "forged@x.test", ID: hex.EncodeToString(id[:]), Date: "2026-06-01"}}}
	if got, kept := o.result(); got["forged@x.test"] != "2026-06-01" || !reflect.DeepEqual(kept, want) {
		t.Fatalf("opened %v, log %+v; want opened and logged today", got, kept)
	}
}

// The log fails closed: a log with no valid start, or one in the future,
// begins today, so nothing is watched yet; an entry whose day is not a date,
// or is outside the log's start to today, counts as today, so a reset log
// trusts none of its old days; an entry the clerk did not write is logged
// again, dated today, and keeps its sender opened on the next read too; and a
// Message-ID another sender used does not stand in for this sender's read.
func TestTheSeenLogFailsClosed(t *testing.T) {
	srv := imaptest.Start(t)
	srv.DeliverAt("INBOX", arrived, rawMail("<a@shop.test>", "news@shop.test", "Sale"), `\Seen`)
	hexID := func(from, mid string) string { id := seenID(from, mid, arrived); return hex.EncodeToString(id[:]) }
	relogged := seenID("forged@x.test", "<a@shop.test>", time.Time{})
	relog := hex.EncodeToString(relogged[:])
	l := NewLive(liveStore(t, srv))
	for _, since := range []string{"someday", "2027-01-01"} {
		log := SeenLog{Since: since, Seen: []Seen{
			{From: "gone@list.test", ID: hexID("gone@list.test", "<g@list.test>"), Date: "someday"},
			{From: "other@evil.test", ID: hexID("other@evil.test", "<a@shop.test>"), Date: "2026-05-30"},
			{From: "forged@x.test", ID: "<a@shop.test>", Date: "2020-01-01"},
			{From: "", ID: hexID("", "<n@x.test>"), Date: "2026-05-30"},
			{From: "later@list.test", ID: hexID("later@list.test", "<l@list.test>"), Date: "2026-09-01"},
			{From: "news@shop.test", ID: hexID("news@shop.test", "<a@shop.test>"), Date: "2026-01-02"},
		}}
		got, kept, err := l.Opened(context.Background(), "2026-06-01", log)
		want := map[string]string{"gone@list.test": "2026-06-01", "other@evil.test": "2026-06-01", "news@shop.test": "2026-06-01", "later@list.test": "2026-06-01", "forged@x.test": "2026-06-01"}
		wantLog := SeenLog{Since: "2026-06-01", Seen: []Seen{
			{From: "forged@x.test", ID: relog, Date: "2026-06-01"},
			{From: "gone@list.test", ID: hexID("gone@list.test", "<g@list.test>"), Date: "2026-06-01"},
			{From: "later@list.test", ID: hexID("later@list.test", "<l@list.test>"), Date: "2026-06-01"},
			{From: "news@shop.test", ID: hexID("news@shop.test", "<a@shop.test>"), Date: "2026-06-01"},
			{From: "other@evil.test", ID: hexID("other@evil.test", "<a@shop.test>"), Date: "2026-06-01"},
		}}
		if err != nil || !maps.Equal(got, want) || !reflect.DeepEqual(kept, wantLog) {
			t.Fatalf("since %s: opened %v, log %+v, err %v; want %v, %+v", since, got, kept, err, want, wantLog)
		}
		if got, _, err := l.Opened(context.Background(), "2026-06-02", kept); err != nil || got["forged@x.test"] != "2026-06-01" {
			t.Fatalf("since %s, read again: opened %v, err %v; want forged@x.test still opened", since, got, err)
		}
	}
}

// Past openedMax the answer fails, not shrinks: a cut list would make the
// senders left out look never opened.
func TestOpenedFailsPastWhatItKeeps(t *testing.T) {
	srv := imaptest.Start(t)
	srv.Deliver("INBOX", rawMail("<a@shop.test>", "news@shop.test", "Sale"), `\Seen`)
	srv.Deliver("INBOX", rawMail("<b@shop.test>", "news@shop.test", "Sale 2"), `\Seen`)
	srv.Deliver("Archive", rawMail("<c@example.test>", "pat@example.test", "Hi"), `\Seen`)
	defer func(n int) { openedMax = n }(openedMax)
	news, pat := len("news@shop.test"), len("pat@example.test")
	openedMax = news + pat + 2*senderCost + 2*news + pat + 3*entryCost
	if _, _, err := NewLive(liveStore(t, srv)).Opened(context.Background(), "2026-10-19", SeenLog{}); err != nil {
		t.Fatalf("at the bound: %v", err)
	}
	openedMax--
	if got, _, err := NewLive(liveStore(t, srv)).Opened(context.Background(), "2026-10-19", SeenLog{}); !errors.Is(err, ErrTooMuchReadMail) || got != nil {
		t.Fatalf("opened %v, err %v; want ErrTooMuchReadMail", got, err)
	}
}

// What one Opened call holds stays within openedMax. Filled until it refuses
// with the shortest distinct senders, or with distinct mails, then started
// again from the log it handed back as stored and read back, the maps, the
// log read in and the log handed back hold no more heap than they were
// charged.
func TestOpenedHoldsNoMoreThanItCharges(t *testing.T) {
	for name, head := range map[string]func(n int) []byte{
		"senders": func(n int) []byte { return []byte(fmt.Sprintf("From: %x@b\r\n\r\n", n)) },
		"mails":   func(n int) []byte { return []byte(fmt.Sprintf("From: s%x@b\r\nMessage-Id: <%x>\r\n\r\n", n%64, n)) },
	} {
		defer func(n int) { openedMax = n }(openedMax)
		openedMax = 32 << 20 // the charge per entry, not the bound's size, is under test
		var ms runtime.MemStats
		runtime.GC()
		runtime.ReadMemStats(&ms)
		before := ms.HeapAlloc
		o, _ := newOpened("2026-10-19", SeenLog{})
		n := 0
		for ; !o.full; n++ {
			if err := o.header(head(n), arrived); err != nil {
				t.Fatal(err)
			}
		}
		first, kept := o.result() // a sender with no logged mail lives only here
		o = nil
		b, _ := json.Marshal(kept) // as the clerk's process stores it
		kept = SeenLog{}
		var log SeenLog
		if err := json.Unmarshal(b, &log); err != nil {
			t.Fatal(err)
		}
		b = nil
		o2, err := newOpened("2026-10-19", log)
		if err != nil {
			t.Fatalf("%s: the log handed back does not load: %v", name, err)
		}
		got, again := o2.result()
		runtime.GC()
		runtime.ReadMemStats(&ms)
		held := int64(ms.HeapAlloc) - int64(before)
		if held > int64(openedMax) {
			t.Fatalf("%s: %d hold %d bytes, more than openedMax %d", name, n, held, openedMax)
		}
		runtime.KeepAlive(first)
		runtime.KeepAlive(log)
		runtime.KeepAlive(got)
		runtime.KeepAlive(again)
		runtime.KeepAlive(o2)
	}
}

// A full read holds no more than it charges either: filled until full, then
// fed as many newer read mails again, each dropping an older one, it holds
// the maps, its heap and the log it hands back within openedMax, and that
// log loads within openedMax (#2841).
func TestAFullReadHoldsNoMoreThanItCharges(t *testing.T) {
	defer func(n int) { openedMax = n }(openedMax)
	openedMax = 32 << 20 // the charge per entry, not the bound's size, is under test
	head := func(n int) []byte { return []byte(fmt.Sprintf("From: s%x@b\r\nMessage-Id: <%x>\r\n\r\n", n%64, n)) }
	var ms runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&ms)
	before := ms.HeapAlloc
	o, _ := newOpened("2026-10-19", SeenLog{})
	n := 0
	for ; !o.full; n++ {
		if err := o.header(head(n), arrived.Add(time.Duration(n)*time.Second)); err != nil {
			t.Fatal(err)
		}
	}
	for i := n; i < 2*n; i++ {
		if err := o.header(head(i), arrived.Add(time.Duration(i)*time.Second)); err != nil {
			t.Fatal(err)
		}
	}
	kept := o.partial()
	runtime.GC()
	runtime.ReadMemStats(&ms)
	if held := int64(ms.HeapAlloc) - int64(before); held > int64(openedMax) {
		t.Fatalf("a full read of %d mails holds %d bytes, more than openedMax %d", 2*n, held, openedMax)
	}
	if o.kept > openedMax || len(kept.Seen) == 0 {
		t.Fatalf("a full read charged %d of %d and kept %d entries", o.kept, openedMax, len(kept.Seen))
	}
	if !slices.ContainsFunc(kept.Seen, func(e Seen) bool {
		id := seenID("s"+fmt.Sprintf("%x", (2*n-1)%64)+"@b", fmt.Sprintf("<%x>", 2*n-1), arrived.Add(time.Duration(2*n-1)*time.Second))
		return e.ID == hex.EncodeToString(id[:])
	}) {
		t.Fatal("a full read dropped the newest read mail")
	}
	o = nil
	if _, err := newOpened("2026-10-19", kept); err != nil {
		t.Fatalf("the log a full read hands back does not load: %v", err)
	}
	runtime.KeepAlive(kept)
}

// A logged entry older than unopenedDays holds no more than oldCost and its
// sender's address until the read finds its mail: a log of only such
// entries, filled to the bound, read in as the clerk's process stores it,
// loads within openedMax, and one whose mail is gone is dropped.
func TestOpenedHoldsNoMoreThanItChargesForOldEntries(t *testing.T) {
	defer func(n int) { openedMax = n }(openedMax)
	openedMax = 32 << 20 // the charge per entry, not the bound's size, is under test
	from := func(n int) string { return fmt.Sprintf("s%x@b", n%64) }
	n := (openedMax - 64*(senderCost+len("s3f@b"))) / (oldCost + len("s3f@b"))
	b := func() []byte { // the log as the clerk's process stores it, held throughout
		log := SeenLog{Since: "2026-01-02", Seen: make([]Seen, n)}
		for i := range log.Seen {
			id := seenID(from(i), fmt.Sprintf("<%x>", i), arrived)
			log.Seen[i] = Seen{From: from(i), ID: hex.EncodeToString(id[:]), Date: "2026-01-02"}
		}
		b, _ := json.Marshal(log)
		return b
	}()
	var log SeenLog
	var ms runtime.MemStats
	runtime.GC()
	runtime.GC() // and the encoder's pooled buffer, which outlives one
	runtime.ReadMemStats(&ms)
	before := ms.HeapAlloc
	if err := json.Unmarshal(b, &log); err != nil {
		t.Fatal(err)
	}
	o, err := newOpened("2026-10-19", log)
	if err != nil {
		t.Fatalf("%d old entries do not load: %v", n, err)
	}
	runtime.GC()
	runtime.ReadMemStats(&ms)
	if held := int64(ms.HeapAlloc) - int64(before); held > int64(openedMax) {
		t.Fatalf("%d old entries hold %d bytes, more than openedMax %d", n, held, openedMax)
	}
	if _, kept := o.result(); len(kept.Seen) != 0 {
		t.Fatalf("kept %d entries whose mail is gone", len(kept.Seen))
	}
	runtime.KeepAlive(log)
	runtime.KeepAlive(b)
}

// Past the bound, deleting logged read mail older than unopenedDays for good
// lets the next read pass (#2742 item 3c): its entry is charged in full only
// while the read still finds its mail. Before, the frozen log kept every
// entry charged, so only deleting mail read since the last good read helped.
func TestDeletingOldReadMailClearsTooMuchReadMail(t *testing.T) {
	srv := imaptest.Start(t)
	srv.DeliverAt("INBOX", arrived, rawMail("<a@shop.test>", "news@shop.test", "Sale"), `\Seen`)
	srv.DeliverAt("INBOX", arrived, rawMail("<b@shop.test>", "news@shop.test", "Sale 2"), `\Seen`)
	l := NewLive(liveStore(t, srv))
	_, log, err := l.Opened(context.Background(), "2026-01-02", SeenLog{})
	if err != nil || len(log.Seen) != 2 {
		t.Fatalf("first read: log %+v, err %v", log, err)
	}
	srv.Deliver("Archive", rawMail("<c@example.test>", "pat@example.test", "Hi"), `\Seen`)
	defer func(n int) { openedMax = n }(openedMax)
	news, pat := len("news@shop.test"), len("pat@example.test")
	// Both logged mails present and charged in full, plus the new read mail.
	openedMax = news + senderCost + 2*news + 2*entryCost + pat + senderCost + pat + entryCost - 1
	const today = "2026-10-19"
	if _, _, err := l.Opened(context.Background(), today, log); !errors.Is(err, ErrTooMuchReadMail) {
		t.Fatalf("past the bound: err %v, want ErrTooMuchReadMail", err)
	}
	srv.Remove("INBOX", "<a@shop.test>")
	got, kept, err := l.Opened(context.Background(), today, log)
	if err != nil || len(kept.Seen) != 2 || got["news@shop.test"] != "2026-01-02" || got["pat@example.test"] != today {
		t.Fatalf("after deleting an old read mail: opened %v, log %+v, err %v", got, kept, err)
	}
}

// The failure path #2841 closes: the owner reads S's mail, the next read
// fails with ErrTooMuchReadMail, and the owner deletes that mail. The failing
// read hands back S's entry with the log it began with, so the next good
// read still counts S opened.
func TestAFailingReadKeepsTheSendersItFound(t *testing.T) {
	srv := imaptest.Start(t)
	srv.DeliverAt("INBOX", arrived, rawMail("<a@shop.test>", "news@shop.test", "Sale"), `\Seen`)
	srv.DeliverAt("INBOX", arrived, rawMail("<b@shop.test>", "news@shop.test", "Sale 2"), `\Seen`)
	l := NewLive(liveStore(t, srv))
	_, log, err := l.Opened(context.Background(), "2026-01-02", SeenLog{})
	if err != nil || len(log.Seen) != 2 {
		t.Fatalf("first read: log %+v, err %v", log, err)
	}
	srv.Deliver("Archive", rawMail("<c@example.test>", "pat@example.test", "Hi"), `\Seen`)
	defer func(n int) { openedMax = n }(openedMax)
	news, pat := len("news@shop.test"), len("pat@example.test")
	// One under the charge of both logged mails and the new read mail, with
	// room for the new mail once the read is full and drops an old entry.
	openedMax = news + senderCost + 2*news + 2*entryCost + pat + senderCost + pat + entryCost - 1
	const today = "2026-10-19"
	got, kept, err := l.Opened(context.Background(), today, log)
	if !errors.Is(err, ErrTooMuchReadMail) || got != nil {
		t.Fatalf("past the bound: opened %v, err %v; want ErrTooMuchReadMail", got, err)
	}
	var found bool
	for _, e := range kept.Seen {
		if e.From == "pat@example.test" && e.Date == today {
			found = true
		}
	}
	if !found || kept.Since != "2026-01-02" {
		t.Fatalf("the failing read handed back %+v, without the read mail it found", kept)
	}
	srv.Remove("Archive", "<c@example.test>")
	openedMax = OpenedMax
	got, again, err := l.Opened(context.Background(), today, kept)
	// The full read made room by dropping an old entry of news's, whose mail
	// is still there, so news is logged again today (fail closed).
	if err != nil || got["pat@example.test"] != today || got["news@shop.test"] != today {
		t.Fatalf("after deleting the mail the failing read found: opened %v, err %v; pat must stay opened", got, err)
	}
	if !slices.ContainsFunc(again.Seen, func(e Seen) bool { return e.From == "pat@example.test" }) {
		t.Fatalf("the good read dropped pat's entry: %+v", again)
	}
}

// A full read keeps the newest read mail. Past the bound it drops the log's
// entries older than unopenedDays first, which open nothing, then the read
// mail it logged with the oldest arrival, whichever folder or order the
// server gives; the log's recent entries stay.
func TestAFullReadKeepsTheNewestReadMail(t *testing.T) {
	srv := imaptest.Start(t)
	srv.DeliverAt("INBOX", arrived, rawMail("<a@shop.test>", "news@shop.test", "Sale"), `\Seen`)
	l := NewLive(liveStore(t, srv))
	_, log, err := l.Opened(context.Background(), "2026-01-02", SeenLog{})
	if err != nil || len(log.Seen) != 1 {
		t.Fatalf("first read: log %+v, err %v", log, err)
	}
	srv.DeliverAt("Archive", time.Date(2026, 9, 30, 9, 0, 0, 0, time.UTC), rawMail("<r@example.test>", "rae@example.test", "Recent"), `\Seen`)
	_, log, err = l.Opened(context.Background(), "2026-10-01", log)
	if err != nil || len(log.Seen) != 2 {
		t.Fatalf("second read: log %+v, err %v", log, err)
	}
	const today = "2026-10-19"
	for i, at := range []time.Time{
		time.Date(2026, 10, 18, 9, 0, 0, 0, time.UTC), // the newest, first in its folder
		time.Date(2026, 3, 1, 9, 0, 0, 0, time.UTC),
		time.Date(2026, 4, 1, 9, 0, 0, 0, time.UTC),
	} {
		folder := []string{"INBOX", "Archive", "Junk"}[i%3]
		srv.DeliverAt(folder, at, rawMail(fmt.Sprintf("<n%d@x.test>", i), fmt.Sprintf("s%d@x.test", i), "New"), `\Seen`)
	}
	defer func(n int) { openedMax = n }(openedMax)
	// The recent entry and the old entry's sender, which a full read never
	// drops, plus room for one entry a full read keeps.
	news, rae := len("news@shop.test"), len("rae@example.test")
	openedMax = news + senderCost + rae + senderCost + rae + entryCost + fullCost("s0@x.test")
	got, kept, err := l.Opened(context.Background(), today, log)
	if !errors.Is(err, ErrTooMuchReadMail) || got != nil {
		t.Fatalf("opened %v, err %v; want ErrTooMuchReadMail", got, err)
	}
	var froms []string
	for _, e := range kept.Seen {
		froms = append(froms, e.From)
	}
	if !slices.Equal(froms, []string{"rae@example.test", "s0@x.test"}) {
		t.Fatalf("a full read kept %v; want the recent entry and the newest read mail", froms)
	}
}
