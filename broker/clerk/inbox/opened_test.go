package inbox

// REQ: VRB-2 (assumption MIG-4-mail-reader-5)

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"maps"
	"reflect"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/clerk/inbox/imapsmtp"
	"github.com/ghbmrk/agentos/broker/clerk/inbox/imapsmtp/imaptest"
)

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

// A folder that cannot be read fails the whole answer, and hands back no log
// to keep: a partial list would make the senders it missed look never opened.
func TestOpenedFailsWhenAFolderCannotBeRead(t *testing.T) {
	srv := imaptest.Start(t)
	srv.Deliver("INBOX", rawMail("<a@shop.test>", "news@shop.test", "Sale"), `\Seen`)
	srv.Deliver("Archive", rawMail("<c@example.test>", "pat@example.test", "Hi"), `\Seen`)
	srv.FailList("Archive", true)
	if got, log, err := NewLive(liveStore(t, srv)).Opened(context.Background(), "2026-10-19", SeenLog{}); err == nil || got != nil || log.Seen != nil {
		t.Fatalf("opened %v, log %v, err %v; want an error", got, log, err)
	}
}

// #2684: each read mail the log lacks is logged once, with only its sender, a
// digest of its Message-ID and today; and a logged sender stays opened after
// its mail is gone for good.
func TestTheSeenLogKeepsADeletedReadMailOpened(t *testing.T) {
	srv := imaptest.Start(t)
	srv.Deliver("INBOX", rawMail("<a@shop.test>", "news@shop.test", "Sale"), `\Seen`)
	srv.Deliver("INBOX", rawMail("<b@spam.test>", "x@spam.test", "Win"))
	l := NewLive(liveStore(t, srv))
	_, log, err := l.Opened(context.Background(), "2026-07-01", SeenLog{})
	id := seenID("news@shop.test", "<a@shop.test>")
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
	srv.Deliver("INBOX", rawMail("<a@shop.test>", "news@shop.test", "Sale"), `\Seen`)
	srv.Deliver("INBOX", rawMail("<c@list.test>", "new@list.test", "Digest"), `\Seen`)
	srv.Deliver("INBOX", "From: bare@none.test\nSubject: x\n\nbody\n", `\Seen`)
	a, gone := seenID("news@shop.test", "<a@shop.test>"), seenID("gone@old.test", "<g@old.test>")
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

// The log fails closed: an entry whose day is not a date counts as today; a
// log with no valid start, or one in the future, begins today, so nothing is
// watched yet; an entry the clerk did not write is skipped; and a Message-ID
// another sender used does not stand in for this sender's read.
func TestTheSeenLogFailsClosed(t *testing.T) {
	srv := imaptest.Start(t)
	srv.Deliver("INBOX", rawMail("<a@shop.test>", "news@shop.test", "Sale"), `\Seen`)
	hexID := func(from, mid string) string { id := seenID(from, mid); return hex.EncodeToString(id[:]) }
	l := NewLive(liveStore(t, srv))
	for _, since := range []string{"someday", "2027-01-01"} {
		log := SeenLog{Since: since, Seen: []Seen{
			{From: "gone@list.test", ID: hexID("gone@list.test", "<g@list.test>"), Date: "someday"},
			{From: "other@evil.test", ID: hexID("other@evil.test", "<a@shop.test>"), Date: "2026-05-30"},
			{From: "forged@x.test", ID: "<a@shop.test>", Date: "2020-01-01"},
			{From: "", ID: hexID("", "<n@x.test>"), Date: "2026-05-30"},
		}}
		got, kept, err := l.Opened(context.Background(), "2026-06-01", log)
		want := map[string]string{"gone@list.test": "2026-06-01", "other@evil.test": "2026-05-30", "news@shop.test": "2026-06-01"}
		wantLog := SeenLog{Since: "2026-06-01", Seen: []Seen{
			{From: "gone@list.test", ID: hexID("gone@list.test", "<g@list.test>"), Date: "2026-06-01"},
			{From: "news@shop.test", ID: hexID("news@shop.test", "<a@shop.test>"), Date: "2026-06-01"},
			{From: "other@evil.test", ID: hexID("other@evil.test", "<a@shop.test>"), Date: "2026-05-30"},
		}}
		if err != nil || !maps.Equal(got, want) || !reflect.DeepEqual(kept, wantLog) {
			t.Fatalf("since %s: opened %v, log %+v, err %v; want %v, %+v", since, got, kept, err, want, wantLog)
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
	if got, _, err := NewLive(liveStore(t, srv)).Opened(context.Background(), "2026-10-19", SeenLog{}); err == nil || got != nil {
		t.Fatalf("opened %v, err %v; want an error", got, err)
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
		var ms runtime.MemStats
		runtime.GC()
		runtime.ReadMemStats(&ms)
		before := ms.HeapAlloc
		o, _ := newOpened("2026-10-19", SeenLog{})
		n := 0
		for ; o.header(head(n)) == nil; n++ {
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
