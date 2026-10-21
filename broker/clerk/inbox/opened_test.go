package inbox

// REQ: VRB-2 (assumption MIG-4-mail-reader-5)

import (
	"context"
	"fmt"
	"maps"
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
	got, err := NewLive(liveStore(t, srv)).Opened(context.Background(), "2026-10-19")
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
	opened, err := NewLive(liveStore(t, srv)).Opened(context.Background(), w.Today)
	if err != nil {
		t.Fatal(err)
	}
	w.LastOpened = opened
	if r, _ := Evaluate(raw["M01"], w); r != RRecentlyOpened {
		t.Fatalf("M01 read once is %s, want %s", r, RRecentlyOpened)
	}
}

// A folder that cannot be read fails the whole answer: a partial list would
// make the senders it missed look never opened.
func TestOpenedFailsWhenAFolderCannotBeRead(t *testing.T) {
	srv := imaptest.Start(t)
	srv.Deliver("INBOX", rawMail("<a@shop.test>", "news@shop.test", "Sale"), `\Seen`)
	srv.Deliver("Archive", rawMail("<c@example.test>", "pat@example.test", "Hi"), `\Seen`)
	srv.FailList("Archive", true)
	if got, err := NewLive(liveStore(t, srv)).Opened(context.Background(), "2026-10-19"); err == nil || got != nil {
		t.Fatalf("opened %v, err %v; want an error", got, err)
	}
}

// Past openedMax bytes of addresses the answer fails, not shrinks: a cut list
// would make the senders left out look never opened.
func TestOpenedFailsPastWhatItKeeps(t *testing.T) {
	srv := imaptest.Start(t)
	srv.Deliver("INBOX", rawMail("<a@shop.test>", "news@shop.test", "Sale"), `\Seen`)
	srv.Deliver("INBOX", rawMail("<b@shop.test>", "news@shop.test", "Sale 2"), `\Seen`)
	srv.Deliver("Archive", rawMail("<c@example.test>", "pat@example.test", "Hi"), `\Seen`)
	defer func(n int) { openedMax = n }(openedMax)
	openedMax = len("news@shop.test") + len("pat@example.test") + 2*entryCost
	if _, err := NewLive(liveStore(t, srv)).Opened(context.Background(), "2026-10-19"); err != nil {
		t.Fatalf("at the bound: %v", err)
	}
	openedMax--
	if got, err := NewLive(liveStore(t, srv)).Opened(context.Background(), "2026-10-19"); err == nil || got != nil {
		t.Fatalf("opened %v, err %v; want an error", got, err)
	}
}

// What Opened keeps stays within openedMax: filled with the shortest
// distinct addresses until it refuses, the map holds no more heap than it
// was charged, so tests/test_egress_memory.py may count openedMax.
func TestOpenedHoldsNoMoreThanItCharges(t *testing.T) {
	var ms runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&ms)
	before := ms.HeapAlloc
	s := senders{m: map[string]string{}}
	n := 0
	for ; s.add(fmt.Sprintf("%x@b", n), "2026-10-19") == nil; n++ {
	}
	runtime.GC()
	runtime.ReadMemStats(&ms)
	if held := int64(ms.HeapAlloc) - int64(before); held > int64(openedMax) {
		t.Fatalf("%d senders hold %d bytes, more than openedMax %d", n, held, openedMax)
	}
	runtime.KeepAlive(s.m)
}
