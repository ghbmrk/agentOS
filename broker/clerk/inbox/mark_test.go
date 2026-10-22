package inbox

// REQ: CLK-2

import (
	"context"
	"slices"
	"testing"

	"github.com/emersion/go-imap"

	"github.com/ghbmrk/agentos/broker/clerk/inbox/imapsmtp"
	"github.com/ghbmrk/agentos/broker/clerk/inbox/imapsmtp/imaptest"
)

// markRig is a Live over a local IMAP server's six standard folders, with
// one mail in the inbox.
func markRig(t *testing.T) (*imaptest.Server, *Live) {
	t.Helper()
	srv := imaptest.Start(t)
	srv.Deliver("INBOX", rawMail("<m1@shop.test>", "a@shop.test", "Order"))
	st, err := imapsmtp.New(imapsmtp.Config{IMAP: srv.IMAP, SMTP: srv.SMTP, IMAPSec: imapsmtp.Plain, SMTPSec: imapsmtp.Plain, From: imaptest.User,
		Credential: func(context.Context) (imapsmtp.Login, error) {
			return imapsmtp.Login{User: imaptest.User, Secret: imaptest.Password}, nil
		}})
	if err != nil {
		t.Fatal(err)
	}
	return srv, NewLive(st)
}

func mark(t *testing.T, l *Live) Mark {
	t.Helper()
	m, err := l.Mark(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return m
}

// The Mark stays the same while nothing changes, and moves when mail
// arrives in any folder, leaves one, is read or marked unread, or a folder
// is renumbered, so a caller re-reads exactly when a read could differ.
func TestMarkChangesExactlyWhenTheMailboxDoes(t *testing.T) {
	srv, l := markRig(t)
	base := mark(t, l)
	var names []string
	for _, f := range base {
		names = append(names, f.Folder)
	}
	if want := []string{"Archive", "Drafts", "INBOX", "Junk", "Sent", "Trash"}; !slices.Equal(names, want) {
		t.Fatalf("mark folders %q, want %q", names, want)
	}
	if !base.Same(mark(t, l)) {
		t.Fatal("an unchanged mailbox gave a different mark")
	}
	for _, c := range []struct {
		name   string
		change func()
	}{
		{"delivered to the trash", func() { srv.Deliver("Trash", rawMail("<m2@shop.test>", "a@shop.test", "Old")) }},
		{"read", func() { srv.SetFlags("<m1@shop.test>", imap.SeenFlag) }},
		{"marked unread", func() { srv.SetFlags("<m1@shop.test>") }},
		{"removed", func() { srv.Remove("Trash", "<m2@shop.test>") }},
		{"renumbered", func() { srv.Renumber("INBOX") }},
	} {
		before := mark(t, l)
		c.change()
		after := mark(t, l)
		if before.Same(after) {
			t.Fatalf("%s: mark unchanged %+v", c.name, after)
		}
		if !after.Same(mark(t, l)) {
			t.Fatalf("%s: mark unstable", c.name)
		}
	}
	srv.AddFolder("Receipts", "")
	if m := mark(t, l); base.Same(m) || len(m) != len(base)+1 {
		t.Fatalf("a new folder left the mark %+v", m)
	}
}

// Same fails closed: no mark, or a folder without a UID validity or next
// UID to go by, is never the same, even compared with itself.
func TestMarkSameFailsClosed(t *testing.T) {
	ok := imapsmtp.Mark{Folder: "INBOX", Validity: 1, Next: 2, Messages: 1}
	for name, m := range map[string]Mark{
		"empty":       nil,
		"no next":     {ok, {Folder: "Trash", Validity: 1}},
		"no validity": {ok, {Folder: "Trash", Next: 1}},
	} {
		if m.Same(m) {
			t.Fatalf("%s: mark %+v is the same as itself", name, m)
		}
	}
	if !(Mark{ok}).Same(Mark{ok}) {
		t.Fatal("a complete mark is not the same as itself")
	}
}

// A folder whose STATUS fails gives no mark, never a partial one.
func TestMarkFailsWithAFolder(t *testing.T) {
	srv, l := markRig(t)
	srv.FailList("Trash", true)
	if m, err := l.Mark(context.Background()); err == nil {
		t.Fatalf("mark %+v despite a failed STATUS", m)
	}
}

// Without CONDSTORE one mail read and another marked unread together leave
// the mark the same: the gap the caller's ceiling re-read covers.
func TestMarkWithoutCondstoreMissesASwappedRead(t *testing.T) {
	srv, l := markRig(t)
	srv.Deliver("INBOX", rawMail("<m2@shop.test>", "a@shop.test", "Ship"), imap.SeenFlag)
	before := mark(t, l)
	srv.SetFlags("<m1@shop.test>", imap.SeenFlag)
	srv.SetFlags("<m2@shop.test>")
	if after := mark(t, l); !before.Same(after) || after[2].ModSeq != "" {
		t.Fatalf("mark %+v changed without CONDSTORE; update this test and the ceiling note", after)
	}
}
