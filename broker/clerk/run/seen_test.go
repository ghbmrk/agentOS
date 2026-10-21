package run

// REQ: VRB-2, CLK-1, STO-2

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/clerk/inbox"
	"github.com/ghbmrk/agentos/broker/clerk/inbox/imapsmtp"
	"github.com/ghbmrk/agentos/broker/clerk/inbox/imapsmtp/imaptest"
)

const today = "2026-10-21"

// seenRig is a mail clerk's directory and its loopback mailbox.
type seenRig struct {
	t    *testing.T
	srv  *imaptest.Server
	dir  string
	box  *inbox.Live
	slot string
}

func newSeenRig(t *testing.T) *seenRig {
	t.Helper()
	srv := imaptest.Start(t)
	st, err := imapsmtp.New(imapsmtp.Config{IMAP: srv.IMAP, SMTP: srv.SMTP, IMAPSec: imapsmtp.Plain, SMTPSec: imapsmtp.Plain,
		Credential: func(context.Context) (imapsmtp.Login, error) {
			return imapsmtp.Login{User: imaptest.User, Secret: imaptest.Password}, nil
		}, From: imaptest.User})
	if err != nil {
		t.Fatal(err)
	}
	return &seenRig{t: t, srv: srv, dir: shortDir(t), box: inbox.NewLive(st), slot: slotOf(MailSettings{Address: imaptest.User, IMAP: srv.IMAP, SMTP: srv.SMTP})}
}

func (r *seenRig) opened(day string) (map[string]string, MailStatus) {
	r.t.Helper()
	ms, err := r.box.Read(context.Background())
	if err != nil {
		r.t.Fatal(err)
	}
	return lastOpened(context.Background(), r.box, r.dir, testSealer(), r.slot, day, ms)
}

func mailFrom(from, id string) string {
	return "From: " + from + "\nTo: " + imaptest.User + "\nSubject: Hi\nMessage-ID: " + id + "\n\nsynthetic body\n"
}

func has(lines []string, part string) bool {
	for _, l := range lines {
		if strings.Contains(l, part) {
			return true
		}
	}
	return false
}

// When the read of opened mail fails, every sender in the listing counts as
// opened today, so VRB-2 passes no unsubscribe, the owner is told why in
// STATUS, and the record is left as it was (#2698 items 1 and 2). An empty
// LastOpened would read as "never opened".
func TestOpenedFailureKeepsEverySenderAndSaysSo(t *testing.T) {
	r := newSeenRig(t)
	r.srv.Deliver("INBOX", mailFrom("news@shop.test", "<n1@shop.test>"))
	r.srv.Deliver("Archive", mailFrom("pat@example.test", "<p1@example.test>"), `\Seen`)
	r.srv.FailList("Archive", true)
	got, st := r.opened(today)
	if got["news@shop.test"] != today {
		t.Fatalf("after a failed read, LastOpened %v: the listed sender is not kept", got)
	}
	if !has(st.Lines, "Unsubscribing is paused") {
		t.Fatalf("status %v names no pause", st.Lines)
	}
	if _, err := os.Stat(filepath.Join(r.dir, seenFile)); !os.IsNotExist(err) {
		t.Fatalf("a failed read wrote a record (%v)", err)
	}
}

// The record is sealed and bound to its account: it names no sender in the
// clear, and a record altered, sealed for another account, or past its bound
// does not load. The next read then starts it over today and says so, so a
// forged record cannot date a read sender's mail into the past (#2698 items
// 11 and 12).
func TestTheSeenRecordIsSealedAndBoundToItsAccount(t *testing.T) {
	r := newSeenRig(t)
	r.srv.Deliver("INBOX", mailFrom("pat@example.test", "<p1@example.test>"), `\Seen`)
	if got, st := r.opened(today); got["pat@example.test"] != today || !has(st.Lines, "began its record") {
		t.Fatalf("first read: %v, %v", got, st.Lines)
	}
	path := filepath.Join(r.dir, seenFile)
	b, err := os.ReadFile(path)
	if err != nil || bytes.Contains(b, []byte("example.test")) {
		t.Fatalf("the record is missing or names a sender in the clear (%v)", err)
	}
	if _, ok := loadSeen(r.dir, testSealer(), r.slot); !ok {
		t.Fatal("the record the clerk wrote does not load")
	}
	if _, ok := loadSeen(r.dir, testSealer(), r.slot+"x"); ok {
		t.Fatal("a record loads under another account")
	}
	b[len(b)/2] ^= 1
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, ok := loadSeen(r.dir, testSealer(), r.slot); ok {
		t.Fatal("an altered record loads")
	}
	if _, st := r.opened(today); !has(st.Lines, "began its record") {
		t.Fatalf("after an altered record, status %v does not say the record started over", st.Lines)
	}
	if err := os.Truncate(path, maxSeen+1); err != nil {
		t.Fatal(err)
	}
	if _, ok := loadSeen(r.dir, testSealer(), r.slot); ok {
		t.Fatal("a record past its bound loads")
	}
}

// Until the record has watched for 90 days the owner is told when
// unsubscribing from a read sender may start; on the first read after, the
// owner is told once how many senders became eligible (#2698 items 3, 10).
func TestTheWarmUpsEndIsToldOnce(t *testing.T) {
	r := newSeenRig(t)
	now, _ := time.Parse(time.DateOnly, today)
	at := func(days int) string { return now.AddDate(0, 0, -days).Format(time.DateOnly) }
	rec := sealedSeen{Log: inbox.SeenLog{Since: at(10)}}
	if err := saveSeen(r.dir, testSealer(), r.slot, rec); err != nil {
		t.Fatal(err)
	}
	if _, st := r.opened(today); !has(st.Lines, "Until "+now.AddDate(0, 0, 80).Format(time.DateOnly)) || len(st.Notices) != 0 {
		t.Fatalf("during the warm-up: %+v", st)
	}

	rec = sealedSeen{Log: inbox.SeenLog{Since: at(100), Seen: []inbox.Seen{
		{From: "old@shop.test", ID: strings.Repeat("ab", 16), Date: at(95)},
		{From: "new@shop.test", ID: strings.Repeat("cd", 16), Date: at(5)},
	}}}
	if err := saveSeen(r.dir, testSealer(), r.slot, rec); err != nil {
		t.Fatal(err)
	}
	_, st := r.opened(today)
	if len(st.Notices) != 1 || !strings.Contains(st.Notices[0], " 1 senders") || has(st.Lines, "Until") {
		t.Fatalf("at the warm-up's end: %+v, want one notice naming 1 sender", st)
	}
	if _, st := r.opened(today); len(st.Notices) != 0 {
		t.Fatalf("the warm-up's end was told again: %v", st.Notices)
	}
}

// A replacement for another account drops the old account's record, a
// password change for the same account keeps it, and a removal drops it.
func TestTheSeenRecordFollowsItsAccount(t *testing.T) {
	r := newSeenRig(t)
	sec, err := OpenSecrets(r.dir, testSealer())
	if err != nil {
		t.Fatal(err)
	}
	s := MailSettings{Address: imaptest.User, IMAP: r.srv.IMAP, SMTP: r.srv.SMTP}
	if err := SetMail(r.dir, sec, s, imaptest.Password); err != nil {
		t.Fatal(err)
	}
	r.opened(today)
	path := filepath.Join(r.dir, seenFile)
	if err := SetMail(r.dir, sec, s, "another-password-1"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("a password change dropped the record (%v)", err)
	}
	s.IMAP = "imap.b.test:993"
	if err := SetMail(r.dir, sec, s, "another-password-2"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("another account kept the old record (%v)", err)
	}
	r.slot = slotOf(s)
	if err := saveSeen(r.dir, testSealer(), r.slot, sealedSeen{}); err != nil {
		t.Fatal(err)
	}
	if err := RemoveMail(r.dir, sec); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("a removal kept the record (%v)", err)
	}
}
