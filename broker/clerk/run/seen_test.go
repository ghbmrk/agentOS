package run

// REQ: VRB-2, CLK-1, STO-2

import (
	"bytes"
	"context"
	"encoding/gob"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/clerk"
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

	// The account OpenMail returns judges VRB-2 in that LastOpened.
	sec, err := OpenSecrets(r.dir, testSealer())
	if err != nil {
		t.Fatal(err)
	}
	if err := SetMail(r.dir, sec, MailSettings{Address: imaptest.User, IMAP: r.srv.IMAP, SMTP: r.srv.SMTP}, imaptest.Password); err != nil {
		t.Fatal(err)
	}
	m, err := OpenMail(context.Background(), r.dir, sec, mailConfig())
	if err != nil {
		t.Fatal(err)
	}
	if got := m.world().LastOpened; got["news@shop.test"] != today {
		t.Fatalf("the account's LastOpened %v does not keep the listed sender", got)
	}
	if !has(m.Status.Lines, "Unsubscribing is paused") {
		t.Fatalf("the clerk's status %v names no pause", m.Status.Lines)
	}
}

// opens counts the records a sealer is asked to open.
type opens struct {
	clerk.Sealer
	n int
}

func (o *opens) Open(blob, aad []byte) ([]byte, error) {
	o.n++
	return o.Sealer.Open(blob, aad)
}

// The record is sealed and bound to its account: it names no sender in the
// clear, and a record altered, sealed for another account, or past its bound
// does not load. The next read then starts it over today and says so, so a
// forged record cannot date a read sender's mail into the past (#2698 items
// 11 and 12).
func TestTheSeenRecordIsSealedAndBoundToItsAccount(t *testing.T) {
	r := newSeenRig(t)
	r.srv.Deliver("INBOX", mailFrom("pat@example.test", "<p1@example.test>"), `\Seen`)
	if got, st := r.opened(today); got["pat@example.test"] != today || !has(st.Lines, "I began my record") {
		t.Fatalf("first read: %v, %v", got, st.Lines)
	}
	path := filepath.Join(r.dir, seenFile)
	b, err := os.ReadFile(path)
	if err != nil || bytes.Contains(b, []byte("example.test")) {
		t.Fatalf("the record is missing or names a sender in the clear (%v)", err)
	}
	if _, st := loadSeen(r.dir, testSealer(), r.slot); st != seenLoaded {
		t.Fatal("the record the clerk wrote does not load")
	}
	if _, st := loadSeen(r.dir, testSealer(), r.slot+"x"); st != seenBad {
		t.Fatal("a record loads under another account")
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, st := loadSeen(r.dir, testSealer(), r.slot); st != seenBad {
		t.Fatal("a record others can read loads")
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	b[len(b)/2] ^= 1
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, st := loadSeen(r.dir, testSealer(), r.slot); st != seenBad {
		t.Fatal("an altered record loads")
	}
	if _, st := r.opened(today); !has(st.Lines, "could not be read, so I began it again") {
		t.Fatalf("after an altered record, status %v does not say the record started over", st.Lines)
	}
	// Past its bound the record is refused before it is read or opened.
	if err := os.Truncate(path, maxSeen+1); err != nil {
		t.Fatal(err)
	}
	o := &opens{Sealer: testSealer()}
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	_, st := loadSeen(r.dir, o, r.slot)
	runtime.ReadMemStats(&after)
	if st != seenBad || o.n != 0 {
		t.Fatalf("a record past its bound loads or is opened (%d opens)", o.n)
	}
	if read := after.TotalAlloc - before.TotalAlloc; read > maxSeen/8 {
		t.Fatalf("refusing a record past its bound took %d bytes: it was read", read)
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
	if _, st := r.opened(today); !has(st.Lines, "Until "+now.AddDate(0, 0, 80).Format("2 January 2006")+", I") || st.WarmedUp != "" {
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
	if st.WarmedUp != warmedUp(1) || has(st.Lines, "Until") {
		t.Fatalf("at the warm-up's end: %+v, want the notice naming 1 sender", st)
	}
	// Until the owner has read it, it is told again, at every read; after,
	// never.
	if _, st := r.opened(today); st.WarmedUp == "" {
		t.Fatalf("the warm-up's end, unread, was not told again: %+v", st)
	}
	if err := markTold(r.dir, testSealer(), r.slot); err != nil {
		t.Fatal(err)
	}
	if _, st := r.opened(today); st.WarmedUp != "" {
		t.Fatalf("the warm-up's end was told again once read: %v", st.WarmedUp)
	}

	// The boundary: a record 89 days old still warms up; at 90 days it has
	// ended, and mail read exactly 90 days ago counts while 89 does not.
	rec = sealedSeen{Log: inbox.SeenLog{Since: at(89)}}
	if err := saveSeen(r.dir, testSealer(), r.slot, rec); err != nil {
		t.Fatal(err)
	}
	if _, st := r.opened(today); !has(st.Lines, "Until "+now.AddDate(0, 0, 1).Format("2 January 2006")) || st.WarmedUp != "" {
		t.Fatalf("on day 89: %+v", st)
	}
	rec = sealedSeen{Log: inbox.SeenLog{Since: at(90), Seen: []inbox.Seen{
		{From: "ninety@shop.test", ID: strings.Repeat("ef", 16), Date: at(90)},
		{From: "eightynine@shop.test", ID: strings.Repeat("01", 16), Date: at(89)},
	}}}
	if err := saveSeen(r.dir, testSealer(), r.slot, rec); err != nil {
		t.Fatal(err)
	}
	if _, st := r.opened(today); has(st.Lines, "Until") || st.WarmedUp != warmedUp(1) {
		t.Fatalf("on day 90: %+v, want one notice naming 1 sender", st)
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

// Every failure the owner is told about gets fixed words and a next step,
// never the server's own text; a mail that is the cause is named by its
// folder, local arrival and subject, quoted so control and bidi characters
// show as escapes (#2698 items 2, 6, 16, 21, 22).
func TestTroubleIsToldInFixedWords(t *testing.T) {
	const leak = "CANARY-SERVER-TEXT"
	arrived := time.Date(2026, 1, 2, 10, 0, 0, 0, time.UTC)
	cases := []struct {
		err  error
		want string
	}{
		{&imapsmtp.LongHeaderError{Folder: "Arch\u202eive", Arrived: arrived, UID: 7, Subject: "Hi\x1b[2J"}, `a read mail in "Arch\u202eive" (arrived ` + arrived.In(time.Local).Format("2 January 2006 at 15:04") + `, subject "Hi\x1b[2J")`},
		{fmt.Errorf("%w: %s", imapsmtp.ErrLoginRefused, leak), "refused my sign-in"},
		{fmt.Errorf("%w, reading mail: %s", imapsmtp.ErrNoSignIn, leak), "doesn't accept a password sign-in"},
		{fmt.Errorf("%w: %s", inbox.ErrTooMuchReadMail, leak), "more read mail than I can keep track of"},
		{fmt.Errorf("%w: %s", imapsmtp.ErrUnreachable, leak), "couldn't reach your mail server"},
		{fmt.Errorf("%w: %s", imapsmtp.ErrTimeout, leak), "stopped answering"},
		{fmt.Errorf("%w: %s", imapsmtp.ErrUnanswered, leak), "did not answer for every read mail"},
		{fmt.Errorf("%w: %s", imapsmtp.ErrReplyTooLarge, leak), "more than I accept in one answer"},
		{errors.New(leak), "not one I could use"},
	}
	for _, c := range cases {
		why, next := trouble(c.err)
		line := why + ". " + next
		if !strings.Contains(why, c.want) || strings.Contains(line, leak) || strings.ContainsFunc(line, func(r rune) bool { return r == 0x202e || r == 0x1b }) || next == "" {
			t.Errorf("%v: told %q", c.err, line)
		}
	}
	// Only a change of setup clears a refusal or a server with no sign-in for
	// this login, so neither promises to try again (#2698 item 32).
	for _, e := range []error{imapsmtp.ErrLoginRefused, imapsmtp.ErrNoSignIn} {
		if _, next := trouble(e); strings.Contains(next, "try again") || !strings.Contains(next, "Wi-Fi page") {
			t.Errorf("%v: next step %q", e, next)
		}
	}
	// No password clears a server that answers before one is sent, so its
	// next step names the server settings, never a password.
	if _, next := trouble(imapsmtp.ErrNoSignIn); strings.Contains(strings.ToLower(next), "password") || !strings.Contains(next, "IMAP and SMTP server settings") {
		t.Errorf("no sign-in: next step %q", next)
	}
	if why, _ := trouble(&imapsmtp.LongHeaderError{Folder: strings.Repeat("f", 500)}); len(why) > 300 {
		t.Errorf("a long folder name is not cut: %d bytes", len(why))
	}
}

// Any log Opened can keep fits the record: the record spends on an entry its
// address and less than Opened charges for the rest, OpenedMax/(1<<20) bytes
// (inbox's entryCost, at searchMax = 1<<20 entries), so a log at Opened's
// bound is within maxSeen whatever its addresses' length (#2732 item 6).
func TestEveryLogOpenedKeepsFitsTheRecord(t *testing.T) {
	charge := inbox.OpenedMax / (1 << 20)
	for _, n := range []int{1, 40, 8 << 10} {
		var log inbox.SeenLog
		log.Since = today
		addr := strings.Repeat("a", n-1) + "@"
		cost := 0
		for i := range 2000 {
			log.Seen = append(log.Seen, inbox.Seen{From: addr, ID: fmt.Sprintf("%032x", i), Date: today})
			cost += n + charge
		}
		var b bytes.Buffer
		if err := gob.NewEncoder(&b).Encode(sealedSeen{Log: log, Told: true}); err != nil {
			t.Fatal(err)
		}
		if b.Len() > cost {
			t.Errorf("addresses of %d bytes: the record spends %d on what Opened charges %d", n, b.Len(), cost)
		}
	}
	if maxSeen < inbox.OpenedMax {
		t.Fatal("maxSeen is under Opened's bound")
	}
}

// The warm-up's end counts its senders in plain words.
func TestTheWarmUpsEndCountsInPlainWords(t *testing.T) {
	for n, want := range map[int]string{0: "None of the senders", 1: "1 sender whose mail you have not opened in 90 days may now be unsubscribed from; it still", 2: "2 senders whose mail you have not opened in 90 days may now be unsubscribed from; each still"} {
		if got := warmedUp(n); !strings.Contains(got, want) {
			t.Errorf("%d: %q", n, got)
		}
	}
}
