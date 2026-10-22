package run

import (
	"bytes"
	"context"
	"encoding/gob"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"github.com/ghbmrk/agentos/broker/clerk"
	"github.com/ghbmrk/agentos/broker/clerk/inbox"
	"github.com/ghbmrk/agentos/broker/clerk/inbox/imapsmtp"
)

// The mail clerk's record of read mail (#2684, #2698 items 1, 2, 10 to 12).
// inbox.Live.Opened turns the mailbox's read mail and the record into
// LastOpened, which VRB-2 reads to keep a sender the owner reads; the clerk's
// process keeps the record, sealed, beside its settings. It is trusted input:
// a forged record with old dates would make read senders look unopened. So it
// is sealed under the clerk's Sealer and bound to the account's slot, its size
// is checked before it is read, and any record that does not load starts over
// today, which keeps every read sender opened for unopenedDays (fail closed).
const (
	seenFile = "seen.log"
	// maxSeen bounds the sealed record before it is read. Opened keeps at most
	// inbox.OpenedMax bytes, charging each entry its address and far more than
	// the record's gob spends on the rest of it (its digest, date and field
	// marks, under 64 bytes), so any log Opened hands back fits, with room for
	// Since, Told and the seal (TestEveryLogOpenedKeepsFitsTheRecord).
	maxSeen = inbox.OpenedMax + 4<<10
	// warmDays is inbox's unopenedDays: how long the record must watch before
	// a read mail's own day counts.
	warmDays = 90
)

// sealedSeen is the record as sealed: the log Opened keeps, and whether the
// owner has read that the warm-up ended.
type sealedSeen struct {
	Log  inbox.SeenLog
	Told bool
}

func seenAAD(slot string) []byte { return []byte("agentOS seen log\n" + slot) }

// seenState is how a record loaded: a record that is missing and one that
// does not load (too large, not the clerk's own file, not sealed under this
// sealer and account, or not a record) both start over, and the owner is told
// which.
type seenState int

const (
	seenLoaded seenState = iota
	seenMissing
	seenBad
)

// loadSeen reads dir's record for the account at slot.
func loadSeen(dir string, s clerk.Sealer, slot string) (r sealedSeen, st seenState) {
	f, err := os.OpenFile(filepath.Join(dir, seenFile), os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if errors.Is(err, os.ErrNotExist) {
		return r, seenMissing
	}
	if err != nil {
		return r, seenBad
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil || privateFile(f) != nil || fi.Size() > maxSeen {
		return r, seenBad
	}
	// Read in one allocation of the file's size: the file is replaced by
	// rename, never written in place, so the open one does not grow.
	blob := make([]byte, fi.Size())
	if _, err := io.ReadFull(f, blob); err != nil {
		return r, seenBad
	}
	plain, err := s.Open(blob, seenAAD(slot))
	if err != nil {
		return r, seenBad
	}
	defer clear(plain)
	if gob.NewDecoder(bytes.NewReader(plain)).Decode(&r) != nil {
		return sealedSeen{}, seenBad
	}
	return r, seenLoaded
}

func saveSeen(dir string, s clerk.Sealer, slot string, r sealedSeen) error {
	var plain bytes.Buffer
	if err := gob.NewEncoder(&plain).Encode(r); err != nil {
		return err
	}
	defer clear(plain.Bytes())
	blob, err := s.Seal(plain.Bytes(), seenAAD(slot))
	if err != nil {
		return err
	}
	if len(blob) > maxSeen {
		return errors.New("run: the record of read mail is past its bound")
	}
	return writeAtomic(dir, seenFile, blob, nil)
}

// markTold records that the owner has read the end of the warm-up, so it is
// not told again. A record that does not load is left alone: it starts over,
// warm-up and all.
func markTold(dir string, s clerk.Sealer, slot string) error {
	r, st := loadSeen(dir, s, slot)
	if st != seenLoaded || r.Told {
		return nil
	}
	r.Told = true
	return saveSeen(dir, s, slot, r)
}

// MailStatus is what the mail clerk tells the owner about unsubscribing.
// Lines hold while their cause does (STATUS); WarmedUp, when not empty, is
// the notice that the warm-up ended, told until the owner has read it.
type MailStatus struct {
	Lines    []string
	WarmedUp string
}

// trouble is the owner's words for why a read of the mailbox failed, and
// what happens next: a fixed reason for each kind of failure, naming the
// mail when one mail is the cause, and never the server's own text, which
// the server chooses (#2698 item 16).
func trouble(err error) (why, next string) {
	const again = "I'll try again at the next check."
	var long *imapsmtp.LongHeaderError
	switch {
	case errors.As(err, &long):
		at := "at an unknown time"
		if !long.Arrived.IsZero() {
			at = long.Arrived.In(time.Local).Format("2 January 2006 at 15:04")
		}
		subject := ""
		if long.Subject != "" {
			subject = ", subject " + quoted(long.Subject)
		}
		return "a read mail in " + quoted(long.Folder) + " (arrived " + at + subject + ") has a From or Message-ID line too long to check safely",
			"Delete it or move it out of your mail, and I'll resume at the next check."
	case errors.Is(err, imapsmtp.ErrLoginRefused):
		return "your mail server refused my sign-in" + forSide(err),
			"Set up the mail account again on my Wi-Fi page. If your provider uses two-step sign-in, use an app password it gives for mail apps."
	case errors.Is(err, imapsmtp.ErrNoSignIn):
		// Only a change of setup clears it: trying again cannot, and nor can
		// another password, since the server answers before one is sent
		// (#2698 item 32).
		servers := map[imapsmtp.Side]string{imapsmtp.Reading: "IMAP", imapsmtp.Sending: "SMTP"}[imapsmtp.SideOf(err)]
		if servers == "" {
			servers = "IMAP and SMTP"
		}
		return "your mail server doesn't accept a password sign-in" + forSide(err) + " with these settings",
			"On my Wi-Fi page, set up the mail account again with the " + servers + " server settings your provider gives for mail apps. If your provider only allows signing in through its own page, I can't use this account yet."
	case errors.Is(err, inbox.ErrTooMuchReadMail):
		return "you have more read mail than I can keep track of", "Delete or archive old read mail outside your mail account, and I'll resume at the next check."
	case errors.Is(err, imapsmtp.ErrUnreachable):
		return "I couldn't reach your mail server", again
	case errors.Is(err, imapsmtp.ErrTimeout):
		return "your mail server stopped answering", again
	case errors.Is(err, imapsmtp.ErrUnanswered):
		return "your mail server did not answer for every read mail", again
	case errors.Is(err, imapsmtp.ErrReplyTooLarge):
		return "your mail server sent more than I accept in one answer", again
	default:
		return "your mail server's answer was not one I could use", again
	}
}

// forSide names the side of the account a sign-in failed on, for the
// owner's text, or nothing when err does not say (#2698 item 32).
func forSide(err error) string {
	if s := imapsmtp.SideOf(err); s != "" {
		return " for " + string(s)
	}
	return ""
}

// quoted is a name the server or a sender chose, quoted for the owner's
// text: control, bidi and other invisible characters show as escapes, and a
// long name is cut.
func quoted(s string) string {
	if r := []rune(s); len(r) > 80 {
		s = string(r[:80]) + "…"
	}
	return strconv.QuoteToGraphic(s)
}

// lastOpened is World.LastOpened for the mails ms of the account at slot, as
// of today, and what the owner is told. When Opened fails, every sender in ms
// counts as opened today, so no unsubscribe passes VRB-2, and the record is
// kept as it was. An empty LastOpened would read as "never opened" and let
// every unsubscribe through (#2698 item 1).
func lastOpened(ctx context.Context, box *inbox.Live, dir string, s clerk.Sealer, slot, today string, ms []inbox.Mail) (map[string]string, MailStatus) {
	var st MailStatus
	rec, loaded := loadSeen(dir, s, slot) // not loaded: an empty record, which Opened starts today
	got, kept, err := box.Opened(ctx, today, rec.Log)
	if err != nil {
		fail := map[string]string{}
		for _, m := range ms {
			if from := inbox.FromAddress(m.Raw); from != "" {
				fail[from] = today
			}
		}
		why, next := trouble(err)
		st.Lines = append(st.Lines, "Unsubscribing is paused: "+why+", so I can't tell whose mail you have read. "+next)
		return fail, st
	}
	switch loaded {
	case seenMissing:
		st.Lines = append(st.Lines, "I began my record of the mail you read today.")
	case seenBad:
		st.Lines = append(st.Lines, "My saved record of the mail you read could not be read, so I began it again today.")
	}
	since, _ := time.Parse(time.DateOnly, kept.Since)
	now, _ := time.Parse(time.DateOnly, today)
	ends := since.AddDate(0, 0, warmDays)
	if now.Before(ends) {
		st.Lines = append(st.Lines, fmt.Sprintf("Until %s, I unsubscribe from no sender you have read mail from: I'm still learning when you read mail.", ends.Format("2 January 2006")))
	} else if !rec.Told {
		n := 0
		for _, d := range got {
			if t, err := time.Parse(time.DateOnly, d); err == nil && !now.Before(t.AddDate(0, 0, warmDays)) {
				n++
			}
		}
		st.WarmedUp = warmedUp(n)
	}
	rec.Log = kept
	if err := saveSeen(dir, s, slot, rec); err != nil {
		// The answer stands for this read; the next read starts from the
		// record as it was, which only re-dates mail to today.
		st.Lines = append(st.Lines, "I could not save my record of the mail you read, so some senders wait longer than they need to before I may unsubscribe from them. I'll try again at the next check.")
	}
	return got, st
}

// warmedUp is the notice that the warm-up ended, with n senders eligible.
func warmedUp(n int) string {
	const learned = "I have learned when you read mail. "
	switch n {
	case 0:
		return learned + fmt.Sprintf("None of the senders whose mail you have read has gone %d days unopened, so I may unsubscribe from none of them yet.", warmDays)
	case 1:
		return learned + fmt.Sprintf("1 sender whose mail you have not opened in %d days may now be unsubscribed from; it still waits its hold, and STOP cancels it.", warmDays)
	}
	return learned + fmt.Sprintf("%d senders whose mail you have not opened in %d days may now be unsubscribed from; each still waits its hold, and STOP cancels it.", n, warmDays)
}
