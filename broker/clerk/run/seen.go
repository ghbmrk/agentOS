package run

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/ghbmrk/agentos/broker/clerk"
	"github.com/ghbmrk/agentos/broker/clerk/inbox"
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
	// maxSeen bounds the sealed record before it is read: as many entries as
	// Opened can keep (one folder's UID SEARCH, 1<<20), at 320 bytes each, an
	// entry's JSON with the longest address.
	maxSeen = (1 << 20) * 320
	// warmDays is inbox's unopenedDays: how long the record must watch before
	// a read mail's own day counts.
	warmDays = 90
)

// sealedSeen is the record as sealed: the log Opened keeps, and whether the
// owner has been told that the warm-up ended.
type sealedSeen struct {
	Log  inbox.SeenLog `json:"log"`
	Told bool          `json:"told"`
}

func seenAAD(slot string) []byte { return []byte("agentOS seen log\n" + slot) }

// loadSeen reads dir's record for the account at slot. ok is false when there
// is a record that does not load (too large, not sealed under this sealer and
// account, or not JSON); a missing record is not ok either, so both start over.
func loadSeen(dir string, s clerk.Sealer, slot string) (r sealedSeen, ok bool) {
	f, err := os.OpenFile(filepath.Join(dir, seenFile), os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return r, false
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil || privateFile(f) != nil || fi.Size() > maxSeen {
		return r, false
	}
	blob, err := io.ReadAll(io.LimitReader(f, maxSeen+1))
	if err != nil || len(blob) > maxSeen {
		return r, false
	}
	plain, err := s.Open(blob, seenAAD(slot))
	if err != nil {
		return r, false
	}
	defer clear(plain)
	if json.Unmarshal(plain, &r) != nil {
		return sealedSeen{}, false
	}
	return r, true
}

func saveSeen(dir string, s clerk.Sealer, slot string, r sealedSeen) error {
	plain, err := json.Marshal(r)
	if err != nil {
		return err
	}
	defer clear(plain)
	blob, err := s.Seal(plain, seenAAD(slot))
	if err != nil {
		return err
	}
	if len(blob) > maxSeen {
		return errors.New("run: the record of read mail is past its bound")
	}
	return writeAtomic(dir, seenFile, blob, nil)
}

// MailStatus is what the mail clerk tells the owner about unsubscribing.
// Lines hold while their cause does (STATUS); Notices are told once.
type MailStatus struct {
	Lines   []string
	Notices []string
}

// lastOpened is World.LastOpened for the mails ms of the account at slot, as
// of today, and what the owner is told. When Opened fails, every sender in ms
// counts as opened today, so no unsubscribe passes VRB-2, and the record is
// kept as it was. An empty LastOpened would read as "never opened" and let
// every unsubscribe through (#2698 item 1).
func lastOpened(ctx context.Context, box *inbox.Live, dir string, s clerk.Sealer, slot, today string, ms []inbox.Mail) (map[string]string, MailStatus) {
	var st MailStatus
	rec, ok := loadSeen(dir, s, slot) // not ok: an empty record, which Opened starts today
	got, kept, err := box.Opened(ctx, today, rec.Log)
	if err != nil {
		fail := map[string]string{}
		for _, m := range ms {
			if from := inbox.FromAddress(m.Raw); from != "" {
				fail[from] = today
			}
		}
		st.Lines = append(st.Lines, "Unsubscribing is paused: the clerk could not read which mail you have opened ("+
			detail(err.Error())+"). It resumes after the next full read of your mailbox.")
		return fail, st
	}
	if !ok {
		st.Lines = append(st.Lines, "The clerk began its record of the mail you read today, for a new account or because the saved record was lost or could not be read.")
	}
	since, _ := time.Parse(time.DateOnly, kept.Since)
	now, _ := time.Parse(time.DateOnly, today)
	ends := since.AddDate(0, 0, warmDays)
	if now.Before(ends) {
		st.Lines = append(st.Lines, fmt.Sprintf("Until %s, the clerk unsubscribes from no sender you have read mail from before: it is still learning when you read it.", ends.Format(time.DateOnly)))
	} else if !rec.Told {
		n := 0
		for _, d := range got {
			if t, err := time.Parse(time.DateOnly, d); err == nil && !now.Before(t.AddDate(0, 0, warmDays)) {
				n++
			}
		}
		st.Notices = append(st.Notices, fmt.Sprintf("The clerk has learned when you read mail. %d senders whose mail you have not opened in %d days may now be unsubscribed from; each still waits its hold, and STOP cancels it.", n, warmDays))
		rec.Told = true
	}
	rec.Log = kept
	if err := saveSeen(dir, s, slot, rec); err != nil {
		// The answer stands for this read; the next read starts from the
		// record as it was, which only re-dates mail to today.
		st.Lines = append(st.Lines, "The clerk could not save its record of the mail you read ("+detail(err.Error())+").")
	}
	return got, st
}
