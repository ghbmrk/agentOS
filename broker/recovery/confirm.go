package recovery

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"sort"
	"time"

	"github.com/ghbmrk/agentos/broker/durable"
)

// The owner's way out of a restore held for want of an anchor
// (PendingUnanchored) or of a log (PendingMissing): W3-forget-b1-4, on
// Mark's rulings D-065 and D-071. The restore leaves a question beside
// its marker (ConfirmSuffix): the restored log's last-forget date among
// decoys, then "later than all of these", then "never". The right answer
// releases the restore and hands its log on for the replay; any other
// keeps it held and closes the question. agentosd asks and answers it
// (writeQuestion). The question holds dates only, never what was
// forgotten.
const ConfirmSuffix = ".confirm"

const confirmFmt = "agentos-restore-confirm-v1"

const (
	// decoys is how many decoy dates are shown, so the owner always sees
	// decoys+1 dates whether or not the log holds a forget.
	decoys = 3
	// decoyGap is the least number of days between two dates shown.
	decoyGap = 45
	// fakeWindow is the days within which backups with no forget share
	// their stand-in date.
	fakeWindow = 90
	dateFmt    = "2006-01-02"
	decoyInfo  = "agentos-restore-confirm-v1"
)

var errBadQuestion = errors.New("recovery: the restore's question does not read")

// Confirmable reports whether a restore held for reason waits on the
// owner's answer; the others stay held (PendingNotice).
func Confirmable(reason string) bool {
	return reason == PendingUnanchored || reason == PendingMissing
}

// Question is what the owner is asked, as the writer checks it. Choices
// are the dates, in order, then Later(), then Never().
type Question struct {
	Reason string
	// Dates are calendar days in the box's zone at the restore, each at
	// midnight UTC, oldest first.
	Dates []time.Time
	// Newer are the verified backups newer than the restored one that the
	// restore command found, newest first.
	Newer []BackupEntry
	// Closed: the owner answered wrongly; the restore stays held.
	Closed bool
}

func (q Question) Later() int   { return len(q.Dates) }
func (q Question) Never() int   { return len(q.Dates) + 1 }
func (q Question) Choices() int { return len(q.Dates) + 2 }

type confirmFile struct {
	Format string          `json:"format"`
	Reason string          `json:"reason"`
	Dates  []string        `json:"dates"`
	Answer int             `json:"answer"`
	Log    json.RawMessage `json:"log,omitempty"`
	Newer  []BackupEntry   `json:"newer,omitempty"`
	Closed bool            `json:"closed,omitempty"`
}

func (f confirmFile) question() (Question, error) {
	if f.Format != confirmFmt || !Confirmable(f.Reason) || len(f.Dates) == 0 || f.Answer < 0 || f.Answer == len(f.Dates) || f.Answer > len(f.Dates)+1 {
		return Question{}, errBadQuestion
	}
	q := Question{Reason: f.Reason, Newer: f.Newer, Closed: f.Closed}
	for i, s := range f.Dates {
		d, err := time.Parse(dateFmt, s)
		if err != nil || i > 0 && !d.After(q.Dates[i-1]) {
			return Question{}, errBadQuestion
		}
		q.Dates = append(q.Dates, d)
	}
	return q, nil
}

// day is t's calendar day in loc, at midnight UTC.
func day(t time.Time, loc *time.Location) time.Time {
	y, m, d := t.In(loc).Date()
	return time.Date(y, m, d, 0, 0, 0, 0, time.UTC)
}

// newQuestion builds the question for a restore held for reason. has
// says the restored vault holds log; its last entry's date is the answer,
// or "never" with none. The decoys sit decoyGap to twice that apart, on
// both sides of the real date as far as the backup's date (created)
// allows, so the real date is at any place in the list; with no real
// date, a past day takes its place as one more decoy. now gives only the
// box's zone: r (decoyStream) and created fix the question, so every
// restore of one backup asks the same one and comparing two shows no
// date in common but the answer.
func newQuestion(reason string, l forgetLog, has bool, now time.Time, newer []BackupEntry, created time.Time, r io.Reader) (confirmFile, error) {
	rnd := func(lo, hi int) (int, error) { // in [lo, hi)
		b, err := random(r, 8)
		if err != nil {
			return 0, err
		}
		return lo + int(binary.BigEndian.Uint64(b)%uint64(hi-lo)), nil
	}
	f := confirmFile{Format: confirmFmt, Reason: reason}
	bound := day(created, now.Location())
	pivot, answer := time.Time{}, -1
	if has && len(l.Entries) > 0 {
		pivot = day(l.Entries[len(l.Entries)-1].At, now.Location())
		answer = 0
	} else {
		n, err := rnd(decoyGap, 366)
		if err != nil {
			return f, err
		}
		// From the start of bound's window, so backups made weeks apart
		// still ask alike.
		start := bound.AddDate(0, 0, -int(bound.Unix()/86400%fakeWindow))
		pivot = start.AddDate(0, 0, -n)
	}
	room := 0 // decoys that fit between the pivot and bound
	for room < decoys && !pivot.AddDate(0, 0, (room+1)*decoyGap).After(bound) {
		room++
	}
	after, err := rnd(0, room+1)
	if err != nil {
		return f, err
	}
	dates := []time.Time{pivot}
	for i, d := 0, pivot; i < after; i++ {
		g, err := rnd(decoyGap, 2*decoyGap)
		if err != nil {
			return f, err
		}
		// Leave room for the decoys still to come.
		if lim := int(bound.Sub(d).Hours()/24) - (after-i-1)*decoyGap; g > lim {
			g = lim
		}
		d = d.AddDate(0, 0, g)
		dates = append(dates, d)
	}
	for i, d := 0, pivot; i < decoys-after; i++ {
		g, err := rnd(decoyGap, 2*decoyGap)
		if err != nil {
			return f, err
		}
		d = d.AddDate(0, 0, -g)
		dates = append(dates, d)
	}
	sort.Slice(dates, func(i, j int) bool { return dates[i].Before(dates[j]) })
	for i, d := range dates {
		f.Dates = append(f.Dates, d.Format(dateFmt))
		if answer >= 0 && d.Equal(pivot) {
			answer = i
		}
	}
	f.Answer = answer
	if answer < 0 {
		f.Answer = len(dates) + 1 // never
	}
	if has {
		if f.Log, err = json.Marshal(l); err != nil {
			return f, err
		}
	}
	for _, b := range newer {
		if b.Verified && b.Created.After(created) {
			b.Key = "" // agentosd names the backup; it needs no key ID
			f.Newer = append(f.Newer, b)
		}
	}
	sort.SliceStable(f.Newer, func(i, j int) bool { return f.Newer[i].Created.After(f.Newer[j].Created) })
	return f, nil
}

// decoyStream is the bytes newQuestion draws the decoys from: an
// HMAC-SHA256 counter stream under a key derived from rk, over the
// restored log's last entry (its ID with none, a fixed label with no
// log). Every restore of a backup, and of any backup with the same last
// forget, draws the same bytes, which no one without rk can predict.
func decoyStream(rk RecoveryKey, l forgetLog, has bool) io.Reader {
	in := []byte("no-log")
	if has && len(l.Entries) > 0 {
		in = append([]byte("entry\x00"), l.Entries[len(l.Entries)-1].MAC...)
	} else if has {
		in = append([]byte("log\x00"), l.ID...)
	}
	return &prfStream{key: hkdf(rk.b[:], nil, decoyInfo, 32), in: in}
}

type prfStream struct {
	key, in, buf []byte
	n            uint64
}

func (s *prfStream) Read(p []byte) (int, error) {
	for len(s.buf) < len(p) {
		m := hmac.New(sha256.New, s.key)
		m.Write(s.in)
		var c [8]byte
		binary.BigEndian.PutUint64(c[:], s.n)
		m.Write(c[:])
		s.buf, s.n = m.Sum(s.buf), s.n+1
	}
	n := copy(p, s.buf)
	s.buf = s.buf[n:]
	return n, nil
}

// writeQuestion leaves f beside the marker of the restore held at path
// (Layout.ForgetLog). agentosd reads and answers it there with no access
// to this package or the vault (cmd/agentosd restoreconfirm.go): the
// right answer writes Log to path, then removes the marker and the
// question; a wrong one sets Closed. testdata/confirm-v1.json pins the
// format for both sides.
func writeQuestion(path string, f confirmFile) error {
	if _, err := f.question(); err != nil {
		return err
	}
	enc, err := json.Marshal(f)
	if err != nil {
		return err
	}
	return durable.WriteFile(path+ConfirmSuffix, enc, 0o600)
}
