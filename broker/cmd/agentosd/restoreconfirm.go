package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// The owner's way out of a restore held for want of an anchor or of a log
// (W3-forget-b1-4, D-065, D-071). broker/recovery leaves a question beside
// the hold's marker (forget-log.json.confirm): the restored log's
// last-forget date among decoys, then "later than all of these", then
// "never". agentosd reads and answers it here without importing recovery
// (the vault process's alone); recovery/testdata/confirm-v1.json pins the
// format for both sides. The texts hold dates only, never what was
// forgotten. Sending them while agentosd is held, and starting once
// released, is the held mode's wiring (b1-7).
const (
	heldUnanchored = "Restore on hold: this new PC can't check your forget list."
	heldMissing    = "Restore on hold: this backup was made before your agent kept a forget list."
	heldAsk        = "When did you last have your agent forget something?"
	heldLater      = "Later than all of these"
	heldNever      = "Never"
	heldWrong      = "Restore stays on hold: this backup is older than your last forget, so it could bring back what you had forgotten."
	heldNoNewer    = "Restore a newer backup, or from your old drive, instead."
	heldReleased   = "Restore confirmed. Your agent starts again shortly."
	heldDateFmt    = "2 Jan 2006"
)

// The question's file, as recovery writes it (recovery confirm.go).
const (
	confirmSuffix     = ".confirm"
	confirmFormat     = "agentos-restore-confirm-v1"
	pendingUnanchored = "forget-log-unanchored"
	pendingMissing    = "forget-log-missing"
)

var (
	errNoQuestion  = errors.New("agentosd: no restore is waiting for the owner's answer")
	errBadQuestion = errors.New("agentosd: the restore's question does not read")
)

type heldBackup struct {
	Destination string    `json:"destination"`
	Created     time.Time `json:"created"`
	Verified    bool      `json:"verified,omitempty"`
}

type heldQuestion struct {
	Format string          `json:"format"`
	Reason string          `json:"reason"`
	Dates  []string        `json:"dates"`
	Answer int             `json:"answer"`
	Log    json.RawMessage `json:"log,omitempty"`
	Newer  []heldBackup    `json:"newer,omitempty"`
	Closed bool            `json:"closed,omitempty"`

	days []time.Time
}

func (q heldQuestion) later() int   { return len(q.days) }
func (q heldQuestion) never() int   { return len(q.days) + 1 }
func (q heldQuestion) choices() int { return len(q.days) + 2 }

// loadHeld reads the question of the restore held in dir. ok is false
// when no restore is held there, or held with no question (a rolled-back
// or forged log, which the owner cannot confirm). A question that does not
// read is an error, and the restore stays held.
func loadHeld(dir string) (heldQuestion, bool, error) {
	path := filepath.Join(dir, forgetLogFile)
	if _, err := os.Lstat(path + ".pending"); os.IsNotExist(err) {
		return heldQuestion{}, false, nil
	} else if err != nil {
		return heldQuestion{}, false, err
	}
	raw, err := os.ReadFile(path + confirmSuffix)
	if os.IsNotExist(err) {
		return heldQuestion{}, false, nil
	} else if err != nil {
		return heldQuestion{}, false, err
	}
	var q heldQuestion
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(&q); err != nil {
		return heldQuestion{}, false, errBadQuestion
	}
	if q.Format != confirmFormat || q.Reason != pendingUnanchored && q.Reason != pendingMissing || len(q.Dates) == 0 {
		return heldQuestion{}, false, errBadQuestion
	}
	for i, s := range q.Dates {
		t, err := time.Parse("2006-01-02", s)
		if err != nil || i > 0 && !t.After(q.days[i-1]) {
			return heldQuestion{}, false, errBadQuestion
		}
		q.days = append(q.days, t)
	}
	// "Later than all of these" is never right: the real date is listed.
	if q.Answer < 0 || q.Answer >= q.choices() || q.Answer == q.later() {
		return heldQuestion{}, false, errBadQuestion
	}
	return q, true, nil
}

// heldText is the text that asks the owner about the restore held in dir,
// or says it stays held once they answered wrongly. ok is false when no
// restore there waits on the owner.
func heldText(dir string) (string, bool, error) {
	q, ok, err := loadHeld(dir)
	if err != nil || !ok {
		return "", false, err
	}
	if q.Closed {
		return wrongText(q), true, nil
	}
	return askText(q), true, nil
}

func askText(q heldQuestion) string {
	head := heldUnanchored
	if q.Reason == pendingMissing {
		head = heldMissing
	}
	lines := []string{head, heldAsk}
	for i, d := range q.days {
		lines = append(lines, string(letter(i))+" "+d.Format(heldDateFmt))
	}
	lines = append(lines, string(letter(q.later()))+" "+heldLater, string(letter(q.never()))+" "+heldNever)
	var replies []string
	for i := 0; i < q.choices(); i++ {
		replies = append(replies, string(letter(i)))
	}
	n := len(replies)
	lines = append(lines, "Reply "+strings.Join(replies[:n-1], ", ")+" or "+replies[n-1]+".")
	return strings.Join(lines, "\n")
}

// wrongText tells the owner the restore stays held, and offers the newest
// newer backup the restore found, if any (D-071).
func wrongText(q heldQuestion) string {
	next := heldNoNewer
	if len(q.Newer) > 0 {
		b := q.Newer[0]
		next = "Restore your newer backup from " + b.Created.Local().Format(heldDateFmt) + " on " + plainName(b.Destination) + " instead."
	}
	return heldWrong + "\n" + next
}

func letter(i int) rune { return rune('A' + i) }

// plainName keeps a destination's name to plain characters and a short
// length, so the text stays GSM-7 and within its segments (CH-12).
func plainName(s string) string {
	s = strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune(" -._", r) {
			return r
		}
		return -1
	}, s)
	if s = strings.TrimSpace(s); len(s) > 24 {
		s = strings.TrimSpace(s[:24])
	}
	if s == "" {
		return "its drive"
	}
	return s
}

// parseChoice reads the owner's reply as one of n letters, alone or after
// "reply"; anything else is no choice.
func parseChoice(msg string, n int) (int, bool) {
	f := strings.Fields(strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' {
			return r
		}
		return ' '
	}, strings.ToUpper(msg)))
	if len(f) == 2 && f[0] == "REPLY" {
		f = f[1:]
	}
	if len(f) != 1 || len(f[0]) != 1 {
		return 0, false
	}
	c := int(f[0][0]) - 'A'
	return c, c >= 0 && c < n
}

// answerHeld takes the owner's reply to the restore held in dir and
// returns the text to send back. The right choice hands the restored log
// on to the replay and lifts the hold (released); any other choice closes
// the question and keeps the restore held, as does every reply after it;
// a reply that is no choice asks again.
func answerHeld(dir, msg string) (string, bool, error) {
	q, ok, err := loadHeld(dir)
	if err != nil {
		return "", false, err
	}
	if !ok {
		return "", false, errNoQuestion
	}
	if q.Closed {
		return wrongText(q), false, nil
	}
	c, ok := parseChoice(msg, q.choices())
	if !ok {
		return askText(q), false, nil
	}
	path := filepath.Join(dir, forgetLogFile)
	if c != q.Answer {
		q.Closed = true
		enc, err := json.Marshal(q)
		if err != nil {
			return "", false, err
		}
		if err := writeSynced(path+confirmSuffix, enc); err != nil {
			return "", false, err
		}
		return wrongText(q), false, nil
	}
	if q.Log != nil {
		if err := writeSynced(path, q.Log); err != nil {
			return "", false, err
		}
	}
	// The marker goes once the log is on disk (writeSynced), and before
	// the question: a crash after it leaves a question that loadHeld no
	// longer reads.
	if err := os.Remove(path + ".pending"); err != nil {
		return "", false, err
	}
	if err := syncDir(dir); err != nil {
		return "", false, err
	}
	if err := os.Remove(path + confirmSuffix); err != nil && !os.IsNotExist(err) {
		return heldReleased, true, err
	}
	return heldReleased, true, nil
}

// writeSynced replaces path with raw through a synced temporary file, so a
// crash leaves the old file or the new one, and syncs the directory so
// the new one stays.
func writeSynced(path string, raw []byte) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".restore-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err := f.Write(raw); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(f.Name(), path); err != nil {
		return err
	}
	return syncDir(filepath.Dir(path))
}

// syncDir makes dir's entries durable, as recovery's writeAtomic does; a
// variable so a test can watch the order.
var syncDir = func(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	serr := d.Sync()
	if err := d.Close(); serr == nil {
		serr = err
	}
	return serr
}
