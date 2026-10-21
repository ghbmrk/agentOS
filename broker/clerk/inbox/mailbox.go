package inbox

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ghbmrk/agentos/broker/clerk/inbox/imapsmtp"
)

// Mailbox is where the clerk's effects land. Do calls it only after the
// step passed the clerk's one check (clerk.Check) and the clerk's own rules,
// so nothing reaches a mailbox that the kernel did not dispatch. Each method
// acts on one mail by the id the clerk read it under and confirms the effect
// before it returns nil. A NotDone error means nothing changed; any other
// error means the effect may have happened and was not confirmed.
type Mailbox interface {
	Label(ctx context.Context, mail, label string) error
	Trash(ctx context.Context, mail string) error
	Post(ctx context.Context, p Post) error
}

// NotDone is a mailbox's refusal before acting, as the clerk's reason.
type NotDone string

func (e NotDone) Error() string { return "inbox: not done: " + string(e) }

// The reasons a mailbox refuses before acting.
const (
	nUnknown    NotDone = "unknown-mail"    // not a mail this mailbox read
	nRenumbered NotDone = "renumbered"      // the folder's UID validity changed
	nNoMove     NotDone = "no-move"         // the server cannot MOVE without EXPUNGE
	nNoTrash    NotDone = "no-trash-folder" // the account has no folder with the trash role
	nNoPoster   NotDone = "no-poster"       // no one-click POSTer is wired (#2601)
	nBadFlag    NotDone = "bad-flag"        // a label that is not one of the clerk's keywords
)

// Synthetic is the eval's mailbox (MIG-3-1): every effect is accepted and
// lands nowhere; the clerk's own record (Effects, Posts) is the outcome.
type Synthetic struct{}

func (Synthetic) Label(context.Context, string, string) error { return nil }
func (Synthetic) Trash(context.Context, string) error         { return nil }
func (Synthetic) Post(context.Context, Post) error            { return nil }

// readMax is how many of the newest inbox mails Live reads: a day's worth
// of the clerk's organize and trash effects (DailyCap), so what is read is
// what one day can act on, and memory stays bounded by readMax times the
// transport's MaxFetch.
const readMax = DailyCap

// fetchBatch is how many mails one fetch asks for.
const fetchBatch = 50

// Live is the owner's mailbox over IMAP and SMTP (SPEC: the mail clerk
// supports any IMAP and SMTP provider). It reads the inbox without marking
// anything read and acts only on the mails it read, by their full reference:
// a label is an IMAP keyword, a trash is a UID MOVE to the account's trash
// folder, never an EXPUNGE. Each effect is read back before it counts.
type Live struct {
	st *imapsmtp.Store

	mu    sync.Mutex
	refs  map[string]liveMail
	trash string // the trash folder's name, "" when the account has none
}

type liveMail struct {
	ref imapsmtp.Ref
	id  string // the Message-ID header, for the trash read-back
}

// NewLive is a mailbox over st.
func NewLive(st *imapsmtp.Store) *Live { return &Live{st: st, refs: map[string]liveMail{}} }

// Read fetches the newest readMax inbox mails with BODY.PEEK, unclassified:
// a class comes from a reader, not from the mailbox. It replaces what an
// earlier Read found.
func (l *Live) Read(ctx context.Context) ([]Mail, error) {
	fs, err := l.st.Folders(ctx)
	if err != nil {
		return nil, err
	}
	inbox, trash := "", ""
	for _, f := range fs {
		switch f.Role {
		case imapsmtp.Inbox:
			inbox = f.Name
		case imapsmtp.Trash:
			if trash == "" {
				trash = f.Name
			}
		}
	}
	if inbox == "" {
		return nil, errors.New("inbox: the account lists no inbox")
	}
	validity, uids, err := l.st.UIDs(ctx, inbox)
	if err != nil {
		return nil, err
	}
	if len(uids) > readMax {
		uids = newest(uids, readMax)
	}
	refs := map[string]liveMail{}
	var out []Mail
	for i := 0; i < len(uids); i += fetchBatch {
		ms, err := l.st.Fetch(ctx, inbox, validity, uids[i:min(i+fetchBatch, len(uids))])
		if err != nil {
			return nil, err
		}
		for _, m := range ms {
			id := fmt.Sprintf("imap-%d-%d", m.Validity, m.UID)
			refs[id] = liveMail{ref: m.Ref, id: messageID(m.Raw)}
			out = append(out, Mail{ID: id, Raw: m.Raw})
		}
	}
	l.mu.Lock()
	l.refs, l.trash = refs, trash
	l.mu.Unlock()
	return out, nil
}

// SeenLog is the clerk's record of each mail turning \Seen (#2684), its own
// state, which Opened replaces whole on each read and the clerk's process
// keeps sealed (MIG-4-run). Since is the day the record began. Each entry
// holds only a sender, a digest naming the mail and the day the clerk first
// saw it read.
type SeenLog struct {
	Since string `json:"since"`
	Seen  []Seen `json:"seen"`
}

// Seen is one SeenLog entry. ID is seenID's digest, never the Message-ID.
type Seen struct {
	From string `json:"from"`
	ID   string `json:"id"`
	Date string `json:"date"`
}

// seenID names a mail by its sender, Message-ID and arrival without keeping
// the Message-ID, which can carry a host or account name. The arrival is the
// server's INTERNALDATE, so a new mail that reuses an earlier one's
// Message-ID is a new entry, dated the day it is first seen read, and cannot
// pass for the old read.
func seenID(from, messageID string, arrived time.Time) [16]byte {
	h := sha256.Sum256([]byte(from + "\n" + messageID + "\n" + strconv.FormatInt(arrived.Unix(), 10)))
	return [16]byte(h[:16])
}

// openedMax bounds what one Opened call holds, in bytes, so a server that
// reports millions of read mails or senders costs a refusal, not the clerk's
// memory; an account past it fails closed. A sender is charged its address
// and senderCost, a log entry its sender and entryCost: the most each costs in
// the maps, the log read in and the log handed back, measured at about 300
// bytes an entry (TestOpenedHoldsNoMoreThanItCharges). The bound is as many
// read mails as one folder's UID SEARCH can name, searchMax, at entryCost
// each, about 384 MiB. It holds the whole call: every folder's read mail, the
// log's entries for mail since deleted, and the senders' addresses on top, so
// an account with more than that fails closed (no sender is unsubscribed),
// where a single folder that large could not be searched at all.
var openedMax = searchMax * entryCost

// searchMax is how many UIDs one search reply can carry: the IMAP client's
// field bound (mail M21; tests/test_egress_memory.py checks the two agree).
const searchMax = 1 << 20

const (
	senderCost = 128
	entryCost  = 384
)

var errTooMuchReadMail = errors.New("inbox: more read mail than the clerk keeps")

// opened is one Opened call's state: LastOpened as it is built, and the log
// by digest, each entry marked when this read found its mail.
type opened struct {
	today   string
	watched bool
	since   string
	senders map[string]string
	log     map[[16]byte]logged
	kept    int
}

type logged struct {
	from, date string
	present    bool
}

func (o *opened) charge(n int) error {
	if o.kept += n; o.kept > openedMax {
		return errTooMuchReadMail
	}
	return nil
}

// newOpened starts from log. Until the log has watched for unopenedDays, and
// for a read mail with no Message-ID or INTERNALDATE, a read mail counts as
// opened today. A log with no valid Since, or one after today, begins today;
// an entry dated outside Since to today counts as today; and an entry the
// clerk did not write is logged again as one it did.
func newOpened(today string, log SeenLog) (*opened, error) {
	o := &opened{today: today, since: log.Since, senders: map[string]string{}, log: map[[16]byte]logged{}}
	now, ok := day(today)
	since, ok2 := day(log.Since)
	if !ok || !ok2 || since.After(now) {
		since, o.since = now, today
	}
	o.watched = int(now.Sub(since).Hours()/24) >= unopenedDays
	for _, e := range log.Seen {
		if e.From == "" {
			continue // names no sender to open
		}
		b, err := hex.DecodeString(e.ID)
		if err != nil || len(b) != 16 {
			// Not an entry the clerk wrote: it is logged again under a digest
			// no read mail has (a logged mail has an arrival), so it keeps its
			// sender opened as long as any other entry, its day held to the
			// same bounds.
			id := seenID(e.From, e.ID, time.Time{})
			b = id[:]
		}
		if d, ok := day(e.Date); !ok || d.Before(since) || d.After(now) {
			e.Date = today
		}
		if err := o.add([16]byte(b), e.From, e.Date, false); err != nil {
			return nil, err
		}
	}
	return o, nil
}

// add logs a mail once and opens its sender on the entry's day; a mail this
// read found is marked present.
func (o *opened) add(id [16]byte, from, date string, present bool) error {
	if e, ok := o.log[id]; ok {
		if present && !e.present {
			e.present = true
			o.log[id] = e
		}
		return nil
	}
	if err := o.charge(len(from) + entryCost); err != nil {
		return err
	}
	if err := o.open(from, date); err != nil {
		return err
	}
	o.log[id] = logged{from: from, date: date, present: present}
	return nil
}

// open sets a sender's day to the latest seen.
func (o *opened) open(from, date string) error {
	if d, ok := o.senders[from]; ok {
		if date > d {
			o.senders[from] = date
		}
		return nil
	}
	if err := o.charge(len(from) + senderCost); err != nil {
		return err
	}
	o.senders[from] = date
	return nil
}

// header takes one read mail's From and Message-ID headers and arrival.
func (o *opened) header(h []byte, arrived time.Time) error {
	from, mid := FromAddress(h), messageID(h)
	if from == "" {
		return nil
	}
	named := mid != "" && !arrived.IsZero()
	if named {
		if err := o.add(seenID(from, mid, arrived), from, o.today, true); err != nil {
			return err
		}
	}
	if !o.watched || !named {
		return o.open(from, o.today)
	}
	return nil
}

// result is LastOpened and the log to keep: every entry this read found, and
// every other one from the last unopenedDays, which still opens its sender;
// an older one whose mail is gone opens nothing and is dropped.
func (o *opened) result() (map[string]string, SeenLog) {
	now, _ := day(o.today)
	out := SeenLog{Since: o.since, Seen: make([]Seen, 0, len(o.log))}
	for id, e := range o.log {
		d, _ := day(e.date)
		if e.present || int(now.Sub(d).Hours()/24) < unopenedDays {
			out.Seen = append(out.Seen, Seen{From: e.from, ID: hex.EncodeToString(id[:]), Date: e.date})
		}
	}
	slices.SortFunc(out.Seen, func(a, b Seen) int { return strings.Compare(a.From+a.ID, b.From+b.ID) })
	return o.senders, out
}

// Opened is World.LastOpened for the account (#2618), keyed by lower-cased
// address, and the log to keep in place of log (#2684). Each read (\Seen)
// mail in any folder that log lacks is logged, dated today, and a logged
// sender is opened on its latest entry's day, so a mail the owner read and
// then deleted for good still counts. IMAP keeps no time a mail was opened,
// so until the log has watched for unopenedDays, and for a read mail with no
// Message-ID or INTERNALDATE, a read mail is taken as opened today whenever it was delivered:
// no sender is unsubscribed on a guess (fail closed). Any folder that cannot
// be read in full fails the whole answer, and the caller then keeps its log
// as it was: no partial answer passes for a full one.
func (l *Live) Opened(ctx context.Context, today string, log SeenLog) (map[string]string, SeenLog, error) {
	o, err := newOpened(today, log)
	if err != nil {
		return nil, SeenLog{}, err
	}
	fs, err := l.st.Folders(ctx)
	if err != nil {
		return nil, SeenLog{}, err
	}
	for _, f := range fs {
		if err := l.st.Seen(ctx, f.Name, o.header); err != nil {
			return nil, SeenLog{}, err
		}
	}
	got, kept := o.result()
	return got, kept, nil
}

// newest is the n highest UIDs, in ascending order.
func newest(uids []uint32, n int) []uint32 {
	s := append([]uint32(nil), uids...)
	slices.Sort(s)
	return s[len(s)-n:]
}

func (l *Live) mail(id string) (liveMail, string, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	m, ok := l.refs[id]
	if !ok {
		return liveMail{}, "", nUnknown
	}
	return m, l.trash, nil
}

// before maps a transport error from a change: one the server refused before
// acting is NotDone, anything else may have acted.
func before(err error) error {
	switch {
	case errors.Is(err, imapsmtp.ErrValidity):
		return nRenumbered
	case errors.Is(err, imapsmtp.ErrNoMove):
		return nNoMove
	case errors.Is(err, imapsmtp.ErrBadFlag):
		return nBadFlag
	}
	return err
}

// errUnconfirmed: the effect was asked for but the read-back does not show it.
var errUnconfirmed = errors.New("inbox: the mailbox does not show the effect")

// Label adds label to the mail as an IMAP keyword and reads it back. Only
// the clerk's own keywords are labels: a system flag such as \Deleted is not.
func (l *Live) Label(ctx context.Context, id, label string) error {
	if !strings.HasPrefix(label, labelPrefix) {
		return nBadFlag
	}
	m, _, err := l.mail(id)
	if err != nil {
		return err
	}
	if err := l.st.SetFlags(ctx, m.ref, []string{label}, nil); err != nil {
		return before(err)
	}
	got, err := l.st.Fetch(ctx, m.ref.Folder, m.ref.Validity, []uint32{m.ref.UID})
	if err != nil {
		return err
	}
	if len(got) != 1 || !hasFlag(got[0].Flags, label) {
		return errUnconfirmed
	}
	return nil
}

// Trash moves the mail to the account's trash folder and reads it back: it
// is gone from where it was and its Message-ID is in the trash. A mail with
// no Message-ID cannot be found there, so its trash is never confirmed.
func (l *Live) Trash(ctx context.Context, id string) error {
	m, trash, err := l.mail(id)
	if err != nil {
		return err
	}
	if trash == "" {
		return nNoTrash
	}
	if err := l.st.Move(ctx, m.ref, trash); err != nil {
		return before(err)
	}
	left, err := l.st.Fetch(ctx, m.ref.Folder, m.ref.Validity, []uint32{m.ref.UID})
	if err != nil {
		return err
	}
	if len(left) != 0 || m.id == "" {
		return errUnconfirmed
	}
	there, err := l.st.Find(ctx, trash, m.id, func(x imapsmtp.Message) bool { return messageID(x.Raw) == m.id })
	if err != nil {
		return err
	}
	if len(there) == 0 {
		return errUnconfirmed
	}
	return nil
}

// Post refuses: the one-click POSTer and its egress rules are #2601, so a
// live unsubscribe is not sent and not reported as sent.
func (l *Live) Post(context.Context, Post) error { return nNoPoster }

func hasFlag(flags []string, f string) bool {
	for _, x := range flags {
		if strings.EqualFold(x, f) {
			return true
		}
	}
	return false
}

// messageID is the message's Message-ID header value, trimmed, or "".
func messageID(raw []byte) string {
	hs, _ := splitMessage(raw)
	for _, h := range hs {
		if h.key() == "message-id" {
			return strings.TrimSpace(string(h.value))
		}
	}
	return ""
}
