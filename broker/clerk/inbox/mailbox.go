package inbox

import (
	"bytes"
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
	nNoPoster   NotDone = "no-poster"       // the mailbox has no one-click POSTer (#2601)
	nBadFlag    NotDone = "bad-flag"        // a label that is not one of the clerk's keywords
	// A change's session signs in before it acts, so a refused sign-in or a
	// server never reached has changed nothing.
	nSignInRefused NotDone = "sign-in-refused" // the server refused the login (imapsmtp.ErrLoginRefused)
	nUnreachable   NotDone = "unreachable"     // the mail server was not reached (imapsmtp.ErrUnreachable)
	nNoSignIn      NotDone = "no-sign-in"      // the server offers no sign-in the clerk supports (imapsmtp.ErrNoSignIn)
	nNoUIDNext     NotDone = "no-uidnext"      // the trash gave no next UID to confirm a move by (imapsmtp.ErrNoUIDNext)
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
	st     *imapsmtp.Store
	poster *Poster // nil, unless WithPoster: unsubscribes are refused (no-poster)

	mu    sync.Mutex
	refs  map[string]liveMail
	trash string // the trash folder's name, "" when the account has none
	// claimed holds the trash copies that confirmed a trash, so a copy
	// confirms one trash only: another mail with the same Message-ID, whose
	// own move was lost, is not confirmed by it.
	claimed map[imapsmtp.Ref]bool
}

type liveMail struct {
	ref imapsmtp.Ref
	id  string // the Message-ID header, for the trash read-back
	// The trash's UID validity and next UID before the first move of this
	// mail, kept for its resends: a move whose answer was lost has put the
	// copy below a UIDNEXT read again.
	trashValidity, trashNext uint32
}

// NewLive is a mailbox over st. It has no Poster, so its unsubscribes are
// refused (no-poster) until WithPoster turns them on.
func NewLive(st *imapsmtp.Store) *Live {
	return &Live{st: st, refs: map[string]liveMail{}, claimed: map[imapsmtp.Ref]bool{}}
}

// WithPoster gives l a Poster on st's own address policy, so its
// unsubscribes reach no address the mail servers could not, and returns l.
// Call it before l is used. The clerk turns it on only once a failing
// Opened read saves the senders it found (#2841, run ASSUMPTIONS
// MIG-4-run-q); until then a sender read recently could look never opened.
func (l *Live) WithPoster() *Live {
	l.poster = NewPoster(l.st.Guard(), nil)
	return l
}

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
// where a single folder that large could not be searched at all. An entry
// older than unopenedDays is charged only oldCost, what reading it in and
// finding it again cost (measured at about 150 bytes,
// TestOpenedHoldsNoMoreThanItChargesForOldEntries), until the read finds its
// mail and it is charged in full: deleting such a mail for good frees the
// rest of its charge (#2742 item 3c), where before the frozen log kept every
// entry charged and a call past the bound failed for good.
var openedMax = OpenedMax

// OpenedMax is openedMax as the package sets it, for what is derived from
// it (the host's sealed seen log).
const OpenedMax = searchMax * entryCost

// searchMax is how many UIDs one search reply can carry: the IMAP client's
// field bound (mail M21; tests/test_egress_memory.py checks the two agree).
const searchMax = 1 << 20

const (
	senderCost = 128
	entryCost  = 384
	oldCost    = 192
)

// ErrTooMuchReadMail fails an Opened call past openedMax. It does not pass
// with time or by archiving, since every folder is read: the owner must
// delete read mail for good, from the trash too. Deleting a mail read since
// the last good read frees its whole charge, so deleting those always clears
// it; a mail the log first saw read more than unopenedDays ago frees about
// half (entryCost less oldCost), and one logged since frees nothing until it
// is that old.
var ErrTooMuchReadMail = errors.New("inbox: more read mail than the clerk keeps")

// opened is one Opened call's state: LastOpened as it is built, and the log
// by digest, each entry marked when this read found its mail.
type opened struct {
	today   string
	watched bool
	since   string
	senders map[string]string
	log     map[[16]byte]logged
	old     []oldEntry // the log's entries older than unopenedDays, by digest
	kept    int
}

// oldEntry is a log entry older than unopenedDays, kept out of the log until
// the read finds its mail: one that is gone is dropped, having cost oldCost.
type oldEntry struct {
	id         [16]byte
	from, date string
}

type logged struct {
	from, date string
	present    bool
}

func (o *opened) charge(n int) error {
	if o.kept += n; o.kept > openedMax {
		return ErrTooMuchReadMail
	}
	return nil
}

// newOpened starts from log. Until the log has watched for unopenedDays, and
// for a read mail with no Message-ID or INTERNALDATE, a read mail counts as
// opened today. A log with no valid Since, or one after today, begins today;
// an entry dated outside Since to today counts as today; and an entry the
// clerk did not write is logged again as one it did, dated today.
func newOpened(today string, log SeenLog) (*opened, error) {
	o := &opened{today: today, since: log.Since, senders: map[string]string{}, log: map[[16]byte]logged{}}
	now, ok := day(today)
	since, ok2 := day(log.Since)
	if !ok || !ok2 || since.After(now) {
		since, o.since = now, today
	}
	o.watched = int(now.Sub(since).Hours()/24) >= unopenedDays
	if o.watched {
		o.old = make([]oldEntry, 0, len(log.Seen))
	}
	for _, e := range log.Seen {
		if e.From == "" {
			continue // names no sender to open
		}
		b, err := hex.DecodeString(e.ID)
		if err != nil || len(b) != 16 {
			// Not an entry the clerk wrote, so its day is not trusted either:
			// it is logged again, dated today, under a digest no read mail
			// has (a logged mail has an arrival), and keeps its sender opened
			// as long as any other entry.
			id := seenID(e.From, e.ID, time.Time{})
			b, e.Date = id[:], today
		}
		d, ok := day(e.Date)
		if !ok || d.Before(since) || d.After(now) {
			d, e.Date = now, today
		}
		if int(now.Sub(d).Hours()/24) >= unopenedDays {
			if err := o.charge(len(e.From) + oldCost); err != nil {
				return nil, err
			}
			if err := o.open(e.From, e.Date); err != nil {
				return nil, err
			}
			o.old = append(o.old, oldEntry{id: [16]byte(b), from: e.From, date: e.Date})
			continue
		}
		if err := o.add([16]byte(b), e.From, e.Date, false); err != nil {
			return nil, err
		}
	}
	slices.SortFunc(o.old, func(a, b oldEntry) int { return bytes.Compare(a.id[:], b.id[:]) })
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
	if present {
		// A logged old entry the read finds keeps its day; its sender and
		// oldCost are already charged.
		if i, ok := slices.BinarySearchFunc(o.old, id, func(e oldEntry, id [16]byte) int { return bytes.Compare(e.id[:], id[:]) }); ok {
			if err := o.charge(entryCost - oldCost); err != nil {
				return err
			}
			o.log[id] = logged{from: o.old[i].from, date: o.old[i].date, present: true}
			return nil
		}
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

// Mark is the mailbox's state across its folders, as STATUS gives it, so a
// caller can skip a full read that would find nothing new (#2742 item 1).
// The caller takes the Mark before a read and keeps it once the read is
// done, whether it succeeded or failed for good (ErrTooMuchReadMail): taken
// after, it would already hold mail that arrived during the read; and a
// lasting failure is tried again only when the owner's changes move the
// Mark. It reads again only when Same says the mailbox changed, or an error
// leaves no Mark, and in any case after a ceiling well under unopenedDays:
// without CONDSTORE a mail read and another marked unread together, with
// nothing else changed, leave the Mark the same, and Opened also moves with
// the day (a read mail with no Message-ID, and every read mail before the
// log has watched for unopenedDays, counts as opened today).
type Mark []imapsmtp.Mark

// Mark is the mailbox's Mark now: one session listing the folders and
// asking each one's STATUS; on any error it is nil.
func (l *Live) Mark(ctx context.Context) (Mark, error) {
	ms, err := l.st.Marks(ctx)
	return Mark(ms), err
}

// Same reports whether m and o show the mailbox unchanged: the same folders
// in the same state, every one with a UID validity and next UID to go by.
// A Mark with a folder the server gave neither is never the same (fail
// closed).
func (m Mark) Same(o Mark) bool {
	if len(m) == 0 || !slices.Equal(m, o) {
		return false
	}
	for _, f := range m {
		if f.Validity == 0 || f.Next == 0 {
			return false
		}
	}
	return true
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
	case errors.Is(err, imapsmtp.ErrLoginRefused):
		return nSignInRefused
	case errors.Is(err, imapsmtp.ErrUnreachable):
		return nUnreachable
	case errors.Is(err, imapsmtp.ErrNoSignIn):
		return nNoSignIn
	case errors.Is(err, imapsmtp.ErrNoUIDNext):
		return nNoUIDNext
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
	// Only a copy that arrives in the trash with this move confirms it: an
	// older one with the same Message-ID would confirm a move that did not
	// happen (#2665).
	validity, next := m.trashValidity, m.trashNext
	if next == 0 {
		if validity, next, err = l.st.Next(ctx, trash); err != nil {
			return before(err)
		}
		l.markTrash(id, validity, next)
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
	there, err := l.st.FindSince(ctx, trash, validity, next, m.id, func(x imapsmtp.Message) bool { return messageID(x.Raw) == m.id })
	if err != nil {
		return err
	}
	if !l.claim(there) {
		return errUnconfirmed
	}
	return nil
}

// claim marks the first of copies that no trash has claimed yet, and reports
// whether there was one.
func (l *Live) claim(copies []imapsmtp.Message) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, c := range copies {
		if !l.claimed[c.Ref] {
			l.claimed[c.Ref] = true
			return true
		}
	}
	return false
}

// markTrash keeps the trash's validity and next UID from before mail id's
// first move.
func (l *Live) markTrash(id string, validity, next uint32) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if m, ok := l.refs[id]; ok && m.trashNext == 0 {
		m.trashValidity, m.trashNext = validity, next
		l.refs[id] = m
	}
}

// Post sends the one-click unsubscribe through the mailbox's Poster
// (#2601). A Live with none, as NewLive gives, refuses (no-poster), so the
// unsubscribe is not sent and not reported as sent.
func (l *Live) Post(ctx context.Context, p Post) error {
	if l.poster == nil {
		return nNoPoster
	}
	return l.poster.Post(ctx, p)
}

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
