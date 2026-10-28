package inbox

import (
	"bytes"
	"container/heap"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"maps"
	"mime"
	"net/mail"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ghbmrk/agentos/broker/clerk/inbox/imapsmtp"
	"github.com/ghbmrk/agentos/broker/clerk/inbox/imapwire"
)

// Mailbox is where the clerk's effects land. Do calls it only after the
// step passed the clerk's one check (check.Check) and the clerk's own rules,
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
// Call it before l is used. The clerk turns it on (#2841): a failing
// Opened read hands back the read mail it found, which the clerk keeps, so
// a sender read recently does not look never opened after the owner deletes
// that mail (run ASSUMPTIONS MIG-4-run-q).
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

// freshCost is what a read past the bound spends on each entry it logged,
// to keep the newest (fresh): one heap slot, at most twice its 24 bytes.
const (
	senderCost = 128
	entryCost  = 384
	oldCost    = 192
	freshCost  = 48
)

// ErrTooMuchReadMail fails an Opened call past openedMax. It does not pass
// by archiving, since every folder is read: the owner must delete read mail
// for good, from the trash too. The failing read still hands back the read
// mail it found (#2841), so a sender read since the last good read stays
// opened when the owner deletes that mail; such an entry is kept, charged in
// full, for unopenedDays, so deleting that mail frees nothing until then. A
// mail the log first saw read more than unopenedDays ago frees about half
// its charge (entryCost less oldCost), and a read mail the failing read did
// not keep frees all of it.
var ErrTooMuchReadMail = errors.New("inbox: more read mail than the clerk keeps")

// TooMuchReadMailError is ErrTooMuchReadMail from a read that went on past
// the bound, with what deleting can free. Every read mail whose deletion
// frees room arrived from After to Before: one the read had to drop, and one
// the log first saw read more than unopenedDays ago (which arrived by that
// day, at a time not kept, so After is then zero). Deleting the read mail
// that arrived in that span lets the next read pass, unless more is read
// meanwhile (TestTheTooMuchReadMailStepWorks). Other read mail the log
// keeps, charged in full for unopenedDays, so deleting it frees nothing
// yet: during the warm-up, mail read long ago among it. Before is zero when
// no deletion frees room: the read dropped nothing, so the log it handed
// back fits, and the next read gets through with no step.
type TooMuchReadMailError struct{ After, Before time.Time }

func (e *TooMuchReadMailError) Error() string { return ErrTooMuchReadMail.Error() }
func (e *TooMuchReadMailError) Unwrap() error { return ErrTooMuchReadMail }

// opened is one Opened call's state: LastOpened as it is built, and the log
// by digest, each entry marked when this read found its mail. Once a charge
// runs past openedMax the read is full: it goes on through every folder, but
// only to log read mail the log lacks, and keeps the newest of it within the
// bound (keep), so the read mail the owner read last is what a failing read
// hands back.
type opened struct {
	today   string
	watched bool
	since   string
	senders map[string]string
	log     map[[16]byte]logged
	old     []oldEntry // the log's entries older than unopenedDays, by digest
	kept    int
	full    bool
	fresh   freshHeap // once full: the entries this read logged, oldest arrival first
	before  time.Time // once full: the latest arrival among the entries dropped
	after   time.Time // and the earliest, zero once an old entry counts
	oldSeen bool      // an old entry counts toward before
}

// fresh is an entry this read logged, by its mail's arrival.
type fresh struct {
	arrived int64
	id      [16]byte
}

type freshHeap []fresh

func (h freshHeap) Len() int           { return len(h) }
func (h freshHeap) Less(i, j int) bool { return h[i].arrived < h[j].arrived }
func (h freshHeap) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }
func (h *freshHeap) Push(x any)        { *h = append(*h, x.(fresh)) }
func (h *freshHeap) Pop() any {
	old := *h
	x := old[len(old)-1]
	*h = old[:len(old)-1]
	return x
}

// oldEntry is a log entry older than unopenedDays, kept out of the log until
// the read finds its mail: one that is gone is dropped, having cost oldCost.
type oldEntry struct {
	id         [16]byte
	from, date string
}

// logged is a log entry; arrived, in Unix seconds, is set only on one this
// read logged.
type logged struct {
	from, date string
	present    bool
	arrived    int64
}

// charge spends n of openedMax, or nothing if n does not fit.
func (o *opened) charge(n int) error {
	if o.kept+n > openedMax {
		return ErrTooMuchReadMail
	}
	o.kept += n
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
		if err := o.add([16]byte(b), e.From, e.Date, false, 0); err != nil {
			return nil, err
		}
	}
	slices.SortFunc(o.old, func(a, b oldEntry) int { return bytes.Compare(a.id[:], b.id[:]) })
	return o, nil
}

// add logs a mail once and opens its sender on the entry's day; a mail this
// read found is marked present, and one the log lacked carries its arrival.
func (o *opened) add(id [16]byte, from, date string, present bool, arrived int64) error {
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
	o.log[id] = logged{from: from, date: date, present: present, arrived: arrived}
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
// A charge past openedMax makes the read full rather than failing it.
func (o *opened) header(h []byte, arrived time.Time) error {
	from, mid := FromAddress(h), messageID(h)
	if from == "" {
		return nil
	}
	named := mid != "" && !arrived.IsZero()
	if o.full {
		if named {
			o.keep(seenID(from, mid, arrived), from, arrived.Unix())
		}
		return nil
	}
	err := error(nil)
	if named {
		err = o.add(seenID(from, mid, arrived), from, o.today, true, arrived.Unix())
	}
	if err == nil && (!o.watched || !named) {
		err = o.open(from, o.today)
	}
	if errors.Is(err, ErrTooMuchReadMail) {
		o.fill()
		if named {
			o.keep(seenID(from, mid, arrived), from, arrived.Unix())
		}
		return nil
	}
	return err
}

// fill makes the read full: every entry it logged so far is kept by arrival
// and charged up to fullCost, so dropping it frees no more than it was
// charged (its sender stays charged as well), and the bound is then made
// good.
func (o *opened) fill() {
	o.full = true
	for id, e := range o.log {
		if e.arrived != 0 {
			o.kept += fullCost(e.from) - len(e.from) - entryCost
			o.fresh = append(o.fresh, fresh{arrived: e.arrived, id: id})
		}
	}
	heap.Init(&o.fresh)
	o.evict()
}

// keep logs, in a full read, a read mail the log lacks, dated today. A full
// read hands back no LastOpened, so its sender is not opened; the entry is
// charged its sender's cost as well, so the log handed back loads within
// openedMax whichever entries are dropped, and dropping it frees it all.
func (o *opened) keep(id [16]byte, from string, arrived int64) {
	if _, ok := o.log[id]; ok {
		return
	}
	if _, ok := slices.BinarySearchFunc(o.old, id, func(e oldEntry, id [16]byte) int { return bytes.Compare(e.id[:], id[:]) }); ok {
		return // kept as it is: an old entry the read finds needs no new day
	}
	o.kept += fullCost(from)
	o.log[id] = logged{from: from, date: o.today, present: true, arrived: arrived}
	heap.Push(&o.fresh, fresh{arrived: arrived, id: id})
	o.evict()
}

// evict brings a full read back within openedMax. It drops the log's
// entries older than unopenedDays first: such an entry opens nothing, and
// if its mail is still there the next read logs it again, dated that day
// (fail closed). Then it drops what this read logged, oldest arrival first,
// so the newest read mail stays. The log's own recent entries, and the
// senders charged, are never dropped: they fitted before this read.
func (o *opened) evict() {
	for o.kept > openedMax {
		if n := len(o.old); n > 0 {
			e := o.old[n-1]
			o.old = o.old[:n-1]
			o.kept -= len(e.from) + oldCost
			o.dropOld(e.date)
			if l, ok := o.log[e.id]; ok && l.arrived == 0 && l.date == e.date {
				delete(o.log, e.id) // found by this read, and charged the rest
				o.kept -= entryCost - oldCost
			}
			continue
		}
		if len(o.fresh) == 0 {
			return
		}
		f := heap.Pop(&o.fresh).(fresh)
		o.kept -= fullCost(o.log[f.id].from)
		delete(o.log, f.id)
		o.drop(time.Unix(f.arrived, 0).UTC())
	}
}

// drop notes that a mail which arrived at t no longer stands in the log.
func (o *opened) drop(t time.Time) {
	if t.After(o.before) {
		o.before = t
	}
	if !o.oldSeen && (o.after.IsZero() || t.Before(o.after)) {
		o.after = t
	}
}

// dropOld notes an entry the log first saw read on day d, older than
// unopenedDays: its mail arrived by the end of d, at a time not kept.
func (o *opened) dropOld(d string) {
	t, _ := day(d)
	o.drop(t.Add(24*time.Hour - time.Second))
	o.oldSeen, o.after = true, time.Time{}
}

// tooMuch is a full read's error: Before covers the mail it dropped and the
// log's entries older than unopenedDays it kept, whose mail, if still there,
// the next read charges in full.
func (o *opened) tooMuch() error {
	for _, e := range o.old {
		o.dropOld(e.date)
	}
	return &TooMuchReadMailError{After: o.after, Before: o.before}
}

// fullCost is what a full read charges an entry it keeps: the entry, its
// heap slot and its sender's cost.
func fullCost(from string) int { return 2*len(from) + entryCost + freshCost + senderCost }

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

// partial is the log to keep after a read that failed: every entry it began
// with, since a read that did not finish cannot tell whose mail is gone, and
// every read mail it logged. It is empty (nil Seen) when the read logged
// none, so the caller keeps its record as it was.
func (o *opened) partial() SeenLog {
	n := 0
	for _, e := range o.log {
		if e.arrived != 0 {
			n++
		}
	}
	if n == 0 {
		return SeenLog{}
	}
	out := SeenLog{Since: o.since, Seen: make([]Seen, 0, len(o.log)+len(o.old))}
	for id, e := range o.log {
		out.Seen = append(out.Seen, Seen{From: e.from, ID: hex.EncodeToString(id[:]), Date: e.date})
	}
	for _, e := range o.old {
		if _, ok := o.log[e.id]; !ok {
			out.Seen = append(out.Seen, Seen{From: e.from, ID: hex.EncodeToString(e.id[:]), Date: e.date})
		}
	}
	slices.SortFunc(out.Seen, func(a, b Seen) int { return strings.Compare(a.From+a.ID, b.From+b.ID) })
	return out
}

// Opened is World.LastOpened for the account (#2618), keyed by lower-cased
// address, and the log to keep in place of log (#2684). Each read (\Seen)
// mail in any folder that log lacks is logged, dated today, and a logged
// sender is opened on its latest entry's day, so a mail the owner read and
// then deleted for good still counts. IMAP keeps no time a mail was opened,
// so until the log has watched for unopenedDays, and for a read mail with no
// Message-ID or INTERNALDATE, a read mail is taken as opened today whenever it was delivered:
// no sender is unsubscribed on a guess (fail closed). Any folder that cannot
// be read in full fails the whole answer, as does a read past openedMax
// (ErrTooMuchReadMail): no partial answer passes for a full one, so no
// LastOpened is handed back. The log is (#2841): a failed read hands back
// every entry it began with and the read mail it logged before it failed
// (partial), the newest within openedMax once past it, so a sender the owner
// read since the last good read stays opened if the owner then deletes that
// mail; when it logged none, the log is empty and the caller keeps its own.
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
			return nil, o.partial(), err
		}
	}
	if o.full {
		return nil, o.partial(), o.tooMuch()
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
	if m.ref.Folder == trash {
		return nil // an earlier trash moved it there and was confirmed
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
	if !l.claim(id, there) {
		return errUnconfirmed
	}
	return nil
}

// claim marks the first of copies that no trash has claimed yet as mail
// id's, so a later step on the mail (an organize after its trash) acts on
// the copy in the trash, and reports whether there was one.
func (l *Live) claim(id string, copies []imapsmtp.Message) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, c := range copies {
		if !l.claimed[c.Ref] {
			l.claimed[c.Ref] = true
			if m, ok := l.refs[id]; ok {
				m.ref = c.Ref
				l.refs[id] = m
			}
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

// The senders read (MAIL-world-b2): who has delivered mail to the owner and
// when, and whom the owner writes to, read from the mailbox in steps for
// VRB-2's History, KnownSenders and Contacts. Only delivered folders count
// as history: over IMAP the Inbox and Archive roles (never All, which RFC
// 6154 lets a server fill with junk, nor any folder with no role); over Gmail
// INBOX and the mail outside SPAM, TRASH, DRAFT and SENT. Contacts are the
// To and Cc of the Sent role (Gmail's SENT). Each date is the server's
// arrival date, never one the sender wrote.

// SendersMax and ContactsMax bound the record: past either, the read gives
// no history (D-154 rule 5, fail closed).
const (
	SendersMax  = 20000
	ContactsMax = 5000
	// addrMax is the longest address counted (RFC 5321's path limit), so
	// the record's size follows from its bounds.
	addrMax = 254
)

// SendersSource is the read's place in one source: an IMAP folder, by
// name, or Gmail's one listing (gmailSource).
type SendersSource struct {
	Validity uint32 // IMAP: the UID validity High is under
	High     uint64 // IMAP: the highest UID read; Gmail: the newest internalDate (ms) of a finished pass
	Through  bool   // read through once
	Page     string // Gmail: the next page of the pass in progress; "" at none
	Top      uint64 // Gmail: the newest internalDate the pass in progress has read
}

// SendersRecord is what the senders read has found, and where it is.
type SendersRecord struct {
	Sources map[string]SendersSource
	Senders map[string]int64 // a delivering sender (canonAddr) to its earliest arrival, Unix seconds
	Sent    map[string]bool  // the addresses the owner's sent mail went to (canonAddr)
}

// Complete reports whether every source the last step counted has been
// read through once.
func (r SendersRecord) Complete() bool {
	if len(r.Sources) == 0 {
		return false
	}
	for _, s := range r.Sources {
		if !s.Through {
			return false
		}
	}
	return true
}

// Over reports whether the record has passed a bound.
func (r SendersRecord) Over() bool { return len(r.Senders) > SendersMax || len(r.Sent) > ContactsMax }

func (r *SendersRecord) init() {
	if r.Sources == nil {
		r.Sources = map[string]SendersSource{}
	}
	if r.Senders == nil {
		r.Senders = map[string]int64{}
	}
	if r.Sent == nil {
		r.Sent = map[string]bool{}
	}
}

// keepOnly drops the sources not in names: a folder gone, or no longer of a
// counted role, no longer holds completeness back.
func (r *SendersRecord) keepOnly(names func(string) bool) {
	for name := range r.Sources {
		if !names(name) {
			delete(r.Sources, name)
		}
	}
}

// heads is what one call of the read found, merged into the record only
// once the call has succeeded, so a call that fails commits nothing.
type heads struct {
	senders map[string]int64
	sent    []string
}

// delivered notes the header's sender, as VRB-2 names it (one From field,
// canonAddr of its address), as having delivered at arrived. A header with
// no From, two, or an address past addrMax counts for no one.
func (h *heads) delivered(header []byte, arrived time.Time) {
	var from []byte
	n := 0
	for _, f := range splitHeader(header) {
		if f.key() == "from" {
			from, n = f.value, n+1
		}
	}
	a := canonAddr(rawAddr([]byte(unfold.Replace(string(from)))))
	if n != 1 || a == "" || len(a) > addrMax || arrived.IsZero() {
		return
	}
	if h.senders == nil {
		h.senders = map[string]int64{}
	}
	if t, ok := h.senders[a]; !ok || arrived.Unix() < t {
		h.senders[a] = arrived.Unix()
	}
}

// wrote notes every address in the header's To and Cc fields as one the
// owner writes to: a list that does not parse is read part by part. More
// addresses only add to the lookalike check.
func (h *heads) wrote(header []byte) {
	for _, f := range splitHeader(header) {
		if k := f.key(); k != "to" && k != "cc" {
			continue
		}
		v := unfold.Replace(string(f.value))
		var as []string
		p := mail.AddressParser{WordDecoder: &mime.WordDecoder{CharsetReader: rawCharset}}
		if l, err := p.ParseList(v); err == nil {
			for _, a := range l {
				as = append(as, a.Address)
			}
		} else {
			for _, part := range strings.FieldsFunc(v, func(r rune) bool { return r == ',' || r == ';' }) {
				as = append(as, bareAddr.FindString(part))
			}
		}
		for _, a := range as {
			if a = canonAddr(a); a != "" && len(a) <= addrMax {
				h.sent = append(h.sent, a)
			}
		}
	}
}

func (h heads) into(r *SendersRecord) {
	for a, t := range h.senders {
		if old, ok := r.Senders[a]; !ok || t < old {
			r.Senders[a] = t
		}
	}
	for _, a := range h.sent {
		r.Sent[a] = true
	}
}

// splitHeader is a header block's fields, as splitMessage reads them.
func splitHeader(header []byte) []header {
	hs, _ := splitMessage(header)
	return hs
}

// SendersStep reads at most limit more mails of the counted folders into r,
// each folder in UID order from above its High: the first read in steps
// until every folder is through, then only what arrived since. A changed
// UID validity reads that folder again. Each folder's addresses come from
// one AddrHeads call (BODY.PEEK, so nothing is marked read), merged only once
// it succeeds. A mail whose From, To or Cc passes the header bound is passed
// over: the call is asked again for the mails below it, and the folder goes
// on above it at the next step, so such a mail counts for no one (a sender
// cannot make the read fail by padding a header). more is whether mail is
// left to read now. Any other failure ends the step with its error; the
// folders read before it keep their progress.
func (l *Live) SendersStep(ctx context.Context, r *SendersRecord, limit int) (more bool, err error) {
	r.init()
	fs, err := l.st.Folders(ctx)
	if err != nil {
		return false, err
	}
	roles := map[string]imapwire.Role{}
	for _, f := range fs {
		switch f.Role {
		case imapwire.Inbox, imapwire.Archive, imapwire.Sent:
			roles[f.Name] = f.Role
		}
	}
	r.keepOnly(func(name string) bool { _, ok := roles[name]; return ok })
	for _, name := range slices.Sorted(maps.Keys(roles)) {
		src := r.Sources[name]
		if limit <= 0 {
			more = more || !src.Through // a folder read through waits for the next step's mail read
			r.Sources[name] = src
			continue
		}
		validity, uids, err := l.st.UIDs(ctx, name)
		if err != nil {
			return false, err
		}
		if validity != src.Validity {
			src = SendersSource{Validity: validity}
		}
		var fresh []uint32
		for _, u := range uids {
			if uint64(u) > src.High {
				fresh = append(fresh, u)
			}
		}
		slices.Sort(fresh)
		take, skip := fresh[:min(len(fresh), limit)], uint32(0)
		for {
			var got heads
			err := l.st.AddrHeads(ctx, name, validity, take, func(h []byte, arrived time.Time) error {
				if roles[name] == imapwire.Sent {
					got.wrote(h)
				} else {
					got.delivered(h, arrived)
				}
				return nil
			})
			var long *imapsmtp.LongHeaderError
			if errors.As(err, &long) {
				if i := slices.Index(take, long.UID); i >= 0 {
					take, skip = take[:i], long.UID
					continue
				}
			}
			if err != nil {
				return false, err
			}
			got.into(r)
			break
		}
		if len(take) > 0 {
			src.High = uint64(take[len(take)-1])
		}
		if skip != 0 {
			src.High = uint64(skip)
		}
		limit -= len(take)
		if skip != 0 {
			limit--
		}
		left := slices.ContainsFunc(fresh, func(u uint32) bool { return uint64(u) > src.High })
		src.Through = src.Through || !left
		more = more || left
		r.Sources[name] = src
	}
	return more, nil
}
