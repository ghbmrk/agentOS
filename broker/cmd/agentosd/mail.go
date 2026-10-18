package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ghbmrk/agentos/broker/daemon"
	"github.com/ghbmrk/agentos/broker/grants"
	"github.com/ghbmrk/agentos/broker/journal"
	"github.com/ghbmrk/agentos/broker/mail"
	"github.com/ghbmrk/agentos/broker/mail/mailsock"
	"github.com/ghbmrk/agentos/broker/verb"
)

// The owner's mail account (SR3-mail-w2): the mail adapter over the vault
// process's mail socket, so agentosd links neither the mailbox credential
// nor an IMAP or SMTP client (M1, ARC-2).
//
// daemon.Config's executors and grants are fixed before daemon.Run opens
// the journal, and the adapter's organize bound reads that journal
// (mail.Config.InUse), so no adapter exists before the engine does. The
// late-bound lateMail stands in for it: the executor under mail.Tool and
// the verifier and escalator under the account. Until bind it refuses:
// Escalate fails, so the gate denies (ADP-2), Execute is NotApplied with
// no effect, and Verify verifies nothing.

// mailAccount is the journal account the owner's mail grant connects.
const mailAccount = "mail"

// mailPoll is how often the binder asks the vault process for the account.
const mailPoll = time.Minute

var (
	errMailUnbound   = errors.New("mail: no mail account is connected")
	errMailNoJournal = errors.New("mail: bind needs the journal")
)

type mailBound struct {
	a    *mail.Adapter
	addr string // as the vault process reported it
	gen  string // the account generation the adapter's store is bound to
}

type lateMail struct {
	account string
	b       atomic.Pointer[mailBound]
	// gens: the generation each intent was first seen under (B1).
	mu   sync.Mutex
	gens map[string]genStamp
	// undoable: the journal keeps organize evidence readable, so the
	// owner's UNDO can restore it (ADP-2). Without that every organize
	// effect is asked (wire).
	undoable bool
	// tune adjusts each adapter's Config before mail.New: tests only.
	tune func(*mail.Config)
}

var (
	_ journal.Executor = (*lateMail)(nil)
	_ grants.Escalator = (*lateMail)(nil)
	_ mailbox          = (*lateMail)(nil)
)

func newLateMail() *lateMail { return &lateMail{account: mailAccount} }

// wire registers l before daemon.Run: the executor under mail.Tool, the
// declaration, and the verifier and escalator under the account.
func (l *lateMail) wire(cfg *daemon.Config) {
	if cfg.Executors == nil {
		cfg.Executors = map[string]journal.Executor{}
	}
	if cfg.Grants.Declared == nil {
		cfg.Grants.Declared = map[string]map[string]string{}
	}
	if cfg.Grants.Verifiers == nil {
		cfg.Grants.Verifiers = map[string]grants.Verifier{}
	}
	cfg.Executors[mail.Tool] = l
	cfg.Grants.Declared[mail.Tool] = mail.Declared()
	cfg.Grants.Verifiers[l.account] = l
	l.undoable = evidenceReadable(cfg.Redactor)
}

// evidenceReadable reports whether organize evidence journaled through red
// still parses, so STATUS can count it and UNDO restore it. Nil is the
// daemon's default, which journals no free text (daemon.Redacted).
func evidenceReadable(red journal.Redactor) bool {
	if red == nil {
		return false
	}
	b, _ := json.Marshal(mail.Change{Op: mail.OpArchive, Record: "<probe@example.invalid>", Sender: "probe@example.invalid", From: "INBOX", To: "Archive"})
	_, err := mail.ParseChange(red(string(b)))
	return err == nil
}

// bind builds the adapter over store for the account at address, with
// its organize bound counted from eng for this account alone (M18), and
// makes it the one l serves.
func (l *lateMail) bind(eng *journal.Engine, store mail.Store, address, gen string, now func() time.Time) error {
	if eng == nil {
		return errMailNoJournal
	}
	account := l.account
	cfg := mail.Config{Account: account, Executor: mail.Tool, Address: address, Store: store, Now: now,
		InUse: func(action string, since time.Time) []journal.Use { return eng.InUse(account, action, since) }}
	if l.tune != nil {
		l.tune(&cfg)
	}
	a, err := mail.New(cfg)
	if err != nil {
		return err
	}
	l.b.Store(&mailBound{a: a, addr: address, gen: gen})
	return nil
}

func (l *lateMail) unbind() { l.b.Store(nil) }

func (l *lateMail) adapter() *mail.Adapter {
	if b := l.b.Load(); b != nil {
		return b.a
	}
	return nil
}

// errMailGen refuses an intent whose authorization was made under another
// mail account generation than the one now bound (MAIL-gen B1).
var errMailGen = errors.New("mail: the mail account changed since this was authorized")

type genStamp struct {
	gen string
	at  time.Time
}

// genKeep is how long an intent's generation is remembered; approvals
// expire long before (grants.DefaultFresh).
const genKeep = 24 * time.Hour

// stamp ties intent id to the generation of b: the first call records it
// and later calls report whether it still matches. An id with no record
// (the daemon restarted) takes the current generation: that residual is
// M19's.
func (l *lateMail) stamp(id string, b *mailBound) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	for k, v := range l.gens {
		if now.Sub(v.at) > genKeep {
			delete(l.gens, k)
		}
	}
	if l.gens == nil {
		l.gens = map[string]genStamp{}
	}
	if v, ok := l.gens[id]; ok {
		return v.gen == b.gen
	}
	l.gens[id] = genStamp{gen: b.gen, at: now}
	return true
}

func (l *lateMail) Execute(ctx context.Context, in journal.Intent, attempt int) journal.Outcome {
	b := l.b.Load()
	if b == nil {
		return journal.Outcome{Result: journal.ResultNotApplied, Evidence: errMailUnbound.Error()}
	}
	if !l.stamp(in.ID, b) {
		return journal.Outcome{Result: journal.ResultNotApplied, Evidence: errMailGen.Error()}
	}
	return b.a.Execute(ctx, in, attempt)
}

func (l *lateMail) Reconcile(ctx context.Context, in journal.Intent, attempt int) journal.Outcome {
	b := l.b.Load()
	if b == nil {
		return journal.Outcome{Result: journal.ResultUnknown, Evidence: errMailUnbound.Error()}
	}
	if !l.stamp(in.ID, b) {
		return journal.Outcome{Result: journal.ResultUnknown, Evidence: errMailGen.Error()}
	}
	return b.a.Reconcile(ctx, in, attempt)
}

func (l *lateMail) Verify(ctx context.Context, in journal.Intent) (grants.Verified, error) {
	b := l.b.Load()
	if b == nil {
		return grants.Verified{}, errMailUnbound
	}
	if !l.stamp(in.ID, b) {
		return grants.Verified{}, errMailGen
	}
	return b.a.Verify(ctx, in)
}

// Escalate is the adapter's guard. An organize effect whose evidence the
// journal cannot read back has no UNDO, so it is asked (ADP-2).
func (l *lateMail) Escalate(ctx context.Context, in journal.Intent) (grants.Escalation, error) {
	b := l.b.Load()
	if b == nil {
		return grants.Escalation{}, errMailUnbound
	}
	if !l.stamp(in.ID, b) {
		return grants.Escalation{}, errMailGen
	}
	e, err := b.a.Escalate(ctx, in)
	if err == nil && !l.undoable && !e.Held && mail.Declared()[in.Action] == verb.Organize {
		e.Ask = true
		if e.Reason == "" {
			e.Reason = "no UNDO yet: the journal does not keep mail changes readable"
		}
	}
	return e, err
}

// Owns reports whether addr is the connected account's own address (CH-20).
func (l *lateMail) Owns(addr string) (string, bool) {
	a := l.adapter()
	if a == nil {
		return "", false
	}
	return l.account, a.Owns(addr)
}

// Main is the connected account's address and account; empty while none is.
func (l *lateMail) Main() (string, string) {
	a := l.adapter()
	if a == nil {
		return "", ""
	}
	return a.Address(), l.account
}

// mailAddresser reports the account the vault process serves now, and
// pins a store to one of its generations: a bound adapter's calls then
// fail once the owner sets up another mailbox (MAIL-gen).
type mailAddresser interface {
	Account(context.Context) (address, generation string, err error)
	Pin(generation string) mail.Store
}

// run keeps l bound to the account the vault process serves, asking every
// tick: bound once it reports an address (again if the address or the account generation changes),
// unbound when none is set up. While the vault is locked or does not
// answer, l stays as it was: a bound adapter's own calls then fail, so its
// guard denies and nothing is organized. Only changes of state are logged.
func (l *lateMail) run(ctx context.Context, eng *journal.Engine, src mailAddresser, now func() time.Time, every time.Duration, logf func(string, ...any)) {
	t := time.NewTicker(every)
	defer t.Stop()
	state := ""
	for {
		if s := l.poll(ctx, eng, src, now); s != state {
			state = s
			logf("%s", s)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// poll is one tick of run; it returns the state's log line.
func (l *lateMail) poll(ctx context.Context, eng *journal.Engine, src mailAddresser, now func() time.Time) string {
	cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	addr, gen, err := src.Account(cctx)
	switch {
	case err == nil:
		if b := l.b.Load(); b != nil && b.addr == addr && b.gen == gen {
			return "mail: connected"
		}
		if err := l.bind(eng, src.Pin(gen), addr, gen, now); err != nil {
			l.unbind()
			return fmt.Sprintf("mail: the account could not be used (%v); organize is refused", err)
		}
		return "mail: connected"
	case errors.Is(err, mailsock.ErrNotConnected):
		l.unbind()
		return "mail: no mail account is set up; organize is refused"
	case errors.Is(err, mailsock.ErrLocked):
		return "mail: the vault is locked; organize waits for the unlock and is retried each minute"
	default:
		return fmt.Sprintf("mail: the vault process did not answer (%v); retried each minute", err)
	}
}

// The mail STATUS note and its UNDO (ADP-2, CH-16). A day's changes
// are the account's organize intents that Succeeded that day (local
// time), read back from the journal; the day's UNDO ID is a keyed hash of
// the account and the day, so it is the same after a restart, names
// neither, and cannot be worked out for another account or day without
// the key. No daily text carries them (DRB-1): STATUS shows the newest
// complete day still undoable, and the owner asks for it.

// undoLookback bounds the days an UNDO ID is looked for: past the window.
const undoLookback = 8

// undoSubkey derives the UNDO IDs' key from agentosd's values key, under
// its own label, so neither key's use reveals the other.
func undoSubkey(valuesKey []byte) []byte {
	m := hmac.New(sha256.New, valuesKey)
	m.Write([]byte("agentos/mail/undo-id/v1"))
	return m.Sum(nil)
}

// undoID is the UNDO ID for account's changes on day ("2006-01-02"):
// three letters of the owner channel's alphabet. The channel's own IDs
// carry a digit, so the two never collide.
func undoID(key []byte, account, day string) string {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(account))
	m.Write([]byte{0})
	m.Write([]byte(day))
	n := binary.BigEndian.Uint64(m.Sum(nil))
	const letters = "ABCDEFGHJKLMNPQRSTUVWXYZ"
	b := make([]byte, 3)
	for i := range b {
		b[i] = letters[n%uint64(len(letters))]
		n /= uint64(len(letters))
	}
	return string(b)
}

// mailDays reads the account's organize changes from the journal.
type mailDays struct {
	account string
	key     []byte
	loc     *time.Location
	now     func() time.Time
	trail   func() []journal.Record
	m       *lateMail
}

const dayFormat = "2006-01-02"

// changes returns the account's Succeeded organize changes by local day.
func (d *mailDays) changes() map[string][]mail.Change {
	ours := map[string]bool{}
	erased := map[string]bool{}
	type obs struct {
		day string
		c   mail.Change
	}
	seen := map[string]obs{}
	var order []string
	declared := mail.Declared()
	for _, r := range d.trail() {
		switch r.Type {
		case journal.RecSubmitted:
			if in := r.Intent; in != nil && in.Account == d.account && in.Executor == mail.Tool && declared[in.Action] == verb.Organize {
				ours[r.ID] = true
			}
		case journal.RecErased:
			erased[r.ID] = true
		case journal.RecObserved:
			if !ours[r.ID] || r.Result != journal.ResultSucceeded {
				continue
			}
			c, err := mail.ParseChange(r.Evidence)
			if err != nil {
				continue
			}
			if _, ok := seen[r.ID]; !ok {
				order = append(order, r.ID)
			}
			seen[r.ID] = obs{r.At.In(d.loc).Format(dayFormat), c}
		}
	}
	out := map[string][]mail.Change{}
	for _, id := range order {
		if !erased[id] {
			o := seen[id]
			out[o.day] = append(out[o.day], o.c)
		}
	}
	return out
}

// dayStart is the start of day in d.loc.
func (d *mailDays) dayStart(day string) time.Time {
	t, _ := time.ParseInLocation(dayFormat, day, d.loc)
	return t
}

// undo answers UNDO id (owner.UndoHook): ok is false for an ID that is not
// a day's with changes in the last undoLookback days.
func (d *mailDays) undo(ctx context.Context, id string) (string, bool) {
	now := d.now().In(d.loc)
	all := d.changes()
	for i := 0; i <= undoLookback; i++ {
		day := now.AddDate(0, 0, -i).Format(dayFormat)
		changes := all[day]
		if len(changes) == 0 || undoID(d.key, d.account, day) != id {
			continue
		}
		if !now.Before(d.dayStart(day).Add(mail.UndoWindow)) {
			return id + " is past its undo window; nothing was restored.", true
		}
		a := d.m.adapter()
		if a == nil {
			return "Mail is not connected right now, so nothing was restored. Try UNDO " + id + " again later.", true
		}
		return a.Undo(ctx, changes).Text(), true
	}
	return "", false
}

// mailNote is the mail STATUS note: the newest complete day in the undo
// window with organize changes, its count and its UNDO. It names no
// sender (CH-12) and is "" until wireMail stores the days.
type mailNote struct{ days atomic.Pointer[mailDays] }

func (n *mailNote) line() string {
	d := n.days.Load()
	if d == nil {
		return ""
	}
	now := d.now().In(d.loc)
	all := d.changes()
	for i := 1; i <= undoLookback; i++ {
		day := now.AddDate(0, 0, -i).Format(dayFormat)
		start := d.dayStart(day)
		if !now.Before(start.Add(mail.UndoWindow)) {
			break
		}
		total := mail.Summarize(all[day]).Total
		if total == 0 {
			continue
		}
		until := start.Add(mail.UndoWindow - time.Nanosecond)
		return fmt.Sprintf("Mail organized %d on %s. UNDO %s until %s.", total, start.Format("Mon Jan 2"), undoID(d.key, d.account, day), until.Format("Mon Jan 2"))
	}
	return ""
}

// wireMail starts l's binder on the vault process's mail socket and, once
// the values key is read, the owner channel's UNDO hook and the mail
// STATUS note. Without the key neither runs: organize still runs, and its
// changes stay in the journal.
func wireMail(ctx context.Context, l *lateMail, d *daemon.Daemon, socket, learnDir string, note *mailNote, now func() time.Time) {
	c := mailsock.NewClient(socket)
	go l.run(ctx, d.Engine(), c, now, mailPoll, log.Printf)
	key, err := readValuesKey(filepath.Join(learnDir, "values.key"))
	if err != nil {
		log.Printf("mail: no UNDO for mail changes: %v", err)
		return
	}
	days := &mailDays{account: l.account, key: undoSubkey(key), loc: time.Local, now: now, trail: d.Engine().Trail, m: l}
	if o := d.Owner(); o != nil {
		o.SetUndo(days.undo)
	}
	if note != nil {
		note.days.Store(days)
	}
}
