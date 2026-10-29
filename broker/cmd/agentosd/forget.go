package main

// The owner's erase by name (LOG-4, KRN-forget b, #3179): find what the box
// holds under a name, erase exactly that on the owner's confirm, and take
// every agent that read it back to before the read before the owner is
// told (D-169). The surface (KRN-forget c, #3414) is a signed-in owner-page
// step with a passkey tap (option A, Mark's card
// cmsg_01R91wiieBzMSvPKFsAJVvuKDWe3qGNc2HPYZ4gA91FXKG): it proves the owner
// and then calls find and confirm, since the kernel does not authenticate
// an erase (KRN-erase design 4).

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/ghbmrk/agentos/broker/owner/kernelsock"
)

const (
	// eraseRewoundFile records each erased subject's reader whose rewind
	// went through, in the state directory (the recall-settled.json
	// pattern).
	eraseRewoundFile = "erase-rewound.json"
	// forgetFor is how long a find's handle can be confirmed.
	forgetFor = 10 * time.Minute
	// maxForgets bounds the finds waiting for a confirm; the oldest goes.
	maxForgets = 8
	// eraseReadsEvery is how often an unanswered erasedreads is asked
	// again while every agent is contained for want of it.
	eraseReadsEvery = 5 * time.Second
	// maxRewindWait bounds the wait between retries of a failed rewind.
	maxRewindWait = 10 * time.Minute
	// eraseReadsAtStart bounds how long the start-up pass waits for the
	// kernel's first erasedreads answer before machines are served; past
	// it, every agent stays contained and watch keeps asking.
	eraseReadsAtStart = 20 * time.Second
	eraseReadsRetry   = 250 * time.Millisecond
)

// ErrForgetHandle is a confirm of a find that expired, was used, or never
// was: nothing is erased.
var ErrForgetHandle = errors.New("agentosd: that forget expired or was already used, so nothing was forgotten; look the name up again")

// errNoMachines is a rewind with no machine plane open.
var errNoMachines = errors.New("agent machines are not open")

// eraser is the kernel's owner seam the forget flow calls
// (kernelsock.Owner).
type eraser interface {
	Named(ctx context.Context, label string) (found, unread []string, err error)
	Recall(ctx context.Context, subject string) (kernelsock.Recall, bool, error)
	Erase(ctx context.Context, subject string) (kernelsock.Confirmation, error)
	Unerased(ctx context.Context) ([]kernelsock.Unerased, error)
	ErasedReads(ctx context.Context) ([]kernelsock.ErasedRead, error)
}

// forgetFlow is find and confirm.
type forgetFlow struct {
	k   eraser
	rw  *eraseRewind
	now func() time.Time

	mu      sync.Mutex
	pending map[string]pendingForget
}

type pendingForget struct {
	found    forgetFound
	subjects []string // exactly the subjects shown
	until    time.Time
}

// forgetFound is what a find shows the owner before the confirm.
type forgetFound struct {
	Handle string         // "" when there is nothing to confirm
	Name   string         // as the owner typed it; never stored
	Items  int            // items found, the names themselves not counted
	Kinds  map[string]int // Items by kind
	Unread bool           // some subjects' names could not be checked
	Closed bool           // stored content cannot be read right now
}

func newForgetFlow(k eraser, rw *eraseRewind) *forgetFlow {
	return &forgetFlow{k: k, rw: rw, now: time.Now, pending: map[string]pendingForget{}}
}

// find looks name up. The subjects it finds are held under a one-time
// handle for forgetFor; nothing found gives no handle.
func (f *forgetFlow) find(ctx context.Context, name string) (forgetFound, error) {
	out := forgetFound{Name: name, Kinds: map[string]int{}}
	found, unread, err := f.k.Named(ctx, name)
	if errors.Is(err, kernelsock.ErrContentClosed) {
		out.Closed = true
		return out, nil
	}
	if err != nil {
		return forgetFound{}, err
	}
	out.Unread = len(unread) > 0
	var subjects []string
	for _, sub := range found {
		r, ok, err := f.k.Recall(ctx, sub)
		if err != nil {
			return forgetFound{}, err
		}
		if !ok || r.Erased {
			continue
		}
		subjects = append(subjects, sub)
		for _, it := range r.Items {
			if it.Class != kernelsock.ClassLabel {
				out.Kinds[it.Class]++
				out.Items++
			}
		}
	}
	if len(subjects) == 0 {
		return out, nil
	}
	out.Handle = randHex(16)
	f.mu.Lock()
	defer f.mu.Unlock()
	now := f.now()
	for h, p := range f.pending {
		if !now.Before(p.until) {
			delete(f.pending, h)
		}
	}
	for len(f.pending) >= maxForgets {
		oldest := ""
		for h, p := range f.pending {
			if oldest == "" || p.until.Before(f.pending[oldest].until) {
				oldest = h
			}
		}
		delete(f.pending, oldest)
	}
	f.pending[out.Handle] = pendingForget{found: out, subjects: subjects, until: now.Add(forgetFor)}
	return out, nil
}

// take removes and returns the live find under handle.
func (f *forgetFlow) take(handle string) (pendingForget, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for h, p := range f.pending {
		if subtle.ConstantTimeCompare([]byte(h), []byte(handle)) == 1 {
			delete(f.pending, h)
			return p, f.now().Before(p.until)
		}
	}
	return pendingForget{}, false
}

// confirm erases exactly the subjects handle's find showed, each once,
// never looking the name up again; then it rewinds every agent that read
// erased content, and only then returns (D-169). A subject erased
// meanwhile is counted, not an error.
func (f *forgetFlow) confirm(ctx context.Context, handle string) (forgetResult, error) {
	p, ok := f.take(handle)
	if !ok {
		return forgetResult{}, ErrForgetHandle
	}
	// Once confirmed, the surface's request ending (a closed tab, a
	// timeout) cancels neither an erase nor the rewind that must follow it;
	// each kernel call keeps its own bound.
	ctx = context.WithoutCancel(ctx)
	r := forgetResult{Name: p.found.Name, Items: p.found.Items, Unread: p.found.Unread}
	held := map[string]kernelsock.BackupHold{}
	for _, sub := range p.subjects {
		c, err := f.k.Erase(ctx, sub)
		switch {
		case c.Subject != "":
			// Logged: an error is a later step, which the kernel retries.
			r.Erased++
			r.Owed = union(r.Owed, c.Unconfirmed)
			for _, h := range c.StillHeld {
				held[h.Backup] = h
			}
			r.BackupsUnknown = r.BackupsUnknown || c.BackupsUnknown
			if err != nil {
				f.rw.logf("forget: an erase is logged but a step after it failed: %v", err)
			}
		case errors.Is(err, kernelsock.ErrErased), errors.Is(err, kernelsock.ErrSubject):
			r.Already++
		default:
			r.NotErased++
			f.rw.logf("forget: an erase did not go through: %v", err)
		}
	}
	for _, b := range slices.Sorted(maps.Keys(held)) {
		r.StillHeld = append(r.StillHeld, held[b])
	}
	// The result tells the owner of these rewinds, so they are marked told
	// once it is built, under the same hold as the rewind, so neither the
	// start-up pass nor watch tells them again.
	f.rw.run.Lock()
	defer f.rw.run.Unlock()
	o := f.rw.rewindLocked(ctx)
	r.Rewound, r.Held, r.Unchecked, r.Voided = o.rewound, o.held, o.unchecked, o.voided
	f.rw.markTold(o.rows)
	return r, nil
}

func union(a, b []string) []string {
	for _, s := range b {
		if !slices.Contains(a, s) {
			a = append(a, s)
		}
	}
	return a
}

// forgetResult is what a confirm reached, rendered by Text.
type forgetResult struct {
	Name           string
	Items          int
	Erased         int // subjects this confirm erased
	Already        int // subjects erased meanwhile
	NotErased      int // subjects whose erase did not go through
	Owed           []string
	StillHeld      []kernelsock.BackupHold
	BackupsUnknown bool
	Unread         bool
	Rewound        []string // lineages that went back
	Held           []string // lineages that could not, and stay contained
	Unchecked      bool     // the readers could not be read: every agent is contained
	Voided         []string // intents the readers queued since, closed unrun
}

// Text is the owner's answer, conclusion first (OWN-6). "Not finished"
// comes from the stores owed, never from a count of items; nothing says the
// content left a disk, since a crash can leave ciphertext in a store.
func (r forgetResult) Text() string {
	var out []string
	what := fmt.Sprintf("everything named %s (%s)", r.Name, plural(r.Items, "item"))
	switch {
	case r.Erased == 0 && r.Already == 0:
		out = append(out, fmt.Sprintf("Nothing was forgotten: I could not forget %s just now, so it is still kept. Look the name up again.", what))
	case r.NotErased > 0:
		out = append(out, fmt.Sprintf("Not finished: I could not forget %s of %s just now, so those are still kept. Look the name up again.", plural(r.NotErased, "thing"), what))
	case len(r.Owed) > 0:
		out = append(out, fmt.Sprintf("Forgot %s, but it is not finished: %s %s not deleted them yet. I keep trying, and STATUS shows it.", what, storeNames(r.Owed), haveHas(len(r.Owed))))
	default:
		out = append(out, fmt.Sprintf("Forgot %s. It can no longer be read.", what))
	}
	if r.Already > 0 {
		out = append(out, fmt.Sprintf("%s had already been forgotten.", capital(plural(r.Already, "thing"))))
	}
	for _, h := range r.StillHeld {
		out = append(out, fmt.Sprintf("The older backup %s may still hold them: %s.", h.Backup, h.Why))
	}
	if r.BackupsUnknown {
		out = append(out, "Older backups may still hold them.")
	}
	if r.Unread {
		out = append(out, fmt.Sprintf("Some things could not be checked, so anything named %s in them is still kept.", r.Name))
	}
	switch {
	case r.Unchecked:
		out = append(out, "I could not check which agents read them, so no agent can copy itself until I can.")
	case len(r.Held) > 0:
		if len(r.Held) > 1 {
			out = append(out, fmt.Sprintf("%s could not go back yet; they are held from copying themselves until they do.", agentList(r.Held)))
		} else {
			out = append(out, fmt.Sprintf("%s could not go back yet; it is held from copying itself until it does.", agentList(r.Held)))
		}
	}
	if len(r.Rewound) > 0 {
		it := "it"
		if len(r.Rewound) > 1 {
			it = "they"
		}
		out = append(out, fmt.Sprintf("%s went back to before %s read them.", agentList(r.Rewound), it))
	}
	if n := len(r.Voided); n > 0 {
		it := "it"
		if n > 1 {
			it = "they"
		}
		out = append(out, fmt.Sprintf("I cancelled %s an agent made after reading them, so %s will not run.", plural(n, "request"), it))
	}
	return strings.Join(out, " ")
}

// Text is a find's readback, or why there is nothing to confirm.
func (f forgetFound) Text() string {
	if f.Closed {
		return "Stored content can't be read right now, so nothing was forgotten."
	}
	var out []string
	if f.Handle == "" {
		out = append(out, fmt.Sprintf("Nothing named %s was found.", f.Name))
	} else {
		var kinds []string
		for _, k := range slices.Sorted(maps.Keys(f.Kinds)) {
			kinds = append(kinds, fmt.Sprintf("%s %d", k, f.Kinds[k]))
		}
		line := fmt.Sprintf("Found %s named %s", plural(f.Items, "item"), f.Name)
		if len(kinds) > 0 {
			line += " (" + strings.Join(kinds, ", ") + ")"
		}
		out = append(out, line+". Confirm to forget them.")
	}
	if f.Unread {
		out = append(out, fmt.Sprintf("Some things could not be checked, so anything named %s in them is still kept.", f.Name))
	}
	return strings.Join(out, " ")
}

// storeName is how the owner reads a store an erase still owes: the key
// table is "the key", never its log name.
func storeName(s string) string {
	if s == kernelsock.KeyTable {
		return "the key"
	}
	return "the " + s + " store"
}

func storeNames(ss []string) string {
	var names []string
	for _, s := range ss {
		names = append(names, storeName(s))
	}
	sort.SliceStable(names, func(i, j int) bool { return names[i] == "the key" && names[j] != "the key" })
	switch len(names) {
	case 0:
		return ""
	case 1:
		return names[0]
	}
	return strings.Join(names[:len(names)-1], ", ") + " and " + names[len(names)-1]
}

func haveHas(n int) string {
	if n == 1 {
		return "has"
	}
	return "have"
}

func plural(n int, what string) string {
	if n == 1 {
		return "1 " + what
	}
	return fmt.Sprintf("%d %ss", n, what)
}

func capital(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

// agentList names lineages as STATUS does.
func agentList(lineages []string) string {
	var names []string
	for _, l := range lineages {
		names = append(names, agentName(l))
	}
	sort.Strings(names)
	if len(names) == 1 {
		return "Agent " + names[0]
	}
	return "Agents " + strings.Join(names[:len(names)-1], ", ") + " and " + names[len(names)-1]
}

// rewoundRead is one erased subject's reader whose rewind went through.
type rewoundRead struct {
	Subject string `json:"subject"`
	Lineage string `json:"lineage"`
	First   int64  `json:"first"`
	Told    bool   `json:"told"`
}

// eraseRewind takes every lineage that read erased content back to before
// its first such read (D-169), contains it until then, and records each
// rewind that went through so no start repeats it (vm ForgetSince: a
// repeat takes back later work too).
type eraseRewind struct {
	path     string
	logf     func(string, ...any)
	machines func() lineageForgetter // nil answer: no machine plane open
	drop     func() error            // the kept and held agent replies
	// void closes what a lineage queued at or after since and still waits
	// on the owner or its undo window (grants.Gate.VoidSince); nil: none.
	void func(lineage string, since time.Time) ([]string, error)
	// startWait bounds settle's wait for the first erased reads.
	startWait time.Duration

	run sync.Mutex // one rewind at a time; never held by Contained

	mu         sync.Mutex
	k          eraser // nil: no kernel, so nothing was ever erased here
	bad        bool   // the record is unreadable: every lineage contained
	readsKnown bool   // erasedreads answered since the last failure
	settled    []rewoundRead
	holding    map[string]bool // lineages owed a rewind
}

// openEraseRewind reads the record. One that cannot be read contains every
// lineage once a kernel is attached, and is never overwritten; a corrupt
// one is set aside and every rewind done again.
func openEraseRewind(path string, logf func(string, ...any)) *eraseRewind {
	w := &eraseRewind{path: path, logf: logf, holding: map[string]bool{}, startWait: eraseReadsAtStart}
	data, err := os.ReadFile(path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
	case err != nil:
		logf("%s unreadable, every agent contained: %v", path, err)
		w.bad = true
	default:
		if err := json.Unmarshal(data, &w.settled); err != nil {
			// A corrupt record is set aside (a durable copy; the next save
			// replaces the original), so every reader of erased
			// content is rewound again (fails closed: later work goes too)
			// and the owner told; kept as it is if it cannot be copied.
			w.settled = nil
			if rerr := writeSynced(path+".corrupt", data); rerr != nil {
				logf("%s corrupt and not set aside, every agent contained: %v; %v", path, err, rerr)
				w.bad = true
			} else {
				logf("%s corrupt, set aside: every agent that read forgotten things goes back again: %v", path, err)
			}
		}
	}
	return w
}

// attach gives the rewind the kernel and what it needs at the rewind.
func (w *eraseRewind) attach(k eraser, machines func() lineageForgetter, drop func() error,
	void func(string, time.Time) ([]string, error)) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.k, w.machines, w.drop, w.void = k, machines, drop, void
}

// Contained is composed into vm.Config.Contained and
// grants.Config.Contained (recallHeld.Contained): a lineage owed a rewind,
// or every lineage while what was read is unknown.
func (w *eraseRewind) Contained(lineage string) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.k == nil {
		return false
	}
	return w.bad || !w.readsKnown || w.holding[lineage]
}

func (w *eraseRewind) isSettled(r kernelsock.ErasedRead) bool {
	return slices.ContainsFunc(w.settled, func(s rewoundRead) bool { return s.Subject == r.Subject && s.Lineage == r.Lineage })
}

// rewound is what one rewind reached.
type rewound struct {
	rewound, held []string
	unchecked     bool
	voided        []string
	rows          []rewoundRead // the records this rewind settled
}

// rewind reads the kernel's erased reads and takes each lineage with one
// not yet settled back to its earliest, closes what it queued since, and
// drops the kept agent replies. A lineage that does not go back, whose
// queue is not closed, or whose record is not written, stays contained
// and is tried again. Each new record is untold until notify or markTold.
func (w *eraseRewind) rewind(ctx context.Context) rewound {
	w.run.Lock()
	defer w.run.Unlock()
	return w.rewindLocked(ctx)
}

// rewindLocked is rewind. Caller holds run.
func (w *eraseRewind) rewindLocked(ctx context.Context) (out rewound) {
	w.mu.Lock()
	k, bad, machines, drop, void := w.k, w.bad, w.machines, w.drop, w.void
	w.mu.Unlock()
	if k == nil {
		return out
	}
	if bad {
		return rewound{unchecked: true}
	}
	reads, err := k.ErasedReads(ctx)
	if err != nil {
		w.mu.Lock()
		w.readsKnown = false
		w.mu.Unlock()
		w.logf("forget: which agents read erased content is unknown, every agent contained: %v", err)
		return rewound{unchecked: true}
	}
	owed := map[string][]kernelsock.ErasedRead{}
	w.mu.Lock()
	for _, r := range reads {
		if !w.isSettled(r) {
			owed[r.Lineage] = append(owed[r.Lineage], r)
		}
	}
	for l := range owed {
		w.holding[l] = true
	}
	w.readsKnown = true
	w.mu.Unlock()
	if len(owed) == 0 {
		return out
	}
	lineages := slices.Sorted(maps.Keys(owed))
	var m lineageForgetter
	if machines != nil {
		m = machines()
	}
	var gone []string
	for _, l := range lineages {
		first := owed[l][0].First
		for _, r := range owed[l] {
			first = min(first, r.First)
		}
		err := errNoMachines
		if m != nil {
			err = m.ForgetSince(ctx, l, time.UnixMilli(first))
		}
		// What the reader queued from the content goes too, whether or
		// not it went back (LOG-4): an approval card or an effect in its
		// undo window would otherwise carry it out later.
		if void != nil {
			ids, verr := void(l, time.UnixMilli(first))
			out.voided = append(out.voided, ids...)
			err = errors.Join(err, verr)
		}
		if err != nil {
			w.logf("forget: agent %s read erased content and could not go back: %v", agentName(l), err)
			out.held = append(out.held, l)
			continue
		}
		gone = append(gone, l)
	}
	// Replies an agent built from the content go only once every reader
	// that could go back has, so none it posts meanwhile is kept. If they
	// cannot, no lineage is settled, and watch does all of it again.
	if drop != nil {
		if err := drop(); err != nil {
			w.logf("forget: kept agent replies not dropped, agents stay contained: %v", err)
			return rewound{held: lineages, voided: out.voided}
		}
	}
	if len(gone) == 0 {
		return out
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	before := len(w.settled)
	for _, l := range gone {
		for _, r := range owed[l] {
			w.settled = append(w.settled, rewoundRead{r.Subject, r.Lineage, r.First, false})
		}
	}
	if err := w.save(); err != nil {
		// Not recorded: they stay contained and are taken back again, so
		// none is reported as gone.
		w.settled = w.settled[:before]
		w.logf("forget: agents went back but %s was not written: %v", w.path, err)
		return rewound{held: lineages, voided: out.voided}
	}
	for _, l := range gone {
		delete(w.holding, l)
	}
	out.rewound = gone
	out.rows = slices.Clone(w.settled[before:])
	return out
}

// settle is the start-up pass, after the machines open and before any is
// served (D-169): it rewinds what a crash left anywhere between an erase
// and its reply, then tells the owner of each rewind not yet told.
// The kernel may not answer yet at start (reachKernel is asynchronous), so
// it asks again for up to startWait; past that every agent stays contained
// and watch keeps asking (STATUS's forgetReadsUnknown).
func (w *eraseRewind) settle(ctx context.Context, tell func(string) error) {
	until := time.Now().Add(w.startWait)
	for w.rewind(ctx).unchecked && !w.isBad() {
		if !time.Now().Before(until) {
			w.logf("forget: the kernel did not say within %s which agents read erased content; every agent stays contained until it does", w.startWait)
			break
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(eraseReadsRetry):
		}
	}
	w.notify(tell)
}

func (w *eraseRewind) isBad() bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.bad
}

// markTold records that the owner was told of the rewinds rows record,
// and of no other: an earlier rewind of the same lineage whose notice did
// not go is still told by notify. Caller holds run.
func (w *eraseRewind) markTold(rows []rewoundRead) {
	if len(rows) == 0 {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	for i, s := range w.settled {
		if slices.ContainsFunc(rows, func(r rewoundRead) bool { return r.Subject == s.Subject && r.Lineage == s.Lineage }) {
			w.settled[i].Told = true
		}
	}
	if err := w.save(); err != nil {
		// Untold on disk: the next start tells the owner again.
		w.logf("%s not written: %v", w.path, err)
	}
}

// notify tells the owner once of each rewind not yet told, by lineage.
// Sends run outside mu, so a slow owner channel never stalls Contained,
// and under run, so two passes never tell the same rewind.
func (w *eraseRewind) notify(tell func(string) error) {
	w.run.Lock()
	defer w.run.Unlock()
	w.mu.Lock()
	untold := map[string]int64{}
	for _, s := range w.settled {
		if f, ok := untold[s.Lineage]; !s.Told && (!ok || s.First < f) {
			untold[s.Lineage] = s.First
		}
	}
	w.mu.Unlock()
	for _, l := range slices.Sorted(maps.Keys(untold)) {
		if err := tell(eraseBackNotice(l, untold[l])); err != nil {
			w.logf("forget: rewind notice for agent %s not sent: %v", agentName(l), err)
			continue
		}
		w.mu.Lock()
		for i := range w.settled {
			if w.settled[i].Lineage == l {
				w.settled[i].Told = true
			}
		}
		if err := w.save(); err != nil {
			w.logf("%s not written: %v", w.path, err)
		}
		w.mu.Unlock()
	}
}

// eraseBackNotice is the owner's notice of one rewind found at start.
func eraseBackNotice(lineage string, first int64) string {
	return fmt.Sprintf("Agent %s had read something you had me forget, so it went back to %s; its work since then is gone.",
		agentName(lineage), time.UnixMilli(first).Local().Format("Jan 2 15:04"))
}

// watch asks for the erased reads again while they are unknown, so every
// agent is contained no longer than the kernel is unreachable, and retries
// each lineage still owed a rewind, waiting twice as long after each
// failure up to maxRewindWait (a repeat rewind takes back later work too,
// which fails closed). The owner is told of each rewind it makes then, as
// the start-up pass tells its own. A notice that did not go is sent
// again on the same backoff, rewind or not.
func (w *eraseRewind) watch(ctx context.Context, every time.Duration, tell func(string) error) {
	t := time.NewTicker(every)
	defer t.Stop()
	wait, next := every, time.Time{}
	tellWait, tellNext := every, time.Time{}
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		w.mu.Lock()
		unknown := w.k != nil && !w.bad && !w.readsKnown
		owed := w.k != nil && !w.bad && len(w.holding) > 0
		untold := slices.ContainsFunc(w.settled, func(s rewoundRead) bool { return !s.Told })
		w.mu.Unlock()
		switch {
		case unknown:
		case owed && !time.Now().Before(next):
			next = time.Now().Add(wait)
			wait = min(2*wait, maxRewindWait)
		default:
			if !owed {
				wait = every
			}
			if !untold {
				tellWait = every
			} else if !time.Now().Before(tellNext) {
				tellNext = time.Now().Add(tellWait)
				tellWait = min(2*tellWait, maxRewindWait)
				w.notify(tell)
			}
			continue
		}
		w.rewind(ctx)
		w.notify(tell)
	}
}

// Note is STATUS's line for contained agents.
func (w *eraseRewind) Note() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	switch {
	case w.k == nil:
		return ""
	case w.bad:
		return forgetRecordUnread
	case !w.readsKnown:
		return forgetReadsUnknown
	case len(w.holding) == 0:
		return ""
	}
	return forgetHeldLine(slices.Sorted(maps.Keys(w.holding)))
}

// save writes the record durably. Caller holds mu.
func (w *eraseRewind) save() error {
	b, err := json.Marshal(w.settled)
	if err != nil {
		return err
	}
	return writeSynced(w.path, b)
}
