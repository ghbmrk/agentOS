package journal

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"runtime/debug"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// REQ: OP-2, OP-4, ADP-9

// The same-effect model (B8): an exhaustive search, to a bounded depth,
// of every interleaving of two or three intents with one effect across
// submit, approve, deny, dispatch (the executor applying it or not, and
// saying so or not), restart, checks through the same tool (proving the
// attempt applied or not, with the engine's resend allowed, refused by
// the recheck, or itself unclear), parking, the owner's RETRY of a parked
// or a not-done intent, the owner's own evidence on any unknown attempt
// (Resolve), the settle loop's release of a held resubmission or of a
// request whose effect went, erase (the owner's or a recall reset's, on
// any intent, held or not), and STOP and RESUME, for an effect that
// widens authority and for one that only narrows it. After every step it
// checks:
//
//   - I1: the effect never applies twice through two rivals unless the
//     second was submitted after the first was known to have succeeded,
//     and one intent applies twice only on the owner's RETRY of a parked
//     attempt (which says "may go twice"); no attempt starts while another
//     intent with the effect may still take effect (in flight, unknown or
//     parked, duplicateOf);
//   - I2: an effect a check proved not done is never lost: it is offered
//     for RETRY (NotResent), or a rival that went, may have gone or waits
//     for approval holds it back, or an authorized rival does that the
//     settle loop's Release dispatches (or that waits behind an unclear
//     intent or a restart fence);
//   - I3: no permanent block: a request for the effect made now is never
//     refused as superseded, and a narrowing intent never is at all;
//   - I4: no deadlock: while something waits to go, no approval or check
//     is outstanding and STOP is off, some dispatch, resend, retry or
//     release still makes progress; and an authorized request whose
//     effect went under a rival after it was made is answered (denied)
//     by the settle loop's Release (R15);
//   - I5 (confirm repeats, D-116): a request whose effect is known to
//     have gone under another request (in the window, which the fixed
//     clock always is) is dispatched only after the owner's confirmation
//     of it given after that success: a "confirm" step, or an "approve"
//     of a request asked after it went. The model's policy asks it as the
//     gate does (grants recentRepeat, decision.covers), from the engine's
//     InUse (Use.Went, Use.Known); an approval given before the rival
//     went does not confirm it (Security B10 on #1433), and an erased
//     success still counts (Security R23).
//
// Rivalry itself (rivals) is restated from the journal, not read from the
// engine's fields.

// mMode is how the model's service handles one Execute call.
type mMode int

const (
	mOK      mMode = iota // apply, acknowledge
	mRefuse               // do not apply, say so (not_applied)
	mDropAck              // apply, outcome lost (unknown)
	mTimeout              // do not apply, outcome lost (unknown)
)

var mModeName = [...]string{"ok", "refuse", "dropack", "timeout"}

// mApply is one application of the effect: which attempt, by what path.
type mApply struct {
	id  string
	n   int
	via string
}

// mExec is the model's service. Its checks tell the truth for the one
// intent a check step names, and are unclear for the rest.
type mExec struct {
	mu      sync.Mutex
	next    mMode
	via     string
	check   string
	applied map[string]bool
	log     []mApply
}

func (x *mExec) Execute(_ context.Context, in Intent, n int) Outcome {
	x.mu.Lock()
	defer x.mu.Unlock()
	switch x.next {
	case mRefuse:
		return Outcome{Result: ResultNotApplied, Evidence: "refused"}
	case mTimeout:
		return Outcome{Result: ResultUnknown}
	}
	if key := AttemptKey(in.ID, n); !x.applied[key] {
		x.applied[key] = true
		x.log = append(x.log, mApply{in.ID, n, x.via})
	}
	if x.next == mDropAck {
		return Outcome{Result: ResultUnknown}
	}
	return Outcome{Result: ResultSucceeded, Evidence: "receipt"}
}

func (x *mExec) Reconcile(_ context.Context, in Intent, n int) Outcome {
	x.mu.Lock()
	defer x.mu.Unlock()
	if in.ID != x.check {
		return Outcome{Result: ResultUnknown}
	}
	if x.applied[AttemptKey(in.ID, n)] {
		return Outcome{Result: ResultSucceeded, Evidence: "found"}
	}
	return Outcome{Result: ResultNotApplied, Evidence: "not found"}
}

// mPolicy allows everything but the intents a step denies and, with
// confirm set, a repeat the owner has not confirmed since its rival went
// (mRepeat): as the gate's decision.covers, an approval given before the
// rival went did not see the repeat (Security B10 on #1433).
type mPolicy struct {
	mu        sync.Mutex
	deny      map[string]bool
	confirm   bool
	confirmed map[string]uint64
	e         *Engine
}

func (p *mPolicy) Check(_ context.Context, _ Phase, in Intent) error {
	p.mu.Lock()
	deny, e := p.deny[in.ID], p.e
	ask, c := p.confirm, p.confirmed[in.ID]
	p.mu.Unlock()
	if deny {
		return errors.New("refused")
	}
	if ask && e != nil {
		if w := mRepeat(e, in); w != 0 && c < w {
			return errors.New("needs the owner's confirmation")
		}
	}
	return nil
}

// mRepeatWindow is grants' repeatWindow.
const mRepeatWindow = 24 * time.Hour

// mRepeat is the gate's confirm-repeats rule (grants recentRepeat) for
// the model, whose intents all name the same record, recipients and
// body: another request on in's account and action known to have gone
// within the window (Use.Known), erased or not (an erased one cannot be
// told apart, Security R23 on #1433). It returns the journal seq at which
// the last of them was known to have gone, or 0: an owner's yes given at
// or after it saw the repeat.
func mRepeat(e *Engine, in Intent) uint64 {
	since := mNow.Add(-mRepeatWindow)
	var w uint64
	for _, u := range e.InUse(in.Account, in.Action, since) {
		if u.Intent.ID == in.ID || !u.Started || u.Went.IsZero() || u.Known.Before(since) {
			continue
		}
		e.mu.Lock()
		if en := e.intents[u.Intent.ID]; en != nil && en.wentSeq > w {
			w = en.wentSeq
		}
		e.mu.Unlock()
	}
	return w
}

// mState is one node of the search: what survives between steps.
type mState struct {
	eng     *Engine // as the step left it; never changed after
	facts   map[string]mFacts
	journal []byte
	fence   map[string][]string
	applied map[string]bool
	log     []mApply
	path    []string
	// confirm: the policy asks the owner to confirm a repeat (mRepeat);
	// confirmed holds, for each intent the owner confirmed, the journal's
	// seq when they did.
	confirm   bool
	confirmed map[string]uint64
}

// key is the node's identity for the search: what the engine's decisions
// and the oracle read, with sequence numbers replaced by their order, so
// histories that differ only in what is not compared meet.
func (s *mState) key(e *Engine) string {
	var b strings.Builder
	var seqs []uint64
	ens := bySeq(e.intents)
	for _, en := range ens {
		for _, q := range []uint64{en.seq, en.firstDispatchSeq, en.provedSeq, en.wentSeq, s.confirmed[en.intent.ID]} {
			if q != 0 {
				seqs = append(seqs, q)
			}
		}
	}
	sort.Slice(seqs, func(i, j int) bool { return seqs[i] < seqs[j] })
	rank := func(q uint64) int {
		if q == 0 {
			return -1
		}
		return sort.Search(len(seqs), func(i int) bool { return seqs[i] >= q })
	}
	for _, en := range ens {
		fmt.Fprintf(&b, "%s:%s:%v:%d,%d,%d,%d,%d[", en.intent.ID, en.state, en.erased,
			rank(en.seq), rank(en.firstDispatchSeq), rank(en.provedSeq), rank(en.wentSeq), rank(s.confirmed[en.intent.ID]))
		for _, a := range en.attempts {
			fmt.Fprintf(&b, "%s/%s/%v ", a.Result, a.Source, a.Parked)
		}
		b.WriteString("]")
	}
	accts := make([]string, 0, len(s.fence))
	for a := range s.fence {
		accts = append(accts, a)
	}
	sort.Strings(accts)
	for _, a := range accts {
		fmt.Fprintf(&b, "|f%s=%v", a, s.fence[a])
	}
	fmt.Fprintf(&b, "|s%v", e.stopped)
	keys := make([]string, 0, len(s.applied))
	for k := range s.applied {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	fmt.Fprintf(&b, "|a%v|l%v", keys, s.log)
	return b.String()
}

// mRun is a live engine restored from a node.
type mRun struct {
	e   *Engine
	x   *mExec
	pol *mPolicy
	st  *MemStore
}

var mNow = time.Date(2026, 10, 14, 9, 0, 0, 0, time.UTC)

// restore opens an engine on s. keepFence restores the node's restart
// fence, which lives in memory; a restart step instead lets Open fence
// what is unknown, as a real restart does.
func restore(t *testing.T, s *mState, keepFence bool) *mRun {
	t.Helper()
	x := &mExec{applied: map[string]bool{}, log: append([]mApply(nil), s.log...)}
	for k, v := range s.applied {
		x.applied[k] = v
	}
	pol := &mPolicy{deny: map[string]bool{}, confirm: s.confirm, confirmed: map[string]uint64{}}
	for k, v := range s.confirmed {
		pol.confirmed[k] = v
	}
	execs := map[string]Executor{"svc": x}
	if keepFence && s.eng != nil {
		e, st := cloneEngine(t, s.eng, pol, execs)
		pol.e = e
		return &mRun{e: e, x: x, pol: pol, st: st}
	}
	st := &MemStore{data: bytes.Clone(s.journal)}
	e, err := Open(st, pol, execs, testRedact, WithClock(func() time.Time { return mNow }))
	if err != nil {
		t.Fatalf("%v: open: %v", s.path, err)
	}
	pol.e = e
	return &mRun{e: e, x: x, pol: pol, st: st}
}

// cloneEngine copies a live engine, memory state included (the restart
// fence, which a replay would rebuild differently), so each step starts
// from its node without replaying the journal. Only a restart step
// replays it, through Open.
func cloneEngine(t *testing.T, e *Engine, pol Policy, execs map[string]Executor) (*Engine, *MemStore) {
	t.Helper()
	if len(e.cold) > 0 || e.broken != nil || len(e.redispatching) > 0 {
		t.Fatal("clone: evicted denials, a broken engine or a redispatch in progress")
	}
	st := &MemStore{data: bytes.Clone(e.store.(*MemStore).data)}
	c := &Engine{store: st, policy: pol, redact: e.redact, execs: execs, now: e.now, seq: e.seq,
		intents: map[string]*entry{}, open: map[string]*entry{}, byEffect: map[string][]*entry{},
		denied: append([]string(nil), e.denied...), cold: map[coldKey]coldVal{}, shapeIx: map[coldShape]uint32{},
		stopped: e.stopped, fence: map[string]map[string]bool{}, missed: e.missed, checks: map[string]int{},
		redispatching: map[string]bool{}, newest: e.newest, lingering: map[string]*entry{}}
	cp := map[*entry]*entry{}
	for id, en := range e.intents {
		n := *en
		n.attempts = make([]Attempt, len(en.attempts))
		for i, a := range en.attempts {
			a.Cancels = append([]Cancel(nil), a.Cancels...)
			n.attempts[i] = a
		}
		c.intents[id], cp[en] = &n, &n
	}
	for id, en := range e.open {
		c.open[id] = cp[en]
	}
	for id, en := range e.lingering {
		c.lingering[id] = cp[en]
	}
	for k, b := range e.byEffect {
		for _, en := range b {
			c.byEffect[k] = append(c.byEffect[k], cp[en])
		}
	}
	for a, ids := range e.fence {
		c.fence[a] = map[string]bool{}
		for id, v := range ids {
			c.fence[a][id] = v
		}
	}
	return c, st
}

func (r *mRun) snapshot(path []string) *mState {
	s := &mState{eng: r.e, journal: bytes.Clone(r.st.data), fence: map[string][]string{}, applied: map[string]bool{},
		log: append([]mApply(nil), r.x.log...), path: path, confirm: r.pol.confirm, confirmed: map[string]uint64{}}
	for k, v := range r.pol.confirmed {
		s.confirmed[k] = v
	}
	for a, ids := range r.e.fence {
		for id := range ids {
			s.fence[a] = append(s.fence[a], id)
		}
		sort.Strings(s.fence[a])
		if len(s.fence[a]) == 0 {
			delete(s.fence, a)
		}
	}
	for k, v := range r.x.applied {
		s.applied[k] = v
	}
	return s
}

// mStep is one transition: its name and what it does to a run.
type mStep struct {
	name string
	do   func(*mRun) error
	// restart: Open fences what is unknown, rather than keeping the
	// node's fence.
	restart bool
}

// mModel is one search configuration.
type mModel struct {
	ids    []string
	narrow bool
	depth  int
	// owner adds the owner's own steps: STOP, RESUME and evidence on an
	// unknown attempt (Resolve).
	owner bool
}

// confirm reports whether the configuration's policy asks the owner to
// confirm repeats: the gate does for a widening effect on an account,
// never for a narrowing one (which may always go again).
func (m *mModel) confirm() bool { return !m.narrow }

// confirmedAt is the journal seq of the owner's last yes on id (an
// approval or a confirmation), or 0.
func (m *mModel) confirmedAt(e *Engine, id string) uint64 {
	pol, ok := e.policy.(*mPolicy)
	if !ok {
		return 0
	}
	pol.mu.Lock()
	defer pol.mu.Unlock()
	return pol.confirmed[id]
}

func (m *mModel) intent(id string) Intent {
	in := intent(id, "mail")
	if m.narrow {
		in.Account, in.Action, in.Params, in.Recipients, in.Visibility = BrokerAccount, ActionGrantPause, nil, nil, ""
	}
	return in
}

// steps lists the transitions enabled at a node.
func (m *mModel) steps(e *Engine) []mStep {
	var out []mStep
	add := func(name string, f func(*mRun) error) { out = append(out, mStep{name: name, do: f}) }
	for i, id := range m.ids {
		id := id
		en := e.intents[id]
		if en == nil {
			if i == 0 || e.intents[m.ids[i-1]] != nil {
				in := m.intent(id)
				add("submit "+id, func(r *mRun) error { _, err := r.e.Submit(in); return err })
			}
			continue
		}
		modes := func(name string, ms []mMode, via string, f func(*mRun) error) {
			for _, md := range ms {
				md := md
				add(name+" "+id+" "+mModeName[md], func(r *mRun) error { r.x.next, r.x.via = md, via; return f(r) })
			}
		}
		all := []mMode{mOK, mRefuse, mDropAck, mTimeout}
		switch en.state {
		case Pending:
			// An ordinary approval, offered before a rival went as
			// after: the owner's yes on the line as it is now, which
			// confirms only the repeats it showed (Security B10).
			add("approve "+id, func(r *mRun) error {
				if m.confirm() {
					r.pol.confirmed[id] = r.e.seq
				}
				_, err := r.e.Authorize(ctx, id)
				return err
			})
			add("deny "+id, func(r *mRun) error {
				r.pol.deny[id] = true
				_, err := r.e.Authorize(ctx, id)
				return err
			})
		case Authorized, NotApplied:
			modes("dispatch", all, "dispatch", func(r *mRun) error { _, err := r.e.Dispatch(ctx, id); return err })
		}
		// The owner's evidence on any unknown attempt, true to the
		// service (Resolve), as a parked or an earlier one may be
		// settled while a later one is still open.
		for _, a := range en.attempts {
			if !m.owner || a.Result != ResultUnknown {
				continue
			}
			k := a.N
			add(fmt.Sprintf("resolve %s#%d", id, k), func(r *mRun) error {
				res := ResultNotApplied
				if r.x.applied[AttemptKey(id, k)] {
					res = ResultSucceeded
				}
				_, err := r.e.Resolve(id, k, Outcome{Result: res, Evidence: "owner"}, "owner")
				return err
			})
		}
		if en.state == OutcomeUnknown {
			n := en.latest().N
			// A check tells the truth; if the attempt did not apply, the
			// engine's resend is allowed (and goes or is unclear) or
			// refused by the recheck (as after a restart).
			check := func(md mMode, refuse bool) func(*mRun) error {
				return func(r *mRun) error {
					r.x.check, r.x.next, r.x.via = id, md, "redispatch"
					r.pol.deny[id] = refuse
					r.e.Reconcile(ctx)
					r.e.checks = map[string]int{}
					return nil
				}
			}
			add("check "+id+" resend-refused", check(mOK, true))
			add("check "+id+" resend-ok", check(mOK, false))
			add("check "+id+" resend-unclear", check(mTimeout, false))
			if en.state == OutcomeUnknown && !en.parked() {
				add("park "+id, func(r *mRun) error { r.e.park(id, n, true); return nil })
			}
			if en.retryable() {
				modes("retry", all, "retry", func(r *mRun) error { _, err := r.e.Retry(ctx, id, n); return err })
			}
		}
		if en.notDone() {
			n := en.latest().N
			modes("resend", []mMode{mOK, mRefuse, mTimeout}, "resend",
				func(r *mRun) error { _, err := r.e.Resend(ctx, id, n); return err })
		}
		// The owner confirms a repeat the policy asks about (I5).
		if m.confirm() && !en.erased && (en.state == Pending || en.state == Authorized || en.state == NotApplied || en.retryable()) &&
			e.intents[id] != nil && mRepeat(e, en.intent) > m.confirmedAt(e, id) {
			add("confirm "+id, func(r *mRun) error {
				r.pol.confirmed[id] = r.e.seq
				return nil
			})
		}
		// Erase is offered on any intent: one that may still take
		// effect must be held, not erased (B9).
		if !en.erased {
			add("erase "+id, func(r *mRun) error { _, _, err := r.e.Erase([]string{id}); return err })
		}
	}
	switch {
	case !m.owner:
	case e.stopped:
		add("resume", func(r *mRun) error { return r.e.Resume() })
	default:
		add("stop", func(r *mRun) error { _, err := r.e.Stop(ctx); return err })
	}
	for _, md := range []mMode{mOK, mTimeout} {
		md := md
		add("release "+mModeName[md], func(r *mRun) error {
			r.x.next, r.x.via = md, "release"
			r.e.Release(ctx, r.e.Dispatch)
			return nil
		})
	}
	out = append(out, mStep{name: "restart", do: func(*mRun) error { return nil }, restart: true})
	return out
}

// run searches breadth first from the empty journal and returns how many
// distinct states it reached.
func (m *mModel) run(t *testing.T) int {
	t.Helper()
	start := &mState{fence: map[string][]string{}, applied: map[string]bool{}, confirm: m.confirm(), confirmed: map[string]uint64{}}
	seen := map[string]bool{start.key(restore(t, start, true).e): true}
	level := []*mState{start}
	for d := 0; d < m.depth && len(level) > 0; d++ {
		var next []*mState
		for _, s := range level {
			r := restore(t, s, true)
			for _, st := range m.steps(r.e) {
				path := append(append([]string(nil), s.path...), st.name)
				var r2 *mRun
				if st.restart {
					r2 = restore(t, s, false)
				} else {
					r2 = restore(t, s, true)
				}
				err := st.do(r2)
				var se *SupersededError
				if m.narrow && errors.As(err, &se) {
					t.Fatalf("I3: %v: a narrowing intent was refused as superseded: %v", path, err)
				}
				ns := r2.snapshot(path)
				// I1's dispatch rule is a property of the step, so it is
				// checked on every step, also one that meets a seen node.
				m.follow(t, s, ns)
				k := ns.key(r2.e)
				if seen[k] {
					continue
				}
				seen[k] = true
				m.check(t, r2, ns)
				next = append(next, ns)
			}
		}
		level = next
	}
	return len(seen)
}

// mFacts is what the journal says of one intent, restated for the oracle.
type mFacts struct {
	seq, firstDispatch, went uint64
	// proved is the seq of the first record that proved an attempt not
	// applied; disp the seq of each attempt's (first) dispatch; erased
	// the seq of its erasure.
	proved uint64
	disp   []uint64
	erased uint64
}

// rivalsOracle: some intent z was proved not applied before at (the
// dispatch that applied the later of the two), and each of a and b is z
// or was requested after z was first dispatched. Evidence that came only
// after the second went (the owner's, say) cannot have told the engine.
func rivalsOracle(f map[string]mFacts, a, b string, at uint64) bool {
	for zid, z := range f {
		if z.proved == 0 || z.proved > at || z.firstDispatch == 0 {
			continue
		}
		ok := func(x string) bool { return x == zid || f[x].seq > z.firstDispatch }
		if ok(a) && ok(b) {
			return true
		}
	}
	return false
}

// unclearOracle reports an intent with an attempt that may still take
// effect: in flight or unknown, and the intent did not go. A denied or
// erased intent counts: denying it does not stop an attempt that went.
func unclearOracle(en *entry) bool {
	if en.state == Succeeded {
		return false
	}
	for _, a := range en.attempts {
		if a.Result == ResultUnknown || a.Result == ResultInFlight {
			return true
		}
	}
	return false
}

// follow reads the step's records into s.facts, what the journal says of
// each intent for the oracle, and checks I1's dispatch rule on them: no
// attempt starts while another intent with the effect may still take
// effect.
func (m *mModel) follow(t *testing.T, parent, s *mState) {
	t.Helper()
	// Only the step's own records are new; replay them on a copy of the
	// node's intents. An erase rewrote the journal: replay it all.
	shadow := map[string]*entry{}
	s.facts = map[string]mFacts{}
	data := s.journal
	if parent.eng != nil && bytes.HasPrefix(s.journal, parent.journal) {
		c, _ := cloneEngine(t, parent.eng, nil, nil)
		shadow, data = c.intents, s.journal[len(parent.journal):]
		for id, f := range parent.facts {
			s.facts[id] = f
		}
	}
	var recs []Record
	for _, line := range bytes.Split(bytes.TrimSuffix(data, []byte("\n")), []byte("\n")) {
		if len(line) == 0 {
			continue
		}
		rec, err := decodeLine(line)
		if err != nil {
			t.Fatal(err)
		}
		recs = append(recs, rec)
	}
	for _, rec := range recs {
		f := s.facts[rec.ID]
		switch rec.Type {
		case RecSubmitted:
			f.seq = rec.Seq
		case RecDispatched:
			if f.firstDispatch == 0 {
				f.firstDispatch = rec.Seq
			}
			if rec.Attempt > len(f.disp) {
				f.disp = append(append([]uint64(nil), f.disp...), rec.Seq)
			}
		case RecObserved:
			if rec.Result == ResultNotApplied && f.proved == 0 {
				f.proved = rec.Seq
			}
			if rec.Result == ResultSucceeded && f.went == 0 {
				f.went = rec.Seq
			}
		case RecErased:
			if f.erased == 0 {
				f.erased = rec.Seq
			}
		}
		if rec.ID != "" {
			s.facts[rec.ID] = f
		}
		if rec.Type == RecSubmitted {
			shadow[rec.ID] = newEntry(rec)
			continue
		}
		en := shadow[rec.ID]
		if en == nil {
			continue
		}
		if rec.Type == RecDispatched && rec.Source != DispatchKey {
			for id, o := range shadow {
				if id == rec.ID || !unclearOracle(o) {
					continue
				}
				t.Fatalf("I1: %v: %s started attempt %d while %s was %s", s.path, rec.ID, rec.Attempt, id, o.state)
			}
		}
		en.apply(rec)
	}
}

func (m *mModel) check(t *testing.T, r *mRun, s *mState) {
	t.Helper()
	e := r.e
	fail := func(inv, format string, args ...any) {
		t.Helper()
		t.Fatalf("%s: %v: %s", inv, s.path, fmt.Sprintf(format, args...))
	}
	f := s.facts

	// I1, effect level.
	if !m.narrow {
		for i, p := range s.log {
			for _, q := range s.log[i+1:] {
				if p.id == q.id {
					if q.via != "retry" {
						fail("I1", "%s applied twice (attempts %d and %d, the second by %s)", p.id, p.n, q.n, q.via)
					}
					continue
				}
				known := f[p.id].went
				if rivalsOracle(f, p.id, q.id, f[q.id].disp[q.n-1]) && (known == 0 || f[q.id].seq < known) {
					fail("I1", "rivals %s and %s both applied; %s was requested before %s was known to have gone", p.id, q.id, q.id, p.id)
				}
			}
		}
	}
	// I5: a repeat of an effect known to have gone is dispatched only
	// after the owner confirmed it.
	if m.confirm() {
		for _, q := range s.log {
			at := f[q.id].disp[q.n-1]
			for pid, p := range f {
				if pid == q.id || p.went == 0 || p.went > at {
					continue
				}
				// The owner's yes must come after p went and before the
				// dispatch: one given earlier did not see the repeat
				// (Security B10 on #1433). An erased p still counts
				// (Security R23).
				if c := s.confirmed[q.id]; c == 0 || c > at || c < p.went {
					fail("I5", "%s attempt %d applied (by %s) after %s was known to have gone, without the owner's confirmation", q.id, q.n, q.via, pid)
				}
			}
		}
	}
	// I2.
	listed := map[string]bool{}
	for _, p := range append(e.NotResent(), e.Parked()...) {
		listed[p.Intent.ID] = true
	}
	for _, id := range m.ids {
		en := e.intents[id]
		if en == nil || !en.notDone() || en.erased || listed[id] {
			continue
		}
		o := e.sameEffect(en)
		switch {
		case o == nil:
			fail("I2", "%s was proved not done and is neither offered nor held back", id)
		case o.wentSeq != 0 && en.seq < o.wentSeq, o.state == Pending, o.unresolved():
		case o.state == Authorized && e.stopped:
			// STOP holds the release until RESUME.
		case o.state == Authorized:
			fr := restore(t, s, true)
			fr.x.next, fr.x.via = mOK, "release"
			fr.e.Release(ctx, fr.e.Dispatch)
			o2 := fr.e.intents[o.intent.ID]
			if o2.state == Authorized && fr.e.duplicateOf(o2) == "" && len(fr.e.fence[o2.intent.Account]) == 0 {
				fail("I2", "%s was proved not done and is hidden behind %s, which nothing dispatches", id, o.intent.ID)
			}
		default:
			fail("I2", "%s is hidden behind %s, which is %s", id, o.intent.ID, o.state)
		}
	}

	// I3: a request made now is never refused as superseded; a narrowing
	// intent never is.
	if m.narrow {
		for _, en := range e.intents {
			if o := e.sameEffect(en); o != nil {
				fail("I3", "narrowing %s is held back by %s", en.intent.ID, o.intent.ID)
			}
		}
	}
	if len(e.intents) > 0 {
		fr := restore(t, s, true)
		fr.x.next, fr.x.via = mOK, "probe"
		in := m.intent("p")
		must(fr.e.Submit(in))
		fr.pol.confirmed["p"] = fr.e.seq // the owner confirms it, if asked (I5)
		must(fr.e.Authorize(ctx, "p"))
		st, err := fr.e.Dispatch(ctx, "p")
		var se *SupersededError
		if errors.As(err, &se) || st.State == Denied {
			fail("I3", "a request made now is refused: %+v %v", st.State, err)
		}
	}

	// I4.
	if e.stopped {
		return // STOP holds everything until the owner's RESUME
	}
	try := func(f func(*mRun)) bool {
		fr := restore(t, s, true)
		fr.x.next, fr.x.via = mOK, "progress"
		before := len(fr.st.data)
		f(fr)
		return len(fr.st.data) != before
	}
	// R15: a request whose effect went under a rival after it was made is
	// answered by Release, not left authorized.
	var answered []string
	for _, id := range m.ids {
		en := e.intents[id]
		if en == nil || en.state != Authorized || len(e.fence[en.intent.Account]) > 0 {
			continue
		}
		if o := e.sameEffect(en); o != nil && o.wentSeq != 0 && en.seq < o.wentSeq {
			answered = append(answered, id)
		}
	}
	if len(answered) > 0 {
		fr := restore(t, s, true)
		fr.x.next, fr.x.via = mOK, "release"
		fr.e.Release(ctx, fr.e.Dispatch)
		for _, id := range answered {
			if st := fr.e.intents[id].state; st != Denied {
				fail("I4", "%s stays %s after Release although its effect went", id, st)
			}
		}
	}
	var waiting []*entry
	for _, id := range m.ids {
		en := e.intents[id]
		if en == nil {
			continue
		}
		if en.state == Pending || (en.state == OutcomeUnknown && (!en.parked() || en.wentSeq != 0)) {
			// An approval or the parking of a check is still to come, or
			// an intent that went waits only on the check of a later
			// attempt (no RETRY sends it again).
			return
		}
		if en.state != Authorized && en.state != NotApplied && !en.retryable() || en.wentSeq != 0 {
			continue // nothing to send: not waiting, or it went
		}
		if o := e.sameEffect(en); o != nil && o.wentSeq != 0 && en.seq < o.wentSeq && en.state != Authorized {
			continue // the effect went; this one is answered when repeated
		}
		waiting = append(waiting, en)
	}
	if len(waiting) == 0 {
		return
	}
	if try(func(fr *mRun) { fr.e.Release(ctx, fr.e.Dispatch) }) {
		return
	}
	// Every intent that could go is tried, not only those counted as
	// waiting (R15 hid behind that).
	var cands []*entry
	for _, id := range m.ids {
		if en := e.intents[id]; en != nil && (en.state == Authorized || en.state == NotApplied || en.retryable()) {
			cands = append(cands, en)
		}
	}
	for _, en := range cands {
		id, n := en.intent.ID, en.latest()
		if (en.state == Authorized || en.state == NotApplied) && try(func(fr *mRun) { _, _ = fr.e.Dispatch(ctx, id) }) {
			return
		}
		if en.notDone() && try(func(fr *mRun) { _, _ = fr.e.Resend(ctx, id, n.N) }) {
			return
		}
		if en.retryable() && try(func(fr *mRun) { _, _ = fr.e.Retry(ctx, id, n.N) }) {
			return
		}
	}
	var ids []string
	for _, en := range waiting {
		ids = append(ids, en.intent.ID+"="+string(en.state))
	}
	fail("I4", "deadlock: %v wait and nothing can go", ids)
}

// TestOP2SameEffectModel runs the search for an effect that widens
// authority, with two and with three intents, and for one that only
// narrows it, and, with the owner's STOP, RESUME and evidence added, for
// two intents of each. Two intents to depth 10 reach the erase of an
// unclear intent and a resubmission after it (B9, depth 9); three to
// depth 9 dispatch all three. It is skipped under the race detector
// (modelRace): CI's broker job runs it without -race, at these bounds,
// in its own step. MODEL_DEPTH (a number added to every depth) sets a
// deeper run; MODEL_ONLY runs the configurations whose name contains it.
func TestOP2SameEffectModel(t *testing.T) {
	if modelRace {
		t.Skip("sequential search: run without -race (CI's model step)")
	}
	more, _ := strconv.Atoi(os.Getenv("MODEL_DEPTH"))
	// The search keeps every level's nodes live; collecting less often
	// halves its time.
	old := debug.SetGCPercent(300)
	t.Cleanup(func() { debug.SetGCPercent(old) })
	for _, m := range []mModel{
		{ids: []string{"a", "b"}, depth: 10},
		{ids: []string{"a", "b", "c"}, depth: 9},
		{ids: []string{"a", "b"}, narrow: true, depth: 10},
		{ids: []string{"a", "b"}, owner: true, depth: 9},
		{ids: []string{"a", "b"}, narrow: true, owner: true, depth: 9},
	} {
		m := m
		m.depth += more
		name := fmt.Sprintf("%d intents, narrowing %v, owner %v, depth %d", len(m.ids), m.narrow, m.owner, m.depth)
		if only := os.Getenv("MODEL_ONLY"); only != "" && !strings.Contains(name, only) {
			continue
		}
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			start := time.Now()
			n := m.run(t)
			t.Logf("%d states in %v", n, time.Since(start))
		})
	}
}

// replay runs one path of the search by its step names, checking the
// invariants after each step as the search does.
func (m *mModel) replay(t *testing.T, path []string) {
	t.Helper()
	s := &mState{fence: map[string][]string{}, applied: map[string]bool{}, confirm: m.confirm(), confirmed: map[string]uint64{}}
	for _, name := range path {
		r := restore(t, s, true)
		var st *mStep
		for _, c := range m.steps(r.e) {
			if c.name == name {
				c := c
				st = &c
				break
			}
		}
		if st == nil {
			t.Fatalf("%v: no step %q", s.path, name)
		}
		r2 := restore(t, s, !st.restart)
		_ = st.do(r2)
		ns := r2.snapshot(append(append([]string(nil), s.path...), name))
		m.follow(t, s, ns)
		m.check(t, r2, ns)
		s = ns
	}
}

// B9: the erase of an intent whose owner's retry the service refused
// while its parked first try may have gone (unclear) must hold it, not
// deny it; otherwise a resubmission goes too, and the effect may go
// twice. The search reaches this at depth 9; the path is pinned here.
func TestOP2ModelErasedUnclearIntentStillHoldsItsEffect(t *testing.T) {
	m := mModel{ids: []string{"a", "b"}}
	m.replay(t, []string{"submit a", "approve a", "dispatch a dropack", "park a", "retry a refuse",
		"erase a", "submit b", "approve b", "dispatch b ok"})
}

// R15: b, authorized, is held back by c, which went after b was made;
// the settle loop's Release answers b (denied), rather than leaving it
// authorized until someone dispatches it.
func TestOP2ModelRivalIsAnsweredOnceTheEffectWent(t *testing.T) {
	m := mModel{ids: []string{"a", "b", "c"}}
	m.replay(t, []string{"submit a", "approve a", "dispatch a refuse", "submit b", "approve b",
		"submit c", "approve c", "dispatch c ok"})
}
