// Package sim runs the real kernel and clerk check against a fake disk, clock
// and world, driven by a seeded hostile planner, and judges every step against
// the invariants. One seed gives one trace, byte for byte (SIM-1).
package sim

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand/v2"
	"reflect"
	"strings"

	"github.com/ghbmrk/agentos/broker/clerk"
	"github.com/ghbmrk/agentos/broker/kernel"
	"github.com/ghbmrk/agentos/broker/kernel/key"
)

// Mutant plants one defect so a test can show the sweep catches it.
type Mutant string

const (
	MutantNone        Mutant = ""
	MutantClerkTrusts Mutant = "clerk-trusts-kernel"  // the clerk skips its own check
	MutantNoDedupe    Mutant = "clerk-no-idempotency" // the clerk acts again on a repeated idem
)

// Config is one run.
type Config struct {
	Seed   uint64
	Ops    int
	Mutant Mutant
}

// Result is what a run leaves for a test to read.
type Result struct {
	Trace   []string
	Entries []kernel.Entry
	Effects int

	// What the faults did, counted where they took effect, not where they were
	// chosen: a fault that changed nothing leaves its counter at zero.
	Refused       int // appends the full disk refused
	ClockBack     int // times the clock really moved back
	StaleRefused  int // old requests redelivered to the world that it did not act on
	AnchorFailed  int // anchor writes that failed
	WidenUnproven int // widenings whose anchor failed, left live until the log is reopened
	UnheldRefused int // plans under a key their signer does not hold, rejected
}

var errAnchor = errors.New("sim: anchor down")

// anchor is a MemAnchor the owner's phone can drop off from: while down, no head is confirmed.
type anchor struct {
	kernel.MemAnchor
	down   bool
	failed int
}

func (a *anchor) Put(h kernel.Head) error {
	if a.down {
		a.failed++
		return errAnchor
	}
	return a.MemAnchor.Put(h)
}

const hour = int64(3_600_000)

type effect struct {
	idem string
	at   int64
	fp   string // root and fingerprint of an irreversible effect, else ""
}

// world is the fake mail service. It applies a step only if the clerk check
// passes, at most once per idem, and records what it did so the invariants can
// be judged without trusting the kernel.
type world struct {
	owner   ed25519.PublicKey
	mutant  Mutant
	rng     *rand.Rand
	done    map[string]bool
	effects []effect
	bad     []string
	race    func() // an owner action landing between the kernel's decision and the clerk
	seen    []kernel.Request
	stale   int // old requests redelivered to the world and not acted on
	// unconfirmed is set while a widening whose anchor failed is live in the
	// kernel's state: nothing may act on it until the log is reopened.
	unconfirmed bool
}

func (w *world) fault(op string) string {
	switch n := w.rng.IntN(20); {
	case n == 0:
		return clerk.FaultFail
	case n == 1:
		return clerk.FaultDrop
	case n == 2:
		return clerk.FaultLostAck
	}
	return clerk.FaultNone
}

func (w *world) Do(r kernel.Request, v kernel.View) kernel.Result {
	res := w.do(r, v)
	if w.rng.IntN(10) == 0 {
		w.do(r, v) // the transport delivers the request twice
	}
	if len(w.seen) > 0 && w.rng.IntN(10) == 0 {
		old := w.do(w.seen[w.rng.IntN(len(w.seen))], v) // an old request arrives out of order
		if old.Detail == "already done" || old.Outcome == "failed" && old.Detail != "fault" {
			w.stale++ // the clerk itself turned it away
		}
	}
	if len(w.seen) < 16 {
		w.seen = append(w.seen, r)
	}
	return res
}

func (w *world) do(r kernel.Request, v kernel.View) kernel.Result {
	if w.race != nil && w.rng.IntN(8) == 0 {
		w.race()
	}
	if w.done[r.Idem] && w.mutant != MutantNoDedupe {
		return kernel.Result{Outcome: "ok", Detail: "already done"}
	}
	if w.mutant != MutantClerkTrusts {
		if rf := clerk.Check(w.owner, "mail", nil, r, v); rf != nil {
			return kernel.Result{Outcome: "failed", Detail: rf.Code}
		}
	}
	switch w.fault("do") {
	case clerk.FaultFail:
		return kernel.Result{Outcome: "failed", Detail: "fault"}
	case clerk.FaultDrop:
		return kernel.Result{Outcome: "unknown", Detail: "no answer"}
	case clerk.FaultLostAck:
		w.apply(r, v)
		return kernel.Result{Outcome: "unknown", Detail: "no answer"}
	}
	w.apply(r, v)
	return kernel.Result{Outcome: "ok"}
}

func (w *world) Probe(r kernel.Request, _ kernel.View) string {
	if w.fault("probe") != clerk.FaultNone {
		return "unknown"
	}
	if w.done[r.Idem] {
		return "done"
	}
	return "notdone"
}

// apply performs the effect and judges it on the spot against what the key
// and the log's view said at that instant.
func (w *world) apply(r kernel.Request, v kernel.View) {
	if w.done[r.Idem] {
		w.bad = append(w.bad, "effect twice for "+r.Idem[:8])
	}
	w.done[r.Idem] = true
	if w.unconfirmed {
		w.bad = append(w.bad, "effect on a widening the anchor never confirmed")
	}
	ver, err := kernel.VerifyPlan(r.Plan, w.owner)
	if err != nil {
		w.effects = append(w.effects, effect{r.Idem, r.Now, ""})
		w.bad = append(w.bad, "effect under an invalid key or one its submitter does not hold")
		return
	}
	st := r.Step()
	fp := ""
	if c, ok := key.ClassOf(st.Verb); ok && c.Irreversible() {
		fp = ver.Root().String() + "|" + kernel.Fingerprint(st)
		for _, e := range w.effects {
			if e.fp == fp && e.at > r.Now-key.DayMS {
				w.bad = append(w.bad, "the same irreversible effect twice within a day, across plans")
			}
		}
	}
	w.effects = append(w.effects, effect{r.Idem, r.Now, fp})
	ch := v.ChangesView()
	if ch.Stopped {
		w.bad = append(w.bad, "effect during STOP")
	}
	for _, id := range ver.IDs {
		if ch.Revoked[id] {
			w.bad = append(w.bad, "effect under a revoked key")
		}
	}
	if !v.Known(ver.Root()) {
		w.bad = append(w.bad, "effect under a root not in the log")
	}
	found := false
	for _, x := range ver.Limits.Verbs {
		found = found || x == string(st.Verb)
	}
	if !found {
		w.bad = append(w.bad, "effect with a verb outside the key")
	}
	if c, ok := key.ClassOf(st.Verb); ok && c.Irreversible() {
		if win := max(ver.Limits.Window(false), ver.Limits.Window(true)); win > 0 {
			h, held := v.Held(r.HeldSeq)
			if !held || r.Now < h.At+ver.Limits.Window(h.Novel) {
				w.bad = append(w.bad, "irreversible effect inside its hold window")
			}
		}
	}
}

type keyPair struct {
	pub  ed25519.PublicKey
	priv ed25519.PrivateKey
}

func gen(r *rand.Rand) keyPair {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(r.IntN(256))
	}
	p := ed25519.NewKeyFromSeed(seed)
	return keyPair{p.Public().(ed25519.PublicKey), p}
}

type sim struct {
	cfg    Config
	rng    *rand.Rand
	disk   *Disk
	anchor *anchor
	w      *world
	k      *kernel.Kernel
	owner  keyPair
	holder keyPair // holds every root: the trusted side
	planr  keyPair // holds only the keys derived to it
	head   keyPair
	pool   []key.Key
	ids    []key.ID
	plans  []string
	now    int64
	trace  []string
	nonce  *rand.ChaCha8

	clockBack, widenUnproven, unheld int
}

func (s *sim) logf(f string, a ...any) {
	s.trace = append(s.trace, fmt.Sprintf("%d "+f, append([]any{s.now}, a...)...))
}

func (s *sim) kcfg() kernel.Config {
	return kernel.Config{Store: s.disk, Anchor: s.anchor, Pub: s.head.pub, Sign: s.head.priv, Rand: s.nonce}
}

// boot reopens the log from the disk and recovers, retrying across crashes
// that fire during recovery itself.
func (s *sim) boot() error {
	for try := 0; try < 8; try++ {
		s.disk.Reboot()
		s.anchor.down, s.w.unconfirmed = false, false
		l, err := kernel.Open(s.kcfg())
		if err == nil {
			s.k, err = kernel.Boot(l, s.owner.pub, map[string]kernel.Clerk{"mail": s.w}, s.now)
		}
		if err == nil {
			return nil
		}
		if !errors.Is(err, errCrash) {
			return fmt.Errorf("boot: %w", err)
		}
	}
	return errors.New("boot never settled")
}

func (s *sim) pick(n int) int { return s.rng.IntN(n) }

var (
	verbs = []key.Verb{key.Trash, key.Organize, key.Unsubscribe, key.Send, key.Buy, key.Read}
	names = []string{"a", "b", "c"}
)

func (s *sim) newRoot() key.Key {
	vs := []key.Verb{}
	for _, v := range verbs {
		if s.pick(2) == 0 {
			vs = append(vs, v)
		}
	}
	if len(vs) == 0 {
		vs = append(vs, key.Trash)
	}
	r := key.Issue(s.owner.priv, key.Root{Holder: s.holder.pub, Clerk: "mail", Verbs: vs,
		Serial: fmt.Sprintf("r%d", len(s.pool))})
	return r
}

func (s *sim) remember(k key.Key) {
	s.pool = append(s.pool, k)
	if key.CheckChain(k, s.owner.pub) == nil {
		s.ids = append(s.ids, k.Tip())
	}
}

func (s *sim) derived() (key.Key, bool) {
	if len(s.pool) == 0 {
		return key.Key{}, false
	}
	base := s.pool[s.pick(len(s.pool))]
	var cav []key.Caveat
	switch s.pick(5) {
	case 0:
		cav = append(cav, key.LimitHold(hour, 4*hour))
	case 1:
		cav = append(cav, key.LimitUses(int64(1+s.pick(3))))
	case 2:
		cav = append(cav, key.LimitExpires(s.now+int64(1+s.pick(8))*hour))
	case 3:
		cav = append(cav, key.LimitVerbs(verbs[s.pick(len(verbs))])) // may try to widen: Verify must refuse
	}
	k, err := key.Derive(base, s.holder.priv, s.planr.pub, cav...)
	return k, err == nil
}

// signed is a plan under the planner's pick of key, signed by whoever submits
// it: the holder for a root, the planner for a key derived to it, and the
// planner again for a key it does not hold, which must confer nothing.
func (s *sim) signed(p kernel.Plan) (kernel.Plan, bool) {
	p.Key = s.anyKey()
	signer, unheld := s.holder.priv, false
	if n := len(p.Key.Links); n > 0 && bytes.Equal(p.Key.Links[n-1].Holder, s.planr.pub) {
		signer = s.planr.priv
	}
	switch s.pick(20) {
	case 0: // strips its key back to the root
		if k, ok := s.derived(); ok {
			p.Key, signer, unheld = key.Key{Root: k.Root}, s.planr.priv, true
		}
	case 1: // forges a link of its own off a root, or re-derives one
		if len(s.pool) > 0 {
			k := s.pool[s.pick(len(s.pool))]
			p.Key = key.Extend(k, s.planr.priv, key.Link{Caveats: []key.Caveat{key.LimitUses(1000)}, Holder: s.planr.pub})
			signer, unheld = s.planr.priv, true
		}
	case 2: // a stranger signs
		signer, unheld = gen(s.rng).priv, true
	}
	return kernel.SignPlan(p, signer), unheld
}

// anyKey is the planner's pick: good keys, narrowed keys, forged or foreign ones.
func (s *sim) anyKey() key.Key {
	switch s.pick(8) {
	case 0:
		foreign := gen(s.rng)
		return key.Issue(foreign.priv, key.Root{Holder: s.holder.pub, Clerk: "mail", Verbs: verbs, Serial: "x"})
	case 1:
		return key.Issue(s.owner.priv, key.Root{Holder: s.holder.pub, Clerk: "mail", Verbs: verbs, Serial: "never-logged"})
	case 2:
		if len(s.pool) > 0 {
			k := s.pool[s.pick(len(s.pool))]
			if len(k.Links) > 0 {
				ls := append([]key.Link(nil), k.Links...)
				ls[0].Sig = append([]byte(nil), ls[0].Sig...)
				ls[0].Sig[0] ^= 1
				k.Links = ls
			}
			return k
		}
	case 3, 4:
		if k, ok := s.derived(); ok {
			return k
		}
	}
	if len(s.pool) == 0 {
		return key.Key{}
	}
	return s.pool[s.pick(len(s.pool))]
}

func (s *sim) step() kernel.PlanStep {
	n := names[s.pick(len(names))]
	clerkName := "mail"
	if s.pick(10) == 0 {
		clerkName = "bank"
	}
	st := kernel.PlanStep{Verb: verbs[s.pick(len(verbs))], Clerk: clerkName, Args: map[string]string{}}
	for _, a := range key.ArgNames(st.Verb) {
		st.Args[a] = n
	}
	if _, ok := st.Args[key.ArgAmount]; ok { // equivalent spellings of one amount
		st.Args[key.ArgAmount] = []string{"1", "01", "+1"}[s.pick(3)]
	}
	return st
}

func (s *sim) submit() error {
	id := fmt.Sprintf("p%d", len(s.plans))
	if len(s.plans) > 0 && s.pick(12) == 0 {
		id = s.plans[s.pick(len(s.plans))] // a replayed plan id
	}
	steps := make([]kernel.PlanStep, 1+s.pick(3))
	if s.pick(40) == 0 {
		steps = make([]kernel.PlanStep, kernel.MaxSteps+1)
	}
	for i := range steps {
		steps[i] = s.step()
	}
	s.logf("submit %s %d steps", id, len(steps))
	p, unheld := s.signed(kernel.Plan{ID: id, Steps: steps})
	err := s.k.Submit(s.now, p)
	if err == nil {
		s.plans = append(s.plans, id)
		if ps := s.k.State().Plans[id]; unheld && ps != nil && ps.Status == kernel.SRejected {
			s.unheld++
		}
	}
	if errors.Is(err, kernel.ErrDuplicatePlan) {
		return nil
	}
	return err
}

func (s *sim) op() error {
	switch c := s.pick(16); {
	case c < 4:
		return s.submit()
	case c < 9:
		s.now += int64(s.pick(5*60)) * 60_000 / 10
		s.logf("tick")
		return s.k.Tick(s.now)
	case c == 9 && len(s.ids) > 0:
		id := s.ids[s.pick(len(s.ids))]
		s.logf("revoke")
		return s.k.Revoke(s.now, id)
	case c == 10 && len(s.ids) > 0:
		id := s.ids[s.pick(len(s.ids))]
		s.logf("pause")
		if s.pick(2) == 0 {
			return s.widened(s.k.Unpause(s.now, id))
		}
		return s.k.Pause(s.now, id)
	case c == 11:
		s.logf("stop/resume")
		if s.pick(2) == 0 {
			return s.widened(s.k.Resume(s.now))
		}
		return s.k.Stop(s.now)
	case c == 12 && len(s.plans) > 0:
		p := s.plans[s.pick(len(s.plans))]
		s.logf("cancel/undo %s", p)
		if s.pick(2) == 0 {
			return s.k.Cancel(s.now, p)
		}
		return s.k.Undo(s.now, p, 0)
	case c == 13:
		s.logf("anchor")
		return s.k.Log().Anchor()
	case c == 14:
		switch s.pick(5) {
		case 0:
			s.logf("disk full")
			s.disk.Fill()
		case 1:
			d := int64(1+s.pick(48)) * hour
			s.now = max(0, s.now-d)
			if es := s.k.Log().Entries(); len(es) > 0 && s.now < es[len(es)-1].At {
				s.clockBack++ // behind the log's own last entry
			}
			s.logf("clock jumps back %dh", d/hour)
		case 2:
			s.logf("anchor down")
			s.anchor.down = true
		default:
			n := 1 + s.pick(8)
			s.logf("arm crash in %d appends", n)
			s.disk.Arm(n)
		}
	case c == 15:
		r := s.newRoot()
		s.logf("issue root")
		if err := s.widened(s.k.Issue(s.now, r)); err != nil {
			return err
		}
		s.remember(r)
	}
	return nil
}

// widened passes on the result of a widening owner action. One that failed to
// anchor is live in the kernel's state but unconfirmed; the kernel must refuse
// to act on it, and the world judges any effect that follows as a violation.
func (s *sim) widened(err error) error {
	if errors.Is(err, errAnchor) {
		s.w.unconfirmed = true
		s.widenUnproven++
	}
	return err
}

func crashed(err error) bool {
	return errors.Is(err, errCrash) || errors.Is(err, errFull) || errors.Is(err, kernel.ErrBroken)
}

// check judges the run so far.
func (s *sim) check() error {
	if len(s.w.bad) > 0 {
		return fmt.Errorf("invariant: %s", s.w.bad[0])
	}
	es := s.k.Log().Entries()
	re, err := kernel.Replay(s.owner.pub, es)
	if err != nil {
		return fmt.Errorf("replay: %w", err)
	}
	if !reflect.DeepEqual(re, s.k.State()) {
		return errors.New("invariant: replay differs from the live state")
	}
	dispatched := map[string]bool{}
	for _, e := range es {
		if e.Type == kernel.TStepDispatch {
			var b struct{ Idem string }
			if json.Unmarshal(e.Body, &b) == nil {
				dispatched[b.Idem] = true
			}
		}
	}
	for _, f := range s.w.effects {
		if !dispatched[f.idem] {
			return errors.New("invariant: an effect with no dispatch record in the log")
		}
	}
	return nil
}

// Run drives one seed and returns the trace, or the first violated invariant.
func Run(c Config) (*Result, error) {
	rng := rand.New(rand.NewPCG(c.Seed, 0xa6e57))
	var nseed [32]byte
	for i := range nseed {
		nseed[i] = byte(rng.IntN(256))
	}
	s := &sim{cfg: c, rng: rng, anchor: &anchor{}, nonce: rand.NewChaCha8(nseed)}
	s.disk = &Disk{rng: rng}
	s.owner, s.holder, s.planr, s.head = gen(rng), gen(rng), gen(rng), gen(rng)
	s.w = &world{owner: s.owner.pub, mutant: c.Mutant, rng: rng, done: map[string]bool{}}
	s.w.race = func() {
		if len(s.ids) > 0 && s.pick(2) == 0 {
			s.logf("race: revoke")
			_ = s.k.Revoke(s.now, s.ids[s.pick(len(s.ids))])
			return
		}
		s.logf("race: stop")
		_ = s.k.Stop(s.now)
	}
	if err := s.boot(); err != nil {
		return nil, err
	}
	for i := 0; i < 2; i++ {
		r := s.newRoot()
		if err := s.k.Issue(0, r); err != nil {
			return nil, err
		}
		s.remember(r)
	}
	fail := func(err error) (*Result, error) {
		return &Result{Trace: s.trace}, fmt.Errorf("seed %d op %d: %w\n%s", c.Seed, len(s.trace), err, strings.Join(tail(s.trace), "\n"))
	}
	for i := 0; i < c.Ops; i++ {
		err := s.op()
		if errors.Is(err, errAnchor) {
			err = nil // the owner's phone is out of reach; the machine keeps running
		}
		if err != nil {
			if !crashed(err) {
				return fail(err)
			}
			s.logf("crash")
			if err := s.boot(); err != nil {
				return fail(err)
			}
		}
		if err := s.check(); err != nil {
			return fail(err)
		}
	}
	if err := s.boot(); err != nil {
		return fail(err)
	}
	if err := s.check(); err != nil {
		return fail(err)
	}
	return &Result{Trace: s.trace, Entries: s.k.Log().Entries(), Effects: len(s.w.effects),
		Refused: s.disk.refused, ClockBack: s.clockBack, StaleRefused: s.w.stale,
		AnchorFailed: s.anchor.failed, WidenUnproven: s.widenUnproven, UnheldRefused: s.unheld}, nil
}

func tail(t []string) []string {
	if len(t) > 12 {
		return t[len(t)-12:]
	}
	return t
}
