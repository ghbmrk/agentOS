// Package sim runs the real kernel and clerk check against a fake disk, clock
// and world, driven by a seeded hostile planner, and judges every step against
// the invariants. One seed gives one trace, byte for byte (SIM-1).
package sim

import (
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
}

const hour = int64(3_600_000)

type effect struct {
	idem string
	at   int64
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
		if rf := clerk.Check(w.owner, "mail", r, v); rf != nil {
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
	w.effects = append(w.effects, effect{r.Idem, r.Now})
	ver, err := key.Verify(r.Key, w.owner)
	if err != nil {
		w.bad = append(w.bad, "effect under an invalid key")
		return
	}
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
		found = found || x == string(r.Step.Verb)
	}
	if !found {
		w.bad = append(w.bad, "effect with a verb outside the key")
	}
	if c, ok := key.ClassOf(r.Step.Verb); ok && c.Irreversible() {
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
	anchor *kernel.MemAnchor
	w      *world
	k      *kernel.Kernel
	owner  keyPair
	holder keyPair
	head   keyPair
	pool   []key.Key
	ids    []key.ID
	plans  []string
	now    int64
	trace  []string
	nonce  *rand.ChaCha8
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
	if v, err := key.Verify(k, s.owner.pub); err == nil {
		s.ids = append(s.ids, v.ID())
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
	k, err := key.Derive(base, s.holder.priv, s.holder.pub, cav...)
	return k, err == nil
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

func (s *sim) step() key.Step {
	n := names[s.pick(len(names))]
	src := key.SrcClerk
	if s.pick(6) == 0 {
		src = key.SrcPlanner
	}
	clerkName := "mail"
	if s.pick(10) == 0 {
		clerkName = "bank"
	}
	return key.Step{Verb: verbs[s.pick(len(verbs))], Clerk: clerkName, Recipient: n, Task: "t",
		Args: map[string]key.Arg{"msg": {Value: n, Source: src}}}
}

func (s *sim) submit() error {
	id := fmt.Sprintf("p%d", len(s.plans))
	if len(s.plans) > 0 && s.pick(12) == 0 {
		id = s.plans[s.pick(len(s.plans))] // a replayed plan id
	}
	steps := make([]key.Step, 1+s.pick(3))
	if s.pick(40) == 0 {
		steps = make([]key.Step, kernel.MaxSteps+1)
	}
	for i := range steps {
		steps[i] = s.step()
	}
	s.logf("submit %s %d steps", id, len(steps))
	err := s.k.Submit(s.now, kernel.Plan{ID: id, Key: s.anyKey(), Steps: steps})
	if err == nil {
		s.plans = append(s.plans, id)
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
			return s.k.Unpause(s.now, id)
		}
		return s.k.Pause(s.now, id)
	case c == 11:
		s.logf("stop/resume")
		if s.pick(2) == 0 {
			return s.k.Resume(s.now)
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
		n := 1 + s.pick(8)
		s.logf("arm crash in %d appends", n)
		s.disk.Arm(n)
	case c == 15:
		r := s.newRoot()
		s.logf("issue root")
		if err := s.k.Issue(s.now, r); err != nil {
			return err
		}
		s.remember(r)
	}
	return nil
}

func crashed(err error) bool { return errors.Is(err, errCrash) || errors.Is(err, kernel.ErrBroken) }

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
	s := &sim{cfg: c, rng: rng, anchor: &kernel.MemAnchor{}, nonce: rand.NewChaCha8(nseed)}
	s.disk = &Disk{rng: rng}
	s.owner, s.holder, s.head = gen(rng), gen(rng), gen(rng)
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
	if err := s.k.Log().Anchor(); err != nil {
		return nil, err
	}
	fail := func(err error) (*Result, error) {
		return &Result{Trace: s.trace}, fmt.Errorf("seed %d op %d: %w\n%s", c.Seed, len(s.trace), err, strings.Join(tail(s.trace), "\n"))
	}
	for i := 0; i < c.Ops; i++ {
		err := s.op()
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
	return &Result{Trace: s.trace, Entries: s.k.Log().Entries(), Effects: len(s.w.effects)}, nil
}

func tail(t []string) []string {
	if len(t) > 12 {
		return t[len(t)-12:]
	}
	return t
}
