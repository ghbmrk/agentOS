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
	"math"
	"math/rand/v2"
	"reflect"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/clerk"
	"github.com/ghbmrk/agentos/broker/clerk/check"
	"github.com/ghbmrk/agentos/broker/kernel"
	"github.com/ghbmrk/agentos/broker/kernel/key"
)

// core.txt grants this package kernel.* and clerk.* because only tests
// link it. The guard holds that wherever the files are reached from (a
// symlink, a vendored copy, a build tag): a binary go test did not build
// stops here (core/ASSUMPTIONS.md, CORE-fixture-imports-a).
func init() {
	if !testing.Testing() {
		panic("kernel/sim is a test fixture: linked into a binary go test did not build")
	}
}

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
	BigRefused    int // big grants refused for a missing second passkey
	HeldByClerk   int // irreversible steps the clerk held back on its own clock
	CutRefused    int // grants a cut-off phone signed, refused
	CutCancelled  int // a cut-off phone's grants still in their hold, cancelled with it
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

// world is the fake mail service: the real clerk.Mail, with its faults drawn
// from the seed and its clock the true time, which the kernel's may run ahead
// of. Every effect the clerk applies is judged on the spot, without trusting
// the kernel or the clerk.
type world struct {
	anchors []key.PublicKey
	mutant  Mutant
	rng     *rand.Rand
	now     *int64 // the true time: the clerk's own clock
	mail    *clerk.Mail
	done    map[string]bool
	effects []effect
	bad     []string
	race    func() // an owner action landing between the kernel's decision and the clerk
	seen    []kernel.Request
	stale   int // old requests redelivered to the world and not acted on
	held    int // irreversible steps the clerk held back on its own clock
	// unconfirmed is set while a widening whose anchor failed is live in the
	// kernel's state: nothing may act on it until the log is reopened.
	unconfirmed bool
	// cut is the passkeys the owner cut off, and dead the grants a cut
	// cancelled while still in their hold: the world's own record, so an
	// effect under either is judged without the kernel's word.
	cut  []key.PublicKey
	dead map[key.ID]bool
}

func (w *world) newMail() *clerk.Mail {
	m := clerk.NewMail("mail", w.anchors)
	m.Fault = func(op string, _ kernel.Request) string { return w.fault(op) }
	m.Clock = func() int64 { return *w.now }
	return m
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
	if w.mutant == MutantClerkTrusts {
		// The mutant clerk acts on the kernel's word, with no check of its own.
		if !w.done[r.Idem()] {
			w.judge(r, v)
		}
		return kernel.Result{Outcome: "ok"}
	}
	m := w.mail
	if w.mutant == MutantNoDedupe {
		m = w.newMail() // the mutant clerk forgets every key it ran
	}
	n := len(m.Effects())
	res := m.Do(r, v)
	if len(m.Effects()) > n {
		w.judge(r, v)
	}
	if res.Outcome == "failed" && res.Detail == check.RHold {
		w.held++
	}
	return res
}

func (w *world) Probe(r kernel.Request, v kernel.View) kernel.Result { return w.mail.Probe(r, v) }

// judge records an effect the clerk just applied and judges it against what
// the key and the log's view said at that instant, on the true clock.
func (w *world) judge(r kernel.Request, v kernel.View) {
	now := *w.now
	if w.done[r.Idem()] {
		w.bad = append(w.bad, "effect twice for "+r.Idem()[:8])
	}
	w.done[r.Idem()] = true
	if w.unconfirmed {
		w.bad = append(w.bad, "effect on a widening the anchor never confirmed")
	}
	ver, err := kernel.VerifyPlan(r.Plan, kernel.PlanOwners(v, w.anchors, r.Plan.Key))
	if err != nil {
		w.effects = append(w.effects, effect{r.Idem(), now, ""})
		w.bad = append(w.bad, "effect under an invalid key or one its submitter does not hold")
		return
	}
	st := r.Step()
	fp := ""
	if c, ok := key.ClassOf(st.Verb); ok && c.Irreversible() {
		fp = ver.Root().String() + "|" + kernel.Fingerprint(st)
		for _, e := range w.effects {
			if e.fp == fp && e.at > now-key.DayMS {
				w.bad = append(w.bad, "the same irreversible effect twice within a day, across plans")
			}
		}
	}
	w.effects = append(w.effects, effect{r.Idem(), now, fp})
	ch := v.ChangesView()
	if ch.Stopped {
		w.bad = append(w.bad, "effect during STOP")
	}
	for _, id := range ver.IDs {
		if ch.Revoked[id] {
			w.bad = append(w.bad, "effect under a revoked key")
		}
		if w.dead[id] {
			w.bad = append(w.bad, "effect under a grant cancelled with its cut-off phone")
		}
	}
	for _, p := range ver.Narrowers {
		if key.In(w.cut, p) {
			w.bad = append(w.bad, "effect under a key a cut-off phone narrowed")
		}
	}
	if kernel.Live(v, ver, now) != nil { // on the true clock
		w.bad = append(w.bad, "effect under a grant not in the log or still in its hold")
	}
	found := false
	for _, x := range ver.Limits.Verbs {
		found = found || x == string(st.Verb)
	}
	if !found {
		w.bad = append(w.bad, "effect with a verb outside the key")
	}
	d, inFlight := v.Dispatched(r)
	if !inFlight {
		w.bad = append(w.bad, "effect for a step the log does not have in flight")
	}
	if c, ok := key.ClassOf(st.Verb); ok && c.Irreversible() {
		if win := max(ver.Limits.Window(false), ver.Limits.Window(true)); win > 0 {
			if !d.Held || now < ver.Limits.Due(d.HeldAt, d.Novel) {
				w.bad = append(w.bad, "irreversible effect inside its hold window")
			}
		}
	}
}

type keyPair struct {
	pub  ed25519.PublicKey
	priv ed25519.PrivateKey
	pk   key.PublicKey     // pub as a passkey
	pass key.Ed25519Signer // priv as the fake authenticator (EVL-1)
}

func gen(r *rand.Rand) keyPair {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(r.IntN(256))
	}
	p := ed25519.NewKeyFromSeed(seed)
	return keyPair{p.Public().(ed25519.PublicKey), p, key.Ed25519(p.Public().(ed25519.PublicKey)), key.Ed25519Signer(p)}
}

type sim struct {
	cfg    Config
	rng    *rand.Rand
	disk   *Disk
	anchor *anchor
	w      *world
	k      *kernel.Kernel
	owner  keyPair // the passkey: holds every root
	spare  keyPair // the second hardware key: co-signs big grants
	holder keyPair // the home clerk: holds the passkey's clerk key of each root
	planr  keyPair // holds only the keys derived to it
	head   keyPair
	phone  keyPair // an enrolled passkey the owner may cut off; zero when none
	roots  []key.Key
	pool   []key.Key
	ids    []key.ID
	plans  []string
	now    int64 // the true time, which the clerk reads
	ahead  int64 // how far the kernel's clock runs ahead of it
	trace  []string
	nonce  *rand.ChaCha8

	// hostile: at each tick the kernel's clock jumps past every held step's
	// window, or a few hours ahead when nothing is held.
	hostile                          bool
	clockBack, widenUnproven, unheld int
	bigRefused, submits              int
	cutRefused, cutCancelled         int
	byPhone                          []key.ID  // grants the current phone signed
	cutPhones                        []keyPair // phones the owner cut off
	phoneKeys                        []key.Key // clerk keys a phone renewed or narrowed, cut off or not
}

// kt is the kernel's clock.
func (s *sim) kt() int64 { return s.now + s.ahead }

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
			s.k, err = kernel.Boot(l, s.w.anchors, map[string]kernel.Clerk{"mail": s.w}, s.kt())
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
	r := key.Issue(s.owner.pass, key.Root{Clerk: "mail", Verbs: vs,
		Serial: fmt.Sprintf("r%d", len(s.roots))})
	return r
}

// clerkKey is the passkey's grant of root to the home clerk (D-146), with a
// spend cap no sim step reaches.
func (s *sim) clerkKey(passkey key.Signer, root key.Key) key.Key {
	k, err := key.ClerkKey(root, passkey, s.holder.pub, s.now, 1<<40)
	if err != nil {
		panic(err)
	}
	return k
}

// remember keeps a granted root and hands its clerk key to the home clerk.
func (s *sim) remember(r, k key.Key) {
	s.roots = append(s.roots, r)
	s.pool = append(s.pool, k)
	s.ids = append(s.ids, r.Tip(), k.Tip())
}

func (s *sim) derived() (key.Key, bool) {
	if len(s.pool) == 0 {
		return key.Key{}, false
	}
	base := s.pool[s.pick(len(s.pool))]
	var cav []key.Caveat
	if s.pick(2) == 0 { // half the derived keys hold irreversible steps
		cav = append(cav, key.LimitHold(hour/6, hour/2))
	}
	switch s.pick(5) {
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
// it: the home clerk for its clerk key, the planner for a key derived to it,
// and either for a key it does not hold, which must confer nothing. A bare
// root is the passkey's alone (D-146).
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
	case 3: // the home clerk signs under a bare root
		if len(s.roots) > 0 {
			p.Key, signer, unheld = s.roots[s.pick(len(s.roots))], s.holder.priv, true
		}
	}
	return kernel.SignPlan(p, signer), unheld
}

// anyKey is the planner's pick: good keys, narrowed keys, forged or foreign ones.
func (s *sim) anyKey() key.Key {
	switch s.pick(8) {
	case 0:
		foreign := gen(s.rng)
		return s.clerkKey(foreign.pass, key.Issue(foreign.pass, key.Root{Clerk: "mail", Verbs: verbs, Serial: "x"}))
	case 1:
		return s.clerkKey(s.owner.pass, key.Issue(s.owner.pass, key.Root{Clerk: "mail", Verbs: verbs, Serial: "never-logged"}))
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
	case 3, 4, 5:
		if k, ok := s.derived(); ok {
			return k
		}
	case 6:
		if len(s.phoneKeys) > 0 { // the home clerk keeps a phone's keys, even past a cut-off
			return s.phoneKeys[s.pick(len(s.phoneKeys))]
		}
	}
	if len(s.pool) == 0 {
		return key.Key{}
	}
	if live := s.live(); len(live) > 0 && s.pick(4) != 0 {
		return live[s.pick(len(live))] // the home clerk mostly uses a key that works
	}
	return s.pool[s.pick(len(s.pool))]
}

// live is the pool's keys the kernel would admit now: granted past their
// hold, and none of their chain revoked.
func (s *sim) live() []key.Key {
	st := s.k.State()
	var out []key.Key
	for _, k := range s.pool {
		v, err := key.Chain(k, st.Passkeys())
		if err != nil || kernel.Live(st, v, s.kt()) != nil {
			continue
		}
		ok := true
		for _, id := range v.IDs {
			ok = ok && !st.Changes.Revoked[id]
		}
		if ok {
			out = append(out, k)
		}
	}
	return out
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
	s.submits++ // a fresh id each time, even after a submit the log kept but a crash cut short
	id := fmt.Sprintf("p%d", s.submits)
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
	err := s.k.Submit(s.kt(), p)
	if err == nil {
		s.plans = append(s.plans, id)
		if ps := s.k.State().Plans[id]; unheld && ps != nil && ps.Status == kernel.SRejected {
			s.unheld++
		} else if unheld {
			s.w.bad = append(s.w.bad, "a plan under a key its signer does not hold was admitted")
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
		if s.pick(25) == 0 { // a day passes, so a new grant's hold runs out
			s.now += kernel.GrantHold
		}
		if s.hostile {
			s.ahead = s.pastHolds()
		}
		s.logf("tick")
		return s.k.Tick(s.kt())
	case c == 9 && len(s.ids) > 0 && s.pick(2) == 0:
		id := s.ids[s.pick(len(s.ids))]
		s.logf("revoke")
		return s.k.Revoke(s.kt(), id)
	case c == 10 && len(s.ids) > 0:
		id := s.ids[s.pick(len(s.ids))]
		s.logf("pause")
		if s.pick(2) == 0 {
			return s.widened(s.k.Unpause(s.kt(), id))
		}
		return s.k.Pause(s.kt(), id)
	case c == 11:
		if s.k.State().Stopped { // the owner resumes what a STOP held
			s.logf("resume")
			return s.widened(s.k.Resume(s.kt(), s.k.State().Stops))
		}
		if s.pick(3) == 0 {
			s.logf("stop")
			return s.k.Stop(s.kt())
		}
	case c == 12 && len(s.plans) > 0:
		p := s.plans[s.pick(len(s.plans))]
		s.logf("cancel/undo %s", p)
		if s.pick(2) == 0 {
			return s.k.Cancel(s.kt(), p)
		}
		return s.k.Undo(s.kt(), p, 0)
	case c == 13 && s.pick(3) != 0:
		return s.phoneOp()
	case c == 13:
		s.logf("anchor")
		return s.k.Log().Anchor()
	case c == 14:
		switch s.pick(6) {
		case 0:
			s.logf("disk full")
			s.disk.Fill()
		case 1:
			d := int64(1+s.pick(48)) * hour
			s.now = max(0, s.now-d)
			if es := s.k.Log().Entries(); len(es) > 0 && s.kt() < es[len(es)-1].At {
				s.clockBack++ // behind the log's own last entry
			}
			s.logf("clock jumps back %dh", d/hour)
		case 2:
			s.logf("anchor down")
			s.anchor.down = true
		case 3:
			// The kernel's clock jumps ahead, or is set right again. The
			// clerk keeps the true time, so a hold still runs its window.
			s.hostile, s.ahead = s.pick(2) == 0, 0
			s.logf("kernel clock hostile %v", s.hostile)
		default:
			n := 1 + s.pick(8)
			s.logf("arm crash in %d appends", n)
			s.disk.Arm(n)
		}
	case c == 15 && len(s.roots) > 0 && s.pick(2) == 0:
		i := s.pick(len(s.roots))
		k := s.clerkKey(s.owner.pass, s.roots[i])
		s.logf("renew clerk key of root %d", i)
		if err := s.grant(k); err != nil {
			return s.refusedBig(err)
		}
		s.pool = append(s.pool, k)
		s.ids = append(s.ids, k.Tip())
	case c == 15:
		r := s.newRoot()
		k := s.clerkKey(s.owner.pass, r)
		s.logf("grant root")
		if err := s.grant(r, k); err != nil {
			return s.refusedBig(err)
		}
		s.remember(r, k)
	}
	return nil
}

// phoneOp enrolls a phone, has it renew or narrow a clerk key, or cuts it
// off (D-146). A phone once cut stays cut: a grant it signs after is refused,
// its grants still in their hold go with it, and no effect runs under a key
// it narrowed.
func (s *sim) phoneOp() error {
	s.syncPhone()
	if !s.phone.pk.Valid() {
		if len(s.cutPhones) > 0 && s.pick(2) == 0 {
			s.cutSigns()
			return nil
		}
		s.phone = gen(s.rng)
		s.logf("enroll phone")
		return s.widened(s.k.Enroll(s.kt(), key.Enroll(s.spare.pass, s.phone.pk)))
	}
	switch s.pick(4) {
	case 0, 1:
		s.logf("phone signs its own cut-off")
		if err := s.k.Unenroll(s.kt(), key.Unenroll(s.phone.pass, s.phone.pk)); !errors.Is(err, kernel.ErrNotUnenrolled) {
			s.w.bad = append(s.w.bad, "a cut-off no hardware key signed was taken")
		}
		s.logf("cut phone off")
		if err := s.k.Unenroll(s.kt(), key.Unenroll(s.owner.pass, s.phone.pk)); err != nil {
			return err
		}
		s.cut()
		if s.pick(2) == 0 { // the hold its cancelled grants were in runs out
			s.now += kernel.GrantHold
			s.logf("a day passes")
			return s.k.Tick(s.kt())
		}
	case 2:
		if len(s.pool) > 0 {
			k, err := key.Narrow(s.pool[s.pick(len(s.pool))], s.phone.pass, key.LimitUses(int64(1+s.pick(4))))
			if err == nil {
				s.logf("phone narrows a clerk key")
				s.pool, s.phoneKeys = append(s.pool, k), append(s.phoneKeys, k)
			}
		}
	default:
		if len(s.roots) == 0 {
			return nil
		}
		i := s.pick(len(s.roots))
		k := s.clerkKey(s.phone.pass, s.roots[i])
		s.logf("phone renews clerk key of root %d", i)
		if err := s.grant(k); err != nil {
			return s.refusedBig(err)
		}
		s.pool, s.phoneKeys = append(s.pool, k), append(s.phoneKeys, k)
		s.ids = append(s.ids, k.Tip())
		s.byPhone = append(s.byPhone, k.Tip())
	}
	return nil
}

// syncPhone reads the phone's standing back from the log after a crash cut
// an enrollment or a cut-off short: cut if the log has it cut, gone if the
// log never enrolled it.
func (s *sim) syncPhone() {
	if !s.phone.pk.Valid() {
		return
	}
	st := s.k.State()
	switch {
	case key.In(st.Unenrolled, s.phone.pk):
		s.cut()
	case !key.In(st.Passkeys(), s.phone.pk):
		s.phone, s.byPhone = keyPair{}, nil
	}
}

// cut records the phone as cut off, in the world's own books: its grants
// the log does not hold live by now never go live.
func (s *sim) cut() {
	st := s.k.State()
	for _, id := range s.byPhone {
		g, ok := st.Grants[id]
		if !ok || g.From > s.kt() { // never live: dropped by a crash, or cancelled in its hold
			s.w.dead[id] = true
		}
		if ok && g.From > s.kt() {
			s.cutCancelled++
		}
	}
	s.w.cut = append(s.w.cut, s.phone.pk)
	s.cutPhones = append(s.cutPhones, s.phone)
	s.phone, s.byPhone = keyPair{}, nil
}

// cutSigns has a phone the owner cut off grant again, with both hardware
// keys' co-signatures: the kernel must still refuse it.
func (s *sim) cutSigns() {
	if len(s.roots) == 0 {
		return
	}
	p := s.cutPhones[s.pick(len(s.cutPhones))]
	k := s.clerkKey(p.pass, s.roots[s.pick(len(s.roots))])
	s.logf("cut-off phone signs a grant")
	err := s.k.Issue(s.kt(), approve([]key.Key{k}, s.owner, s.spare), k)
	if _, taken := s.k.State().Grants[k.Tip()]; taken {
		s.w.bad = append(s.w.bad, "a grant a cut-off phone signed was taken")
	} else if !crashed(err) {
		s.cutRefused++
	}
}

// approve is each passkey's co-signature over the batch keys.
func approve(keys []key.Key, by ...keyPair) []key.Cosign {
	var cos []key.Cosign
	for _, p := range by {
		cos = append(cos, key.Approve(p.pass, kernel.BatchHash(keys...)))
	}
	return cos
}

// grant issues a batch the owner's two hardware keys co-sign most of the
// time, and otherwise the owner's alone, the owner's and the home clerk's,
// which counts for nothing, or none: a big batch is then refused whole
// (D-146).
func (s *sim) grant(keys ...key.Key) error {
	var cos []key.Cosign
	switch s.pick(8) {
	case 0:
	case 1:
		cos = approve(keys, s.owner, s.holder)
	case 2:
		cos = approve(keys, s.owner)
	default:
		cos = approve(keys, s.owner, s.spare)
	}
	err := s.widened(s.k.Issue(s.kt(), cos, keys...))
	if errors.Is(err, kernel.ErrNeedsCosign) {
		for _, c := range cos {
			if c.By == s.spare.pk {
				s.w.bad = append(s.w.bad, "a batch the second hardware key co-signed was refused")
			}
		}
	}
	return err
}

// refusedBig counts a big batch refused for its missing second passkey; any
// other error stands.
func (s *sim) refusedBig(err error) error {
	if errors.Is(err, kernel.ErrNeedsCosign) {
		s.bigRefused++
		return nil
	}
	return err
}

// pastHolds is a jump that puts the kernel's clock just past every held
// step's window, or a few hours when nothing is held: a hostile clock.
func (s *sim) pastHolds() int64 {
	ahead := int64(1+s.pick(6)) * hour
	st := s.k.State()
	for _, id := range st.Order {
		p := st.Plans[id]
		for i := range p.Steps {
			if p.Steps[i].Phase != kernel.PHeld {
				continue
			}
			if v, err := kernel.VerifyPlan(p.Plan, s.w.anchors); err == nil {
				if due := v.Limits.Due(p.Steps[i].HeldAt, p.Steps[i].Novel); due < math.MaxInt64 {
					ahead = max(ahead, due-s.now+60_000) // a step never due sets no jump
				}
			}
		}
	}
	return ahead
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

// rederive checks that the live log, before a boot can drop its unconfirmed
// tail, gives every decision in it again from the entries before it (KRN-1).
// Each entry is in the log at some boot, so this sees every one; it runs only
// there because it reverifies every plan.
func (s *sim) rederive() error {
	if _, err := kernel.Rederive(s.w.anchors, s.k.Box(), s.k.Log().Entries()); err != nil {
		return fmt.Errorf("invariant: %w", err)
	}
	return nil
}

// check judges the run so far.
func (s *sim) check() error {
	if len(s.w.bad) > 0 {
		return fmt.Errorf("invariant: %s", s.w.bad[0])
	}
	es := s.k.Log().Entries()
	re, err := kernel.Replay(s.w.anchors, es)
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
	s.hostile = rng.IntN(2) == 0
	s.owner, s.holder, s.planr, s.head = gen(rng), gen(rng), gen(rng), gen(rng)
	s.spare = gen(rng)
	s.w = &world{anchors: []key.PublicKey{s.owner.pk, s.spare.pk}, mutant: c.Mutant, rng: rng, now: &s.now, done: map[string]bool{}, dead: map[key.ID]bool{}}
	s.w.mail = s.w.newMail()
	s.w.race = func() {
		if len(s.ids) > 0 && s.pick(2) == 0 {
			s.logf("race: revoke")
			_ = s.k.Revoke(s.kt(), s.ids[s.pick(len(s.ids))])
			return
		}
		s.logf("race: stop")
		_ = s.k.Stop(s.kt())
	}
	if err := s.boot(); err != nil {
		return nil, err
	}
	for i := 0; i < 4; i++ { // set up a day ago, so past the hold
		r := s.newRoot()
		k := s.clerkKey(s.owner.pass, r)
		if err := s.k.Issue(-kernel.GrantHold, approve([]key.Key{r, k}, s.owner, s.spare), r, k); err != nil {
			return nil, err
		}
		s.remember(r, k)
		// The home clerk also narrows its key to hold irreversible steps,
		// so held steps meet the hostile clock in every run.
		if hk, err := key.Derive(k, s.holder.priv, s.holder.pub, key.LimitHold(hour/6, hour/2)); err == nil {
			s.pool = append(s.pool, hk)
		}
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
			if err := s.rederive(); err != nil {
				return fail(err)
			}
			if err := s.boot(); err != nil {
				return fail(err)
			}
		}
		if err := s.check(); err != nil {
			return fail(err)
		}
	}
	if err := s.rederive(); err != nil {
		return fail(err)
	}
	if err := s.boot(); err != nil {
		return fail(err)
	}
	if err := s.check(); err != nil {
		return fail(err)
	}
	return &Result{Trace: s.trace, Entries: s.k.Log().Entries(), Effects: len(s.w.effects),
		Refused: s.disk.refused, ClockBack: s.clockBack, StaleRefused: s.w.stale,
		AnchorFailed: s.anchor.failed, WidenUnproven: s.widenUnproven, UnheldRefused: s.unheld, BigRefused: s.bigRefused,
		HeldByClerk: s.w.held, CutRefused: s.cutRefused, CutCancelled: s.cutCancelled}, nil
}

func tail(t []string) []string {
	if len(t) > 12 {
		return t[len(t)-12:]
	}
	return t
}
