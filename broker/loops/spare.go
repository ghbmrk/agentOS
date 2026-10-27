package loops

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"math"
	"math/big"
	"slices"
	"sync"

	"github.com/ghbmrk/agentos/broker/kernel"
	"github.com/ghbmrk/agentos/broker/kernel/key"
)

// Spare is the spare envelope on the kernel meter (LOOP-2, MIG-4-spend-m): a
// key of its own, never the guests', that every loop model call is charged
// to. Loop plans cite Key(); the model clerk charges each call to that key
// and, through its chain, to the envelope, so the owner's budget is the day
// cap the current key holds. Loop code has no other handle on it. The
// envelope itself is never handed out: every key loops cite is a derivation
// of it, so a lowering can revoke them all.
type Spare struct {
	// State is the kernel's state (Kernel.State); the spend charged to the
	// envelope is read from its ledger.
	State func() *kernel.State
	// Envelope is the spare envelope as the owner granted it, with a day
	// spend cap; Holder holds it and derives the narrower keys.
	Envelope key.Key
	Holder   ed25519.PrivateKey
	// Widen is the owner's passkey (KEY-6): it returns a fresh envelope,
	// held by Holder, with day cap n. Raising the cap past the current one
	// is a widening (KEY-6), even back up to a cap held before a lowering.
	// Nil: the cap is never raised.
	Widen func(n int64) (key.Key, error)
	// Revoke is the owner's revocation (Kernel.Revoke), a narrowing: a
	// lowering revokes every key handed out before it, so none stays live
	// at its old cap. Nil: the cap is never lowered once a key is out.
	Revoke func(id key.ID) error
	// OutPerM is the spare route's output price, minor units per million
	// tokens: what turns the owner's calls into a cap (SpareCap).
	OutPerM int64

	mu   sync.Mutex
	set  bool
	cur  key.Key  // the key loop plans cite: the envelope or a narrowing of it
	cap  int64    // cur's day cap
	envs []key.ID // every envelope held: spend under each counts toward the day
	out  []key.ID // every key handed out and not yet revoked; EvalKey's are their children
}

// ErrNoWiden refuses a cap above the current one when no passkey can widen
// it.
var ErrNoWiden = errors.New("loops: raising the spare cap needs the owner's passkey")

// ErrNoRevoke refuses a lowering when keys handed out at the old cap cannot
// be revoked.
var ErrNoRevoke = errors.New("loops: lowering the spare cap needs the owner's revocation")

// dayCap is the lowest day spend cap k's chain sets.
func dayCap(k key.Key) (int64, bool) {
	var cs []key.Caveat
	for _, l := range k.Links {
		cs = append(cs, l.Caveats...)
	}
	lim, err := key.Fold(cs)
	if err != nil {
		return 0, false
	}
	n, ok := int64(0), false
	for _, c := range lim.Caps {
		if c.Kind == key.KSpendDay && (!ok || c.N < n) {
			n, ok = c.N, true
		}
	}
	return n, ok
}

// ErrMoved refuses a Commit whose envelope or cap changed after Prepare: a
// lowering landed while the owner's passkey was asked, and it stands.
var ErrMoved = errors.New("loops: the spare cap changed while the passkey was asked")

// Prepared is a cap change Prepare checked, for Commit: the cap asked, the
// envelope and cap Prepare saw, and the widened envelope when the change
// needed the owner's passkey.
type Prepared struct {
	n       int64
	set     bool
	tip     key.ID
	cap     int64
	widened key.Key
}

// Prepare checks that n can be the day cap. A cap above the current one is a
// widening (KEY-6): Prepare asks Widen for a fresh envelope with day cap n,
// with no lock held, so Cap, Key, EvalKey, Used and a lowering never wait on
// the passkey. Before the first cap is set, the current cap is the
// envelope's.
func (s *Spare) Prepare(n int64) (Prepared, error) { return s.prepare(n, true) }

// prepare is Prepare; with widen false, a cap that needs the passkey is
// refused with ErrNoWiden instead of asking for it.
func (s *Spare) prepare(n int64, widen bool) (Prepared, error) {
	if n < 0 {
		return Prepared{}, errors.New("loops: negative spare cap")
	}
	s.mu.Lock()
	p := Prepared{n: n, set: s.set, tip: s.Envelope.Tip(), cap: s.cap}
	envCap, ok := dayCap(s.Envelope)
	held := append([]key.ID{}, s.envs...)
	if !s.set {
		held = []key.ID{p.tip}
	}
	widenFn := s.Widen
	s.mu.Unlock()
	if !ok {
		return Prepared{}, errors.New("loops: the spare envelope has no day spend cap")
	}
	base := envCap
	if p.set {
		base = p.cap
	}
	if n <= base {
		return p, nil
	}
	if !widen || widenFn == nil {
		return Prepared{}, ErrNoWiden
	}
	w, err := widenFn(n)
	if err != nil {
		return Prepared{}, err
	}
	if c, ok := dayCap(w); !ok || c != n {
		return Prepared{}, errors.New("loops: the widened spare envelope does not hold the cap asked")
	}
	// A fresh envelope sits under none already held, so no spend under it
	// counts twice in Used.
	for i := range w.Links {
		if slices.Contains(held, (key.Key{Root: w.Root, Links: w.Links[:i]}).Tip()) {
			return Prepared{}, errors.New("loops: the widened spare envelope is under one already held")
		}
	}
	p.widened = w
	return p, nil
}

// Commit makes p's cap the day cap of the key loop plans cite: a derivation
// of the envelope, or of the fresh envelope Prepare widened to. It refuses
// with ErrMoved when the envelope or the cap changed since Prepare. A
// lowering first revokes every key handed out before it, Key's and
// EvalKey's, so the kernel holds every plan to the new cap at once (L3 on
// #2837). On an error the cap and key do not change; keys already revoked
// stay revoked, which only refuses calls.
func (s *Spare) Commit(p Prepared) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if p.set != s.set || p.tip != s.Envelope.Tip() || p.cap != s.cap {
		return ErrMoved
	}
	n, env, envs := p.n, s.Envelope, s.envs
	if !s.set {
		envs = []key.ID{env.Tip()}
	} else if len(envs) > 0 && envs[len(envs)-1] != env.Tip() {
		return errors.New("loops: the spare envelope changed outside Commit")
	}
	if w := p.widened; len(w.Links) > 0 {
		env = w
		if !slices.Contains(envs, w.Tip()) {
			envs = append(append([]key.ID{}, envs...), w.Tip())
		}
	}
	nonce, err := rand.Int(rand.Reader, big.NewInt(math.MaxInt64/2))
	if err != nil {
		return err
	}
	// The use cap is a nonce no loop reaches: derivation is deterministic,
	// so without it a cap set again would derive a key already revoked. The
	// day cap counts the whole account, so the day's earlier spend under
	// every envelope and key counts toward it, and a key set at the same or
	// a lower cap than a later one cannot add to the day (#2838).
	cur, err := key.Derive(env, s.Holder, s.Holder.Public().(ed25519.PublicKey),
		key.LowerSpendDay(n), key.LimitUses(math.MaxInt64-nonce.Int64()))
	if err != nil {
		return err
	}
	if s.set && n < s.cap {
		if len(s.out) > 0 && s.Revoke == nil {
			return ErrNoRevoke
		}
		for len(s.out) > 0 {
			if err := s.Revoke(s.out[0]); err != nil {
				return err
			}
			s.out = s.out[1:]
		}
	}
	s.Envelope, s.envs, s.cur, s.cap, s.set = env, envs, cur, n, true
	s.out = append(s.out, cur.Tip())
	return nil
}

// SetCap is Prepare then Commit, for callers that do not race. Every raise
// past the current cap needs the owner's passkey, a re-raise after a
// lowering included (KEY-6).
func (s *Spare) SetCap(n int64) error {
	p, err := s.Prepare(n)
	if err != nil {
		return err
	}
	return s.Commit(p)
}

// Key is the key loop plans cite now. A lowering revokes it, so a plan cites
// the key current when it is made.
func (s *Spare) Key() key.Key {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.cur
}

// Cap is the current day cap, in minor units.
func (s *Spare) Cap() int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.cap
}

// Used is the spend charged to every spare envelope held in the day before
// now (unix ms), in minor units: settled calls at what they used, calls in
// flight at their worst case (LOG-7).
func (s *Spare) Used(now int64) int64 {
	s.mu.Lock()
	envs := append([]key.ID{}, s.envs...)
	s.mu.Unlock()
	led := s.State().Ledger()
	var sum int64
	for _, id := range envs {
		for _, u := range led.Uses(id) {
			if u.At > now-key.DayMS {
				sum = satAdd(sum, u.Amount)
			}
		}
	}
	return sum
}

// Room reports whether the day cap has room left at now.
func (s *Spare) Room(now int64) bool { return s.Used(now) < s.Cap() }

// Tokens turns an amount in minor units back into the output tokens it buys
// on the spare route, the unit the scheduler measures cost in.
func (s *Spare) Tokens(amount int64) int64 {
	if s.OutPerM <= 0 {
		return 0
	}
	return mulDiv(amount, 1_000_000, s.OutPerM, false)
}

// Calls is how many spare calls amount is, rounded up: what the owner's
// budget and digest count.
func (s *Spare) Calls(amount int64) int64 {
	per := SpareCap(1, s.OutPerM)
	if per <= 0 {
		return 0
	}
	return mulDiv(amount, 1, per, true)
}

// EvalKey is evaluation's key (LOOP-5): a child of the spare key whose own
// day cap is EvalReserve of the budget, so replay machines that cite it
// spend at most that share. It descends from the current key, so a lowering
// revokes it with that key. Evaluating stays the loop's own predicate,
// checked before a call goes to the clerk.
func (s *Spare) EvalKey() (key.Key, error) {
	s.mu.Lock()
	cur, n, set := s.cur, s.cap, s.set
	s.mu.Unlock()
	if !set {
		return key.Key{}, errors.New("loops: spare cap not set")
	}
	return key.Derive(cur, s.Holder, s.Holder.Public().(ed25519.PublicKey), key.LimitSpendDay(mulDiv(n, evalNum, evalDen, true)))
}

// evalNum/evalDen is EvalReserve as an exact fraction, for caps past 2^53.
const evalNum, evalDen = 3, 10

// mulDiv is a*b/c in big arithmetic, rounded up or down, clamped to int64.
func mulDiv(a, b, c int64, up bool) int64 {
	if a <= 0 || b <= 0 || c <= 0 {
		return 0
	}
	x := new(big.Int).Mul(big.NewInt(a), big.NewInt(b))
	q, m := new(big.Int).QuoRem(x, big.NewInt(c), new(big.Int))
	if up && m.Sign() != 0 {
		q.Add(q, big.NewInt(1))
	}
	if !q.IsInt64() {
		return math.MaxInt64
	}
	return q.Int64()
}

func satAdd(a, b int64) int64 {
	if b > 0 && a > math.MaxInt64-b {
		return math.MaxInt64
	}
	return a + b
}
