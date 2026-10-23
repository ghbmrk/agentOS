package loops

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"math"
	"math/big"
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
	// held by Holder, with day cap n. Raising the cap past the envelope's
	// is a widening no derivation can make. Nil: the cap is never raised
	// past the envelope's.
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

// ErrNoWiden refuses a cap above the envelope's when no passkey can widen it.
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

// SetCap makes n the day cap of the key loop plans cite: a derivation of the
// envelope, or, for a cap above the envelope's, of a fresh envelope from
// Widen. A lowering first revokes every key handed out before it, Key's and
// EvalKey's, so the kernel holds every plan to the new cap at once (L3 on
// #2837). On an error the cap and key do not change; keys already revoked
// stay revoked, which only refuses calls.
func (s *Spare) SetCap(n int64) error {
	if n < 0 {
		return errors.New("loops: negative spare cap")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	env := s.Envelope
	if !s.set {
		s.envs = []key.ID{env.Tip()}
	} else if len(s.envs) > 0 && s.envs[len(s.envs)-1] != env.Tip() {
		return errors.New("loops: the spare envelope changed outside SetCap")
	}
	envCap, ok := dayCap(env)
	if !ok {
		return errors.New("loops: the spare envelope has no day spend cap")
	}
	envs := s.envs
	if n > envCap {
		if s.Widen == nil {
			return ErrNoWiden
		}
		w, err := s.Widen(n)
		if err != nil {
			return err
		}
		// A chain never loosens, so an envelope with the higher cap
		// cannot sit under one already held, and no spend counts twice.
		if c, ok := dayCap(w); !ok || c != n {
			return errors.New("loops: the widened spare envelope does not hold the cap asked")
		}
		env, envCap = w, n
		envs = append(append([]key.ID{}, s.envs...), w.Tip())
	}
	nonce, err := rand.Int(rand.Reader, big.NewInt(math.MaxInt64/2))
	if err != nil {
		return err
	}
	// The use cap is a nonce no loop reaches: derivation is deterministic,
	// so without it a cap set again would derive a key already revoked.
	cur, err := key.Derive(env, s.Holder, s.Holder.Public().(ed25519.PublicKey),
		key.LimitSpendDay(n), key.LimitUses(math.MaxInt64-nonce.Int64()))
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
