package kernel

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"math/bits"
	"strconv"

	"github.com/ghbmrk/agentos/broker/kernel/key"
)

// The second passkey (D-146 item 5). A big change needs two enrolled
// passkeys, one of them an anchor, a hardware key: a grant that gives a
// clerk, or the passkeys' own one-offs, a verb they lacked or a daily cap
// past the owner's line; a one-off whose spend is past the line; and a raised
// line. Everything else still waits the grant hold, or never waits.

// DefaultLine is the owner's line, in percent of a limit: more than double is big.
const DefaultLine = 200

// CCosign refuses a very large one-off that lacks its second passkey.
const CCosign = "needs-cosign"

// ErrNeedsCosign refuses a big grant or a raised line without its second passkey.
var ErrNeedsCosign = errors.New("kernel: a big change needs a second passkey, one a hardware key")

// ErrLine refuses a line under 100%: a renewal at the same limits would be big.
var ErrLine = errors.New("kernel: the line is at least 100%")

// BatchHash names a grant batch for its co-signatures.
func BatchHash(keys ...key.Key) [32]byte {
	b, _ := json.Marshal(keys)
	return sha256.Sum256(append([]byte("agentos.grants.v1\x00"), b...))
}

// PlanHash names a one-off for its co-signatures: the key and what its signer signed.
func PlanHash(p Plan) [32]byte {
	tip := p.Key.Tip()
	return sha256.Sum256(append(append([]byte("agentos.oneoff.v1\x00"), tip[:]...), p.use()...))
}

// LineHash names the change of the line to percent, as the n-th line change.
func LineHash(n int, percent int64) [32]byte {
	return sha256.Sum256([]byte(fmt.Sprintf("agentos.line.v1\x00%d\x00%d", n, percent)))
}

// EdgeEnrollHash names enrolling edge under the core's head key as the n-th
// edge change (State.EdgeChanges), replacing replaces (nil if none is live),
// so a signature over one enrolment never replays as another, nor after a
// cut or a revoke.
func EdgeEnrollHash(n int, head, edge, replaces ed25519.PublicKey) [32]byte {
	m := binary.BigEndian.AppendUint64([]byte(DomainEdgeEnroll), uint64(n))
	for _, k := range [][]byte{head, edge, replaces} {
		m = append(binary.BigEndian.AppendUint16(m, uint16(len(k))), k...)
	}
	return sha256.Sum256(m)
}

// power is what one holder can do at one clerk: the verbs its grants reach
// and, under each root, its largest daily spend cap. The passkeys' one-offs
// are holder "".
type power struct {
	verbs map[key.Verb]bool
	days  map[key.ID]int64
}

// day is the holder's daily budget at the clerk: each root's is its own
// account (key.account), so they add up. The sum saturates before it adds,
// so a cap near MaxInt64 never wraps it negative (Defect: KEY, #2950).
func (p *power) day() int64 {
	var n int64
	for _, d := range p.days {
		n += min(max(d, 0), math.MaxInt64/2-n)
	}
	return n
}

type holderAt struct{ clerk, holder string }

// powers folds the grants live at at, those still in their hold too when
// pending, and keys, into each holder's power. A paused grant is none.
func (s *State) powers(at int64, pending bool, keys []key.Key) map[holderAt]*power {
	out := map[holderAt]*power{}
	add := func(k key.Key) {
		w := holderAt{k.Root.Clerk, ""}
		day := int64(0)
		if len(k.Links) > 0 {
			exp := lapse(k.Links[0].Caveats)
			if exp != nil && *exp <= at {
				return
			}
			w.holder = string(k.Links[0].Holder)
			day = spendDay(k.Links[0].Caveats)
		}
		p := out[w]
		if p == nil {
			p = &power{verbs: map[key.Verb]bool{}, days: map[key.ID]int64{}}
			out[w] = p
		}
		for _, v := range key.Reach(k) {
			p.verbs[key.Verb(v)] = true
		}
		p.days[rootOf(k)] = max(p.days[rootOf(k)], day)
	}
	for id, g := range s.Grants {
		if s.Changes.Revoked[id] || s.Changes.Revoked[rootOf(g.Key)] || s.Changes.Paused[id] || g.From > at && !pending {
			continue
		}
		add(g.Key)
	}
	for _, k := range keys {
		add(k)
	}
	return out
}

// over reports whether a is past line percent of b, without overflow.
func over(a, b, line int64) bool {
	hi, lo := bits.Mul64(uint64(max(a, 0)), 100)
	bhi, blo := bits.Mul64(uint64(max(b, 0)), uint64(line))
	return hi > bhi || hi == bhi && lo > blo
}

func spendDay(cs []key.Caveat) int64 {
	for _, c := range cs {
		if c.Kind == key.KSpendDay {
			return c.N
		}
	}
	return 0
}

// big reports whether granting keys at at gives any holder a verb it lacks
// or a daily budget past the line. What it has is the live grants; what it
// would have adds the grants still in their hold, so raises in one hold
// cannot each pass as small: a renewal's cap replaces its root's, and a new
// root's adds to the budget.
func (s *State) big(keys []key.Key, at int64) bool {
	before := s.powers(at, false, nil)
	for w, a := range s.powers(at, true, keys) {
		b := before[w]
		if b == nil {
			b = &power{}
		}
		for v := range a.verbs {
			if !b.verbs[v] {
				return true
			}
		}
		if over(a.day(), b.day(), s.line()) {
			return true
		}
	}
	return false
}

// cosigned reports whether a big batch has its two passkeys, one an anchor:
// co-signers over the whole batch. The keys' own signatures count for
// nothing, since a batch may carry a key a passkey signed long ago.
func (s *State) cosigned(keys []key.Key, cos []key.Cosign) bool {
	return key.Approved(s.Passkeys(), s.Anchors, BatchHash(keys...), nil, cos)
}

// LineChanges is how many times the line has changed: a raise's co-signers
// sign LineHash(LineChanges(), percent), so an old approval cannot replay.
func (s *State) LineChanges() int { return s.lines }

func (s *State) line() int64 {
	if s.Line == 0 {
		return DefaultLine
	}
	return s.Line
}

// lineOK is the check a line change passes: at least 100%, and a raise has
// its two passkeys.
func (s *State) lineOK(b lineSet) error {
	if b.Percent < 100 {
		return ErrLine
	}
	if b.Percent > s.line() && !key.Approved(s.Passkeys(), s.Anchors, LineHash(s.lines, b.Percent), nil, b.Cosigns) {
		return ErrNeedsCosign
	}
	return nil
}

// OneOffLine is the most a one-off under root may spend without a second
// passkey: the line times the largest daily cap of a live clerk key under
// it, so with none, any spend needs one.
func (s *State) OneOffLine(root key.ID, now int64) int64 {
	day := int64(0)
	for id, g := range s.Grants {
		if len(g.Key.Links) == 1 && rootOf(g.Key) == root && g.From <= now && !s.Changes.Revoked[id] && !s.Changes.Revoked[root] {
			if exp := lapse(g.Key.Links[0].Caveats); exp != nil && *exp > now {
				day = max(day, spendDay(g.Key.Links[0].Caveats))
			}
		}
	}
	if day > math.MaxInt64/s.line() {
		return math.MaxInt64
	}
	return day * s.line() / 100
}

// OneOff refuses a one-off under a bare root whose spend is past the line
// unless a second passkey, one of the two an anchor, co-signed it.
func OneOff(v View, owners, anchors []key.PublicKey, p Plan, now int64) *key.Refusal {
	if len(p.Key.Links) > 0 {
		return nil
	}
	total := int64(0)
	for i := range p.Steps {
		total = min(total+min(max(p.Step(i).Amount, 0), math.MaxInt64/2), math.MaxInt64/2) // both halves, so no wrap
	}
	if total <= v.OneOffLine(p.Key.Tip(), now) {
		return nil
	}
	signer := key.UseSigner(p.Key, owners, p.use(), p.Sig)
	if !key.Approved(owners, anchors, PlanHash(p), []key.PublicKey{signer}, p.Cosigns) {
		return &key.Refusal{Code: CCosign, Detail: strconv.FormatInt(total, 10)}
	}
	return nil
}
