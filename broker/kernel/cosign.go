package kernel

import (
	"crypto/ed25519"
	"crypto/sha256"
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

// power is what one holder can do at one clerk: the verbs its grants reach
// and its largest daily spend cap. The passkeys' one-offs are holder "".
type power struct {
	verbs map[key.Verb]bool
	day   int64
}

type holderAt struct{ clerk, holder string }

// powers folds the grants live at at, and keys, into each holder's power.
// A grant still in its hold is not power yet, so two raises in one hold are
// each judged against the live grants, never against each other.
func (s *State) powers(at int64, keys []key.Key) map[holderAt]*power {
	out := map[holderAt]*power{}
	add := func(k key.Key) {
		w := holderAt{k.Root.Clerk, ""}
		day := int64(0)
		if len(k.Links) > 0 {
			exp, _ := expiry(k.Links[0].Caveats)
			if exp != nil && *exp <= at {
				return
			}
			w.holder = string(k.Links[0].Holder)
			day = spendDay(k.Links[0].Caveats)
		}
		p := out[w]
		if p == nil {
			p = &power{verbs: map[key.Verb]bool{}}
			out[w] = p
		}
		for _, v := range k.Root.Verbs {
			p.verbs[v] = true
		}
		p.day = max(p.day, day)
	}
	for id, g := range s.Grants {
		if s.Changes.Revoked[id] || s.Changes.Revoked[rootOf(g.Key)] || g.From > at {
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
// or a daily cap past the line.
func (s *State) big(keys []key.Key, at int64) bool {
	before := s.powers(at, nil)
	for w, a := range s.powers(at, keys) {
		b := before[w]
		if b == nil {
			b = &power{}
		}
		for v := range a.verbs {
			if !b.verbs[v] {
				return true
			}
		}
		if over(a.day, b.day, s.line()) {
			return true
		}
	}
	return false
}

// cosigned reports whether a big batch has its second passkey: its signers
// and co-signers are two passkeys, one an anchor.
func (s *State) cosigned(keys []key.Key, cos []key.Cosign) bool {
	owners := s.Passkeys()
	var signers []ed25519.PublicKey
	for _, k := range keys {
		signers = append(signers, key.GrantSigner(k, owners))
	}
	return key.Approved(owners, s.Anchors, BatchHash(keys...), signers, cos)
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
			if exp, _ := expiry(g.Key.Links[0].Caveats); exp != nil && *exp > now {
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
func OneOff(v View, owners, anchors []ed25519.PublicKey, p Plan, now int64) *key.Refusal {
	if len(p.Key.Links) > 0 {
		return nil
	}
	total := int64(0)
	for i := range p.Steps {
		total = min(total+max(p.Step(i).Amount, 0), math.MaxInt64/2) // no wrap past the line
	}
	if total <= v.OneOffLine(p.Key.Tip(), now) {
		return nil
	}
	signer := key.UseSigner(p.Key, owners, p.use(), p.Sig)
	if !key.Approved(owners, anchors, PlanHash(p), []ed25519.PublicKey{signer}, p.Cosigns) {
		return &key.Refusal{Code: CCosign, Detail: strconv.FormatInt(total, 10)}
	}
	return nil
}
