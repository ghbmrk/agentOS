package key

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
)

// Signing domains. A key signature and a log-head signature (kernel.DomainHead)
// never verify as one another (KEY-3).
const (
	DomainRoot = "agentos.key.root.v1\x00"
	DomainLink = "agentos.key.link.v1\x00"
	DomainUse  = "agentos.key.use.v1\x00"
	domainID   = "agentos.key.id.v1\x00"
)

// MaxLinks bounds a chain, so verification cost is bounded.
const MaxLinks = 32

// DayMS is the window of the per-day caveats, in milliseconds.
const DayMS int64 = 24 * 60 * 60 * 1000

var (
	ErrMalformed   = errors.New("key: malformed")
	ErrWrongOwner  = errors.New("key: root not signed by the owner")
	ErrBadSig      = errors.New("key: bad signature")
	ErrLoosens     = errors.New("key: link removes or loosens a limit")
	ErrNotHolder   = errors.New("key: signer does not hold the key")
	ErrUnknownKind = errors.New("key: unknown caveat kind")
)

// ID names a key or any prefix of its chain. Revoking an ID revokes every key
// whose chain passes through it (KEY-7).
type ID [32]byte

func (i ID) String() string { return hex.EncodeToString(i[:]) }

func (i ID) MarshalText() ([]byte, error) { return []byte(hex.EncodeToString(i[:])), nil }

func (i *ID) UnmarshalText(b []byte) error {
	d, err := hex.DecodeString(string(b))
	if err != nil || len(d) != len(i) {
		return ErrMalformed
	}
	copy(i[:], d)
	return nil
}

// Root is the owner-signed grant: one clerk, a set of verbs, and the first
// holder (KEY-1). Widening is issuing a new root, which only the owner's
// passkey can sign (KEY-4).
type Root struct {
	Owner  ed25519.PublicKey `json:"owner"`
	Holder ed25519.PublicKey `json:"holder"`
	Clerk  string            `json:"clerk"`
	Verbs  []Verb            `json:"verbs"`
	Serial string            `json:"serial"`
	Sig    []byte            `json:"sig"`
}

// Link adds caveats and names the next holder. It is signed by the previous
// holder. A key is bearer of nothing: only its last holder can use it, by
// signing the use (Sign), so dropping links leaves a key nobody in reach of
// the dropped links can use (KEY-1, KEY-3).
type Link struct {
	Caveats []Caveat          `json:"caveats"`
	Holder  ed25519.PublicKey `json:"holder"`
	Sig     []byte            `json:"sig"`
}

// Key is a root and the links derived from it.
type Key struct {
	Root  Root   `json:"root"`
	Links []Link `json:"links"`
}

// Caveat kinds (KEY-2). The set is closed.
const (
	KVerbs         = "verbs"
	KArg           = "arg"
	KContent       = "content"
	KLabels        = "labels"
	KSpendTask     = "spend-task"
	KSpendDay      = "spend-day"
	KRateDay       = "rate-day"
	KRateRecipient = "rate-recipient-day"
	KExpires       = "expires"
	KUses          = "uses"
	KHold          = "hold"
)

// Caveat is one typed predicate. Which fields count depends on Kind: Set for
// verbs, content and labels; Arg for arg; N for a cap, an expiry (unix ms) or
// a hold's base window (ms); M for a hold's novelty window (ms).
type Caveat struct {
	Kind string    `json:"kind"`
	Set  []string  `json:"set"`
	Arg  *ArgBound `json:"arg"`
	N    int64     `json:"n"`
	M    int64     `json:"m"`
}

// ArgBound bounds one typed argument. A nil OneOf and nil Min or Max leave
// that bound open; an empty non-nil OneOf allows no value.
type ArgBound struct {
	Name  string   `json:"name"`
	OneOf []string `json:"one_of"`
	Min   *int64   `json:"min"`
	Max   *int64   `json:"max"`
}

func set(s []string) []string {
	out := append([]string{}, s...)
	sort.Strings(out)
	w := 0
	for i, v := range out {
		if i == 0 || v != out[w-1] {
			out[w] = v
			w++
		}
	}
	return out[:w]
}

func LimitVerbs(v ...Verb) Caveat {
	s := make([]string, len(v))
	for i := range v {
		s[i] = string(v[i])
	}
	return Caveat{Kind: KVerbs, Set: set(s)}
}
func LimitLabels(l ...string) Caveat  { return Caveat{Kind: KLabels, Set: set(l)} }
func LimitContent(c ...string) Caveat { return Caveat{Kind: KContent, Set: set(c)} }
func LimitArg(b ArgBound) Caveat {
	if b.OneOf != nil {
		b.OneOf = set(b.OneOf)
	}
	return Caveat{Kind: KArg, Arg: &b}
}
func LimitSpendTask(n int64) Caveat     { return Caveat{Kind: KSpendTask, N: n} }
func LimitSpendDay(n int64) Caveat      { return Caveat{Kind: KSpendDay, N: n} }
func LimitRate(n int64) Caveat          { return Caveat{Kind: KRateDay, N: n} }
func LimitRateRecipient(n int64) Caveat { return Caveat{Kind: KRateRecipient, N: n} }
func LimitExpires(atMS int64) Caveat    { return Caveat{Kind: KExpires, N: atMS} }
func LimitUses(n int64) Caveat          { return Caveat{Kind: KUses, N: n} }
func LimitHold(baseMS, noveltyMS int64) Caveat {
	return Caveat{Kind: KHold, N: baseMS, M: noveltyMS}
}

// Cap is one counted limit and the chain prefix that set it. Counts are
// charged to every prefix of a step's key, so a parent's cap limits all its
// children together.
type Cap struct {
	Scope ID
	Kind  string
	N     int64
}

// Limits is the conjunction of a chain: the longest hold, the earliest expiry,
// every set an intersection (KEY-3).
type Limits struct {
	Clerk       string
	Verbs       []string
	Content     []string // nil: unrestricted
	Labels      []string // nil: unrestricted
	Args        map[string]ArgBound
	Caps        []Cap
	NotAfter    *int64
	HoldBase    int64
	HoldNovelty int64
}

func subset(a, b []string) bool {
	m := make(map[string]bool, len(b))
	for _, v := range b {
		m[v] = true
	}
	for _, v := range a {
		if !m[v] {
			return false
		}
	}
	return true
}

func canonical(s []string) bool { return s != nil && equal(s, set(s)) }

func equal(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func narrowSet(cur *[]string, c Caveat, what string) error {
	if !canonical(c.Set) {
		return fmt.Errorf("%w: %s set not canonical", ErrMalformed, what)
	}
	if *cur != nil && !subset(c.Set, *cur) {
		return fmt.Errorf("%w: %s", ErrLoosens, what)
	}
	*cur = c.Set
	return nil
}

// apply adds one caveat to l, refusing one that would loosen it.
func (l *Limits) apply(c Caveat, scope ID) error {
	switch c.Kind {
	case KVerbs:
		for _, v := range c.Set {
			if !Valid(Verb(v)) {
				return fmt.Errorf("%w: verb %q", ErrMalformed, v)
			}
		}
		return narrowSet(&l.Verbs, c, "verbs")
	case KContent:
		return narrowSet(&l.Content, c, "content")
	case KLabels:
		return narrowSet(&l.Labels, c, "labels")
	case KArg:
		b := c.Arg
		if b == nil || b.Name == "" || (b.OneOf != nil && !canonical(b.OneOf)) ||
			(b.Min != nil && b.Max != nil && *b.Min > *b.Max) {
			return fmt.Errorf("%w: arg bound", ErrMalformed)
		}
		if old, ok := l.Args[b.Name]; ok {
			if old.OneOf != nil && (b.OneOf == nil || !subset(b.OneOf, old.OneOf)) {
				return fmt.Errorf("%w: arg %s set", ErrLoosens, b.Name)
			}
			if old.Min != nil && (b.Min == nil || *b.Min < *old.Min) {
				return fmt.Errorf("%w: arg %s min", ErrLoosens, b.Name)
			}
			if old.Max != nil && (b.Max == nil || *b.Max > *old.Max) {
				return fmt.Errorf("%w: arg %s max", ErrLoosens, b.Name)
			}
		}
		if l.Args == nil {
			l.Args = map[string]ArgBound{}
		}
		l.Args[b.Name] = *b
	case KSpendTask, KSpendDay, KRateDay, KRateRecipient, KUses:
		if c.N < 0 {
			return fmt.Errorf("%w: negative cap", ErrMalformed)
		}
		for _, o := range l.Caps {
			if o.Kind == c.Kind && c.N > o.N {
				return fmt.Errorf("%w: %s", ErrLoosens, c.Kind)
			}
		}
		l.Caps = append(l.Caps, Cap{Scope: scope, Kind: c.Kind, N: c.N})
	case KExpires:
		if l.NotAfter != nil && c.N > *l.NotAfter {
			return fmt.Errorf("%w: expiry", ErrLoosens)
		}
		n := c.N
		l.NotAfter = &n
	case KHold:
		if c.N < 0 || c.M < c.N {
			return fmt.Errorf("%w: hold", ErrMalformed)
		}
		if c.N < l.HoldBase || c.M < l.HoldNovelty {
			return fmt.Errorf("%w: hold", ErrLoosens)
		}
		l.HoldBase, l.HoldNovelty = c.N, c.M
	default:
		return ErrUnknownKind
	}
	return nil
}

// Window is the hold before an irreversible step runs: the longest any link
// sets (KEY-8). A novel step gets the novelty window.
func (l Limits) Window(novel bool) int64 {
	if novel {
		return l.HoldNovelty
	}
	return l.HoldBase
}

func rootBody(r Root) []byte {
	b, _ := json.Marshal(struct {
		Owner  ed25519.PublicKey `json:"owner"`
		Holder ed25519.PublicKey `json:"holder"`
		Clerk  string            `json:"clerk"`
		Verbs  []Verb            `json:"verbs"`
		Serial string            `json:"serial"`
	}{r.Owner, r.Holder, r.Clerk, r.Verbs, r.Serial})
	return b
}

func linkBody(l Link) []byte {
	b, _ := json.Marshal(struct {
		Caveats []Caveat          `json:"caveats"`
		Holder  ed25519.PublicKey `json:"holder"`
	}{l.Caveats, l.Holder})
	return b
}

func rootID(r Root) ID {
	h := sha256.New()
	h.Write([]byte(domainID))
	h.Write(rootBody(r))
	h.Write(r.Sig)
	var id ID
	h.Sum(id[:0])
	return id
}

func linkID(prev ID, l Link) ID {
	h := sha256.New()
	h.Write([]byte(domainID))
	h.Write(prev[:])
	h.Write(linkBody(l))
	h.Write(l.Sig)
	var id ID
	h.Sum(id[:0])
	return id
}

func linkMsg(prev ID, l Link) []byte {
	return append(append([]byte(DomainLink), prev[:]...), linkBody(l)...)
}

// Issue signs a root with the owner's key (KEY-4). The root's verbs are
// normalised.
func Issue(owner ed25519.PrivateKey, r Root) Key {
	r.Owner = owner.Public().(ed25519.PublicKey)
	vs := make([]string, len(r.Verbs))
	for i, v := range r.Verbs {
		vs[i] = string(v)
	}
	r.Verbs = r.Verbs[:0:0]
	for _, v := range set(vs) {
		r.Verbs = append(r.Verbs, Verb(v))
	}
	r.Sig = ed25519.Sign(owner, append([]byte(DomainRoot), rootBody(r)...))
	return Key{Root: r}
}

// Tip is the ID of the key's last link, or of its root.
func (k Key) Tip() ID {
	id := rootID(k.Root)
	for _, l := range k.Links {
		id = linkID(id, l)
	}
	return id
}

func (k Key) holder() ed25519.PublicKey {
	if n := len(k.Links); n > 0 {
		return k.Links[n-1].Holder
	}
	return k.Root.Holder
}

// Extend signs and appends l without checking narrowness. Verify rejects a
// loosening link whoever signed it, so this exists for tests and the
// hostile-planner simulator; Derive is the checked path.
func Extend(k Key, holder ed25519.PrivateKey, l Link) Key {
	prev := k.Tip()
	l.Sig = nil
	l.Sig = ed25519.Sign(holder, linkMsg(prev, l))
	out := Key{Root: k.Root, Links: append(append([]Link{}, k.Links...), l)}
	return out
}

// Derive narrows k by caveats and hands it to next (KEY-3). It needs no owner
// step. It refuses a caveat that would loosen k.
func Derive(k Key, holder ed25519.PrivateKey, next ed25519.PublicKey, cav ...Caveat) (Key, error) {
	if !bytes.Equal(holder.Public().(ed25519.PublicKey), k.holder()) {
		return Key{}, ErrNotHolder
	}
	v, err := verifyChain(k, nil)
	if err != nil {
		return Key{}, err
	}
	scope := v.IDs[len(v.IDs)-1]
	l := v.Limits
	for _, c := range cav {
		if err := l.apply(c, scope); err != nil {
			return Key{}, err
		}
	}
	return Extend(k, holder, Link{Caveats: cav, Holder: next}), nil
}

// Verified is a key whose chain has checked out.
type Verified struct {
	Key    Key
	IDs    []ID // the root's ID, then each link's: every prefix
	Limits Limits
	held   bool // set by Verify only: the submitter signed as the tip's holder
}

// Sign is the tip holder's proof of possession: its signature over the key's
// tip and one use of it, such as a plan. A key without it is inert.
func Sign(k Key, holder ed25519.PrivateKey, use []byte) []byte {
	return ed25519.Sign(holder, useMsg(k.Tip(), use))
}

func useMsg(tip ID, use []byte) []byte {
	return append(append([]byte(DomainUse), tip[:]...), use...)
}

// Verify checks the chain from the owner's public key, every signature and
// every link narrowing and canonical, and that sig is the tip holder's
// signature over use. It is the only way to a Verified, so nothing is
// authorized for a submitter who cannot sign as the key's last holder.
func Verify(k Key, owner ed25519.PublicKey, use, sig []byte) (*Verified, error) {
	if len(owner) != ed25519.PublicKeySize || !bytes.Equal(k.Root.Owner, owner) {
		return nil, ErrWrongOwner
	}
	v, err := verifyChain(k, owner)
	if err != nil {
		return nil, err
	}
	if !ed25519.Verify(k.holder(), useMsg(v.ID(), use), sig) {
		return nil, ErrNotHolder
	}
	v.held = true
	return v, nil
}

// Chain checks a key as data, without a use: for a key the log already
// vouches for, a plan's key (held when its plan was admitted) or an
// extension the owner granted. Its Verified can be charged (Spend) but never
// authorizes a step, since nobody has signed as its holder.
func Chain(k Key, owner ed25519.PublicKey) (*Verified, error) {
	if len(owner) != ed25519.PublicKeySize || !bytes.Equal(k.Root.Owner, owner) {
		return nil, ErrWrongOwner
	}
	return verifyChain(k, owner)
}

// CheckChain checks a key as data, without a use: for an owner issuing a
// root into the log. It confers nothing.
func CheckChain(k Key, owner ed25519.PublicKey) error {
	_, err := Chain(k, owner)
	return err
}

// verifyChain verifies k. With owner nil it skips only the root signature
// check, for Derive, which has already been handed a key the caller holds.
func verifyChain(k Key, owner ed25519.PublicKey) (*Verified, error) {
	r := k.Root
	if len(r.Owner) != ed25519.PublicKeySize || len(r.Holder) != ed25519.PublicKeySize ||
		r.Clerk == "" || len(r.Verbs) == 0 || len(k.Links) > MaxLinks {
		return nil, ErrMalformed
	}
	vs := make([]string, len(r.Verbs))
	for i, v := range r.Verbs {
		if !Valid(v) {
			return nil, fmt.Errorf("%w: verb %q", ErrMalformed, v)
		}
		vs[i] = string(v)
	}
	if !canonical(vs) {
		return nil, fmt.Errorf("%w: root verbs not canonical", ErrMalformed)
	}
	if owner != nil && !ed25519.Verify(r.Owner, append([]byte(DomainRoot), rootBody(r)...), r.Sig) {
		return nil, ErrBadSig
	}
	v := &Verified{Key: k, IDs: []ID{rootID(r)}, Limits: Limits{Clerk: r.Clerk, Verbs: vs}}
	holder := r.Holder
	for _, l := range k.Links {
		prev := v.IDs[len(v.IDs)-1]
		if len(l.Holder) != ed25519.PublicKeySize {
			return nil, ErrMalformed
		}
		if owner != nil && !ed25519.Verify(holder, linkMsg(prev, l), l.Sig) {
			return nil, ErrBadSig
		}
		id := linkID(prev, l)
		for _, c := range l.Caveats {
			if err := v.Limits.apply(c, id); err != nil {
				return nil, err
			}
		}
		v.IDs = append(v.IDs, id)
		holder = l.Holder
	}
	return v, nil
}

// ID is the key's own ID: its tip.
func (v *Verified) ID() ID { return v.IDs[len(v.IDs)-1] }

// Root is the ID of the root, shared by every key derived from it.
func (v *Verified) Root() ID { return v.IDs[0] }
