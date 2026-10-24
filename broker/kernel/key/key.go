package key

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"slices"
	"sort"
)

// Signing domains. A key signature and a log-head signature (kernel.DomainHead)
// never verify as one another (KEY-3).
const (
	DomainRoot = "agentos.key.root.v1\x00"
	DomainLink = "agentos.key.link.v1\x00"
	DomainUse  = "agentos.key.use.v1\x00"
	// DomainEnroll signs a passkey into the owner's set (D-146).
	DomainEnroll = "agentos.key.enroll.v1\x00"
	domainID     = "agentos.key.id.v1\x00"
)

// MaxLinks bounds a chain, so verification cost is bounded.
const MaxLinks = 32

// DayMS is the window of the per-day caveats, in milliseconds.
const DayMS int64 = 24 * 60 * 60 * 1000

// ClerkLife is how long a clerk key lives (D-146). Every passkey tap renews
// it, so it lapses only after this long with no tap at all.
const ClerkLife = 30 * DayMS

var (
	ErrMalformed   = errors.New("key: malformed")
	ErrWrongOwner  = errors.New("key: root not signed by the owner")
	ErrBadSig      = errors.New("key: bad signature")
	ErrLoosens     = errors.New("key: link removes or loosens a limit")
	ErrNotHolder   = errors.New("key: signer does not hold the key")
	ErrUnknownKind = errors.New("key: unknown caveat kind")
	ErrUncaveated  = errors.New("key: a key derived from the root carries no expiry or no daily spend cap")
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

// Root is the owner-signed grant: one clerk and a set of verbs (KEY-1). Its
// holder is its owner, the passkey, so only a passkey tap uses a bare root or
// derives from it (D-146). Widening is issuing a new root (KEY-4).
type Root struct {
	Owner  ed25519.PublicKey `json:"owner"`
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
	KTask          = "task"
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
func LimitTask(id string) Caveat        { return Caveat{Kind: KTask, Set: []string{id}} }
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
	Task        string // the one task the key serves; "" for none (KRN-5)
}

// Fold is the limits of caveats cs alone, as one link sets them.
func Fold(cs []Caveat) (Limits, error) {
	var l Limits
	for _, c := range cs {
		if err := l.apply(c, ID{}); err != nil {
			return Limits{}, err
		}
	}
	return l, nil
}

// Within reports whether l allows nothing b does not, its expiry aside: every
// limit b sets, l sets at least as tightly.
func (l Limits) Within(b Limits) bool {
	sets := [][2][]string{{l.Verbs, b.Verbs}, {l.Content, b.Content}, {l.Labels, b.Labels}}
	for _, s := range sets {
		if s[1] != nil && (s[0] == nil || !subset(s[0], s[1])) {
			return false
		}
	}
	for name, o := range b.Args {
		a, ok := l.Args[name]
		if !ok { // a bare bound is a limit too: the arg may not come from the planner (KEY-2)
			return false
		}
		if (o.OneOf != nil && (a.OneOf == nil || !subset(a.OneOf, o.OneOf))) ||
			(o.Min != nil && (a.Min == nil || *a.Min < *o.Min)) || (o.Max != nil && (a.Max == nil || *a.Max > *o.Max)) {
			return false
		}
	}
	for _, o := range b.Caps {
		if !slices.ContainsFunc(l.Caps, func(c Cap) bool { return c.Kind == o.Kind && c.N <= o.N }) {
			return false
		}
	}
	return (b.Task == "" || l.Task == b.Task) && l.HoldBase >= b.HoldBase && l.HoldNovelty >= b.HoldNovelty
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
	case KTask:
		if len(c.Set) != 1 || c.Set[0] == "" {
			return fmt.Errorf("%w: task", ErrMalformed)
		}
		if l.Task != "" && l.Task != c.Set[0] {
			return fmt.Errorf("%w: task", ErrLoosens) // a key moves to no other task
		}
		l.Task = c.Set[0]
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

// Due is when a step held at heldAt may run. A due time past int64 is never
// due, so a hold near MaxInt64, which any holder may narrow to, cannot wrap to
// a time already past (KEY-8, #2952).
func (l Limits) Due(heldAt int64, novel bool) int64 {
	w := l.Window(novel)
	if heldAt > 0 && w > math.MaxInt64-heldAt {
		return math.MaxInt64
	}
	return heldAt + w
}

func rootBody(r Root) []byte {
	b, _ := json.Marshal(struct {
		Owner  ed25519.PublicKey `json:"owner"`
		Clerk  string            `json:"clerk"`
		Verbs  []Verb            `json:"verbs"`
		Serial string            `json:"serial"`
	}{r.Owner, r.Clerk, r.Verbs, r.Serial})
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

// holder is who signs a use of k or the next link: the last link's holder,
// or for a bare root any passkey in the owner's set (nil here).
func (k Key) holder() ed25519.PublicKey {
	if n := len(k.Links); n > 0 {
		return k.Links[n-1].Holder
	}
	return nil
}

// signedBy reports whether pk signed msg, as one named signer or, when
// signer is nil, as any passkey in owners.
func signedBy(signer ed25519.PublicKey, owners []ed25519.PublicKey, msg, sig []byte) bool {
	if signer != nil {
		return ed25519.Verify(signer, msg, sig)
	}
	return whoSigned(owners, msg, sig) != nil
}

// SignedBy reports whether pk signed grant k: a root it issued, or a first
// link it signed.
func SignedBy(k Key, pk ed25519.PublicKey) bool {
	if len(pk) != ed25519.PublicKeySize {
		return false
	}
	if len(k.Links) == 0 {
		return bytes.Equal(k.Root.Owner, pk)
	}
	return ed25519.Verify(pk, linkMsg(rootID(k.Root), k.Links[0]), k.Links[0].Sig)
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
// step below the root. It refuses a caveat that would loosen k, and a key off
// the root without an expiry and a daily spend cap: the chain check below is
// the one place both rules live.
func Derive(k Key, holder ed25519.PrivateKey, next ed25519.PublicKey, cav ...Caveat) (Key, error) {
	if h := k.holder(); h != nil && !bytes.Equal(holder.Public().(ed25519.PublicKey), h) {
		return Key{}, ErrNotHolder
	}
	out := Extend(k, holder, Link{Caveats: cav, Holder: next})
	if _, err := verifyChain(out, nil); err != nil {
		return Key{}, err
	}
	return out, nil
}

// Narrow is a passkey narrowing k for k's own holder: the new link keeps the
// holder and is signed by the passkey, not by the holder, so it proves the
// owner approved exactly these caveats (OWN-9). It hands out no power the
// holder lacked, so it is no grant and waits no hold (D-146), and its caps
// count against the link alone. It refuses a bare root, where a new link
// would be a grant.
func Narrow(k Key, passkey ed25519.PrivateKey, cav ...Caveat) (Key, error) {
	h := k.holder()
	if h == nil {
		return Key{}, ErrNotHolder
	}
	out := Extend(k, passkey, Link{Caveats: cav, Holder: h})
	if _, err := verifyChain(out, nil); err != nil {
		return Key{}, err
	}
	return out, nil
}

// ClerkKey is the passkey's grant to a clerk: the root narrowed by caveats,
// living ClerkLife from now under a daily spend cap (D-146). A renewal is a
// new ClerkKey; plans already admitted keep the key they cite.
func ClerkKey(root Key, passkey ed25519.PrivateKey, clerk ed25519.PublicKey, now, spendDay int64, cav ...Caveat) (Key, error) {
	return Derive(root, passkey, clerk, append([]Caveat{LimitExpires(now + ClerkLife), LimitSpendDay(spendDay)}, cav...)...)
}

// Reach is the verbs k reaches: its root's, narrowed by its links; none when
// k is malformed. It checks no signature.
func Reach(k Key) []string {
	v, err := verifyChain(k, nil)
	if err != nil {
		return nil
	}
	return v.Limits.Verbs
}

// TaskOf is the task k serves, from its task caveat; "" for a key that serves
// none or is malformed. It checks no signature (KRN-5).
func TaskOf(k Key) string {
	v, err := verifyChain(k, nil)
	if err != nil {
		return ""
	}
	return v.Limits.Task
}

// PlanPrefix starts the charge key of a plan whose key serves no task. The
// planner names its plans, so no task id may start with it (the kernel opens
// none that does): a plan named like a task is never charged as that task.
const PlanPrefix = "\x00plan\x00"

// ChargeTask is what a plan's steps and metered calls are charged under, the
// task a per-task cap counts (LOG-7, KRN-5): the task k serves, so the cap
// spans every re-plan of it, else the plan itself under PlanPrefix.
func ChargeTask(k Key, plan string) string {
	if t := TaskOf(k); t != "" {
		return t
	}
	return PlanPrefix + plan
}

// Verified is a key whose chain has checked out.
type Verified struct {
	Key    Key
	IDs    []ID // the root's ID, then each link's: every prefix
	Limits Limits
	held   bool // set by Verify only: the submitter signed as the tip's holder
	// ByOwner is set when the tip is a link after the first that a passkey
	// signed for its parent's holder (Narrow): the owner's approval of it.
	ByOwner bool
	// Narrowers are the passkeys that signed such links, checked against
	// the passkeys cut off since (kernel.Live).
	Narrowers []ed25519.PublicKey
	account   ID // the first link's budget (account)
}

// Sign is the tip holder's proof of possession: its signature over the key's
// tip and one use of it, such as a plan. A key without it is inert.
func Sign(k Key, holder ed25519.PrivateKey, use []byte) []byte {
	return ed25519.Sign(holder, useMsg(k.Tip(), use))
}

func useMsg(tip ID, use []byte) []byte {
	return append(append([]byte(DomainUse), tip[:]...), use...)
}

// Verify checks the chain from the owner's passkeys, every signature and
// every link narrowing and canonical, and that sig is the tip holder's
// signature over use. It is the only way to a Verified, so nothing is
// authorized for a submitter who cannot sign as the key's last holder. The
// root is signed by its owner, which must be in owners; a first link, and a
// use of a bare root, by any passkey in owners (D-146).
func Verify(k Key, owners []ed25519.PublicKey, use, sig []byte) (*Verified, error) {
	v, err := Chain(k, owners)
	if err != nil {
		return nil, err
	}
	if !signedBy(k.holder(), owners, useMsg(v.ID(), use), sig) {
		return nil, ErrNotHolder
	}
	v.held = true
	return v, nil
}

// Chain checks a key as data, without a use: for a key the log already
// vouches for, a plan's key (held when its plan was admitted) or an
// extension the owner granted. Its Verified can be charged (Spend) but never
// authorizes a step, since nobody has signed as its holder.
func Chain(k Key, owners []ed25519.PublicKey) (*Verified, error) {
	if !In(owners, k.Root.Owner) {
		return nil, ErrWrongOwner
	}
	return verifyChain(k, owners)
}

// verifyChain verifies k. With owners nil it skips the signature checks, for
// Derive, which has already been handed a key the caller holds.
func verifyChain(k Key, owners []ed25519.PublicKey) (*Verified, error) {
	r := k.Root
	if len(r.Owner) != ed25519.PublicKeySize || r.Clerk == "" || len(r.Verbs) == 0 || len(k.Links) > MaxLinks {
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
	if owners != nil && !ed25519.Verify(r.Owner, append([]byte(DomainRoot), rootBody(r)...), r.Sig) {
		return nil, ErrBadSig
	}
	v := &Verified{Key: k, IDs: []ID{rootID(r)}, Limits: Limits{Clerk: r.Clerk, Verbs: vs}}
	var holder ed25519.PublicKey // a first link: any passkey in owners
	for _, l := range k.Links {
		prev := v.IDs[len(v.IDs)-1]
		if len(l.Holder) != ed25519.PublicKeySize {
			return nil, ErrMalformed
		}
		v.ByOwner = false
		if owners != nil && !signedBy(holder, owners, linkMsg(prev, l), l.Sig) {
			// A passkey may narrow a key for its own holder (Narrow).
			p := whoSigned(owners, linkMsg(prev, l), l.Sig)
			if p == nil || !bytes.Equal(l.Holder, holder) {
				return nil, ErrBadSig
			}
			v.ByOwner = true
			v.Narrowers = append(v.Narrowers, p)
		}
		id := linkID(prev, l)
		scope := id
		if len(v.IDs) == 1 {
			// Full power stays with the passkeys: every key derived from
			// the root lapses and is capped (D-145, D-146), and its caps
			// count against the clerk's account under the root, so a
			// renewal starts no fresh budget.
			if !bounded(l.Caveats) {
				return nil, ErrUncaveated
			}
			scope = account(prev, l.Holder)
			v.account = scope
		}
		for _, c := range l.Caveats {
			if err := v.Limits.apply(c, scope); err != nil {
				return nil, err
			}
		}
		v.IDs = append(v.IDs, id)
		holder = l.Holder
	}
	return v, nil
}

// account names a clerk's budget under a root: every first link to that
// holder, a renewal or a wider grant, is charged to it.
func account(root ID, holder ed25519.PublicKey) ID {
	h := sha256.New()
	h.Write([]byte(domainID))
	h.Write([]byte("account\x00"))
	h.Write(root[:])
	h.Write(holder)
	var id ID
	h.Sum(id[:0])
	return id
}

// Scopes are what a use of v is charged to: every prefix of its chain and
// the clerk's account under the root.
func (v *Verified) Scopes() []ID {
	if len(v.IDs) < 2 {
		return v.IDs
	}
	return append(append([]ID{}, v.IDs...), v.account)
}

// ID is the key's own ID: its tip.
func (v *Verified) ID() ID { return v.IDs[len(v.IDs)-1] }

// Root is the ID of the root, shared by every key derived from it.
func (v *Verified) Root() ID { return v.IDs[0] }

// bounded reports whether a first link sets an expiry and a daily spend cap.
func bounded(cs []Caveat) bool {
	var exp, spend bool
	for _, c := range cs {
		exp = exp || c.Kind == KExpires
		spend = spend || c.Kind == KSpendDay
	}
	return exp && spend
}

// Enrollment is an anchor's signature adding a passkey, such as a new phone,
// to the owner's set (D-146). The anchors are the device-bound hardware keys;
// a synced phone passkey is enrolled under them, so no cloud account is the
// root.
type Enrollment struct {
	Passkey ed25519.PublicKey `json:"passkey"`
	By      ed25519.PublicKey `json:"by"`
	Sig     []byte            `json:"sig"`
}

func enrollMsg(pk ed25519.PublicKey) []byte { return append([]byte(DomainEnroll), pk...) }

// Enroll is anchor's signature enrolling pk.
func Enroll(anchor ed25519.PrivateKey, pk ed25519.PublicKey) Enrollment {
	return Enrollment{Passkey: pk, By: anchor.Public().(ed25519.PublicKey), Sig: ed25519.Sign(anchor, enrollMsg(pk))}
}

// Passkeys is the owner's set: the anchors, then each passkey an anchor
// enrolled, less every revoked one. A revoked passkey never comes back, so an
// old enrollment replayed adds nothing, and an enrollment no anchor signed
// adds nothing, so the set needs no trust in whoever keeps the list.
func Passkeys(anchors []ed25519.PublicKey, es []Enrollment, revoked []ed25519.PublicKey) []ed25519.PublicKey {
	var set []ed25519.PublicKey
	add := func(pk ed25519.PublicKey) {
		if len(pk) == ed25519.PublicKeySize && !In(set, pk) {
			set = append(set, pk)
		}
	}
	for _, a := range anchors { // an anchor is never cut off: only recovery replaces one
		add(a)
	}
	for _, e := range es {
		if In(anchors, e.By) && !In(revoked, e.Passkey) && ed25519.Verify(e.By, enrollMsg(e.Passkey), e.Sig) {
			add(e.Passkey)
		}
	}
	return set
}

// In reports whether pk is in set.
func In(set []ed25519.PublicKey, pk ed25519.PublicKey) bool {
	for _, p := range set {
		if len(p) == ed25519.PublicKeySize && bytes.Equal(p, pk) {
			return true
		}
	}
	return false
}
