package key_test

// REQ: EVL-1, KEY-2, KEY-3

// The reference model of the caveat rules (EVL-1, A20, D-149). It is written
// apart from the key library, from SPEC KEY-1..KEY-4 and the closed verb list,
// and it is deliberately simple: a chain is a list of predicates, a link is
// valid when each of its caveats is at least as tight as every earlier caveat
// of its kind, and a step is admitted when it satisfies every predicate on its
// own. The library folds a chain into one Limits as it goes; the model never
// folds. The fuzz below builds keys, steps and logs from one byte string and
// fails on any disagreement about whether a chain verifies, what it limits,
// or whether a step or a metered call is admitted.
//
// The model reads only the library's exported data types (Caveat, Step, Use)
// and, to name a ledger scope, Verified.IDs and Verified.Scopes. Signatures
// are not modelled as bytes: the generator records who signed each part, and
// the model judges that.

import (
	"crypto/ed25519"
	"fmt"
	"math/rand"
	"slices"
	"strconv"
	"testing"

	"github.com/ghbmrk/agentos/broker/kernel/key"
)

// --- the model -----------------------------------------------------------

// mVerbs is VRB-2's closed list, with each verb's declared arguments.
var mVerbs = map[string][]string{
	"read": {"query"}, "fetch": {"url"}, "draft": {"to", "msg"}, "organize": {"target", "label"},
	"trash": {"target"}, "unsubscribe": {"to"}, "send": {"to", "msg"}, "post": {"to", "msg"},
	"buy": {"to", "amount", "item"}, "share": {"to", "item"}, "delete-remote": {"target"},
	"change-account": {"target", "value"}, "reveal-or-create-secret": {"target"},
	"actuate": {"target", "value"}, "actuate-physical": {"target", "value"}, "present": {"msg"},
}

const mDay = 24 * 60 * 60 * 1000

// Parties. The owner's passkeys are the anchor and the phone.
const (
	pAnchor = iota
	pPhone
	pClerkA
	pClerkB
	pStranger
	nParties
)

func mOwner(p int) bool { return p == pAnchor || p == pPhone }

// mLink is one link as the model sees it: who signed it, who holds it next.
type mLink struct {
	signer, holder int
	cavs           []key.Caveat
}

// mKey is a key as the model sees it.
type mKey struct {
	issuer   int // who signed the root
	rootBad  bool
	clerk    string
	verbs    []string // as issued: sorted and unique
	links    []mLink
	useBy    int   // who signed the use
	nRevoked []int // chain prefixes revoked: 0 the root, i link i-1
	nPaused  []int
}

// mUse is one charged use and the scope it is charged to: "acct" for the
// first link's budget, "L<i>" for link i's, anything else a decoy no cap
// reads.
type mUse struct {
	scope string
	use   key.Use
}

type mWorld struct {
	k        mKey
	step     key.Step
	now      int64
	noView   bool // no revocation view
	stopped  bool
	noLedger bool
	uses     []mUse
	spendFor string // the task of a metered call
	spendAmt int64
}

func sortedUnique(s []string) bool {
	if s == nil {
		return false
	}
	for i := 1; i < len(s); i++ {
		if s[i-1] >= s[i] {
			return false
		}
	}
	return true
}

func within(a, b []string) bool {
	for _, x := range a {
		if !slices.Contains(b, x) {
			return false
		}
	}
	return true
}

func isCap(kind string) bool {
	switch kind {
	case key.KSpendTask, key.KSpendDay, key.KRateDay, key.KRateRecipient, key.KUses:
		return true
	}
	return false
}

// wellFormed judges one caveat alone.
func (m mutant) wellFormed(c key.Caveat) bool {
	switch c.Kind {
	case key.KVerbs:
		for _, v := range c.Set {
			if _, ok := mVerbs[v]; !ok {
				return false
			}
		}
		return sortedUnique(c.Set)
	case key.KContent, key.KLabels:
		return sortedUnique(c.Set)
	case key.KArg:
		a := c.Arg
		return a != nil && a.Name != "" && (a.OneOf == nil || sortedUnique(a.OneOf)) &&
			(a.Min == nil || a.Max == nil || *a.Min <= *a.Max)
	case key.KSpendTask, key.KSpendDay, key.KRateDay, key.KRateRecipient, key.KUses:
		return c.N >= 0
	case key.KExpires:
		return true
	case key.KTask:
		return len(c.Set) == 1 && c.Set[0] != ""
	case key.KHold:
		return c.N >= 0 && c.M >= c.N
	}
	return false
}

// tighter judges whether c is at least as tight as an earlier caveat e of
// the same kind (and, for an argument, the same name).
func (m mutant) tighter(c, e key.Caveat) bool {
	switch c.Kind {
	case key.KVerbs, key.KContent, key.KLabels:
		return within(c.Set, e.Set)
	case key.KArg:
		a, b := c.Arg, e.Arg
		return (b.OneOf == nil || (a.OneOf != nil && within(a.OneOf, b.OneOf))) &&
			(b.Min == nil || (a.Min != nil && *a.Min >= *b.Min)) &&
			(b.Max == nil || (a.Max != nil && *a.Max <= *b.Max))
	case key.KExpires:
		return c.N <= e.N
	case key.KTask:
		return c.Set[0] == e.Set[0]
	case key.KHold:
		return c.N >= e.N && c.M >= e.M
	}
	if isCap(c.Kind) {
		return c.N <= e.N || m == loosenCap
	}
	return false
}

func sameKind(c, e key.Caveat) bool {
	return c.Kind == e.Kind && (c.Kind != key.KArg || c.Arg.Name == e.Arg.Name)
}

// chainOK judges whether the key verifies with the use signature.
func (m mutant) chainOK(k mKey) bool {
	if !mOwner(k.issuer) || k.rootBad || k.clerk == "" || len(k.verbs) == 0 {
		return false
	}
	for _, v := range k.verbs {
		if _, ok := mVerbs[v]; !ok {
			return false
		}
	}
	var seen []key.Caveat
	holder := -1 // the bare root: any passkey
	for i, l := range k.links {
		bySigner := l.signer == holder || (holder < 0 && mOwner(l.signer))
		byPasskeyForHolder := holder >= 0 && mOwner(l.signer) && (l.holder == holder || m == narrowAnyHolder)
		if !bySigner && !byPasskeyForHolder {
			return false
		}
		if i == 0 && m != unboundedFirst {
			var exp, spend bool
			for _, c := range l.cavs {
				exp = exp || c.Kind == key.KExpires
				spend = spend || c.Kind == key.KSpendDay
			}
			if !exp || !spend {
				return false
			}
		}
		for _, c := range l.cavs {
			if !m.wellFormed(c) {
				return false
			}
			if c.Kind == key.KVerbs && !within(c.Set, k.verbs) {
				return false
			}
			for _, e := range seen {
				if sameKind(c, e) && !m.tighter(c, e) {
					return false
				}
			}
			seen = append(seen, c)
		}
		holder = l.holder
	}
	if holder < 0 {
		return mOwner(k.useBy)
	}
	return k.useBy == holder
}

func (k mKey) all() []key.Caveat {
	var cs []key.Caveat
	for _, l := range k.links {
		cs = append(cs, l.cavs...)
	}
	return cs
}

// derived is what the model says a verified chain limits.
type derived struct {
	verbs        []string
	notAfter     *int64
	hold, novel  int64
	task         string
	byOwner      bool
	content, lbl []string // nil: open
}

func (m mutant) derive(k mKey) derived {
	d := derived{verbs: slices.Clone(k.verbs)}
	for _, c := range k.all() {
		switch c.Kind {
		case key.KVerbs:
			d.verbs = slices.DeleteFunc(d.verbs, func(v string) bool { return !slices.Contains(c.Set, v) })
		case key.KExpires:
			if d.notAfter == nil || c.N < *d.notAfter {
				n := c.N
				d.notAfter = &n
			}
		case key.KHold:
			d.hold, d.novel = max(d.hold, c.N), max(d.novel, c.M)
		case key.KTask:
			d.task = c.Set[0]
		}
	}
	if n := len(k.links); n >= 2 {
		d.byOwner = k.links[n-1].signer != k.links[n-2].holder
	}
	return d
}

// scope names the ledger scope link i's caps count against.
func scopeOf(i int) string {
	if i == 0 {
		return "acct"
	}
	return fmt.Sprintf("L%d", i)
}

// live returns the refusal codes every use shares.
func (m mutant) live(w mWorld) []string {
	if w.noView {
		return []string{key.RMalformed}
	}
	var out []string
	if w.stopped {
		out = append(out, key.RStopped)
	}
	if len(w.k.nRevoked) > 0 && (m != rootRevokeIgnored || slices.ContainsFunc(w.k.nRevoked, func(i int) bool { return i > 0 })) {
		out = append(out, key.RRevoked)
	}
	if len(w.k.nPaused) > 0 {
		out = append(out, key.RPaused)
	}
	for _, c := range w.k.all() {
		if c.Kind == key.KExpires && (w.now >= c.N && m != expiryInclusive || w.now > c.N && m == expiryInclusive) {
			out = append(out, key.RExpired)
			break
		}
	}
	return out
}

// caps returns the refusal codes of every cap a charge of amount under
// step s breaks. spendOnly keeps the spend caps alone.
func (m mutant) caps(w mWorld, s key.Step, spendOnly bool) []string {
	var out []string
	for i, l := range w.k.links {
		for _, c := range l.cavs {
			if !isCap(c.Kind) || (spendOnly && c.Kind != key.KSpendTask && c.Kind != key.KSpendDay) {
				continue
			}
			if w.noLedger {
				return []string{key.RMalformed}
			}
			var sum, n int64
			for _, u := range w.uses {
				if u.scope != scopeOf(i) {
					continue
				}
				recent := u.use.At > w.now-mDay
				if m == dayWindowInclusive {
					recent = u.use.At >= w.now-mDay
				}
				switch c.Kind {
				case key.KSpendTask:
					if u.use.Task == s.Task {
						sum += u.use.Amount
					}
				case key.KSpendDay:
					if recent {
						sum += u.use.Amount
					}
				case key.KRateDay:
					if recent {
						n++
					}
				case key.KRateRecipient:
					if recent && u.use.Recipient == s.Recipient {
						n++
					}
				case key.KUses:
					n++
				}
			}
			switch c.Kind {
			case key.KSpendTask, key.KSpendDay:
				if sum+s.Amount > c.N {
					out = append(out, c.Kind)
				}
			case key.KRateDay, key.KRateRecipient:
				if n+1 > c.N {
					out = append(out, key.RRate)
				}
			case key.KUses:
				if n+1 > c.N {
					out = append(out, key.RUses)
				}
			}
		}
	}
	return out
}

// authorize returns every refusal code the step earns; none admits it.
func (m mutant) authorize(w mWorld) []string {
	out := m.live(w)
	if w.noView {
		return out
	}
	s, k := w.step, w.k
	if s.Clerk != k.clerk {
		out = append(out, key.RClerk)
	}
	if !slices.Contains(m.derive(k).verbs, string(s.Verb)) {
		out = append(out, key.RVerb)
	}
	want := mVerbs[string(s.Verb)]
	declared := len(s.Args) == len(want)
	for _, n := range want {
		declared = declared && s.Args[n].Value != ""
	}
	if !declared {
		out = append(out, key.RArg)
	}
	for _, c := range k.all() {
		switch c.Kind {
		case key.KContent:
			if !slices.Contains(c.Set, s.Content) {
				out = append(out, key.RContent)
			}
		case key.KLabels:
			if !within(s.Labels, c.Set) && m != labelsIgnored {
				out = append(out, key.RLabels)
			}
		case key.KArg:
			a, ok := s.Args[c.Arg.Name]
			fromOwnerOrClerk := a.Source == key.SrcOwner || a.Source == key.SrcClerk || (m == plannerArgs && a.Source == key.SrcPlanner)
			if !ok || !fromOwnerOrClerk || (c.Arg.OneOf != nil && !slices.Contains(c.Arg.OneOf, a.Value)) {
				out = append(out, key.RArg)
				continue
			}
			if c.Arg.Min != nil || c.Arg.Max != nil {
				n, err := strconv.ParseInt(a.Value, 10, 64)
				if err != nil || (c.Arg.Min != nil && n < *c.Arg.Min) || (c.Arg.Max != nil && n > *c.Arg.Max) {
					out = append(out, key.RArg)
				}
			}
		}
	}
	if s.Amount < 0 {
		return append(out, key.RMalformed)
	}
	return append(out, m.caps(w, s, false)...)
}

// spend returns every refusal code a metered call earns; none admits it.
func (m mutant) spend(w mWorld) []string {
	out := m.live(w)
	if w.noView {
		return out
	}
	if w.spendAmt < 0 {
		return append(out, key.RMalformed)
	}
	if !slices.ContainsFunc(w.k.all(), func(c key.Caveat) bool { return c.Kind == key.KSpendTask || c.Kind == key.KSpendDay }) {
		return append(out, key.RMalformed)
	}
	return append(out, m.caps(w, key.Step{Task: w.spendFor, Amount: w.spendAmt}, true)...)
}

// mutant plants one bug in the model, for the control test: a fuzz that
// cannot find a planted bug would not find a real one.
type mutant int

const (
	faithful           mutant = iota
	loosenCap                 // a link may raise a cap
	unboundedFirst            // a first link needs no expiry or daily spend cap
	narrowAnyHolder           // a passkey's narrowing may hand the key on
	expiryInclusive           // a key is still live at its expiry
	dayWindowInclusive        // a use a day old still counts against today
	labelsIgnored             // a labels caveat is not checked
	plannerArgs               // a bounded argument may come from the planner
	rootRevokeIgnored         // revoking the root revokes nothing
	nMutants
)

// --- the generator -------------------------------------------------------

// bits reads choices from a fuzz input; past its end every choice is 0.
type bits struct {
	b    []byte
	i    int
	args []string // the step's declared arguments, which arg caveats mostly bound
}

func (r *bits) n(k int) int {
	if r.i >= len(r.b) {
		return 0
	}
	r.i++
	return int(r.b[r.i-1]) % k
}

func (r *bits) pick(s []string) string { return s[r.n(len(s))] }

func (r *bits) chance(in256 int) bool { return r.n(256) < in256 }

func (r *bits) subset(pool []string) []string {
	out := []string{}
	for _, v := range pool {
		if r.chance(128) {
			out = append(out, v)
		}
	}
	switch r.n(16) {
	case 0:
		return nil
	case 1:
		if len(out) > 0 {
			return append(out, out[0]) // not canonical
		}
	}
	return out
}

func (r *bits) i64(s ...int64) int64 { return s[r.n(len(s))] }

func (r *bits) bound(s ...int64) *int64 {
	if r.chance(128) {
		return nil
	}
	v := r.i64(s...)
	return &v
}

var (
	gVerbs   = []string{"buy", "read", "send", "trash"} // sorted
	gContent = []string{"a", "b", "c"}
	gKinds   = []string{key.KVerbs, key.KArg, key.KArg, key.KArg, key.KContent, key.KLabels, key.KSpendTask, key.KSpendDay,
		key.KRateDay, key.KRateRecipient, key.KExpires, key.KUses, key.KHold, key.KTask, "bogus"}
	gTimes = []int64{-5, 0, 49, 50, 99, 100, 1000, mDay, mDay + 50}
)

func (r *bits) caveat(kind string) key.Caveat {
	c := key.Caveat{Kind: kind}
	switch kind {
	case key.KVerbs:
		c.Set = r.subset(append(slices.Clone(gVerbs), "bogus"))
	case key.KContent, key.KLabels:
		c.Set = r.subset(gContent)
	case key.KArg:
		if r.n(16) == 0 {
			return c
		}
		a := key.ArgBound{Name: r.pick([]string{"to", "amount", "zz", ""})}
		if len(r.args) > 0 && r.n(4) != 0 {
			a.Name = r.pick(r.args)
		}
		if r.chance(128) {
			a.OneOf = r.subset([]string{"1", "5", "x"})
		}
		a.Min, a.Max = r.bound(0, 1, 5), r.bound(1, 5, 10)
		c.Arg = &a
	case key.KExpires:
		c.N = r.i64(gTimes...)
	case key.KHold:
		c.N, c.M = r.i64(-1, 0, 10, 20), r.i64(0, 10, 30)
	case key.KTask:
		c.Set = [][]string{{"t1"}, {"t2"}, {}, {""}, {"t1", "t2"}, nil}[r.n(6)]
	default:
		c.N = r.i64(-1, 0, 1, 2, 3, 10, 100)
	}
	return c
}

func (r *bits) world() mWorld {
	var w mWorld
	k := &w.k
	k.issuer = pAnchor
	switch r.n(16) {
	case 0:
		k.issuer = pStranger
	case 1:
		k.issuer = pPhone
	}
	k.rootBad = r.n(32) == 0
	k.clerk = []string{"mail", "mail", "mail", "bank", ""}[r.n(5)]
	for _, v := range append(slices.Clone(gVerbs), "bogus") {
		if r.chance(160) && (v != "bogus" || r.n(8) == 0) {
			k.verbs = append(k.verbs, v)
		}
	}
	slices.Sort(k.verbs)
	verb := r.pick(append(slices.Clone(gVerbs), "bogus"))
	if len(k.verbs) > 0 && r.n(8) != 0 {
		verb = r.pick(k.verbs)
	}
	r.args = mVerbs[verb]
	holder := -1
	for range r.n(5) {
		l := mLink{holder: r.n(nParties)}
		switch {
		case r.n(8) == 0:
			l.signer = r.n(nParties)
		case holder < 0:
			l.signer = []int{pAnchor, pPhone}[r.n(2)]
		case r.n(6) == 0: // a passkey narrows for the holder (Narrow)
			l.signer, l.holder = pPhone, holder
		default:
			l.signer = holder
		}
		if holder < 0 && r.n(4) != 0 {
			l.cavs = append(l.cavs, key.LimitExpires(r.i64(50, 100, 1000, mDay+100, mDay+100)), key.LimitSpendDay(r.i64(0, 3, 10, 100, 1000)))
		}
		for range r.n(3) {
			l.cavs = append(l.cavs, r.caveat(gKinds[r.n(len(gKinds))]))
		}
		k.links = append(k.links, l)
		holder = l.holder
	}
	k.useBy = holder
	if holder < 0 {
		k.useBy = pAnchor
	}
	if r.n(8) == 0 {
		k.useBy = r.n(nParties)
	}

	s := key.Step{Verb: key.Verb(verb), Clerk: k.clerk, Args: map[string]key.Arg{}}
	if r.n(8) == 0 {
		s.Clerk = r.pick([]string{"mail", "bank"})
	}
	for _, n := range mVerbs[string(s.Verb)] {
		if r.n(16) != 0 {
			s.Args[n] = key.Arg{Value: r.pick([]string{"1", "5", "x", "7", "10", "1", "5", ""}), Source: []key.Source{key.SrcOwner, key.SrcClerk, key.SrcPlanner, ""}[r.n(4)]}
		}
	}
	if r.n(16) == 0 {
		s.Args["zz"] = key.Arg{Value: "1", Source: key.SrcOwner}
	}
	s.Content = r.pick([]string{"a", "b", "d", ""})
	for _, v := range []string{"a", "b", "d"} {
		if r.chance(64) {
			s.Labels = append(s.Labels, v)
		}
	}
	s.Amount = r.i64(-1, 0, 1, 3, 50)
	s.Recipient = r.pick([]string{"r1", "r2"})
	s.Task = r.pick([]string{"t1", "t2"})
	w.step = s

	w.now = r.i64(gTimes...)
	w.noView = r.n(32) == 0
	w.stopped = r.n(32) == 0
	w.noLedger = r.n(32) == 0
	for i := 0; i <= len(k.links); i++ {
		if r.n(24) == 0 {
			k.nRevoked = append(k.nRevoked, i)
		}
		if r.n(24) == 0 {
			k.nPaused = append(k.nPaused, i)
		}
	}
	scopes := []string{"acct", "acct", "L1", "L2", "L3", "id0", "id1"}
	for range r.n(8) {
		w.uses = append(w.uses, mUse{scope: r.pick(scopes), use: key.Use{
			// a use's time is often at a window's edge from now
			At: w.now - r.i64(0, 1, mDay-1, mDay, mDay, mDay+1, w.now-r.i64(gTimes...)), Amount: r.i64(0, 1, 3, 50), Recipient: r.pick([]string{"r1", "r2"}), Task: r.pick([]string{"t1", "t2"}),
		}})
	}
	w.spendFor, w.spendAmt = r.pick([]string{"t1", "t2"}), r.i64(-1, 0, 1, 3, 50)
	return w
}

// --- the differential check ----------------------------------------------

var parties = func() (ps [nParties]ed25519.PrivateKey) {
	for i := range ps {
		seed := make([]byte, ed25519.SeedSize)
		seed[0], seed[1] = 0xEF, byte(i)
		ps[i] = ed25519.NewKeyFromSeed(seed)
	}
	return
}()

func pub(p int) ed25519.PublicKey { return parties[p].Public().(ed25519.PublicKey) }

// build makes the library's key from the model's.
func build(w mWorld) key.Key {
	vs := make([]key.Verb, len(w.k.verbs))
	for i, v := range w.k.verbs {
		vs[i] = key.Verb(v)
	}
	k := key.Issue(parties[w.k.issuer], key.Root{Clerk: w.k.clerk, Verbs: vs, Serial: "ref"})
	if w.k.rootBad {
		k.Root.Sig[0] ^= 1
	}
	for _, l := range w.k.links {
		k = key.Extend(k, parties[l.signer], key.Link{Caveats: l.cavs, Holder: pub(l.holder)})
	}
	return k
}

type ledger map[key.ID][]key.Use

func (l ledger) Uses(id key.ID) []key.Use { return l[id] }

// disagree runs the library and model m on one world and describes the
// first disagreement, or returns "".
func disagree(w mWorld, m mutant) string {
	k := build(w)
	use := []byte("ref-use")
	owners := []ed25519.PublicKey{pub(pAnchor), pub(pPhone)}
	v, err := key.Verify(k, owners, use, key.Sign(k, parties[w.k.useBy], use))
	if ok := m.chainOK(w.k); ok != (err == nil) {
		return fmt.Sprintf("chain: model ok=%v, library err=%v", ok, err)
	}
	if err != nil {
		return ""
	}

	d := m.derive(w.k)
	if got := v.Limits.Verbs; !slices.Equal(got, d.verbs) && !(len(got) == 0 && len(d.verbs) == 0) {
		return fmt.Sprintf("verbs: model %v, library %v", d.verbs, got)
	}
	if (d.notAfter == nil) != (v.Limits.NotAfter == nil) || (d.notAfter != nil && *d.notAfter != *v.Limits.NotAfter) {
		return fmt.Sprintf("expiry: model %v, library %v", d.notAfter, v.Limits.NotAfter)
	}
	if v.Limits.Window(false) != d.hold || v.Limits.Window(true) != d.novel {
		return fmt.Sprintf("hold: model %d/%d, library %d/%d", d.hold, d.novel, v.Limits.Window(false), v.Limits.Window(true))
	}
	if v.Limits.Task != d.task || v.ByOwner != d.byOwner {
		return fmt.Sprintf("task/by-owner: model %q/%v, library %q/%v", d.task, d.byOwner, v.Limits.Task, v.ByOwner)
	}

	// Name each model scope by the library's ID: the first link's budget is
	// the clerk's account, the last of Scopes; link i's is its own ID.
	ids := v.IDs
	name := map[string]key.ID{"id0": ids[0]}
	if len(ids) >= 2 {
		sc := v.Scopes()
		name["acct"], name["id1"] = sc[len(sc)-1], ids[1]
		for i := 1; i < len(ids)-1; i++ {
			name[scopeOf(i)] = ids[i+1]
		}
	}
	c := key.Context{Now: w.now}
	if !w.noView {
		c.Changes = &key.Changes{Revoked: map[key.ID]bool{}, Paused: map[key.ID]bool{}, Stopped: w.stopped}
		for _, i := range w.k.nRevoked {
			c.Changes.Revoked[ids[i]] = true
		}
		for _, i := range w.k.nPaused {
			c.Changes.Paused[ids[i]] = true
		}
	}
	if !w.noLedger {
		l := ledger{}
		for _, u := range w.uses {
			if id, ok := name[u.scope]; ok {
				l[id] = append(l[id], u.use)
			}
		}
		c.Ledger = l
	}

	if s := agree("authorize", m.authorize(w), v.Authorize(w.step, c)); s != "" {
		return s
	}
	return agree("spend", m.spend(w), v.Spend(w.spendFor, w.spendAmt, c))
}

// agree compares the model's refusal codes with the library's one: both
// admit, or the library refuses for a reason the model also finds.
func agree(what string, model []string, lib *key.Refusal) string {
	switch {
	case lib == nil && len(model) == 0:
		return ""
	case lib == nil:
		return fmt.Sprintf("%s: model refuses %v, library admits", what, model)
	case !slices.Contains(model, lib.Code):
		return fmt.Sprintf("%s: model %v, library refuses %v", what, model, lib)
	}
	return ""
}

// refSeeds is how many seeded worlds the plain test runs: enough to reach
// every planted bug below several times over.
const refSeeds = 5000

func seeded(i int) mWorld {
	b := make([]byte, 256)
	rand.New(rand.NewSource(int64(i))).Read(b)
	return (&bits{b: b}).world()
}

// TestRefModelAgrees fuzzes the library against the model over fixed seeds,
// so every kernel change runs it with the race shards (EVL-1).
func TestRefModelAgrees(t *testing.T) {
	var admitted, verified int
	for i := range refSeeds {
		w := seeded(i)
		if s := disagree(w, faithful); s != "" {
			t.Fatalf("seed %d: %s\nworld: %+v", i, s, w)
		}
		if faithful.chainOK(w.k) {
			verified++
			if len(faithful.authorize(w)) == 0 {
				admitted++
			}
		}
	}
	// A generator that never builds a valid chain or an admitted step
	// would agree vacuously.
	if verified < refSeeds/10 || admitted < refSeeds/100 {
		t.Fatalf("coverage too thin: %d chains verified, %d steps admitted of %d", verified, admitted, refSeeds)
	}
}

// TestRefModelFindsPlantedBugs is the control: each bug planted in the model
// must show as a disagreement within the seeds TestRefModelAgrees runs.
func TestRefModelFindsPlantedBugs(t *testing.T) {
	for m := faithful + 1; m < nMutants; m++ {
		found := false
		for i := 0; i < refSeeds && !found; i++ {
			found = disagree(seeded(i), m) != ""
		}
		if !found {
			t.Errorf("planted bug %d not found in %d seeds", m, refSeeds)
		}
	}
}

// FuzzRefModel is the open-ended run of the same check.
func FuzzRefModel(f *testing.F) {
	for i := range 64 {
		b := make([]byte, 256)
		rand.New(rand.NewSource(int64(i))).Read(b)
		f.Add(b)
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		w := (&bits{b: b}).world()
		if s := disagree(w, faithful); s != "" {
			t.Fatalf("%s\nworld: %+v", s, w)
		}
	})
}
