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
//
// Every predicate the model evaluates is guarded by its own planted bug (a
// mutant): m.on(x) is false only under mutant x, which drops that one
// predicate, and m.slack(x) moves one bound by one. The seeded test fails
// unless every mutant disagrees with the library on some seed, so a rule the
// generator stops reaching fails the test instead of passing silently.

import (
	"crypto/ed25519"
	"fmt"
	"math/rand"
	"runtime"
	"slices"
	"sort"
	"strconv"
	"sync"
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

// mutant plants one bug in the model; faithful plants none.
type mutant int

func (m mutant) on(x mutant) bool { return m != x }

func (m mutant) slack(x mutant) int64 {
	if m == x {
		return 1
	}
	return 0
}

// The planted bugs, one per predicate, in the order the model below
// evaluates them. Each comment says what the bug lets through.
const (
	faithful mutant = iota
	// chainOK
	mIssuer            // a root issued by a non-passkey
	mRootSig           // a root with a bad signature
	mRootClerk         // a root for no clerk
	mRootVerbs         // a root with no verbs
	mRootVerbValid     // a root verb off the list
	mFirstSigner       // a first link signed by a non-passkey
	mLinkSig           // a later link signed by neither the holder nor a passkey
	mNarrowKeepsHolder // a passkey's narrowing that hands the key on
	mFirstExpiry       // a first link with no expiry
	mFirstSpendDay     // a first link with no daily spend cap
	mVerbsInRoot       // a verbs caveat wider than the root
	mUseBareRoot       // a bare root's use signed by a non-passkey
	mUseTip            // a use not signed by the tip's holder
	// wellFormed
	mVerbsCanonical    // an unsorted, duplicated or nil verbs set
	mContentCanonical  // the same for content
	mLabelsCanonical   // the same for labels
	mArgNamed          // an arg bound with no bound or no name
	mArgOneOfCanonical // an arg set not canonical
	mArgMinMax         // an arg bound with min above max
	mCapNonNeg         // a negative cap
	mTaskShape         // a task caveat naming no task or two
	mHoldNonNeg        // a negative hold
	mHoldOrder         // a novelty hold shorter than the base hold
	mUnknownKind       // a caveat of no known kind
	// tighter
	mVerbsTighter
	mContentTighter
	mLabelsTighter
	mArgOneOfTighter // a later arg set dropped or widened
	mArgMinTighter   // a later arg min dropped or lowered
	mArgMaxTighter   // a later arg max dropped or raised
	mExpiryTighter
	mTaskTighter // a later link moving the key to another task
	mHoldBaseTighter
	mHoldNoveltyTighter
	mSpendTaskTighter
	mSpendDayTighter
	mRateDayTighter
	mRateRecipientTighter
	mUsesTighter
	// derive
	mDeriveVerbs   // a verbs caveat not narrowing the reported verbs
	mDeriveExpiry  // the first expiry reported, not the earliest
	mDeriveHold    // the first base hold reported, not the longest
	mDeriveNovelty // the first novelty hold reported, not the longest
	mDeriveTask    // the task not reported
	mDeriveByOwner // a passkey's narrowing not reported
	// live
	mNoView      // a check with no revocation view
	mStopped     // a step while stop is in force
	mRevokedRoot // a revoked root
	mRevokedMid  // a revoked link short of the tip
	mRevokedTip  // a revoked tip
	mPaused      // a paused prefix
	mExpired     // an expired key
	mExpiryEdge  // a key at its expiry
	// authorize
	mClerk          // a step on another clerk
	mStepVerbRoot   // a verb outside the root
	mStepVerbCaveat // a verb outside a verbs caveat
	mArgCount       // a step with an extra argument
	mArgMissing     // a step missing a declared argument
	mArgEmpty       // a declared argument with no value
	mContent        // content outside a content caveat
	mLabels         // labels outside a labels caveat
	mLabelsAll      // a label outside it after the first
	mArgPresent     // a bounded argument absent
	mArgPlanner     // a bounded argument from the planner
	mArgSource      // a bounded argument from no named source
	mArgOneOf       // a bounded argument outside its set
	mArgParse       // a range-bounded argument that is no number
	mArgMin         // a bounded argument below its min
	mArgMinEdge     // a bounded argument one below its min
	mArgMax         // a bounded argument above its max
	mArgMaxEdge     // a bounded argument one above its max
	mAmountNeg      // a negative amount
	// caps
	mNoLedger           // a capped key checked with no ledger
	mSpendRate          // Spend checking rate and use caps too (stricter)
	mCapScope           // a cap counting uses of every scope (stricter)
	mSpendTaskMatch     // a per-task cap counting every task (stricter)
	mSpendTask          // over the per-task cap
	mSpendTaskEdge      // one over the per-task cap
	mSpendDayWindow     // a daily cap counting old uses (stricter)
	mSpendDayWindowEdge // a daily cap counting a use exactly a day old
	mSpendDay           // over the daily spend cap
	mSpendDayEdge       // one over the daily spend cap
	mRateDayWindow
	mRateDayWindowEdge
	mRateDay
	mRateDayEdge
	mRateRecipientWindow
	mRateRecipientWindowEdge
	mRateRecipientMatch // a per-recipient rate counting every recipient (stricter)
	mRateRecipient
	mRateRecipientEdge
	mUsesAllTime // a uses cap counting only the last day
	mUses
	mUsesEdge
	// spend
	mSpendAmountNeg // a negative metered amount
	mSpendCapped    // a metered call on a key with no spend cap
	nMutants
)

var tighterMutant = map[string]mutant{
	key.KVerbs: mVerbsTighter, key.KContent: mContentTighter, key.KLabels: mLabelsTighter,
	key.KExpires: mExpiryTighter, key.KTask: mTaskTighter,
	key.KSpendTask: mSpendTaskTighter, key.KSpendDay: mSpendDayTighter, key.KRateDay: mRateDayTighter,
	key.KRateRecipient: mRateRecipientTighter, key.KUses: mUsesTighter,
}

var canonicalMutant = map[string]mutant{key.KVerbs: mVerbsCanonical, key.KContent: mContentCanonical, key.KLabels: mLabelsCanonical}

// capCode is the refusal code each cap kind earns.
var capCode = map[string]string{
	key.KSpendTask: key.RSpendTask, key.KSpendDay: key.RSpendDay,
	key.KRateDay: key.RRate, key.KRateRecipient: key.RRate, key.KUses: key.RUses,
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

func isCap(kind string) bool { _, ok := capCode[kind]; return ok }

func isSpend(kind string) bool { return kind == key.KSpendTask || kind == key.KSpendDay }

// argOf and taskOf read a caveat a planted bug let through malformed.
func argOf(c key.Caveat) key.ArgBound {
	if c.Arg == nil {
		return key.ArgBound{}
	}
	return *c.Arg
}

func taskOf(c key.Caveat) string {
	if len(c.Set) == 0 {
		return ""
	}
	return c.Set[0]
}

// wellFormed judges one caveat alone.
func (m mutant) wellFormed(c key.Caveat) bool {
	switch c.Kind {
	case key.KVerbs, key.KContent, key.KLabels:
		if c.Kind == key.KVerbs {
			for _, v := range c.Set {
				if _, ok := mVerbs[v]; !ok {
					return false
				}
			}
		}
		return sortedUnique(c.Set) || !m.on(canonicalMutant[c.Kind])
	case key.KArg:
		if c.Arg == nil || c.Arg.Name == "" {
			return !m.on(mArgNamed)
		}
		a := c.Arg
		if m.on(mArgOneOfCanonical) && a.OneOf != nil && !sortedUnique(a.OneOf) {
			return false
		}
		return !m.on(mArgMinMax) || a.Min == nil || a.Max == nil || *a.Min <= *a.Max
	case key.KSpendTask, key.KSpendDay, key.KRateDay, key.KRateRecipient, key.KUses:
		return c.N >= 0 || !m.on(mCapNonNeg)
	case key.KExpires:
		return true
	case key.KTask:
		return (len(c.Set) == 1 && c.Set[0] != "") || !m.on(mTaskShape)
	case key.KHold:
		return (c.N >= 0 || !m.on(mHoldNonNeg)) && (c.M >= c.N || !m.on(mHoldOrder))
	}
	return !m.on(mUnknownKind)
}

// tighter judges whether c is at least as tight as an earlier caveat e of
// the same kind (and, for an argument, the same name).
func (m mutant) tighter(c, e key.Caveat) bool {
	switch c.Kind {
	case key.KVerbs, key.KContent, key.KLabels:
		return within(c.Set, e.Set) || !m.on(tighterMutant[c.Kind])
	case key.KArg:
		a, b := argOf(c), argOf(e)
		return (!m.on(mArgOneOfTighter) || b.OneOf == nil || (a.OneOf != nil && within(a.OneOf, b.OneOf))) &&
			(!m.on(mArgMinTighter) || b.Min == nil || (a.Min != nil && *a.Min >= *b.Min)) &&
			(!m.on(mArgMaxTighter) || b.Max == nil || (a.Max != nil && *a.Max <= *b.Max))
	case key.KExpires:
		return c.N <= e.N || !m.on(mExpiryTighter)
	case key.KTask:
		return taskOf(c) == taskOf(e) || !m.on(mTaskTighter)
	case key.KHold:
		return (c.N >= e.N || !m.on(mHoldBaseTighter)) && (c.M >= e.M || !m.on(mHoldNoveltyTighter))
	}
	if isCap(c.Kind) {
		return c.N <= e.N || !m.on(tighterMutant[c.Kind])
	}
	return true // an unknown kind a planted bug let through
}

func sameKind(c, e key.Caveat) bool {
	return c.Kind == e.Kind && (c.Kind != key.KArg || argOf(c).Name == argOf(e).Name)
}

// chainOK judges whether the key verifies with the use signature.
func (m mutant) chainOK(k mKey) bool {
	if (m.on(mIssuer) && !mOwner(k.issuer)) || (m.on(mRootSig) && k.rootBad) ||
		(m.on(mRootClerk) && k.clerk == "") || (m.on(mRootVerbs) && len(k.verbs) == 0) {
		return false
	}
	if m.on(mRootVerbValid) {
		for _, v := range k.verbs {
			if _, ok := mVerbs[v]; !ok {
				return false
			}
		}
	}
	var seen []key.Caveat
	holder := -1 // the bare root: any passkey
	for i, l := range k.links {
		if holder < 0 && m.on(mFirstSigner) && !mOwner(l.signer) {
			return false
		}
		byPasskey := mOwner(l.signer) && (l.holder == holder || !m.on(mNarrowKeepsHolder))
		if holder >= 0 && m.on(mLinkSig) && l.signer != holder && !byPasskey {
			return false
		}
		if i == 0 {
			exp := slices.ContainsFunc(l.cavs, func(c key.Caveat) bool { return c.Kind == key.KExpires })
			spend := slices.ContainsFunc(l.cavs, func(c key.Caveat) bool { return c.Kind == key.KSpendDay })
			if (m.on(mFirstExpiry) && !exp) || (m.on(mFirstSpendDay) && !spend) {
				return false
			}
		}
		for _, c := range l.cavs {
			if !m.wellFormed(c) {
				return false
			}
			if m.on(mVerbsInRoot) && c.Kind == key.KVerbs && !within(c.Set, k.verbs) {
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
		return mOwner(k.useBy) || !m.on(mUseBareRoot)
	}
	return k.useBy == holder || !m.on(mUseTip)
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
	verbs       []string
	notAfter    *int64
	hold, novel int64
	task        string
	byOwner     bool
}

func (m mutant) derive(k mKey) derived {
	d := derived{verbs: slices.Clone(k.verbs)}
	var holds int
	for _, c := range k.all() {
		switch c.Kind {
		case key.KVerbs:
			if m.on(mDeriveVerbs) {
				d.verbs = slices.DeleteFunc(d.verbs, func(v string) bool { return !slices.Contains(c.Set, v) })
			}
		case key.KExpires:
			if d.notAfter == nil || (c.N < *d.notAfter && m.on(mDeriveExpiry)) {
				n := c.N
				d.notAfter = &n
			}
		case key.KHold:
			if holds == 0 || m.on(mDeriveHold) {
				d.hold = max(d.hold, c.N)
			}
			if holds == 0 || m.on(mDeriveNovelty) {
				d.novel = max(d.novel, c.M)
			}
			holds++
		case key.KTask:
			if m.on(mDeriveTask) {
				d.task = taskOf(c)
			}
		}
	}
	if n := len(k.links); n >= 2 && m.on(mDeriveByOwner) {
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
	if w.noView && m.on(mNoView) {
		return []string{key.RMalformed}
	}
	var out []string
	if !w.noView {
		if w.stopped && m.on(mStopped) {
			out = append(out, key.RStopped)
		}
		tip := len(w.k.links)
		for _, i := range w.k.nRevoked {
			which := mRevokedMid
			switch i {
			case 0:
				which = mRevokedRoot
			case tip:
				which = mRevokedTip
			}
			if m.on(which) {
				out = append(out, key.RRevoked)
			}
		}
		if len(w.k.nPaused) > 0 && m.on(mPaused) {
			out = append(out, key.RPaused)
		}
	}
	for _, c := range w.k.all() {
		if c.Kind == key.KExpires && m.on(mExpired) && w.now >= c.N+m.slack(mExpiryEdge) {
			out = append(out, key.RExpired)
		}
	}
	return out
}

// recent reports whether a use at at counts in the day before now, under the
// window rule and the edge rule of one cap kind.
func (m mutant) recent(at, now int64, window, edge mutant) bool {
	return !m.on(window) || at > now-mDay-m.slack(edge)
}

// caps returns the refusal codes of every cap a charge under step s breaks.
// spendOnly keeps the spend caps alone.
func (m mutant) caps(w mWorld, s key.Step, spendOnly bool) []string {
	var out []string
	for i, l := range w.k.links {
		for _, c := range l.cavs {
			if !isCap(c.Kind) || (spendOnly && !isSpend(c.Kind) && m.on(mSpendRate)) {
				continue
			}
			if w.noLedger {
				if m.on(mNoLedger) {
					return []string{key.RMalformed}
				}
				return nil
			}
			var sum, n int64
			for _, u := range w.uses {
				if u.scope != scopeOf(i) && m.on(mCapScope) {
					continue
				}
				at := u.use.At
				switch c.Kind {
				case key.KSpendTask:
					if u.use.Task == s.Task || !m.on(mSpendTaskMatch) {
						sum += u.use.Amount
					}
				case key.KSpendDay:
					if m.recent(at, w.now, mSpendDayWindow, mSpendDayWindowEdge) {
						sum += u.use.Amount
					}
				case key.KRateDay:
					if m.recent(at, w.now, mRateDayWindow, mRateDayWindowEdge) {
						n++
					}
				case key.KRateRecipient:
					if m.recent(at, w.now, mRateRecipientWindow, mRateRecipientWindowEdge) &&
						(u.use.Recipient == s.Recipient || !m.on(mRateRecipientMatch)) {
						n++
					}
				case key.KUses:
					if m.on(mUsesAllTime) || at > w.now-mDay {
						n++
					}
				}
			}
			var broken bool
			switch c.Kind {
			case key.KSpendTask:
				broken = m.on(mSpendTask) && sum+s.Amount > c.N+m.slack(mSpendTaskEdge)
			case key.KSpendDay:
				broken = m.on(mSpendDay) && sum+s.Amount > c.N+m.slack(mSpendDayEdge)
			case key.KRateDay:
				broken = m.on(mRateDay) && n+1 > c.N+m.slack(mRateDayEdge)
			case key.KRateRecipient:
				broken = m.on(mRateRecipient) && n+1 > c.N+m.slack(mRateRecipientEdge)
			case key.KUses:
				broken = m.on(mUses) && n+1 > c.N+m.slack(mUsesEdge)
			}
			if broken {
				out = append(out, capCode[c.Kind])
			}
		}
	}
	return out
}

// authorize returns every refusal code the step earns; none admits it.
func (m mutant) authorize(w mWorld) []string {
	out := m.live(w)
	if w.noView && m.on(mNoView) {
		return out
	}
	s, k := w.step, w.k
	if s.Clerk != k.clerk && m.on(mClerk) {
		out = append(out, key.RClerk)
	}
	if !slices.Contains(k.verbs, string(s.Verb)) && m.on(mStepVerbRoot) {
		out = append(out, key.RVerb)
	}
	want := mVerbs[string(s.Verb)]
	if len(s.Args) != len(want) && m.on(mArgCount) {
		out = append(out, key.RArg)
	}
	for _, n := range want {
		a, ok := s.Args[n]
		if (!ok && m.on(mArgMissing)) || (ok && a.Value == "" && m.on(mArgEmpty)) {
			out = append(out, key.RArg)
		}
	}
	for _, c := range k.all() {
		switch c.Kind {
		case key.KVerbs:
			if !slices.Contains(c.Set, string(s.Verb)) && m.on(mStepVerbCaveat) {
				out = append(out, key.RVerb)
			}
		case key.KContent:
			if !slices.Contains(c.Set, s.Content) && m.on(mContent) {
				out = append(out, key.RContent)
			}
		case key.KLabels:
			ls := s.Labels
			if !m.on(mLabelsAll) {
				ls = ls[:min(1, len(ls))]
			}
			if !within(ls, c.Set) && m.on(mLabels) {
				out = append(out, key.RLabels)
			}
		case key.KArg:
			b := argOf(c)
			a, ok := s.Args[b.Name]
			switch {
			case !ok:
				if m.on(mArgPresent) {
					out = append(out, key.RArg)
				}
				continue
			case a.Source == key.SrcPlanner:
				if m.on(mArgPlanner) {
					out = append(out, key.RArg)
					continue
				}
			case a.Source != key.SrcOwner && a.Source != key.SrcClerk:
				if m.on(mArgSource) {
					out = append(out, key.RArg)
					continue
				}
			}
			if b.OneOf != nil && !slices.Contains(b.OneOf, a.Value) && m.on(mArgOneOf) {
				out = append(out, key.RArg)
			}
			if b.Min != nil || b.Max != nil {
				n, err := strconv.ParseInt(a.Value, 10, 64)
				switch {
				case err != nil:
					if m.on(mArgParse) {
						out = append(out, key.RArg)
					}
				case b.Min != nil && n < *b.Min-m.slack(mArgMinEdge) && m.on(mArgMin),
					b.Max != nil && n > *b.Max+m.slack(mArgMaxEdge) && m.on(mArgMax):
					out = append(out, key.RArg)
				}
			}
		}
	}
	if s.Amount < 0 && m.on(mAmountNeg) {
		return append(out, key.RMalformed)
	}
	return append(out, m.caps(w, s, false)...)
}

// spend returns every refusal code a metered call earns; none admits it.
func (m mutant) spend(w mWorld) []string {
	out := m.live(w)
	if w.noView && m.on(mNoView) {
		return out
	}
	if w.spendAmt < 0 && m.on(mSpendAmountNeg) {
		return append(out, key.RMalformed)
	}
	if !slices.ContainsFunc(w.k.all(), func(c key.Caveat) bool { return isSpend(c.Kind) }) && m.on(mSpendCapped) {
		return append(out, key.RMalformed)
	}
	return append(out, m.caps(w, key.Step{Task: w.spendFor, Amount: w.spendAmt}, true)...)
}

// outcome is what one world shows, from the library or from a model.
type outcome struct {
	chain        bool
	chainErr     error
	d            derived
	auth, spendc []string // the model's codes, or the library's one code
}

func (m mutant) run(w mWorld) outcome {
	if !m.chainOK(w.k) {
		return outcome{}
	}
	return outcome{chain: true, d: m.derive(w.k), auth: m.authorize(w), spendc: m.spend(w)}
}

// --- the generator -------------------------------------------------------

// bits reads choices from a fuzz input; past its end every choice is 0.
type bits struct {
	b []byte
	i int
	// A clean world has only well-formed parts, signed as they should be,
	// and caveats that mostly fit the step, so chains verify and a step
	// often breaks one rule alone. Other worlds are drawn freely.
	clean bool
	args  []string // the step's declared arguments, which arg caveats mostly bound
	verbs []string // the root's verbs, which verbs caveats mostly narrow
	step  key.Step // the step's verb, content and labels, drawn first
}

// fit is a caveat set drawn from pool, in a clean world canonical and often
// holding want.
func (r *bits) fit(pool, want []string) []string {
	if !r.clean {
		return r.subset(pool)
	}
	out := []string{}
	for _, v := range pool {
		if r.chance(128) || (slices.Contains(want, v) && r.n(4) != 0) {
			out = append(out, v)
		}
	}
	return out
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
		if r.chance(160) {
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
	gVerbs = func() []string {
		var vs []string
		for v := range mVerbs {
			vs = append(vs, v)
		}
		sort.Strings(vs)
		return vs
	}()
	gContent = []string{"a", "b", "c"}
	gKinds   = []string{key.KVerbs, key.KArg, key.KArg, key.KContent, key.KLabels, key.KSpendTask, key.KSpendDay,
		key.KRateDay, key.KRateRecipient, key.KRateRecipient, key.KExpires, key.KUses, key.KHold, key.KHold, key.KTask, "bogus"}
	gTimes = []int64{-5, 0, 49, 50, 99, 100, 1000, mDay, mDay + 50}
)

func (r *bits) caveat(kind string) key.Caveat {
	c := key.Caveat{Kind: kind}
	switch kind {
	case key.KVerbs:
		c.Set = r.fit(r.verbs, []string{string(r.step.Verb)})
		if !r.clean && r.n(8) == 0 {
			c.Set = r.subset(append(slices.Clone(gVerbs), "bogus"))
		}
	case key.KContent:
		c.Set = r.fit(gContent, []string{r.step.Content})
	case key.KLabels:
		c.Set = r.fit(gContent, r.step.Labels)
	case key.KArg:
		if !r.clean && r.n(16) == 0 {
			return c
		}
		a := key.ArgBound{Name: r.pick([]string{"to", "amount", "zz", ""})}
		if len(r.args) > 0 && r.n(8) != 0 {
			a.Name = r.pick(r.args)
		}
		if r.chance(128) {
			a.OneOf = r.fit([]string{"1", "5", "x"}, nil)
		}
		a.Min, a.Max = r.bound(0, 1, 5), r.bound(1, 5, 10)
		if r.clean && a.Min != nil && a.Max != nil && *a.Min > *a.Max {
			a.Min, a.Max = a.Max, a.Min
		}
		c.Arg = &a
	case key.KExpires:
		c.N = r.i64(gTimes...)
	case key.KHold:
		c.N, c.M = r.i64(-1, 0, 10, 20), r.i64(0, 10, 30)
		if r.clean {
			c.N = max(c.N, 0)
			c.M = c.N + r.i64(0, 10)
		}
	case key.KTask:
		c.Set = [][]string{{"t1"}, {"t2"}, {"t1"}, {}, {""}, {"t1", "t2"}, nil}[r.n(7)]
		if r.clean {
			c.Set = []string{"t1"}
		}
	default:
		c.N = r.i64(-1, 0, 1, 2, 3, 10, 100)
		if r.clean {
			c.N = r.i64(0, 1, 2, 2, 3, 3, 10, 100)
		}
	}
	return c
}

// nudge is a copy of e moved one step: tighter, equal or looser. Most later
// caveats are nudges of an earlier one, so the narrowing rules are exercised
// on chains that otherwise verify.
func (r *bits) nudge(e key.Caveat) key.Caveat {
	c := e
	d := r.i64(-1, 0, 0, 1) // -1 tighter, 1 looser
	if r.clean && d > 0 && r.n(4) != 0 {
		d = 0
	}
	switch e.Kind {
	case key.KVerbs, key.KContent, key.KLabels:
		pool := gContent
		if e.Kind == key.KVerbs {
			pool = r.verbs
			if r.n(4) == 0 {
				pool = gVerbs // perhaps wider than the root
			}
		}
		c.Set = slices.Clone(e.Set)
		if c.Set == nil {
			c.Set = []string{}
		}
		switch {
		case d < 0 && len(c.Set) > 0:
			i := r.n(len(c.Set))
			c.Set = append(c.Set[:i], c.Set[i+1:]...)
		case d > 0 && len(pool) > 0:
			if v := r.pick(pool); !slices.Contains(c.Set, v) {
				c.Set = append(c.Set, v)
				sort.Strings(c.Set)
			}
		}
	case key.KArg:
		if e.Arg == nil {
			return c
		}
		a := *e.Arg
		move := func(p *int64, dir int64) *int64 {
			if r.n(8) == 0 {
				return nil
			}
			if p == nil {
				v := r.i64(0, 1, 5, 10)
				return &v
			}
			v := *p + dir
			return &v
		}
		switch r.n(3) {
		case 0:
			a.Min = move(a.Min, -d) // a higher min is tighter
		case 1:
			a.Max = move(a.Max, d)
		default:
			if r.n(8) == 0 {
				a.OneOf = nil
			} else if a.OneOf != nil {
				a.OneOf = slices.Clone(a.OneOf)
				if d < 0 && len(a.OneOf) > 0 {
					i := r.n(len(a.OneOf))
					a.OneOf = append(a.OneOf[:i], a.OneOf[i+1:]...)
				} else if d > 0 && !slices.Contains(a.OneOf, "7") {
					a.OneOf = append(a.OneOf, "7")
					sort.Strings(a.OneOf)
				}
			}
		}
		c.Arg = &a
	case key.KHold:
		if r.n(2) == 0 {
			c.N -= d
		} else {
			c.M -= d
		}
	case key.KTask:
		if d > 0 {
			c.Set = []string{"t2"}
		}
	default: // an expiry or a cap: a larger N is looser
		c.N += d
	}
	return c
}

// fitStep moves s to meet the chain's content, label and argument
// caveats, with each bounded argument at a bound or one past it, so what
// decides the step is the rest: the caps, the expiry and the log's view.
func (r *bits) fitStep(k *mKey, s *key.Step) {
	content, labels := []string{"a", "b", "c", "d", ""}, slices.Clone(s.Labels)
	bounds := map[string][]key.ArgBound{}
	for _, c := range k.all() {
		switch c.Kind {
		case key.KContent:
			content = slices.DeleteFunc(content, func(v string) bool { return !slices.Contains(c.Set, v) })
		case key.KLabels:
			labels = slices.DeleteFunc(labels, func(v string) bool { return !slices.Contains(c.Set, v) })
		case key.KArg:
			a := argOf(c)
			bounds[a.Name] = append(bounds[a.Name], a)
		}
	}
	if len(content) > 0 {
		s.Content = r.pick(content)
	}
	s.Labels = labels
	for _, n := range mVerbs[string(s.Verb)] {
		var lo, hi *int64
		vals, set := []string{"1", "5", "7", "x"}, false
		for _, b := range bounds[n] {
			if b.OneOf != nil {
				set = true
				vals = slices.DeleteFunc(vals, func(v string) bool { return !slices.Contains(b.OneOf, v) })
			}
			if b.Min != nil && (lo == nil || *b.Min > *lo) {
				lo = b.Min
			}
			if b.Max != nil && (hi == nil || *b.Max < *hi) {
				hi = b.Max
			}
		}
		var edge []string
		for _, b := range []*int64{lo, hi} {
			if b != nil {
				edge = append(edge, strconv.FormatInt(*b, 10), strconv.FormatInt(*b, 10), strconv.FormatInt(*b-1, 10), strconv.FormatInt(*b+1, 10))
			}
		}
		if len(edge) > 0 && (!set || r.n(2) == 0) && r.n(8) != 0 {
			vals = edge
		}
		if len(vals) > 0 {
			s.Args[n] = key.Arg{Value: r.pick(vals), Source: []key.Source{key.SrcOwner, key.SrcClerk, key.SrcOwner, key.SrcClerk, key.SrcPlanner, ""}[r.n(6)]}
		}
	}
	if r.n(4) != 0 {
		delete(s.Args, "zz")
	}
}

// flaw makes c malformed in one of the ways its kind can be, so a clean
// chain fails on that alone.
func (r *bits) flaw(c key.Caveat) key.Caveat {
	switch c.Kind {
	case key.KVerbs, key.KContent, key.KLabels:
		if len(c.Set) > 0 && r.n(2) == 0 {
			c.Set = append(slices.Clone(c.Set), c.Set[0])
		} else {
			c.Set = nil
		}
	case key.KArg:
		if c.Arg == nil {
			return c
		}
		a := *c.Arg
		switch r.n(5) {
		case 0:
			c.Arg = nil
			return c
		case 4:
			a.OneOf = []string{"x", "x"}
		case 1:
			a.Name = ""
		case 2:
			a.OneOf = []string{"5", "1"}
		default:
			lo, hi := int64(5), int64(1)
			a.Min, a.Max = &lo, &hi
		}
		c.Arg = &a
	case key.KHold:
		if r.n(2) == 0 {
			c.N = -1
		} else {
			c.M = c.N - 1
		}
	case key.KTask:
		c.Set = [][]string{{}, {""}, {"t1", "t2"}}[r.n(3)]
	case key.KExpires:
		c.Kind = "bogus"
	default:
		c.N = -1
	}
	return c
}

func (r *bits) world() mWorld {
	var w mWorld
	k := &w.k
	r.clean = r.n(2) == 0
	k.issuer = pAnchor
	switch r.n(16) {
	case 0:
		k.issuer = pStranger
	case 1:
		k.issuer = pPhone
	}
	k.rootBad = r.n(32) == 0
	k.clerk = []string{"mail", "mail", "mail", "bank", ""}[r.n(5)]
	if r.clean {
		k.issuer, k.rootBad, k.clerk = []int{pAnchor, pPhone}[r.n(2)], false, "mail"
	}
	if r.clean || r.n(32) != 0 {
		for _, v := range append(slices.Clone(gVerbs), "bogus") {
			if r.chance(128) && (v != "bogus" || (!r.clean && r.n(8) == 0)) {
				k.verbs = append(k.verbs, v)
			}
		}
	}
	verb := r.pick(append(slices.Clone(gVerbs), "bogus"))
	if len(k.verbs) > 0 && r.n(8) != 0 {
		verb = r.pick(k.verbs)
	}
	if r.clean && !slices.Contains(k.verbs, verb) && r.n(4) != 0 {
		if verb = r.pick(gVerbs); !slices.Contains(k.verbs, verb) {
			k.verbs = append(k.verbs, verb)
		}
	}
	slices.Sort(k.verbs)
	r.verbs = k.verbs
	r.args = mVerbs[verb]
	r.step = key.Step{Verb: key.Verb(verb), Content: r.pick([]string{"a", "b", "d", ""})}
	for _, v := range []string{"a", "b", "c", "d"} {
		if r.chance(128) {
			r.step.Labels = append(r.step.Labels, v)
		}
	}
	holder := -1
	var prior []key.Caveat
	for range r.n(5) {
		l := mLink{holder: r.n(nParties)}
		switch {
		case !r.clean && r.n(8) == 0:
			l.signer = r.n(nParties)
		case holder < 0:
			l.signer = []int{pAnchor, pPhone}[r.n(2)]
		case r.n(6) == 0: // a passkey narrows for the holder (Narrow)
			l.signer, l.holder = pPhone, holder
		default:
			l.signer = holder
		}
		if holder < 0 && (r.clean || r.n(4) != 0) {
			exp, spend := r.i64(50, 100, 1000, mDay+100, mDay+100), r.i64(0, 3, 10, 100, 1000)
			if r.clean && r.n(2) == 0 {
				exp, spend = mDay+100, r.i64(10, 100, 1000)
			}
			l.cavs = append(l.cavs, key.LimitExpires(exp), key.LimitSpendDay(spend))
			prior = append(prior, l.cavs...)
		}
		for range r.n(4) {
			kinds := gKinds
			if r.clean {
				kinds = kinds[:len(kinds)-1] // no unknown kind
			}
			c := r.caveat(kinds[r.n(len(kinds))])
			if len(prior) > 0 && r.chance(150) {
				// The first link's expiry and spend cap are most of
				// prior; nudge them no more often than any other.
				e := prior[r.n(len(prior))]
				if e.Kind == key.KExpires || e.Kind == key.KSpendDay {
					e = prior[r.n(len(prior))]
				}
				c = r.nudge(e)
			}
			l.cavs = append(l.cavs, c)
			prior = append(prior, c)
		}
		k.links = append(k.links, l)
		holder = l.holder
	}
	if r.clean && len(k.links) > 0 && r.n(4) == 0 {
		l := &k.links[r.n(len(k.links))]
		if len(l.cavs) > 0 {
			l.cavs = slices.Clone(l.cavs)
			i := r.n(len(l.cavs))
			l.cavs[i] = r.flaw(l.cavs[i])
		}
	}
	k.useBy = holder
	if holder < 0 {
		k.useBy = pAnchor
	}
	if !r.clean && r.n(8) == 0 {
		k.useBy = r.n(nParties)
	}

	s := key.Step{Verb: key.Verb(verb), Clerk: k.clerk, Args: map[string]key.Arg{}, Content: r.step.Content, Labels: r.step.Labels}
	if r.n(8) == 0 {
		s.Clerk = r.pick([]string{"mail", "bank"})
	}
	for _, n := range mVerbs[string(s.Verb)] {
		if r.n(16) == 0 {
			continue
		}
		// Values sit at each bound on the name, and one either side of it.
		vals := []string{"1", "5", "x", "7", "10", ""}
		if r.clean {
			vals = vals[:len(vals)-1]
		}
		for _, c := range k.all() {
			if a := argOf(c); c.Kind == key.KArg && a.Name == n {
				for _, b := range []*int64{a.Min, a.Max} {
					if b != nil {
						vals = append(vals, strconv.FormatInt(*b-1, 10), strconv.FormatInt(*b, 10), strconv.FormatInt(*b+1, 10))
					}
				}
				vals = append(vals, a.OneOf...)
			}
		}
		src := []key.Source{key.SrcOwner, key.SrcClerk, key.SrcClerk, key.SrcPlanner, ""}[r.n(5)]
		if r.clean && r.n(4) != 0 {
			src = key.SrcClerk
		}
		s.Args[n] = key.Arg{Value: r.pick(vals), Source: src}
	}
	if r.n(10) == 0 {
		s.Args["zz"] = key.Arg{Value: "1", Source: key.SrcOwner}
	}
	s.Amount = r.i64(-1, 0, 1, 3, 50)
	if r.clean {
		s.Amount = r.i64(0, 0, 1, 3)
	}
	s.Recipient = r.pick([]string{"r1", "r2"})
	s.Task = r.pick([]string{"t1", "t2"})
	if r.clean && r.n(4) != 0 {
		r.fitStep(k, &s)
	}
	w.step = s

	w.now = r.i64(gTimes...)
	w.noView = !r.clean && r.n(32) == 0
	w.stopped = r.n(32) == 0
	w.noLedger = r.n(32) == 0
	odds := 24
	if r.clean {
		odds = 64
	}
	for i := 0; i <= len(k.links); i++ {
		if r.n(odds) == 0 {
			k.nRevoked = append(k.nRevoked, i)
		}
		if r.n(odds) == 0 {
			k.nPaused = append(k.nPaused, i)
		}
	}
	w.spendFor, w.spendAmt = r.pick([]string{"t1", "t2"}), r.i64(-1, 0, 1, 3, 50)

	// A use's age is often at a window's edge, and its recipient and task
	// often the step's.
	age := func() int64 { return r.i64(0, 0, 1, mDay-1, mDay, mDay, mDay+1) }
	use := func(scope string, amount int64) mUse {
		u := key.Use{At: w.now - age(), Amount: amount, Recipient: s.Recipient, Task: s.Task}
		if r.n(3) == 0 {
			u.Recipient = "r9"
		}
		if r.n(3) == 0 {
			u.Task = "t9"
		}
		return mUse{scope: scope, use: u}
	}
	scopes := []string{"acct", "acct", "L1", "L2", "L3", "id0", "id1"}
	for range r.n(4) {
		w.uses = append(w.uses, use(r.pick(scopes), r.i64(0, 1, 3, 50)))
	}
	// Then uses sized to each cap: a count one short of, at or one over
	// it, or one use that brings the spend to the cap give or take one.
	for i, l := range k.links {
		for _, c := range l.cavs {
			if !isCap(c.Kind) || r.n(3) == 0 {
				continue
			}
			if isSpend(c.Kind) {
				w.uses = append(w.uses, use(scopeOf(i), max(0, c.N-s.Amount+r.i64(-1, 0, 1))))
				continue
			}
			for range min(c.N+r.i64(-1, 0, 0, 1), 12) {
				w.uses = append(w.uses, use(scopeOf(i), 0))
			}
		}
	}
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

func code(r *key.Refusal) []string {
	if r == nil {
		return nil
	}
	return []string{r.Code}
}

// library runs the key library on one world.
func library(w mWorld) outcome {
	k := build(w)
	use := []byte("ref-use")
	owners := []ed25519.PublicKey{pub(pAnchor), pub(pPhone)}
	v, err := key.Verify(k, owners, use, key.Sign(k, parties[w.k.useBy], use))
	if err != nil {
		return outcome{chainErr: err}
	}
	o := outcome{chain: true, d: derived{
		verbs: v.Limits.Verbs, notAfter: v.Limits.NotAfter, hold: v.Limits.Window(false), novel: v.Limits.Window(true),
		task: v.Limits.Task, byOwner: v.ByOwner,
	}}

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
	o.auth = code(v.Authorize(w.step, c))
	o.spendc = code(v.Spend(w.spendFor, w.spendAmt, c))
	return o
}

// disagree compares the library's outcome with a model's and describes the
// first disagreement, or returns "".
func disagree(lib, mod outcome) string {
	if lib.chain != mod.chain {
		return fmt.Sprintf("chain: model ok=%v, library err=%v", mod.chain, lib.chainErr)
	}
	if !lib.chain {
		return ""
	}
	l, d := lib.d, mod.d
	if !slices.Equal(l.verbs, d.verbs) && !(len(l.verbs) == 0 && len(d.verbs) == 0) {
		return fmt.Sprintf("verbs: model %v, library %v", d.verbs, l.verbs)
	}
	if (d.notAfter == nil) != (l.notAfter == nil) || (d.notAfter != nil && *d.notAfter != *l.notAfter) {
		return fmt.Sprintf("expiry: model %v, library %v", d.notAfter, l.notAfter)
	}
	if l.hold != d.hold || l.novel != d.novel {
		return fmt.Sprintf("hold: model %d/%d, library %d/%d", d.hold, d.novel, l.hold, l.novel)
	}
	if l.task != d.task || l.byOwner != d.byOwner {
		return fmt.Sprintf("task/by-owner: model %q/%v, library %q/%v", d.task, d.byOwner, l.task, l.byOwner)
	}
	if s := agree("authorize", mod.auth, lib.auth); s != "" {
		return s
	}
	return agree("spend", mod.spendc, lib.spendc)
}

// agree compares the model's refusal codes with the library's one: both
// admit, or the library refuses for a reason the model also finds.
func agree(what string, model, lib []string) string {
	switch {
	case len(lib) == 0 && len(model) == 0:
		return ""
	case len(lib) == 0:
		return fmt.Sprintf("%s: model refuses %v, library admits", what, model)
	case !slices.Contains(model, lib[0]):
		return fmt.Sprintf("%s: model %v, library refuses %v", what, model, lib[0])
	}
	return ""
}

// refSeeds is how many seeded worlds the plain test runs.
const refSeeds = 20000

func input(seed int) []byte {
	b := make([]byte, 1024)
	rand.New(rand.NewSource(int64(seed))).Read(b)
	return b
}

func seeded(i int) mWorld { return (&bits{b: input(i)}).world() }

// Reach floors: how often, in refSeeds, each caveat kind repeats within a
// chain that verifies, and each refusal code is a step's only one.
const (
	repeatFloor = 20
	soleFloor   = 10
)

var allCodes = []string{key.RMalformed, key.RStopped, key.RRevoked, key.RPaused, key.RExpired, key.RClerk,
	key.RVerb, key.RArg, key.RContent, key.RLabels, key.RSpendTask, key.RSpendDay, key.RRate, key.RUses}

// TestRefModelAgrees fuzzes the library against the model over fixed seeds,
// so every kernel change runs it with the race shards (EVL-1). It also
// proves its own reach: every planted bug must disagree with the library on
// some seed, every caveat kind must repeat in verified chains and every
// refusal code must be some step's only one, so a rule the seeds stop
// reaching fails here rather than passing unseen.
func TestRefModelAgrees(t *testing.T) {
	found := make([]bool, nMutants)
	repeats, sole := map[string]int{}, map[string]int{}
	// The library's side is the signatures, nearly all the cost, so it runs
	// on every core; the model's side runs in seed order.
	worlds, libs := make([]mWorld, refSeeds), make([]outcome, refSeeds)
	var wg sync.WaitGroup
	for p := range runtime.GOMAXPROCS(0) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := p; i < refSeeds; i += runtime.GOMAXPROCS(0) {
				worlds[i] = seeded(i)
				libs[i] = library(worlds[i])
			}
		}()
	}
	wg.Wait()
	var admitted, verified int
	for i := range refSeeds {
		w, lib := worlds[i], libs[i]
		mod := faithful.run(w)
		if s := disagree(lib, mod); s != "" {
			t.Fatalf("seed %d: %s\nworld: %+v", i, s, w)
		}
		for m := faithful + 1; m < nMutants; m++ {
			found[m] = found[m] || disagree(lib, m.run(w)) != "" // once found, not run again
		}
		if !mod.chain {
			continue
		}
		verified++
		if len(mod.auth) == 0 {
			admitted++
		}
		seen := map[string]int{}
		for _, c := range w.k.all() {
			kind := c.Kind
			if kind == key.KArg {
				kind += ":" + argOf(c).Name
			}
			if seen[kind]++; seen[kind] == 2 {
				repeats[c.Kind]++
			}
		}
		for _, codes := range [][]string{mod.auth, mod.spendc} {
			if len(codes) > 0 && !slices.ContainsFunc(codes, func(c string) bool { return c != codes[0] }) {
				sole[codes[0]]++
			}
		}
	}
	// A generator that never builds a valid chain or an admitted step
	// would agree vacuously.
	if verified < refSeeds/10 || admitted < refSeeds/100 {
		t.Errorf("coverage too thin: %d chains verified, %d steps admitted of %d", verified, admitted, refSeeds)
	}
	for m := faithful + 1; m < nMutants; m++ {
		if !found[m] {
			t.Errorf("planted bug %d not found in %d seeds", m, refSeeds)
		}
	}
	for _, kind := range gKinds[:len(gKinds)-1] {
		if repeats[kind] < repeatFloor {
			t.Errorf("caveat kind %s repeats in %d verified chains, want %d", kind, repeats[kind], repeatFloor)
		}
	}
	for _, c := range allCodes {
		if sole[c] < soleFloor {
			t.Errorf("refusal %s is the only one on %d seeds, want %d", c, sole[c], soleFloor)
		}
	}
}

// FuzzRefModel is the open-ended run of the same check.
func FuzzRefModel(f *testing.F) {
	for i := range 64 {
		f.Add(input(i))
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		w := (&bits{b: b}).world()
		if s := disagree(library(w), faithful.run(w)); s != "" {
			t.Fatalf("%s\nworld: %+v", s, w)
		}
	})
}
