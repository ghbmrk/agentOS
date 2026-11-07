package key

import (
	"math"
	"math/rand"
	"slices"
	"sort"
	"testing"
)

// REQ: KEY-9

// ch3 is CH-3's table, typed here from SPEC.md by hand and not read from
// the table in worth.go, so a table edit that lowers a row fails against the spec's own
// words (D-307: CH-3 stays the floor and the audit cases).
var ch3 = []struct {
	act   Act
	proof Proof
}{
	{ActStop, P0},
	{ActChat, P0},
	{ActApproveLow, P1},
	{ActApproveHigh, P3},
	{ActUnlock, P3},
	{ActGrant, P3Local},
	{ActRecovery, PRecovery},
	{ActRetryOn, P3},
	{ActDeviceConnect, P3Local},
	{ActDeviceReadOnly, P3},
	{ActDeviceKeyLow, P1},
	{ActDeviceKeySafety, P3},
	{ActPhysicalUnsafe, P3},
	{ActReverseEngineer, P3Local},
	{ActFirmwareWrite, P3},
}

func TestEveryCH3RowIsPricedAtLeastItsProof(t *testing.T) {
	if len(ch3) != int(acts) {
		t.Fatalf("the table prices %d acts, CH-3 has %d rows", acts, len(ch3))
	}
	for i, row := range ch3 {
		if row.act != Act(i) {
			t.Fatalf("row %d is act %d", i, row.act)
		}
		// At the lowest worth an act costs exactly its row: the table
		// starts at CH-3 and only raises it.
		if got := Price(row.act, 0); got != row.proof {
			t.Errorf("act %d at worth 0: %d, CH-3 says %d", row.act, got, row.proof)
		}
		for r := Rank(0); r <= MaxRank; r++ {
			if got := Price(row.act, r); got < row.proof {
				t.Errorf("act %d at worth %d: %d, below CH-3's %d", row.act, r, got, row.proof)
			}
		}
	}
}

func TestPricesFromReach(t *testing.T) {
	owner, holder := gen(1), gen(2)
	mk := func(capped bool, vs ...Verb) Key {
		sort.Slice(vs, func(i, j int) bool { return vs[i] < vs[j] })
		r := Issue(owner.pass, Root{Clerk: "c", Verbs: vs, Serial: "r"})
		if !capped {
			return r
		}
		k, err := ClerkKey(r, owner.pass, holder.pub, 0, 100)
		if err != nil {
			t.Fatal(err)
		}
		return k
	}
	for _, c := range []struct {
		name  string
		k     Key
		rank  Rank
		grant Proof
		appr  Proof
	}{
		{"organize only", mk(true, Organize, Draft), 0, P3Local, P1},
		{"a mailbox", mk(true, Read, Send), 1, P3Local, P1},
		{"capped spend", mk(true, Buy), 2, P3Local, P1},
		{"uncapped spend", mk(false, Buy), 3, P4, P3},
		{"account change", mk(true, ChangeAccount), 3, P4, P3},
		{"a secret", mk(true, RevealOrCreateSecret), 3, P4, P3},
		{"a lock", mk(true, ActuatePhysical), 3, P4, P3},
	} {
		r, err := Worth(c.k)
		if err != nil || r != c.rank {
			t.Errorf("%s: worth %d %v, want %d", c.name, r, err, c.rank)
		}
		if p := Price(ActGrant, r); p != c.grant {
			t.Errorf("%s: grant %d, want %d", c.name, p, c.grant)
		}
		if p := Price(ActApproveLow, r); p != c.appr {
			t.Errorf("%s: approve-low %d, want %d", c.name, p, c.appr)
		}
	}
	if HoldExtra(0) != 0 || HoldExtra(MaxRank) < HoldExtra(0) || HoldExtra(MaxRank+1) != HoldExtra(MaxRank) {
		t.Fatal("hold extra")
	}
}

func TestUnknownPricesHighest(t *testing.T) {
	if WorthOf(AssetsOf("teleport"), true) != MaxRank {
		t.Error("an unknown verb is not priced as reaching every class")
	}
	if WorthOf([]Asset{Asset(99)}, true) != MaxRank {
		t.Error("an unknown class is not priced highest")
	}
	if Price(acts, 0) != PRecovery || Price(ActStop, MaxRank+1) != PRecovery {
		t.Error("an unknown act or rank is not priced at the top rung")
	}
	if r, err := Worth(Key{}); err == nil || r != MaxRank {
		t.Error("a malformed key is not priced highest")
	}
}

// Generated keys: adding a verb never lowers worth, and narrowing (fewer
// verbs, a spend cap) never raises it; price never falls as worth rises.
func TestWorthIsMonotone(t *testing.T) {
	all := make([]Verb, 0, len(classes))
	for v := range classes {
		all = append(all, v)
	}
	sort.Slice(all, func(i, j int) bool { return all[i] < all[j] })
	worth := func(vs []Verb, capped bool) Rank {
		var reach []Asset
		for _, v := range vs {
			reach = append(reach, AssetsOf(v)...)
		}
		return WorthOf(reach, capped)
	}
	rng := rand.New(rand.NewSource(9))
	for i := 0; i < 5000; i++ {
		var vs []Verb
		for _, v := range all {
			if rng.Intn(3) == 0 {
				vs = append(vs, v)
			}
		}
		capped := rng.Intn(2) == 0
		w := worth(vs, capped)
		grown := append(slices.Clone(vs), all[rng.Intn(len(all))])
		if worth(grown, capped) < w {
			t.Fatalf("adding a verb to %v lowered its worth", vs)
		}
		if worth(vs, true) > worth(vs, false) {
			t.Fatalf("a cap raised %v's worth", vs)
		}
		if len(vs) > 0 && worth(vs[:rng.Intn(len(vs))], capped) > w {
			t.Fatalf("dropping verbs from %v raised its worth", vs)
		}
	}
	for a := Act(0); a < acts; a++ {
		for r := Rank(1); r <= MaxRank; r++ {
			if Price(a, r) < Price(a, r-1) || HoldExtra(r) < HoldExtra(r-1) {
				t.Fatalf("act %d falls at worth %d", a, r)
			}
		}
	}
}

// A real narrowing through the library: a derived key never prices above
// the key it came from.
func TestDeriveNeverRaisesWorth(t *testing.T) {
	owner, holder, next := gen(1), gen(2), gen(3)
	r := Issue(owner.pass, Root{Clerk: "c", Verbs: []Verb{Buy, Read, Send}, Serial: "r"})
	k, err := ClerkKey(r, owner.pass, holder.pub, 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	d, err := Derive(k, holder.priv, next.pub, LimitVerbs(Read))
	if err != nil {
		t.Fatal(err)
	}
	wr, _ := Worth(r)
	wk, _ := Worth(k)
	wd, _ := Worth(d)
	if !(wr >= wk && wk >= wd) || wr != 3 || wk != 2 || wd != 1 {
		t.Fatalf("root %d, capped %d, read-only %d", wr, wk, wd)
	}
}

// The table's own rules (KRN-3): every verb on the closed list has a reach,
// a higher class never ranks lower, a cap never raises a rank, and no column
// falls as worth rises.
func TestTableHoldsItsRules(t *testing.T) {
	for v := range classes {
		if _, ok := reaches[v]; !ok {
			t.Errorf("verb %q has no reach", v)
		}
	}
	if len(reaches) != len(classes) {
		t.Error("a reach names a verb off the list")
	}
	for a := Asset(0); a < assets; a++ {
		if ranks[a][0] > ranks[a][1] || ranks[a][1] > MaxRank {
			t.Errorf("class %d: a cap raises it, or it is past the table", a)
		}
		if a > 0 && (ranks[a][0] < ranks[a-1][0] || ranks[a][1] < ranks[a-1][1]) {
			t.Errorf("class %d ranks below class %d", a, a-1)
		}
	}
	for r := Rank(1); r <= MaxRank; r++ {
		if widen[r] < widen[r-1] || approve[r] < approve[r-1] || holdExtra[r] < holdExtra[r-1] {
			t.Errorf("a column falls at worth %d", r)
		}
	}
	// KRN-4's high-risk verbs, uncapped, are worth the most; share reaches only
	// data, and its approval is high risk by CH-10's act, not its worth.
	for v, c := range classes {
		if c == IrreversibleHigh && v != Share && WorthOf(AssetsOf(v), false) != MaxRank {
			t.Errorf("%s is high risk but worth %d", v, WorthOf(AssetsOf(v), false))
		}
	}
}

// Every verb's reach and worth, typed by hand from CLK-14's effect classes
// (KEY-9-reach-a-1), so a table edit that lowers one fails here. A device is
// safety only by a declaration (Mark, 2026-11-07, #4999), so `actuate` and
// `present` stay low and only `actuate-physical` is safety.
func TestEveryVerbsReachIsPinned(t *testing.T) {
	d, m, id, s := AssetData, AssetMoney, AssetIdentity, AssetSafety
	want := map[Verb]struct {
		reach            []Asset
		capped, uncapped Rank
	}{
		Read: {[]Asset{d}, 1, 1}, Fetch: {[]Asset{d}, 1, 1}, Draft: {[]Asset{AssetNone}, 0, 0},
		Organize: {[]Asset{AssetNone}, 0, 0}, Trash: {[]Asset{d}, 1, 1}, Present: {[]Asset{d}, 1, 1},
		Unsubscribe: {[]Asset{d}, 1, 1}, Send: {[]Asset{d}, 1, 1}, Post: {[]Asset{d}, 1, 1},
		Actuate: {[]Asset{AssetNone}, 0, 0}, Buy: {[]Asset{m}, 2, 3}, Share: {[]Asset{d}, 1, 1},
		DeleteRemote: {[]Asset{d, id}, 3, 3}, ChangeAccount: {[]Asset{id, d, m}, 3, 3},
		RevealOrCreateSecret: {[]Asset{id, d}, 3, 3}, ActuatePhysical: {[]Asset{s}, 3, 3},
	}
	if len(want) != len(classes) {
		t.Fatalf("pinned %d verbs, the list has %d", len(want), len(classes))
	}
	for v, w := range want {
		got := AssetsOf(v)
		if !slices.Equal(got, w.reach) {
			t.Errorf("%s reaches %v, want %v", v, got, w.reach)
		}
		if c, u := WorthOf(got, true), WorthOf(got, false); c != w.capped || u != w.uncapped {
			t.Errorf("%s worth %d capped, %d uncapped; want %d, %d", v, c, u, w.capped, w.uncapped)
		}
	}
}

// The hold lengthens with worth (KEY-9): pinned per rank, and strictly
// longer at the top than at the bottom.
func TestHoldGrowsWithWorth(t *testing.T) {
	want := [MaxRank + 1]int64{0, 0, 3600_000, 4 * 3600_000}
	for r := Rank(0); r <= MaxRank; r++ {
		if HoldExtra(r) != want[r] {
			t.Errorf("worth %d: hold extra %d, want %d", r, HoldExtra(r), want[r])
		}
	}
	if HoldExtra(MaxRank) <= HoldExtra(0) {
		t.Fatal("the hold does not lengthen with worth")
	}
}

// Only a spend cap counts as capped: a rate cap bounds no money. A class just
// past the table ranks highest rather than indexing past it.
func TestCappedMeansSpendCap(t *testing.T) {
	for _, c := range []struct {
		kind string
		want bool
	}{{KSpendDay, true}, {KSpendTask, true}, {KRateDay, false}, {KRateRecipient, false}, {KUses, false}} {
		if got := (Limits{Caps: []Cap{{Kind: c.kind, N: 1}}}).Capped(); got != c.want {
			t.Errorf("%s: capped %v, want %v", c.kind, got, c.want)
		}
	}
	if (Limits{}).Capped() {
		t.Error("no caps is capped")
	}
	if WorthOf([]Asset{assets}, true) != MaxRank {
		t.Error("the class just past the table is not priced highest")
	}
}

// Each step's hold is priced by what that step's own verb reaches at its
// key's caps, not by the key's highest verb (Mark, 2026-11-07, #4999): under
// one capped key a read waits the key's window, a buy an hour more and an
// account change four. A bare root's step is the owner's own tap and gains
// none; a window near MaxInt64 saturates rather than wraps.
func TestStepHoldIsPricedByItsOwnVerb(t *testing.T) {
	owner, holder := gen(1), gen(2)
	r := Issue(owner.pass, Root{Clerk: "c", Verbs: []Verb{Read, Buy, ChangeAccount, Actuate, ActuatePhysical}, Serial: "r"})
	const base, novel = int64(60_000), int64(600_000)
	k, err := ClerkKey(r, owner.pass, holder.pub, 0, 100, LimitHold(base, novel))
	if err != nil {
		t.Fatal(err)
	}
	v, err := Chain(k, []PublicKey{owner.pk})
	if err != nil {
		t.Fatal(err)
	}
	for vb, extra := range map[Verb]int64{Read: 0, Actuate: 0, Buy: 3600_000, ChangeAccount: 4 * 3600_000, ActuatePhysical: 4 * 3600_000} {
		if got := v.Window(vb, false); got != base+extra {
			t.Errorf("%s base window %d, want %d", vb, got, base+extra)
		}
		if got := v.Due(vb, 1000, true); got != 1000+novel+extra {
			t.Errorf("%s novel due %d, want %d", vb, got, 1000+novel+extra)
		}
	}
	rv, err := Chain(r, []PublicKey{owner.pk})
	if err != nil {
		t.Fatal(err)
	}
	if w := rv.Window(ChangeAccount, true); w != 0 {
		t.Errorf("a bare root's step waits %d", w)
	}
	huge, err := ClerkKey(r, owner.pass, holder.pub, 0, 100, LimitHold(math.MaxInt64-1, math.MaxInt64-1))
	if err != nil {
		t.Fatal(err)
	}
	hv, err := Chain(huge, []PublicKey{owner.pk})
	if err != nil {
		t.Fatal(err)
	}
	if w, d := hv.Window(ChangeAccount, false), hv.Due(ChangeAccount, 5, false); w != math.MaxInt64 || d != math.MaxInt64 {
		t.Errorf("a window near MaxInt64 wraps: window %d, due %d", w, d)
	}
}

// Only a one-use passkey narrowing is a step approved one by one (Security
// 6706162072): a passkey narrowing of many uses keeps the worth term on
// every step, and one of exactly one use waives it.
func TestOnlyAOneUseApprovalWaivesTheWorthTerm(t *testing.T) {
	owner, holder := gen(1), gen(2)
	r := Issue(owner.pass, Root{Clerk: "c", Verbs: []Verb{ChangeAccount}, Serial: "r"})
	k, err := ClerkKey(r, owner.pass, holder.pub, 0, 100, LimitHold(60_000, 600_000))
	if err != nil {
		t.Fatal(err)
	}
	for uses, want := range map[int64]int64{1000: 60_000 + 4*3600_000, 2: 60_000 + 4*3600_000, 1: 60_000} {
		n, err := Narrow(k, owner.pass, LimitUses(uses))
		if err != nil {
			t.Fatal(err)
		}
		v, err := Chain(n, []PublicKey{owner.pk})
		if err != nil {
			t.Fatal(err)
		}
		if !v.ByOwner {
			t.Fatal("a passkey narrowing is not ByOwner")
		}
		if got := v.Window(ChangeAccount, false); got != want {
			t.Errorf("a %d-use passkey narrowing waits %d, want %d", uses, got, want)
		}
	}
}
