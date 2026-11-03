package key

import (
	"math/rand"
	"testing"
)

// REQ: KEY-9

// ch3 restates CH-3's table row by row, apart from the code's floor, so a
// floor lowered in worth.go fails here (D-307: CH-3 stays the floor and the
// audit cases).
var ch3 = []struct {
	row  string
	act  Action
	need Proof
}{
	{"STOP", ActStop, ProofNumber},
	{"task chat, STATUS: number + session unlocked by an approval code", ActTaskChat, ProofSession},
	{"approve low-risk irreversible: texted code", ActApproveLow, ProofText},
	{"approve high-risk irreversible: approval code on the owner page", ActApproveHigh, ProofPage},
	{"unlock on an unknown host: passphrase + approval code on the page", ActUnlockHost, ProofPage},
	{"new key, raise budget, adopt a release, add a trusted host: passkey signing", ActNewKey, ProofPasskey},
	{"recovery: the recovery key", ActRecovery, ProofRecovery},
	{"computer-use retry back on: approval code on the owner page", ActRetryOn, ProofPage},
	{"connect devices, capture, widen bounds or audience, tier-4 device keys", ActDeviceWide, ProofPasskey},
	{"connect a verified read-only device: approval code on the page", ActDeviceRead, ProofPage},
	{"key actuate or present, no safety or access role: texted code", ActDeviceLow, ProofText},
	{"key actuate-physical, or a safety or access device: code on the page", ActDeviceSafety, ProofPage},
	{"unsafe direction or out of bounds: code on the page per action", ActUnsafe, ProofPage},
	{"start reverse engineering: local confirmation on the local page", ActReverseEngineer, ProofPage},
	{"write firmware: change-account key (tier 4), then a code per write", ActWriteFirmware, ProofPasskey},
}

// limitsFor are limits from none to every cap the worth table reads.
func limitsFor() []Limits {
	lo, hi := int64(0), int64(10)
	all, err := Fold([]Caveat{LimitSpendDay(100), LimitSpendTask(50), LimitRate(5), LimitUses(3),
		LimitArg(ArgBound{Name: "value", Min: &lo, Max: &hi})})
	if err != nil {
		panic(err)
	}
	money, _ := Fold([]Caveat{LimitSpendDay(100)})
	return []Limits{{}, money, all}
}

// reaches is every set of asset classes, the unknown class included.
func reaches() [][]Asset {
	var out [][]Asset
	for m := 0; m < 1<<(nAssets+1); m++ {
		var r []Asset
		for a := Asset(0); a <= nAssets; a++ {
			if m&(1<<a) != 0 {
				r = append(r, a)
			}
		}
		out = append(out, r)
	}
	return out
}

// Every CH-3 row is a case: whatever the key reaches and however it is
// capped, the price is at least the row's proof.
func TestKEY9_CH3IsTheFloor(t *testing.T) {
	if len(ch3) != int(nActions) {
		t.Fatalf("%d CH-3 cases for %d actions: every row is a case", len(ch3), nActions)
	}
	for _, c := range ch3 {
		for _, r := range reaches() {
			for _, l := range limitsFor() {
				if p := PriceOf(c.act, r, l); p.Proof < c.need {
					t.Errorf("%s: reach %v priced at %d, below CH-3's %d", c.row, r, p.Proof, c.need)
				}
			}
		}
		if p := PriceOf(c.act, nil, Limits{}); p.Proof != c.need {
			t.Errorf("%s: a key reaching nothing asks %d, CH-3 asks %d", c.row, p.Proof, c.need)
		}
	}
	if p := PriceOf(nActions, nil, Limits{}); p.Proof != ProofRecovery {
		t.Errorf("an action outside CH-3 asks %d, want the most", p.Proof)
	}
}

// The ladder only climbs: a dearer worth never asks a cheaper proof or a
// shorter hold, and a cap never raises a class's worth.
func TestKEY9_TableIsMonotone(t *testing.T) {
	for w := 1; w < len(proofOf); w++ {
		if proofOf[w] < proofOf[w-1] || holdOf[w] < holdOf[w-1] {
			t.Errorf("worth %d asks less than worth %d", w, w-1)
		}
	}
	if len(proofOf) != int(WorthTop)+1 || len(holdOf) != len(proofOf) {
		t.Fatal("every worth has a proof and a hold")
	}
	for a := Asset(0); a < nAssets; a++ {
		if worthOf[a][1] > worthOf[a][0] {
			t.Errorf("asset %d: capped worth %d above uncapped %d", a, worthOf[a][1], worthOf[a][0])
		}
	}
	// A widening of standing money or safety power with no cap needs a
	// second passkey; a key over identity needs the passkey at least.
	for _, a := range []Asset{AssetMoney, AssetSafety} {
		if p := PriceOf(ActNewKey, []Asset{a}, Limits{}); p.Proof != ProofCosign || p.Hold != DayMS {
			t.Errorf("uncapped asset %d priced %+v", a, p)
		}
	}
	if p := PriceOf(ActApproveLow, []Asset{AssetIdentity}, Limits{}); p.Proof != ProofPasskey {
		t.Errorf("identity reach priced %+v, want the passkey", p)
	}
}

// Adding a class to the reach never lowers the worth, and a class the table
// does not know prices at the top.
func TestKEY9_GrowingReachNeverLowersWorth(t *testing.T) {
	rng := rand.New(rand.NewSource(9))
	ls := limitsFor()
	for i := 0; i < 2000; i++ {
		l := ls[rng.Intn(len(ls))]
		var r []Asset
		w := WorthOf(r, l)
		for j := 0; j < 6; j++ {
			r = append(r, Asset(rng.Intn(int(nAssets)+3)))
			nw := WorthOf(r, l)
			if nw < w {
				t.Fatalf("reach %v under %+v: worth fell %d to %d", r, l, w, nw)
			}
			w = nw
		}
	}
	for _, a := range []Asset{nAssets, nAssets + 1, 255} {
		if w := WorthOf([]Asset{a}, Limits{}); w != WorthTop {
			t.Errorf("unknown class %d is worth %d, want the top", a, w)
		}
	}
}

// Narrowing a key never raises its worth: each caveat a link may add leaves
// every class's worth where it was or lower (KEY-3).
func TestKEY9_NarrowingNeverRaisesWorth(t *testing.T) {
	rng := rand.New(rand.NewSource(3))
	gen := func() Caveat {
		n := int64(rng.Intn(1000) + 1)
		lo, hi := int64(rng.Intn(5)), int64(5+rng.Intn(5))
		switch rng.Intn(8) {
		case 0:
			return LimitSpendDay(n)
		case 1:
			return LimitSpendTask(n)
		case 2:
			return LimitRate(n)
		case 3:
			return LimitRateRecipient(n)
		case 4:
			return LimitUses(n)
		case 5:
			return LimitArg(ArgBound{Name: "value", Min: &lo, Max: &hi})
		case 6:
			return LimitArg(ArgBound{Name: "value", OneOf: []string{"off", "on"}[:1+rng.Intn(2)]})
		}
		return LimitLabels("work")
	}
	for i := 0; i < 2000; i++ {
		var l Limits
		r := []Asset{Asset(rng.Intn(int(nAssets)))}
		w := WorthOf(r, l)
		for j := 0; j < 6; j++ {
			if l.apply(gen(), ID{byte(j)}) != nil {
				continue // a loosening link is refused (KEY-3)
			}
			nw := WorthOf(r, l)
			if nw > w {
				t.Fatalf("reach %v: a caveat raised worth %d to %d (%+v)", r, w, nw, l)
			}
			w = nw
		}
	}
}
