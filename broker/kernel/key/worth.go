package key

// Reach sets the price (KEY-9, D-307). A key's worth is the highest rank of
// the asset classes its verbs reach, after its spend caps, by the fixed table
// below, shipped in the signed image like the verb classes (KRN-3). An owner
// act's price is the larger of its CH-3 row (the floor, never lowered) and
// the table's column for the act at the key's worth. worth_test.go checks the
// table's own rules: no rank, price or hold falls as worth rises.
//
// Reach here is a key's own verbs. The closure over the declarations' edges
// (CLK-10, CLK-14), the wiring into grants and the hold, and
// grows-then-narrows are #4999.

// Proof is a rung of the CH-3 ladder, ordered by what an attacker must hold.
type Proof uint8

const (
	P0        Proof = iota // a text or call claims the owner's number
	P1                     // the texted one-time code (CH-10 low risk)
	P2                     // the owner's handset: a speed-dial token call (CH-5)
	P3                     // the owner page at home: a passkey tap or approval code
	P3Local                // P3 with local confirmation, the passkey signing (KEY-4)
	P4                     // a hardware key's signature (KEY-4, ID-1)
	PRecovery              // the recovery key, through the longest hold (REC-3)
)

// Asset is a class a key can reach (KEY-9), in rising order.
type Asset uint8

const (
	AssetNone Asset = iota
	AssetData
	AssetMoney
	AssetIdentity
	AssetSafety
	assets
)

// Rank is a key's worth.
type Rank uint8

// reaches is what each verb reaches directly (CLK-14's effect classes:
// sends and data readable or destroyable are data, accounts are identity,
// devices are safety until a declaration rules it out).
var reaches = map[Verb][]Asset{
	Read: {AssetData}, Fetch: {AssetData}, Draft: {AssetNone}, Organize: {AssetNone},
	Trash: {AssetData}, Present: {AssetData, AssetSafety}, Unsubscribe: {AssetData},
	Send: {AssetData}, Post: {AssetData}, Actuate: {AssetSafety}, Buy: {AssetMoney},
	Share: {AssetData}, DeleteRemote: {AssetData, AssetIdentity},
	ChangeAccount:        {AssetIdentity, AssetData, AssetMoney},
	RevealOrCreateSecret: {AssetIdentity, AssetData}, ActuatePhysical: {AssetSafety},
}

// ranks is each class's worth, [capped, uncapped]: only a spend cap lowers it.
var ranks = [assets][2]Rank{{0, 0}, {1, 1}, {2, 3}, {3, 3}, {3, 3}}

// MaxRank is the table's highest worth.
const MaxRank Rank = 3

// widen, approve and holdExtra are the columns by rank. holdExtra lengthens
// an irreversible step's KEY-8 hold, in ms.
var (
	widen     = [MaxRank + 1]Proof{P3Local, P3Local, P3Local, P4}
	approve   = [MaxRank + 1]Proof{P1, P1, P1, P3}
	holdExtra = [MaxRank + 1]int64{0, 0, 3600_000, 4 * 3600_000}
)

// Act is an owner act: one row of CH-3's table.
type Act uint8

const (
	ActStop            Act = iota // STOP
	ActChat                       // task chat, STATUS (in a session opened at P3)
	ActApproveLow                 // a low-risk irreversible effect (CH-10)
	ActApproveHigh                // a high-risk irreversible effect (CH-10)
	ActUnlock                     // unlock on an unknown host (STO-2)
	ActGrant                      // new key, raise budget, adopt a release, add a trusted host
	ActRecovery                   // recovery (REC-3)
	ActRetryOn                    // the computer-use retry back on (CLK-5)
	ActDeviceConnect              // connect, capture, widen bounds or audience, re-pin, tier-4 device keys
	ActDeviceReadOnly             // a verified device that needs no secret, read only (DEV-10)
	ActDeviceKeyLow               // actuate or present on a device not marked safety or access
	ActDeviceKeySafety            // actuate-physical, or a device marked safety or access
	ActPhysicalUnsafe             // the unsafe direction, or a value outside bounds (DEV-5)
	ActReverseEngineer            // start a reverse-engineering task (DEV-12)
	ActFirmwareWrite              // write firmware or software, per write (DEV-12)
	acts
)

// floor is CH-3: each act's proof, and the column worth raises it by (nil:
// none, as a narrowing or a session costs the same whatever it reaches).
var floor = [acts]struct {
	proof  Proof
	column *[MaxRank + 1]Proof
}{
	{P0, nil}, {P0, nil}, {P1, &approve}, {P3, &approve}, {P3, nil}, {P3Local, &widen},
	{PRecovery, nil}, {P3, nil}, {P3Local, &widen}, {P3, &approve}, {P1, &approve},
	{P3, &approve}, {P3, &approve}, {P3Local, nil}, {P3, &approve},
}

// AssetsOf is what verb v reaches. An unknown verb reaches every class.
func AssetsOf(v Verb) []Asset {
	if as, ok := reaches[v]; ok {
		return append([]Asset(nil), as...)
	}
	return []Asset{AssetNone, AssetData, AssetMoney, AssetIdentity, AssetSafety}
}

// WorthOf ranks a reach: its highest class's rank, capped or not. A class
// past the table ranks highest.
func WorthOf(reach []Asset, capped bool) Rank {
	col := 1
	if capped {
		col = 0
	}
	var r Rank
	for _, a := range reach {
		if a >= assets {
			return MaxRank
		}
		r = max(r, ranks[a][col])
	}
	return r
}

// Capped reports whether l bounds spend: a daily or per-task cap on some
// link. A bare root has none.
func (l Limits) Capped() bool {
	for _, c := range l.Caps {
		if c.Kind == KSpendDay || c.Kind == KSpendTask {
			return true
		}
	}
	return false
}

// Worth is k's worth from its own verbs and caps; a malformed key is worth
// the most, with its error. It checks no signature.
func Worth(k Key) (Rank, error) {
	v, err := verifyChain(k, nil)
	if err != nil {
		return MaxRank, err
	}
	var reach []Asset
	for _, vb := range v.Limits.Verbs {
		reach = append(reach, AssetsOf(Verb(vb))...)
	}
	return WorthOf(reach, v.Limits.Capped()), nil
}

// Price is the proof act a needs at worth r: the larger of its CH-3 floor
// and its column at r. An act or rank past the table is priced at the top
// rung, so a caller's slip never prices low.
func Price(a Act, r Rank) Proof {
	if a >= acts || r > MaxRank {
		return PRecovery
	}
	f := floor[a]
	if f.column == nil {
		return f.proof
	}
	return max(f.proof, f.column[r])
}

// HoldExtra lengthens an irreversible step's KEY-8 hold at worth r, in ms.
func HoldExtra(r Rank) int64 { return holdExtra[min(r, MaxRank)] }
