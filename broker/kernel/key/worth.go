package key

// KEY-9 (D-307): a key's worth is the highest asset class in its reach after
// its caps, ranked by the fixed table below, and the proof that grants or
// widens it costs more to fake than that worth, never less than CH-3 asks.
// The tables are Go literals compiled into the signed kernel (KRN-3): a data
// file would put a parser in the trusted core for no gain.

// Asset is an asset class a key can reach through the graph (CLK-10). Its
// names are the graph's classes.
type Asset uint8

const (
	AssetNone Asset = iota
	AssetData
	AssetIdentity
	AssetMoney
	AssetSafety
	nAssets
)

// Worth is a key's rank in the worth table.
type Worth uint8

const (
	WorthNone Worth = iota
	WorthLow
	WorthMid
	WorthHigh
	WorthTop
)

// Proof is a rung of CH-3's ladder, ordered by what it costs to fake: a SIM
// swap yields the first two, the code generator the next, the owner page at
// home the one after, then the passkey, two passkeys one an anchor (D-146),
// and the recovery key (REC-3).
type Proof uint8

const (
	ProofNumber   Proof = iota // a message from the owner's number
	ProofText                  // the texted code of that request, replied from the number
	ProofSession               // a session unlocked by a code-generator code (CH-14, CH-19)
	ProofPage                  // a code-generator code, or local confirmation, on the owner page
	ProofPasskey               // approval code + local confirmation, the passkey signing (KEY-4)
	ProofCosign                // a second passkey co-signs, one of the two an anchor (D-146)
	ProofRecovery              // the recovery key, through the longest hold (REC-3)
)

// worthOf is the fixed table: [asset][capped]. An uncapped key is worth at
// least as much as a capped one of the same class.
var worthOf = [nAssets][2]Worth{
	AssetNone:     {WorthNone, WorthNone},
	AssetData:     {WorthMid, WorthLow},
	AssetIdentity: {WorthHigh, WorthHigh},
	AssetMoney:    {WorthTop, WorthMid},
	AssetSafety:   {WorthTop, WorthHigh},
}

// proofOf is the proof each worth needs, and holdOf how much it lengthens
// the novelty window of an irreversible step under the key (KEY-8). The base
// window is untouched, so a step the owner accepted before may still wait
// nothing (D-307, law 3).
var (
	proofOf = [...]Proof{ProofNumber, ProofText, ProofPage, ProofPasskey, ProofCosign}
	holdOf  = [...]int64{0, 0, 0, DayMS / 24, DayMS}
)

// Capped reports whether l caps what a key can do to class a: a spend cap for
// money, a count cap for data, a bound on the value for safety. Identity has
// no cap: one change to an account takes it. Caveats only add caps, so
// narrowing never uncaps (KEY-3).
func Capped(l Limits, a Asset) bool {
	has := func(kinds ...string) bool {
		for _, c := range l.Caps {
			for _, k := range kinds {
				if c.Kind == k {
					return true
				}
			}
		}
		return false
	}
	switch a {
	case AssetMoney:
		return has(KSpendDay, KSpendTask)
	case AssetData:
		return has(KRateDay, KRateRecipient, KUses)
	case AssetSafety:
		b, ok := l.Args["value"]
		return ok && (b.OneOf != nil || b.Min != nil && b.Max != nil)
	}
	return false
}

// WorthOf is the highest worth in reach under l. A class outside the table
// is worth the most, so what cannot be classed is never under-priced.
func WorthOf(reach []Asset, l Limits) Worth {
	w := WorthNone
	for _, a := range reach {
		x := WorthTop
		if a < nAssets {
			c := 0
			if Capped(l, a) {
				c = 1
			}
			x = worthOf[a][c]
		}
		w = max(w, x)
	}
	return w
}

// Action is one row of CH-3's table.
type Action uint8

const (
	ActStop            Action = iota // STOP
	ActTaskChat                      // task chat, STATUS
	ActApproveLow                    // approve a low-risk irreversible effect (CH-10)
	ActApproveHigh                   // approve a high-risk irreversible effect (CH-10)
	ActUnlockHost                    // unlock on an unknown host (STO-2)
	ActNewKey                        // new key, raise budget, adopt a release, add a trusted host
	ActRecovery                      // recovery (REC-3)
	ActRetryOn                       // turn the computer-use retry back on (CLK-5)
	ActDeviceWide                    // connect devices, capture, widen bounds or audience, tier-4 device keys
	ActDeviceRead                    // connect a verified read-only device (DEV-10)
	ActDeviceLow                     // key actuate or present on a device with no safety or access role
	ActDeviceSafety                  // key actuate-physical, or a safety or access device
	ActUnsafe                        // a physical action in the unsafe direction or out of bounds (DEV-5)
	ActReverseEngineer               // start a reverse-engineering task (DEV-12)
	ActWriteFirmware                 // write firmware or software to a device (DEV-12)
	nActions
)

// floor is CH-3's proof for each row: the least any price may ask (D-307).
// A row whose proof has two parts takes the dearer.
var floor = [nActions]Proof{
	ActStop:            ProofNumber,
	ActTaskChat:        ProofSession,
	ActApproveLow:      ProofText,
	ActApproveHigh:     ProofPage,
	ActUnlockHost:      ProofPage,
	ActNewKey:          ProofPasskey,
	ActRecovery:        ProofRecovery,
	ActRetryOn:         ProofPage,
	ActDeviceWide:      ProofPasskey,
	ActDeviceRead:      ProofPage,
	ActDeviceLow:       ProofText,
	ActDeviceSafety:    ProofPage,
	ActUnsafe:          ProofPage,
	ActReverseEngineer: ProofPage,
	ActWriteFirmware:   ProofPasskey,
}

// Price is what an authority change costs: the proof it needs and how much it
// lengthens the novelty window (KEY-8, KEY-9).
type Price struct {
	Worth Worth
	Proof Proof
	Hold  int64
}

// PriceOf prices act for a key reaching reach under l: the dearer of CH-3's
// row and the worth table's proof. An action outside CH-3 asks the most.
func PriceOf(act Action, reach []Asset, l Limits) Price {
	w := WorthOf(reach, l)
	p := ProofRecovery
	if act < nActions {
		p = max(floor[act], proofOf[w])
	}
	return Price{Worth: w, Proof: p, Hold: holdOf[w]}
}
