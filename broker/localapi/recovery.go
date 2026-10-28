package localapi

// Recovery-key ops (REC-4, BAK-1; MIG-4-recovery-r4a, route A of D-201):
// the Recovery key page replaces the recovery key on the running box. The
// page makes the new card and takes its confirm (agentosd links no card
// code), then sends the new key's 32 bytes (card.StoreRecoveryKey of the
// new card) for a hardware key's challenge, and with the tap the Owner
// Card factor that opens the store. agentosd asks the kernel for the
// approval, hands the factor, the new key and the approval to the
// keeper's root one-shot, and switches the kernel to the new recipient.
// agentosd serves them only with -passkey-rp-id, as the backup ops, since
// the tap is a WebAuthn ceremony on the page's name. Each needs a session.
// The factor and the new key cross only this socket and agentosd's
// memory: no log, no file, and never the kernel, which sees recipient IDs
// and the approval only.
const (
	// OpRecoveryBegin (RecoveryBegin) takes the new key and answers a
	// RecoveryBegun: the challenge a hardware key signs to change the
	// backup recipient Old to Next. Nothing is kept, nothing asked of the
	// kernel but a read.
	OpRecoveryBegin = "page_recovery_begin"
	// OpRecoveryRotate (RecoveryRotate) takes the factor, the same new key
	// and the hardware key's get() assertion over that challenge, and
	// answers a RecoveryDone once the store holds the new key.
	OpRecoveryRotate = "page_recovery_rotate"
)

// RecoveryOps lists the recovery-key ops, for the disjointness test.
var RecoveryOps = []string{OpRecoveryBegin, OpRecoveryRotate}

// The recovery-key ops' fixed refusals, beside ErrUnauthorized, ErrBadArgs
// and ErrLimited. Each changed nothing. No kernel or keeper text reaches
// the page: every other failure is ErrRecoveryUnavailable.
const (
	// ErrRecoveryNotAnchor: the tap was a phone passkey's; only a
	// hardware key replaces the recovery key (a widening).
	ErrRecoveryNotAnchor = "recovery not anchor"
	// ErrRecoveryBadAssertion: no listed key made that tap over this
	// change's challenge.
	ErrRecoveryBadAssertion = "recovery bad assertion"
	// ErrRecoveryFactor: the passphrase or recovery key does not open the
	// store.
	ErrRecoveryFactor = "recovery factor"
	// ErrRecoveryStale: the backup recipient changed since the challenge
	// (another rotation finished), or the approval lapsed; start again.
	ErrRecoveryStale = "recovery stale"
	// ErrRecoveryBusy: another rotation is running.
	ErrRecoveryBusy = "recovery busy"
	// ErrRecoverySetup: the kernel is waiting for setup.
	ErrRecoverySetup = "recovery setup"
	// ErrRecoveryUnavailable: the kernel or the keeper could not be
	// reached, or answered something else.
	ErrRecoveryUnavailable = "recovery unavailable"
)

// RecoveryCodes is the closed set the recovery-key ops refuse with past
// the session and argument checks.
var RecoveryCodes = []string{ErrRecoveryNotAnchor, ErrRecoveryBadAssertion, ErrRecoveryFactor, ErrRecoveryStale,
	ErrRecoveryBusy, ErrRecoverySetup, ErrRecoveryUnavailable}

// Bounds on the recovery-key frames.
const (
	// RecoveryKeyLen is the new key's and a recovery-key factor's length
	// (seal.RecoveryLen, card.StoreKeyLen).
	RecoveryKeyLen = 32
	// MaxRecoveryPassphrase bounds a passphrase factor, in bytes.
	MaxRecoveryPassphrase = 512
	// RecoveryIDLen is a backup recipient ID's length: 16 bytes in
	// lowercase hex (backup.Recipient.ID).
	RecoveryIDLen = 32
)

// The factors that open the store on a running box (seal.Passphrase,
// seal.Recovery): the keeper's one-shot takes these words.
const (
	RecoveryFactorPassphrase = "passphrase"
	RecoveryFactorRecovery   = "recovery"
)

// RecoveryBegin carries the new recovery key.
type RecoveryBegin struct {
	Token string `json:"token"`
	Next  []byte `json:"next"`
}

// RecoveryBegun is the challenge for the hardware key's get(), over
// changing the backup recipient Old ("" when the store holds none) to
// Next, the new key's. The page shows both IDs: the tap binds only them.
type RecoveryBegun struct {
	Old       string `json:"old"`
	Next      string `json:"next"`
	Challenge []byte `json:"challenge"`
}

// RecoveryRotate carries the factor that opens the store (Factor one of
// RecoveryFactorPassphrase, its normalized words, or
// RecoveryFactorRecovery, the current key's RecoveryKeyLen bytes), the new
// key Begin named, and the hardware key's get() assertion as the browser
// returned it.
type RecoveryRotate struct {
	Token             string `json:"token"`
	Factor            string `json:"factor"`
	Secret            []byte `json:"secret"`
	Next              []byte `json:"next"`
	AuthenticatorData []byte `json:"authenticator_data"`
	ClientDataJSON    []byte `json:"client_data_json"`
	Signature         []byte `json:"signature"`
}

// RecoveryDone answers a rotation the store took. Switched is false when
// the kernel had not yet taken the new recipient: agentosd keeps retrying
// it with the same approval, and the kernel's next start reads it from
// the store anyway.
type RecoveryDone struct {
	Switched bool `json:"switched"`
}
