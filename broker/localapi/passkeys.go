package localapi

// Passkey ops (#2779a; KEY-4, ID-1, REC-3): the owner page lists the
// owner's passkeys, enrols a phone passkey under a hardware key's tap, and
// cuts a phone passkey off. agentosd serves them only when it runs with
// -passkey-rp-id (localsrv Config.Passkeys); without it they are not
// registered at all. Each needs a session. The page sends only what a
// WebAuthn ceremony returned and a listed key's ID; agentosd builds the
// enrollment, and the kernel decides it.
const (
	// OpPasskeys (Auth) answers a PasskeyList.
	OpPasskeys = "page_passkeys"
	// OpPasskeyBegin (PasskeyBegin) takes the new credential's P-256 point
	// from the page's create() and answers a PasskeyBegun: the challenge a
	// hardware key signs to enrol it. The point is kept for the session
	// that sent it for PasskeyPending; a new begin replaces it.
	OpPasskeyBegin = "page_passkey_begin"
	// OpPasskeyFinish (PasskeyFinish) takes the hardware key's get()
	// assertion over that challenge and answers Text{} once the kernel
	// has enrolled the point.
	OpPasskeyFinish = "page_passkey_finish"
	// OpPasskeyCutOff (PasskeyCutOff) takes a hardware key's get()
	// assertion over a listed phone passkey's CutChallenge, cuts it off for
	// good and answers Text{}; a hardware key is ErrPasskeyAnchor (#3209).
	OpPasskeyCutOff = "page_passkey_cut_off"
)

// PasskeyOps lists the passkey ops, for the disjointness test.
var PasskeyOps = []string{OpPasskeys, OpPasskeyBegin, OpPasskeyFinish, OpPasskeyCutOff}

// The passkey ops' fixed refusals, beside ErrUnauthorized, ErrBadArgs and
// ErrLimited. No kernel text reaches the page: every other failure is
// ErrPasskeyUnavailable.
const (
	// ErrPasskeyAnchor: the key is one of the owner's hardware keys, which
	// only recovery replaces (REC-3).
	ErrPasskeyAnchor = "passkey anchor"
	// ErrPasskeyNotAnchor: the tap was a phone passkey's, and only a
	// hardware key enrols or cuts off another.
	ErrPasskeyNotAnchor = "passkey not anchor"
	// ErrPasskeyBadAssertion: no listed key made that tap over this
	// enrolment's or cut-off's challenge.
	ErrPasskeyBadAssertion = "passkey bad assertion"
	// ErrPasskeyRefused: the kernel refused what passed agentosd's checks.
	ErrPasskeyRefused = "passkey refused"
	// ErrPasskeyStale: no begin waits for this session, or it lapsed.
	ErrPasskeyStale = "passkey stale"
	// ErrPasskeySetup: the kernel is waiting for setup.
	ErrPasskeySetup = "passkey setup"
	// ErrPasskeyUnavailable: the kernel could not be reached, or answered
	// something else.
	ErrPasskeyUnavailable = "passkey unavailable"
)

// PasskeyCodes is the closed set the passkey ops refuse with past the
// session and argument checks.
var PasskeyCodes = []string{ErrPasskeyAnchor, ErrPasskeyNotAnchor, ErrPasskeyBadAssertion, ErrPasskeyRefused,
	ErrPasskeyStale, ErrPasskeySetup, ErrPasskeyUnavailable}

// Bounds on the passkey frames.
const (
	// PasskeyPoint is an uncompressed P-256 point, 0x04 ‖ X ‖ Y.
	PasskeyPoint = 65
	// MaxPasskeyAssertion bounds each part of an assertion. A get()'s
	// authenticator data is 37 bytes without extensions, its client data
	// about 200 bytes (browsers add a hint field of about 100), and an
	// ECDSA DER signature at most 72; 2 KiB leaves room for extension
	// data and longer client data while keeping a frame a few KiB.
	MaxPasskeyAssertion = 2 << 10
	// PasskeyIDLen is a listed key's ID: SHA-256, lowercase hex.
	PasskeyIDLen = 64
	// PasskeyChallenge is the challenge's length, a SHA-256.
	PasskeyChallenge = 32
)

// Passkey is one key as the page lists it: kernel-derived fields only.
type Passkey struct {
	// ID names the key to OpPasskeyCutOff: the SHA-256 of its encoding.
	ID string `json:"id"`
	// Fingerprint is a short form of ID to show.
	Fingerprint string `json:"fingerprint"`
	// Alg is "es256" or "ed25519".
	Alg string `json:"alg"`
	// By is the enrolling hardware key's Fingerprint; "" for a hardware key.
	By string `json:"by,omitempty"`
	// CutChallenge is the challenge a hardware key signs to cut a live
	// phone passkey off; absent for the others.
	CutChallenge []byte `json:"cut_challenge,omitempty"`
}

// PasskeyList is the owner's keys as the kernel's log has them: the
// hardware keys setup logged, the phone passkeys enrolled and still live,
// and those cut off.
type PasskeyList struct {
	Anchors  []Passkey `json:"anchors"`
	Enrolled []Passkey `json:"enrolled"`
	CutOff   []Passkey `json:"cut_off"`
}

// PasskeyBegin carries the new credential's point.
type PasskeyBegin struct {
	Token string `json:"token"`
	Point []byte `json:"point"`
}

// PasskeyBegun is the challenge for the hardware key's get().
type PasskeyBegun struct {
	Challenge []byte `json:"challenge"`
}

// PasskeyFinish carries the hardware key's get() assertion as the browser
// returned it.
type PasskeyFinish struct {
	Token             string `json:"token"`
	AuthenticatorData []byte `json:"authenticator_data"`
	ClientDataJSON    []byte `json:"client_data_json"`
	Signature         []byte `json:"signature"`
}

// PasskeyCutOff names a listed key by its ID, with the hardware key's
// get() assertion over its CutChallenge as the browser returned it.
type PasskeyCutOff struct {
	Token             string `json:"token"`
	ID                string `json:"id"`
	AuthenticatorData []byte `json:"authenticator_data,omitempty"`
	ClientDataJSON    []byte `json:"client_data_json,omitempty"`
	Signature         []byte `json:"signature,omitempty"`
}
