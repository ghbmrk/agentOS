package localapi

// Erase ops (LOG-4, KRN-forget c, #3414, D-284): the owner page's Forget
// step. The owner types a name, agentosd looks it up and answers the
// readback (counts and kinds, never content) with a one-time handle and
// the challenge a passkey signs over exactly that list; a tap by one of
// the owner's passkeys (a hardware key or an enrolled phone passkey)
// erases exactly the list shown. agentosd serves them only with
// -passkey-rp-id, as the passkey ops, since the tap is a WebAuthn ceremony
// on the page's name. Each needs a session; the texts are agentosd's,
// which the page shows unchanged.
const (
	// OpEraseFind (EraseFind) answers an EraseFound.
	OpEraseFind = "page_erase_find"
	// OpEraseConfirm (EraseConfirm) erases what the handle's find showed,
	// on a passkey's get() assertion over its challenge, and answers
	// Text{} with the result.
	OpEraseConfirm = "page_erase_confirm"
)

// EraseOps lists the erase ops, for the disjointness test.
var EraseOps = []string{OpEraseFind, OpEraseConfirm}

// The erase ops' fixed refusals, beside ErrUnauthorized, ErrBadArgs and
// ErrLimited. No kernel text reaches the page: every other failure is
// ErrEraseUnavailable, and nothing is erased on any refusal.
const (
	// ErrEraseBadAssertion: no passkey of the owner's made that tap over
	// this list's challenge.
	ErrEraseBadAssertion = "erase bad assertion"
	// ErrEraseStale: the find expired, was confirmed already, or never
	// was.
	ErrEraseStale = "erase stale"
	// ErrEraseUnavailable: the kernel could not be reached, or answered
	// something else.
	ErrEraseUnavailable = "erase unavailable"
)

// EraseCodes is the closed set the erase ops refuse with past the session
// and argument checks.
var EraseCodes = []string{ErrEraseBadAssertion, ErrEraseStale, ErrEraseUnavailable}

const (
	// MaxEraseName bounds the name looked up (the kernel's label bound).
	MaxEraseName = 256
	// EraseHandle is a find's handle length: 16 random bytes in hex.
	EraseHandle = 32
)

// EraseFind carries the name to look up.
type EraseFind struct {
	Token string `json:"token"`
	Name  string `json:"name"`
}

// EraseFound is a find's readback. With nothing to confirm (nothing
// found, or stored content closed), Handle and Challenge are empty.
type EraseFound struct {
	Text      string `json:"text"`
	Handle    string `json:"handle,omitempty"`
	Challenge []byte `json:"challenge,omitempty"`
}

// EraseConfirm carries a find's handle and a passkey's get() assertion
// over its challenge, as the browser returned it.
type EraseConfirm struct {
	Token             string `json:"token"`
	Handle            string `json:"handle"`
	AuthenticatorData []byte `json:"authenticator_data"`
	ClientDataJSON    []byte `json:"client_data_json"`
	Signature         []byte `json:"signature"`
}
