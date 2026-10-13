package localapi

import "time"

// Setup's ops on localui.sock (P2-2w c2; Security L6 on the P2-2w plan;
// ONB-3, ONB-6, CRED-8). agentosd serves them only on a box with no
// owner yet, and only until setup's finish is recorded; from then on it
// refuses every one with ErrSetupClosed, across restarts, and the full
// page ops (Ops) never include them. The code generator's seed is made
// inside the vault process (egress K17): the page asks agentosd for a new
// enrollment link each time it shows the step and never holds a seed.
const (
	// OpSetupProgress is setup's boot progress; an answer at all means
	// setup is still open.
	OpSetupProgress = "page_setup_progress"
	// OpSetupEnroll asks the vault process for a new code-generator seed
	// and answers its otpauth link, once.
	OpSetupEnroll = "page_setup_enroll"
	// OpSetupConfirm checks one code from the newest seed; a match is
	// sealed only by finish, and a new seed voids it.
	OpSetupConfirm = "page_setup_confirm"
	// OpSetupFinish has the vault seal the confirmed seed, records the
	// owner's number and closes setup for good.
	OpSetupFinish = "page_setup_finish"
	// OpSetupJoin has agentosd's netjoin helper write the home Wi-Fi
	// connection (P2-2w c3; Security L8 on the P2-2w plan) and answers
	// once the helper does: success when it joined or saved the network,
	// ErrNotJoined otherwise. It is answered within JoinTimeout.
	OpSetupJoin = "page_setup_join"
	// OpSetupProviders lists the AI providers the vault process serves,
	// whether each holds a key, and the owner's private-data answer
	// (P2-2w c4e; CRED-5, CAP-9).
	OpSetupProviders = "page_setup_providers"
	// OpSetupAPIKey stores one provider API key in the vault. agentosd
	// passes it on and keeps nothing (CRED-1).
	OpSetupAPIKey = "page_setup_api_key"
	// OpSetupPrivateOK records whether a provider may see private data.
	OpSetupPrivateOK = "page_setup_private_ok"
	// OpSetupNetworks lists the home networks in range from agentosd's
	// netjoin helper (P2-2w c4b): no args, Networks out. It answers an
	// empty list when the helper has none or cannot be asked.
	OpSetupNetworks = "page_setup_networks"
	// OpSetupCard reports the page's Owner Card step (HW-1, #1115): the
	// page builds, shows and latches the card (agentosd links no card
	// code, ARC-2), and reports here before finish that the card is
	// confirmed and provisioned. agentosd's setup mode serves it beside
	// SetupOps, and finish answers ErrCardPending until it is reported.
	OpSetupCard = "page_setup_card"
)

// SetupOps lists setup's ops, for the disjointness test.
var SetupOps = []string{OpSetupProgress, OpSetupEnroll, OpSetupConfirm, OpSetupFinish, OpSetupJoin,
	OpSetupProviders, OpSetupAPIKey, OpSetupPrivateOK, OpSetupNetworks}

// Setup's fixed refusals, beside ErrBadArgs, ErrLimited and ErrFailed.
const (
	// ErrSetupClosed: setup's finish is recorded, or its record cannot be
	// read; nothing reopens it but recovery.
	ErrSetupClosed = "setup closed"
	// ErrEnrolled: the vault holds the code-generator seed this setup
	// confirmed, already sealed, so setup shows none and finish accepts it.
	ErrEnrolled = "enrolled"
	// ErrEnrollUnavailable: this box cannot finish setup: its vault never
	// opened setup's enrollment, or holds a seal setup's record has no
	// confirmation for (P2-2w c2 r1). Nothing on the page fixes it.
	ErrEnrollUnavailable = "enrollment unavailable"
	// ErrNoEnrollment: no seed waits for confirmation; show a new link.
	ErrNoEnrollment = "no enrollment"
	// ErrNotEnrolled: Finish with no seed confirmed since the last new
	// one.
	ErrNotEnrolled = "not enrolled"
	// ErrNotJoined: the helper did not join or save the network (wrong
	// password, not in range, busy, refused, or an error), or no helper
	// is configured. The page shows its one network error for all of
	// them (Security L8.4).
	ErrNotJoined = "not joined"
	// ErrCardPending: finish before the page reported the Owner Card
	// confirmed (OpSetupCard).
	ErrCardPending = "card pending"
)

// JoinTimeout bounds one OpSetupJoin call from the page. agentosd's own
// call to the helper ends sooner (Security L8.4: each caller waits longer
// than the one it calls).
const JoinTimeout = 34 * time.Second

// Join's shape bounds: an SSID is 1 to 32 bytes, a password 8 to 64.
// The helper checks the exact rule (Security L8.5); agentosd checks shape
// only (L8.8).
const (
	MaxSSID     = 32
	MinPassword = 8
	MaxPassword = 64
)

// MaxNetworks bounds OpSetupNetworks' list; each name is at most MaxSSID
// bytes.
const MaxNetworks = 20

// MaxEnrollLink bounds an enrollment link (otpauth URI) in bytes.
const MaxEnrollLink = 512

// SetupProgress is the box's boot progress as setup shows it (ONB-4).
type SetupProgress struct {
	// Phase is "booting", "updating", "offline" or "ready".
	Phase   string `json:"phase"`
	Updated bool   `json:"updated"`
	Online  bool   `json:"online"`
	// NeverOnline: the last join was saved (netjoin L8.4) and the box has
	// had no uplink for a while since (P2-2w c4).
	NeverOnline bool `json:"never_online,omitempty"`
}

// EnrollLink is a new seed's otpauth link, shown once.
type EnrollLink struct {
	URI string `json:"uri"`
}

// String keeps the link out of logs.
func (EnrollLink) String() string { return "[code-generator enrollment]" }

// Confirm carries one code from the newest seed.
type Confirm struct {
	Code string `json:"code"`
}

// Confirmed is a confirmation's result: OK false is a wrong code.
type Confirmed struct {
	OK bool `json:"ok"`
}

// Join carries the home network's name and password. The password is
// reusable authentication material (CRED-1): it goes only to the helper.
type Join struct {
	SSID     string `json:"ssid"`
	Password string `json:"password"`
}

// String and GoString keep the password out of logs.
func (Join) String() string   { return "[home Wi-Fi join]" }
func (Join) GoString() string { return "[home Wi-Fi join]" }

// Networks is OpSetupNetworks' answer: home network names, strongest
// first. Names only (CRED-1).
type Networks struct {
	SSIDs []string `json:"ssids"`
}

// SetupCard is the page's report of its Owner Card step: Confirmed once
// the card is confirmed and provisioned. Confirmed false is refused.
type SetupCard struct {
	Confirmed bool `json:"confirmed"`
}

// Finish carries the owner's number, E.164.
type Finish struct {
	Owner string `json:"owner"`
}

// MaxAPIKey bounds a provider API key in bytes; a key is printable ASCII
// with no spaces, as the proxy sends it in a header.
const MaxAPIKey = 512

// APIKeysPerMinute limits OpSetupAPIKey; past it the op answers
// ErrLimited.
const APIKeysPerMinute = 10

// SetupProvider is one AI provider as setup shows it. DeviceCode is false
// until plan sign-in at setup is served (c4e2).
type SetupProvider struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	APIKey     bool   `json:"api_key"`
	DeviceCode bool   `json:"device_code"`
	Connected  bool   `json:"connected"`
	PrivateOK  bool   `json:"private_ok"`
}

// SetupProviders is OpSetupProviders' answer.
type SetupProviders struct {
	Providers []SetupProvider `json:"providers"`
}

// APIKey carries one provider API key to the vault (CRED-5).
type APIKey struct {
	Provider string `json:"provider"`
	Key      string `json:"key"`
}

// String and GoString keep the key out of logs.
func (APIKey) String() string   { return "[provider API key]" }
func (APIKey) GoString() string { return "[provider API key]" }

// PrivateOK carries the owner's private-data answer for one provider.
type PrivateOK struct {
	Provider string `json:"provider"`
	OK       bool   `json:"ok"`
}
