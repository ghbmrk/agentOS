package localapi

import (
	"regexp"
	"time"
)

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
	// OpSetupLine answers whether setup can text and the box's own number
	// (P2-2w c4c; §8.1, CH-12): Ready while the modem bridge reports the
	// line usable, Number when the bridge knows it.
	OpSetupLine = "page_setup_line"
	// OpSetupSend has the box text one of setup's fixed texts (SetupText)
	// to a number, and answers once the bridge reports it sent, or
	// ErrNotSent. It is answered within SetupSendTimeout.
	OpSetupSend = "page_setup_send"
	// OpSetupInbound waits up to SetupInboundWait for a text that reached
	// the box and starts with PAIR, and answers it, or nothing. Each text
	// is answered once; the page offers it to setup (§8.1 pairing).
	OpSetupInbound = "page_setup_inbound"
)

// SetupOps lists setup's ops, for the disjointness test.
var SetupOps = []string{OpSetupProgress, OpSetupEnroll, OpSetupConfirm, OpSetupFinish, OpSetupJoin,
	OpSetupLine, OpSetupSend, OpSetupInbound}

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
	// ErrNotSent: the text did not go: no usable line, the bridge
	// reported a failure, or no result came in time.
	ErrNotSent = "not sent"
)

// Setup's text waits. agentosd's own wait for the bridge ends sooner
// than the page's call (Security L8.4: each caller waits longer than the
// one it calls); an inbound wait ends before the socket's idle timeout.
const (
	SetupSendWait    = 40 * time.Second
	SetupSendTimeout = SetupSendWait + 5*time.Second
	SetupInboundWait = 20 * time.Second
)

// SetupTextsPerHour caps the texts setup sends in an hour, whoever asks:
// the page is not trusted to bound what the box's SIM spends.
const SetupTextsPerHour = 20

// setupTexts are the only texts setup sends (localui's number step,
// claim and PAIR replies), so the page cannot have the box's SIM send
// anything else. The product name's case is matched either way.
var setupTexts = regexp.MustCompile(`^(?:` +
	`[Aa]gentOS setup code: [0-9]{6}\. Type it on the setup page\.` +
	`|[Aa]gentOS page code: [0-9]{6}\. Type it on the setup page\.` +
	`|[Aa]gentOS is running on this PC\. This is your box's number; save it as [Aa]gentOS\.(?: Page code: [0-9]{6}\.)?` +
	`|That pairing code did not match\. Check the setup page\.` +
	`|Could not save your number\. Try again\.` +
	`)$`)

// SetupText says text is one of setup's fixed texts.
func SetupText(text string) bool { return setupTexts.MatchString(text) }

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

// Finish carries the owner's number, E.164.
type Finish struct {
	Owner string `json:"owner"`
}

// SetupLine is whether setup can text, and the box's own number, E.164
// ("" when the bridge does not know it).
type SetupLine struct {
	Ready  bool   `json:"ready"`
	Number string `json:"number,omitempty"`
}

// SetupSend is one fixed text (SetupText) to a number, E.164.
type SetupSend struct {
	To   string `json:"to"`
	Text string `json:"text"`
}

// SetupInbound is a PAIR text that reached the box: From is E.164, both
// empty when none came in the wait.
type SetupInbound struct {
	From string `json:"from,omitempty"`
	Text string `json:"text,omitempty"`
}

// String and GoString keep numbers and texts out of logs.
func (SetupSend) String() string      { return "[setup text]" }
func (SetupSend) GoString() string    { return "[setup text]" }
func (SetupInbound) String() string   { return "[setup inbound text]" }
func (SetupInbound) GoString() string { return "[setup inbound text]" }
