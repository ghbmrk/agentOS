package localapi

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
	// OpSetupConfirm checks one code from the newest seed; a match seals
	// enrollment.
	OpSetupConfirm = "page_setup_confirm"
	// OpSetupFinish records the owner's number and closes setup for good.
	OpSetupFinish = "page_setup_finish"
)

// SetupOps lists setup's ops, for the disjointness test.
var SetupOps = []string{OpSetupProgress, OpSetupEnroll, OpSetupConfirm, OpSetupFinish}

// Setup's fixed refusals, beside ErrBadArgs, ErrLimited and ErrFailed.
const (
	// ErrSetupClosed: setup's finish is recorded, or its record cannot be
	// read; nothing reopens it but recovery.
	ErrSetupClosed = "setup closed"
	// ErrEnrolled: the vault holds a sealed code-generator seed (or never
	// opened setup's enrollment), so setup shows none.
	ErrEnrolled = "enrolled"
	// ErrNoEnrollment: no seed waits for confirmation; show a new link.
	ErrNoEnrollment = "no enrollment"
	// ErrNotEnrolled: Finish before any enrollment was confirmed.
	ErrNotEnrolled = "not enrolled"
)

// MaxEnrollLink bounds an enrollment link (otpauth URI) in bytes.
const MaxEnrollLink = 512

// SetupProgress is the box's boot progress as setup shows it (ONB-4).
type SetupProgress struct {
	// Phase is "booting", "updating" or "ready".
	Phase   string `json:"phase"`
	Updated bool   `json:"updated"`
	Online  bool   `json:"online"`
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

// Finish carries the owner's number, E.164.
type Finish struct {
	Owner string `json:"owner"`
}
