// Package localapi is the local UI's contract with agentosd on
// localui.sock (P2-2w; ARC-2, L15, CH-7, CH-10). The local UI
// (agentos-localui) serves the box's Wi-Fi page under its own uid and is
// always the client. It decodes untrusted input (photos, forms from
// anyone on the access point), so it is treated as compromised: agentosd
// decides every op that carries authority, from its own state (Security
// L1 on the P2-2w plan). A code or grid cell passes through to agentosd,
// which mints an opaque session token on a good sign-in; every op that
// acts or reads the owner's requests presents that token. Only status,
// STOP, the grid cell's challenge and sign-in itself need none.
//
// agentosd links this package and not the local UI, whose QR decoder
// parses untrusted photos (L15). It carries no network client.
package localapi

import (
	"time"

	"github.com/ghbmrk/agentos/broker/owner"
)

// Socket is the local UI's socket file in agentosd's socket directory.
const Socket = "localui.sock"

// Ops on localui.sock. All carry the "page_" prefix, so none can be an
// op of another socket (Security L3).
const (
	OpStatus   = "page_status"    // no token: the box's flags and the owner line's note
	OpStop     = "page_stop"      // no token: STOP is fail-safe (Security L4)
	OpGridCell = "page_grid_cell" // no token: the sign-in challenge
	OpSignIn   = "page_sign_in"   // a code or grid cell: a token
	OpSignOut  = "page_sign_out"
	OpSession  = "page_session" // a token's session: is it live, until when
	OpLines    = "page_lines"   // STATUS's full lines
	OpResume   = "page_resume"
	OpRequests = "page_requests"
	OpAnswer   = "page_answer"
	OpWaiting  = "page_waiting"
	// OpFollowRoot shows what following a root the owner brought would
	// mean; agentosd holds the root under the summary's digest.
	OpFollowRoot = "page_follow_root"
	// OpFollow asks to follow a shown root under the owner's name for it
	// (OSS-10, WF3); the owner then approves it with a code like any
	// tier-4 request.
	OpFollow = "page_follow"
)

// Ops lists every op, for the disjointness test.
var Ops = []string{OpStatus, OpStop, OpGridCell, OpSignIn, OpSignOut, OpSession, OpLines, OpResume, OpRequests, OpAnswer, OpWaiting, OpFollowRoot, OpFollow}

// Fixed refusals, sent as sockets codes.
const (
	ErrUnauthorized = "unauthorized" // no token, or one agentosd did not mint or has revoked
	ErrBadArgs      = "bad args"     // a field missing or past its bound
	ErrLimited      = "limited"      // too many wrong codes on this socket in the last minute
	ErrFailed       = "failed"       // the owner channel could not act
)

// Bounds on string fields (Security L3). Tokens are TokenBytes random
// bytes, hex.
const (
	TokenBytes = 16
	MaxCode    = 64
	MaxID      = 16
	MaxSum     = 128
	// MaxRoot bounds a root brought to follow; MaxFollowName bounds the
	// owner's name for it in bytes (40 characters of up to 4 bytes).
	MaxRoot       = 64 << 10
	MaxFollowName = 160
	// DigestLen is a shown root's digest: SHA-256, lowercase hex.
	DigestLen = 64
)

// Status is the box's state as the page shows it before sign-in: fixed
// flags and fixed wording only, never task text, request contents,
// recipients or counts (Security D1 on the P2-2w plan).
type Status struct {
	Stopped       bool      `json:"stopped"`
	Unlocked      bool      `json:"unlocked"`
	UnlockedUntil time.Time `json:"unlocked_until"`
	LowLocked     bool      `json:"low_locked"`
	Challenged    bool      `json:"challenged"`
	// UnlockDays is how long a sign-in lasts, in days (CH-14's N).
	UnlockDays int `json:"unlock_days"`
	// LineNote is the owner line's note, empty while the line is fine
	// (Potency R2): fixed text, shown on the home page.
	LineNote string `json:"line_note,omitempty"`
}

// SignIn carries a code-generator code or the grid cell's answer.
type SignIn struct {
	Code string `json:"code"`
}

// Session is a sign-in's result: the token, valid until Until unless
// revoked first (sign-out, a session lock).
type Session struct {
	Token string    `json:"token,omitempty"`
	Until time.Time `json:"until"`
	// Refusal, on a refused sign-in: RefusedWrongCode or RefusedTooMany,
	// fixed only. The op is untokened, so what is left of the day's tries
	// is told only on a signed-in page_resume (Security D1, UX-2wb-2).
	Refusal string `json:"refusal,omitempty"`
}

// Auth carries a token.
type Auth struct {
	Token string `json:"token"`
}

// Lines are STATUS's own lines, OP-9 causes included (Potency R3).
type Lines struct {
	Status string `json:"status"`
}

// Resume is RESUME from a signed-in page. Within FreshFor of the
// session's last sign-in it needs no code; after that it takes a
// code-generator code or the asked grid cell, checked as a sign-in
// (Security S2 on step a, UX option B): RESUME undoes STOP, and a token
// may be days old.
type Resume struct {
	Token string `json:"token"`
	Code  string `json:"code,omitempty"`
}

// FreshFor is how long after a sign-in the page may RESUME without a code.
const FreshFor = 15 * time.Minute

// Text is a fixed reply from the owner channel.
type Text struct {
	Text string `json:"text"`
}

// Answer settles one request from the page.
type Answer struct {
	Token   string `json:"token"`
	ID      string `json:"id"`
	Sum     string `json:"sum"`
	Approve bool   `json:"approve"`
	Code    string `json:"code,omitempty"`
}

// Answered is the channel's reply to an Answer or a Resume. Refusal, when set, is
// one of the Refused* values; Text is then the channel's own wording
// (tries left, the texted code's hint), if any.
type Answered struct {
	Text    string `json:"text,omitempty"`
	Refusal string `json:"refusal,omitempty"`
}

// Refusals of an Answer, each an owner channel error.
const (
	RefusedWrongCode  = "wrong code"
	RefusedTooMany    = "too many"
	RefusedNoRequest  = "no request"
	RefusedChanged    = "changed"
	RefusedTextedCode = "texted code"
	RefusedNotSettled = "not settled"
	// RefusedCodeNeeded: a RESUME past FreshFor came without a code.
	RefusedCodeNeeded = "code needed"
)

// Requests are the open requests, as the owner channel lists them.
type Requests struct {
	Requests []owner.LocalRequest `json:"requests"`
}

// FollowRoot is a root the owner brought to follow, exactly as published.
type FollowRoot struct {
	Token string `json:"token"`
	Root  []byte `json:"root"`
}

// RootSummary is what following a root means, as the page shows it before
// the owner asks (update.RootSummary). Refusal, when set, is
// RefusedRoot and nothing else is.
type RootSummary struct {
	Version    int64               `json:"version,omitempty"`
	Keys       map[string][]string `json:"keys,omitempty"`
	Thresholds map[string]int      `json:"thresholds,omitempty"`
	Expires    time.Time           `json:"expires,omitempty"`
	Digest     string              `json:"digest,omitempty"`
	Refusal    string              `json:"refusal,omitempty"`
	Reason     string              `json:"reason,omitempty"`
	// Project: the root has the project's own root keys, as the image
	// ships them, so the page may offer switching back (WF1).
	Project bool `json:"project,omitempty"`
}

// RefusedRoot: the root does not verify (signatures, thresholds, expiry by
// the box's clock guard) or is not one to follow.
const RefusedRoot = "not a root to follow"

// The coarse causes of a RefusedRoot (OSS-10w L3). Each reveals only what
// the owner's own root file and the box's clock already say; anything else
// carries no reason.
const (
	RootExpired    = "expired"    // past its expiry by the box's clock
	RootSignatures = "signatures" // too few valid signatures for its threshold
	RootThreshold  = "threshold"  // a threshold below the box's floor
)

// Follow asks to follow the shown root with this digest. An empty Name
// switches back to the project, which agentosd admits only for the
// project's own root keys (WF1).
type Follow struct {
	Token  string `json:"token"`
	Name   string `json:"name"`
	Digest string `json:"digest"`
}
