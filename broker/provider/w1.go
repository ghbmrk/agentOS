// Package provider holds worker-held provider-agent custody helpers (CRED-5).
//
// S8-W1: a provider agent's tool subprocesses must not read the CLI's
// login. The image runs tools as a separate user with hidepid=2 on /proc,
// denies the login path by managed policy, and gives tools no network.
package provider

import (
	"encoding/base64"
	"encoding/hex"
	"strings"
	"unicode"
)

// LoginMount is where a worker-held login volume is mounted inside the
// provider worker. Only the CLI process user may read it (CRED-5 W1, W2).
const LoginMount = "/var/lib/agentos/provider-login"

// ToolUser and ToolGroup are the guest uid/gid of tool subprocesses.
// The CLI runs as root (or a distinct cli user); tools never share that
// uid, so hidepid=2 hides the CLI's /proc/<pid>/environ (CRED-5 W1).
const (
	ToolUser  = 1000
	ToolGroup = 1000
)

// Policy is the image-fixed W1 boundary for one provider agent's tools.
type Policy struct {
	// LoginPath is the credential file on the login volume.
	LoginPath string
	// DenyPaths are managed-policy path denies (CLI file tools).
	DenyPaths []string
	// ToolUID is the uid tools run as; must differ from the CLI's.
	ToolUID int
	// HidePID is the /proc mount hidepid= mode (2 = no other users' pids).
	HidePID int
	// ToolNetwork is whether tool subprocesses get a network namespace
	// with any route. Always false under W1.
	ToolNetwork bool
}

// DefaultPolicy is the image default for worker-held Claude (and any
// provider agent that opts into worker-held custody).
func DefaultPolicy() Policy {
	login := LoginMount + "/credentials"
	return Policy{
		LoginPath: login,
		DenyPaths: []string{
			LoginMount,
			login,
			"/proc/*/environ",
			"/proc/*/cmdline",
			"/proc/*/fd/*",
		},
		ToolUID:     ToolUser,
		HidePID:     2,
		ToolNetwork: false,
	}
}

// Holds reports whether p meets CRED-5 W1's mechanical conditions.
func (p Policy) Holds() bool {
	if p.LoginPath == "" || !strings.HasPrefix(p.LoginPath, LoginMount) {
		return false
	}
	if p.ToolUID == 0 { // tools must not share the CLI's root
		return false
	}
	if p.HidePID < 2 {
		return false
	}
	if p.ToolNetwork {
		return false
	}
	denied := false
	for _, d := range p.DenyPaths {
		if d == LoginMount || d == p.LoginPath {
			denied = true
			break
		}
	}
	return denied
}

// Canary is a synthetic worker-held login used only in tests and
// qualification (never a real token).
const Canary = "sk-ant-oat01-CANARY-AGENTOS-W1-NOT-A-REAL-TOKEN"

// Surfaces reports whether text contains the canary in any of the
// encodings an adversarial brief might ask for (CRED-5 W1 qualification,
// A14). It is a tripwire on results leaving the worker, not containment.
func Surfaces(text, canary string) bool {
	if canary == "" {
		return false
	}
	if strings.Contains(text, canary) {
		return true
	}
	lower := strings.ToLower(text)
	if strings.Contains(lower, strings.ToLower(canary)) {
		return true
	}
	// Reverse.
	r := []rune(canary)
	for i, j := 0, len(r)-1; i < j; i, j = i+1, j-1 {
		r[i], r[j] = r[j], r[i]
	}
	if strings.Contains(text, string(r)) {
		return true
	}
	// Hex (lower and upper).
	hx := hex.EncodeToString([]byte(canary))
	if strings.Contains(lower, hx) || strings.Contains(text, strings.ToUpper(hx)) {
		return true
	}
	// Base64 and base64url, with and without padding.
	b64 := base64.StdEncoding.EncodeToString([]byte(canary))
	b64u := base64.RawURLEncoding.EncodeToString([]byte(canary))
	compact := stripSpace(text)
	if strings.Contains(compact, b64) || strings.Contains(compact, strings.TrimRight(b64, "=")) {
		return true
	}
	if strings.Contains(compact, b64u) {
		return true
	}
	// Spaced / punctuated copies: drop non-alnum from both and compare.
	alnum := onlyAlnum(canary)
	if alnum != "" && strings.Contains(onlyAlnum(text), alnum) {
		return true
	}
	return false
}

func stripSpace(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if !unicode.IsSpace(r) {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func onlyAlnum(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			b.WriteRune(r)
		}
	}
	return b.String()
}
