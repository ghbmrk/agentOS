package loops

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

// The finding vocabulary the off-the-shelf probes (probe.go, corpus.go,
// machine.go) and ../probecmd report in. The Guard that acted on findings
// through the change pipeline was deleted with the pipeline (#2785,
// MIG-4-untrusted-change-c2).

// Severity decides how the owner hears about a finding (LOOP-9).
type Severity string

const (
	// Low findings go in the digest.
	Low Severity = "low"
	// High findings are texted at once.
	High Severity = "high"
)

// Check names the check behind a finding.
type Check string

// Target is what containment pauses: a grant or an executor (LOOP-9).
type Target struct {
	Kind string `json:"kind"` // "grant" or "executor"
	Name string `json:"name"` // the grant ID or executor name
	// Label is what the owner calls it ("pre-allowance P4", "the mail
	// tool"), from the wiring; owner text never says grant or executor.
	Label string `json:"label,omitempty"`
}

// Finding is one thing a check found. ID is stable while the same
// problem persists, so it is handled once.
type Finding struct {
	ID       string   `json:"id"`
	Check    Check    `json:"check"`
	Subject  string   `json:"subject"`
	Detail   string   `json:"detail"`
	Severity Severity `json:"severity"`
	Contain  *Target  `json:"contain,omitempty"`
	// Rule is the regression fixture's input, empty when the finding is
	// not something a change could reintroduce (expiry, drift).
	Rule []byte `json:"rule,omitempty"`
}

// FindingID is the stable ID of a finding of check c about subject with
// detail; a probe that sets its own IDs uses it, such as probecmd with an
// empty detail (P3-4b-4a).
func FindingID(c Check, subject, detail string) string {
	h := sha256.Sum256([]byte(string(c) + "\x00" + subject + "\x00" + detail))
	return string(c) + "-" + hex.EncodeToString(h[:6])
}

// CheckFuzz and CheckProbe name findings from Loop 7's off-the-shelf
// checks (P3-4b-3): a fuzz target's crash and an in-guest socket probe's
// failure. plainname.go words them.
const (
	CheckFuzz  Check = "fuzz"
	CheckProbe Check = "probe"
)

// safeName keeps owner-facing names to a fixed alphabet.
func safeName(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r < 128 && (r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("-_./: ", r)) {
			b.WriteRune(r)
		}
		if b.Len() >= 48 {
			break
		}
	}
	return b.String()
}
