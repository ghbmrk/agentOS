// Package header holds the header names a plan route may send upstream and
// those it may pass back to the guest, the words that mark a name as
// carrying a credential, and the checks on a declared header name and
// value, shared by the model and plan clerks and the old core's egress
// (#5278, #5320), so their lists and checks cannot drift. The request and
// answer lists are separate data with separate checks (#5346): a name safe
// to pass back to a guest is not thereby safe to send to a provider.
package header

import (
	_ "embed"
	"errors"
	"fmt"
	"slices"
	"strings"
)

// requestList and answerList are the vendor-owned lists (CLK-14): lines
// that start with a vendor's name, then the names its route sends or reads,
// each exactly. This code names no vendor.
var (
	//go:embed requests.txt
	requestList string
	//go:embed answers.txt
	answerList string
)

// genericRequests and genericAnswers are the names any HTTP route sends or
// reads, each as the CLI does (#4914). None carries a credential, reshapes
// the request or ends at the next hop, and only Content-Type frames it,
// which a refresh may not declare: the clerk sets its own.
var (
	genericRequests = []string{"Accept", "Content-Type", "User-Agent"}
	genericAnswers  = []string{"Content-Type", "Retry-After", "X-Request-Id"}
)

var (
	requests = load(genericRequests, requestList)
	answers  = load(genericAnswers, answerList)
)

// credentialWords mark a name as carrying a credential (#2623): the
// hostiletext corpus's words, which a test holds these to. The clerks and
// egress all refuse by this one list (#5320).
var credentialWords = []string{"key", "token", "auth", "secret", "session", "csrf", "xsrf", "signature", "password", "cookie", "credential"}

// tchar is every byte an RFC 9110 token, so a header name, may hold.
const tchar = "!#$%&'*+-.^_`|~0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

// load returns generic's names, then each vendor line's names. A # starts
// a comment anywhere on a line, and a name holding * is dropped: there are
// no prefixes, so each name passes only exactly (#5320). A name holding a
// byte outside an RFC 9110 token, such as a non-ASCII look-alike, panics,
// so a list that holds one stops the process at start (#5346).
func load(generic []string, list string) []string {
	n := slices.Clone(generic)
	for _, line := range strings.Split(list, "\n") {
		line, _, _ = strings.Cut(line, "#")
		f := strings.Fields(line)
		if len(f) == 0 {
			continue
		}
		for _, h := range f[1:] {
			if strings.ContainsFunc(h, func(r rune) bool { return !strings.ContainsRune(tchar, r) }) {
				panic(fmt.Sprintf("header: the name %q holds a byte outside an RFC 9110 token", h))
			}
			if !strings.Contains(h, "*") {
				n = append(n, h)
			}
		}
	}
	return n
}

// Requests returns a copy of the names a plan route may send upstream, so
// no caller can change the list.
func Requests() []string { return slices.Clone(requests) }

// Answers returns a copy of the names a plan route may pass back to the
// guest, so no caller can change the list.
func Answers() []string { return slices.Clone(answers) }

// Request refuses a declared request name the request list does not hold
// byte for byte: an answer-only name is refused (#5346).
func Request(h string) error {
	if !slices.Contains(requests, h) {
		return fmt.Errorf("header %q is not on the request allowlist", h)
	}
	return nil
}

// Answer refuses a declared answer name the answer list does not hold
// byte for byte, or one that names a credential, so no credential a
// provider's answer carries reaches a guest (CLK-1): a vendor list entry
// cannot override the word check.
func Answer(h string) error {
	if !slices.Contains(answers, h) {
		return fmt.Errorf("header %q is not on the answer allowlist", h)
	}
	if w := Credential(h); w != "" {
		return fmt.Errorf("header %q names a credential (%q)", h, w)
	}
	return nil
}

// Credential returns the first credential word h holds in any case, or ""
// if it holds none.
func Credential(h string) string {
	l := strings.ToLower(h)
	for _, w := range credentialWords {
		if strings.Contains(l, w) {
			return w
		}
	}
	return ""
}

// Value refuses a declared header value that is empty, holds a byte other
// than visible ASCII or a space (so no line break or control character adds
// a header line or reaches the remote), or begins or ends with a space. The
// error says which rule it broke.
func Value(v string) error {
	switch {
	case v == "":
		return errors.New("the value is empty")
	case strings.ContainsFunc(v, func(r rune) bool { return r < ' ' || r > '~' }):
		return errors.New("the value holds a control character or a byte outside visible ASCII")
	case v[0] == ' ' || v[len(v)-1] == ' ':
		return errors.New("the value begins or ends with a space")
	}
	return nil
}
