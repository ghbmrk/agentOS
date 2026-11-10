// Package header holds the header names a plan route may pass, the words
// that mark a name as carrying a credential, and the checks on a declared
// header name and value, shared by the model and plan clerks and the old
// core's egress (#5278, #5320), so their lists and checks cannot drift.
package header

import (
	_ "embed"
	"errors"
	"fmt"
	"slices"
	"strings"
)

// vendors is the vendor-owned list (CLK-14): lines that start with a
// vendor's name, then the names its route passes, each exactly. This code
// names no vendor.
//
//go:embed vendors.txt
var vendors string

// generic are the names any HTTP route passes, each as the CLI sends or
// reads it (#4914). None carries a credential, reshapes the request or ends
// at the next hop, and only Content-Type frames it, which a refresh may not
// declare: the clerk sets its own.
var generic = []string{"Accept", "Content-Type", "User-Agent", "Retry-After", "X-Request-Id"}

var names = load(vendors)

// credentialWords mark a name as carrying a credential (#2623): the
// hostiletext corpus's words, which a test holds these to. The clerks and
// egress all refuse by this one list (#5320).
var credentialWords = []string{"key", "token", "auth", "secret", "session", "csrf", "xsrf", "signature", "password", "cookie", "credential"}

// load returns the generic names, then each vendor line's names. A # starts
// a comment anywhere on a line, and a name holding * is dropped: there are
// no prefixes, so each name passes only exactly (#5320).
func load(list string) []string {
	n := slices.Clone(generic)
	for _, line := range strings.Split(list, "\n") {
		line, _, _ = strings.Cut(line, "#")
		f := strings.Fields(line)
		if len(f) == 0 {
			continue
		}
		for _, h := range f[1:] {
			if !strings.Contains(h, "*") {
				n = append(n, h)
			}
		}
	}
	return n
}

// Names returns a copy of the names a plan route may pass, so no caller
// can change the list.
func Names() []string { return slices.Clone(names) }

// Name refuses a declared name the list does not hold byte for byte.
func Name(h string) error {
	if !slices.Contains(names, h) {
		return fmt.Errorf("header %q is not on the allowlist", h)
	}
	return nil
}

// Answer refuses a declared answer name that Name refuses or that names a
// credential, so no credential a provider's answer carries reaches a guest
// (CLK-1): a vendor list entry cannot override the word check.
func Answer(h string) error {
	if err := Name(h); err != nil {
		return err
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
