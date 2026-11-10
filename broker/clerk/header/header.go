// Package header holds the header names a plan route may pass and the
// checks on a declared header name, prefix and value and on an answer
// header a prefix passes, shared by the model and plan clerks and the old
// core's egress (#5278), so their lists and checks cannot drift.
package header

import (
	_ "embed"
	"errors"
	"fmt"
	"slices"
	"strings"
)

// vendors is the vendor-owned list (CLK-14): one line per vendor, its name
// and then the names its route passes; a name ending in * is an answer
// prefix. This code names no vendor.
//
//go:embed vendors.txt
var vendors string

// generic are the names any HTTP route passes, each as the CLI sends or
// reads it (#4914). None carries a credential, reshapes the request or ends
// at the next hop, and only Content-Type frames it, which a refresh may not
// declare: the clerk sets its own.
var generic = []string{"Accept", "Content-Type", "User-Agent", "Retry-After", "X-Request-Id"}

var names, prefixes = load(vendors)

// credentialWords mark a name as carrying a credential (#2623): the
// hostiletext corpus's words, which a test holds these to.
var credentialWords = []string{"key", "token", "auth", "secret", "session", "csrf", "xsrf", "signature", "password", "cookie", "credential"}

// load returns the generic names, then each vendor line's names and
// prefixes, skipping blank lines and # comments.
func load(list string) (n, p []string) {
	n = slices.Clone(generic)
	for _, line := range strings.Split(list, "\n") {
		f := strings.Fields(line)
		if len(f) == 0 || strings.HasPrefix(f[0], "#") {
			continue
		}
		for _, h := range f[1:] {
			if pre, ok := strings.CutSuffix(h, "*"); ok {
				p = append(p, pre)
			} else {
				n = append(n, h)
			}
		}
	}
	return n, p
}

// Names returns a copy of the names a plan route may pass, so no caller
// can change the list.
func Names() []string { return slices.Clone(names) }

// Prefixes returns a copy of the answer prefixes a plan route may pass.
func Prefixes() []string { return slices.Clone(prefixes) }

// Name refuses a declared name the list does not hold byte for byte.
func Name(h string) error {
	if !slices.Contains(names, h) {
		return fmt.Errorf("header %q is not on the allowlist", h)
	}
	return nil
}

// Prefix refuses a declared answer prefix the list does not hold byte for
// byte.
func Prefix(p string) error {
	if !slices.Contains(prefixes, p) {
		return fmt.Errorf("header prefix %q is not on the allowlist", p)
	}
	return nil
}

// Answer refuses an answer header k that does not begin with the declared
// prefix pre, or that names a credential in any case, so no credential a
// provider's answer carries in a prefixed header reaches a guest (CLK-1).
func Answer(k, pre string) error {
	if !strings.HasPrefix(k, pre) {
		return fmt.Errorf("header %q does not begin with the prefix %q", k, pre)
	}
	l := strings.ToLower(k)
	for _, w := range credentialWords {
		if strings.Contains(l, w) {
			return fmt.Errorf("header %q names a credential (%q)", k, w)
		}
	}
	return nil
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
