// Package guesterr is the one filter between broker tools and the guest
// (SR2-3g, security F5 on SR2-3f). Every error a broker tool answers
// leaves the guest plane through Filter: text a tool family wrote for the
// guest from fixed words passes as it is; anything else, which may name
// host paths or internal IDs, becomes a ref, with the detail only in the
// broker's log, which no agent machine can read.
package guesterr

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"regexp"
)

// Literal is a string constant: an untyped constant converts to it, a
// string value does not, so New(err.Error()) does not compile. An explicit
// conversion is refused by TestToolErrorsAreBuiltOnlyFromSafeText.
type Literal string

// Safe is an error carrying text a tool family wrote for the guest;
// Filter shows the guest GuestText and nothing else, so a type that
// embeds a Safe error passes only the embedded text, never its own. The
// types that declare GuestText are an allowlist, one per tool family,
// kept by TestOnlyAllowlistedTypesAreSafe; none wraps another error.
type Safe interface {
	error
	GuestText() string
}

// Text is error text a tool wrote for the guest: fixed words and values
// typed as safe to show it (Arg). It wraps nothing, so no cause's text
// can ride along.
type Text struct{ s string }

func (e Text) Error() string { return e.s }

// GuestText is the text Filter shows the guest.
func (e Text) GuestText() string { return e.s }

// Arg is a value Newf may put in a guest's error text.
type Arg interface{ guestArg() any }

// Num is a count, size or bound; Guest is text the guest itself sent (a
// request ID, a tool name). Newf shows a Guest value only when it is
// ID-shaped (guestRE), so a host path passed as one cannot reach the
// guest (SR2-3k); any other is shown as unshown.
type (
	Num   int64
	Guest string
)

func (n Num) guestArg() any { return int64(n) }

// guestArg checks the value here, not in Newf, so a type embedding Guest
// is checked too: it is an Arg only by this promoted method (release 1,
// L3 on #398).
func (g Guest) guestArg() any {
	if !guestRE.MatchString(string(g)) {
		return unshown
	}
	return string(g)
}

var guestRE = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)

// unshown stands in for a Guest value that is not ID-shaped.
const unshown = "(not shown)"

// New is fixed error text for the guest.
func New(s Literal) Text { return Text{string(s)} }

// Newf is error text for the guest from a literal format and safe values.
func Newf(format Literal, args ...Arg) Text {
	vs := make([]any, len(args))
	for i, a := range args {
		vs[i] = a.guestArg()
	}
	return Text{fmt.Sprintf(string(format), vs...)}
}

// Filter is what the guest sees of err from tool, called by machine: a
// Safe error's GuestText; anything else as "<tool> failed (ref <8 hex>)",
// the detail only in the broker's log. Only err's own method set counts:
// a Safe error wrapped by fmt.Errorf or errors.Join is a ref.
func Filter(machine, tool string, err error) error {
	if s, ok := err.(Safe); ok {
		return Text{s.GuestText()}
	}
	return Text{tool + " " + Logged("guest", machine, tool, err)}
}

// Logged writes err to the broker's log under a fresh ref, prefixed by
// who (the filter that saw it), and returns only the ref's text.
func Logged(who, machine, tool string, err error) string {
	ref := NewRef()
	log.Printf("%s: %s: %s: ref %s: %q", who, machine, tool, ref, fmt.Sprint(err))
	return "failed (ref " + ref + "); the broker's log has the detail"
}

// NewRef is a fresh 8-hex reference, used for nothing but tying a guest's
// error to its log line.
func NewRef() string {
	b := make([]byte, 4)
	if _, err := rand.Read(b); err != nil {
		return "00000000"
	}
	return hex.EncodeToString(b)
}
