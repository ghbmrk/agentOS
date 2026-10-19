// Package notice is the vault process's owner notices as data: a fixed
// code, and for a provider notice the provider's name, which agentosd
// renders into the owner's text from one table (P2-2w c4e4 s2, #1421).
// The vault process never hands agentosd free text to send.
package notice

import (
	"regexp"
	"slices"
	"strings"
)

// Socket is the vault process's notice socket, in its run directory. It
// admits agentosd's uid only.
const Socket = "notice.sock"

// Code names one owner notice.
type Code string

const (
	MailReplaced     Code = "mail_replaced"
	MailRemoved      Code = "mail_removed"
	LineCallReplaced Code = "line_call_replaced"
	LineCallRemoved  Code = "line_call_removed"
	LineTextReplaced Code = "line_text_replaced"
	LineTextRemoved  Code = "line_text_removed"
	LineTextsMissed  Code = "line_texts_missed"
	PrivateAllowed   Code = "private_allowed"
	PrivateWithdrawn Code = "private_withdrawn"
	WrongCode        Code = "wrong_code"
	CodesLocked      Code = "codes_locked"
)

// Notice is one owner notice. Name is the provider for PrivateAllowed and
// PrivateWithdrawn, what a wrong code was for (a key of wrongFor, or
// empty) for WrongCode, and empty otherwise.
type Notice struct {
	Code Code   `json:"code"`
	Name string `json:"name,omitempty"`
}

// Item is a notice with its number in the vault process's queue.
type Item struct {
	Seq uint64 `json:"seq"`
	Notice
}

// Batch is the notice socket's answer: the notices after the caller's
// last seen number, in order, and how many were dropped unread because
// the queue was full. Boot changes when the vault process restarts.
type Batch struct {
	Boot    string `json:"boot"`
	Notices []Item `json:"notices"`
	Missed  uint64 `json:"missed,omitempty"`
}

const ifNotYou = " If that wasn't you, sign in there and check it."

// fixed are the notices that take no name.
var fixed = map[Code]string{
	MailReplaced:     "Your mail account was replaced on my Wi-Fi page." + ifNotYou,
	MailRemoved:      "Your mail account was removed on my Wi-Fi page." + ifNotYou,
	LineCallReplaced: "My second line's calling account was replaced on my Wi-Fi page." + ifNotYou,
	LineCallRemoved:  "My second line's calling account was removed on my Wi-Fi page." + ifNotYou,
	LineTextReplaced: "My second line's texting account was replaced on my Wi-Fi page." + ifNotYou,
	LineTextRemoved:  "My second line's texting account was removed on my Wi-Fi page." + ifNotYou,
	LineTextsMissed:  "Some texts to my second line may have been missed.",
	CodesLocked:      "Too many wrong codes were typed to unlock me, so that unlock was stopped. If that wasn't you, someone on my Wi-Fi is trying to unlock me.",
}

// wrongFor maps what the vault process says a wrong code was for to the
// words the owner reads.
var wrongFor = map[string]string{
	"a vault unlock":                   " to unlock me",
	"a trusted-host change":            " to change which PCs are trusted",
	"allowing a provider private data": " to allow a provider your private data",
	"an owner pin change":              " to change an owner pin",
	"a card rotation":                  " to replace the Owner Card",
}

// nameRE is a provider's display name: the built-in names and plain ids.
// It has no dot, so a name never reads as a web address in a text.
var nameRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9 -]{0,31}$`)

// Codes lists every code, sorted.
func Codes() []Code {
	cs := []Code{PrivateAllowed, PrivateWithdrawn, WrongCode}
	for c := range fixed {
		cs = append(cs, c)
	}
	slices.Sort(cs)
	return cs
}

// Text renders n as the owner's text, or false for an unknown code, a
// missing or badly shaped name, or a name on a notice that takes none.
func Text(n Notice) (string, bool) {
	switch n.Code {
	case PrivateAllowed, PrivateWithdrawn:
		if !nameRE.MatchString(n.Name) {
			return "", false
		}
		if n.Code == PrivateAllowed {
			return n.Name + " may now get your private data: it was allowed on my Wi-Fi page. If that wasn't you, withdraw it there.", true
		}
		return n.Name + " may no longer get your private data: it was withdrawn on my Wi-Fi page.", true
	case WrongCode:
		what, ok := wrongFor[n.Name]
		if !ok && n.Name != "" {
			return "", false
		}
		return "A wrong code was typed on my Wi-Fi page" + what + ". If that wasn't you, someone on my Wi-Fi is trying to change things.", true
	}
	if n.Name != "" {
		return "", false
	}
	s, ok := fixed[n.Code]
	return s, ok
}

// fromLog maps the vault process's fixed notice lines to codes; they are
// its sipaccount.go, smsaccount.go, mailaccount.go and custody.go lines,
// and its tests check each one maps.
var fromLog = map[string]Code{
	"The mail account was replaced on my Wi-Fi page.":                  MailReplaced,
	"The mail account was removed on my Wi-Fi page.":                   MailRemoved,
	"The second line's calling account was replaced on my Wi-Fi page.": LineCallReplaced,
	"The second line's calling account was removed on my Wi-Fi page.":  LineCallRemoved,
	"The second line's texting account was replaced on my Wi-Fi page.": LineTextReplaced,
	"The second line's texting account was removed on my Wi-Fi page.":  LineTextRemoved,
	"Some texts to your second line may have been missed.":             LineTextsMissed,
	"too many wrong codes for a vault unlock; key discarded":           CodesLocked,
}

// FromLog maps one of the vault process's notice lines to an owner
// notice. Every other line is false: it stays in the log only.
func FromLog(line string) (Notice, bool) {
	if c, ok := fromLog[line]; ok {
		return Notice{Code: c}, true
	}
	for prefix, c := range map[string]Code{"private data allowed for ": PrivateAllowed, "private data withdrawn for ": PrivateWithdrawn} {
		if name, ok := strings.CutPrefix(line, prefix); ok && nameRE.MatchString(name) {
			return Notice{Code: c, Name: name}, true
		}
	}
	if what, ok := strings.CutPrefix(line, "wrong code for "); ok {
		if _, known := wrongFor[what]; known {
			return Notice{Code: WrongCode, Name: what}, true
		}
		return Notice{Code: WrongCode}, true
	}
	return Notice{}, false
}
