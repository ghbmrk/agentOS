package header

// REQ: CLK-1, CLK-3, CLK-7, CLK-14

import (
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/hostiletext"
)

// Value refuses the header-value corpus, an empty value, padding, a tab and
// a byte outside ASCII, takes inner spaces and every visible byte, and says
// which rule fired (#5278). Catches a check that lets a line break, a
// control character or a padded value reach the remote, or a refusal that
// does not say why.
func TestValueRefusesTheCorpus(t *testing.T) {
	hostiletext.RunHeaderValues(t, func(v string) bool { return Value(v) == nil })
	for v, rule := range map[string]string{
		"":      "the value is empty",
		" v":    "the value begins or ends with a space",
		"v ":    "the value begins or ends with a space",
		" ":     "the value begins or ends with a space",
		"v\t":   "the value holds a control character or a byte outside visible ASCII",
		"\tv":   "the value holds a control character or a byte outside visible ASCII",
		"v\x1f": "the value holds a control character or a byte outside visible ASCII",
		"vé":    "the value holds a control character or a byte outside visible ASCII",
		"v\xff": "the value holds a control character or a byte outside visible ASCII",
	} {
		err := Value(v)
		if err == nil || err.Error() != rule {
			t.Errorf("Value(%q) = %v, want %q", v, err, rule)
		}
	}
	for _, v := range []string{"v", "2023-06-01 v", "~v~", "!", "a b c"} {
		if err := Value(v); err != nil {
			t.Errorf("Value(%q) = %v, want it taken", v, err)
		}
	}
}

// Names is exactly the names review accepted, the generic ones from code
// and the rest from the vendor list, and Name refuses the header-name
// corpus in every case, saying why (#4914, #5278, #5291): the plan clerk and
// egress both pass only these. Catches a widened list or a silent refusal.
func TestPassHeadersRefuseTheCorpus(t *testing.T) {
	hostiletext.RunHeaders(t, func(h string) bool { return Name(h) == nil }, hostiletext.Exactly(t, Names(),
		"Accept", "Content-Type", "User-Agent", "Openai-Beta", "Originator", "Version",
		"Session_id", "Conversation_id", "Chatgpt-Account-Id", "X-Openai-Internal-Codex-Responses-Lite",
		"Retry-After", "X-Request-Id", "Openai-Model")...)
	if got := Prefixes(); len(got) != 1 || got[0] != "X-Codex-" {
		t.Errorf("Prefixes() = %q, review accepted [X-Codex-]", got)
	}
	for _, e := range hostiletext.HeaderNames() {
		if Prefix(e.Text) == nil {
			t.Errorf("the corpus name %q is a passed prefix", e.Text)
		}
		for _, p := range Prefixes() {
			if strings.HasPrefix(e.Text, p) {
				t.Errorf("the corpus name %q begins with the passed prefix %q", e.Text, p)
			}
		}
	}
	for _, p := range []string{"X-", "x-codex-", "X-Codex", "Set-", "Proxy-Auth", ""} {
		if err := Prefix(p); err == nil || err.Error() != fmt.Sprintf("header prefix %q is not on the allowlist", p) {
			t.Errorf("Prefix(%q) = %v, want it refused as not on the allowlist", p, err)
		}
	}
	if err := Prefix("X-Codex-"); err != nil {
		t.Errorf(`Prefix("X-Codex-") = %v, want it taken`, err)
	}
	// Openai-Organization is a vendor name the vendor list does not hold.
	for _, h := range []string{"Openai-Organization", "accept", "X-Api-Key"} {
		if err := Name(h); err == nil || err.Error() != fmt.Sprintf("header %q is not on the allowlist", h) {
			t.Errorf("Name(%q) = %v, want it refused as not on the allowlist", h, err)
		}
	}
}

// Answer passes a prefixed answer header only if it names no credential:
// the corpus's credential names and words, after the prefix and in every
// case, are refused with the word that fired, while each quota header the
// pinned CLI reads passes (#5291, CLK-1). Catches the plan clerk passing
// X-Codex-Session-Token to the guest, a dropped word, or a lost quota header.
func TestAnswerRefusesPrefixedCredentials(t *testing.T) {
	for _, e := range hostiletext.HeaderNames() {
		if !strings.HasPrefix(e.Name, "credential ") {
			continue
		}
		err := Answer("X-Codex-"+e.Text, "X-Codex-")
		if err == nil || !strings.HasPrefix(err.Error(), fmt.Sprintf("header %q names a credential (", "X-Codex-"+e.Text)) {
			t.Errorf("Answer(%q) = %v, want it refused as naming a credential", "X-Codex-"+e.Text, err)
		}
	}
	for h, w := range map[string]string{"X-Codex-Session-Token": "token", "X-Codex-Auth": "auth", "X-Codex-API-KEY": "key", "X-Codex-Csrf": "csrf"} {
		if err := Answer(h, "X-Codex-"); err == nil || err.Error() != fmt.Sprintf("header %q names a credential (%q)", h, w) {
			t.Errorf("Answer(%q) = %v, want it refused naming %q", h, err, w)
		}
	}
	for _, h := range []string{
		"X-Codex-Primary-Used-Percent", "X-Codex-Primary-Window-Minutes", "X-Codex-Primary-Reset-At",
		"X-Codex-Secondary-Used-Percent", "X-Codex-Secondary-Window-Minutes", "X-Codex-Secondary-Reset-At",
		"X-Codex-Credits-Has-Credits", "X-Codex-Credits-Unlimited", "X-Codex-Credits-Balance",
		"X-Codex-Rate-Limit-Reached-Type",
	} {
		if err := Answer(h, "X-Codex-"); err != nil {
			t.Errorf("Answer(%q) = %v, want the quota header passed", h, err)
		}
	}
	for _, h := range []string{"X-Other-A", "x-codex-a", "X-Codex"} {
		if err := Answer(h, "X-Codex-"); err == nil || err.Error() != fmt.Sprintf(`header %q does not begin with the prefix "X-Codex-"`, h) {
			t.Errorf("Answer(%q) = %v, want it refused as not prefixed", h, err)
		}
	}
}

// Names and Prefixes hand out copies: a caller that edits or appends to
// what it got does not change the next answer, so no importer can widen
// the list at run time (#5291).
func TestListsAreCopies(t *testing.T) {
	n, p := Names(), Prefixes()
	n[0], p[0] = "Authorization", ""
	_ = append(n[:1], "Cookie")
	_ = append(p[:0], "X-")
	if Names()[0] != "Accept" || Names()[1] != "Content-Type" || Prefixes()[0] != "X-Codex-" || Name("Authorization") == nil || Prefix("") == nil || Name("Cookie") == nil || Prefix("X-") == nil {
		t.Errorf("an edit of a returned list reached the lists: Names() = %q, Prefixes() = %q", Names(), Prefixes())
	}
}

// load reads the vendor list as data (CLK-14): the generic names always,
// then each vendor line's names and * prefixes, skipping blank lines and
// comments, so a vendor name absent from the list is refused (#5291).
func TestLoadReadsTheVendorList(t *testing.T) {
	n, p := load("")
	if !slices.Equal(n, []string{"Accept", "Content-Type", "User-Agent", "Retry-After", "X-Request-Id"}) || p != nil {
		t.Errorf(`load("") = %q, %q, want only the generic names`, n, p)
	}
	n, p = load("# a B-C D-*\n\nv\n  v A-B E-*  F-G\nw H-I\n")
	if !slices.Equal(n[5:], []string{"A-B", "F-G", "H-I"}) || !slices.Equal(p, []string{"E-"}) {
		t.Errorf("load = %q, %q, want [A-B F-G H-I] and [E-]", n[5:], p)
	}
	n[0] = "X"
	if generic[0] != "Accept" {
		t.Error("load shares the generic list with its caller")
	}
}
