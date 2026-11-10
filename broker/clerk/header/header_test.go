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
// and the rest from the vendor list, each quota header by its exact name,
// and Name refuses the header-name corpus in every case, saying why (#4914,
// #5278, #5291, #5320): the plan clerk and egress both pass only these.
// Catches a widened list, a prefix, or a silent refusal.
func TestPassHeadersRefuseTheCorpus(t *testing.T) {
	hostiletext.RunHeaders(t, func(h string) bool { return Name(h) == nil }, hostiletext.Exactly(t, Names(),
		"Accept", "Content-Type", "User-Agent", "Openai-Beta", "Originator", "Version",
		"Session_id", "Conversation_id", "Chatgpt-Account-Id", "X-Openai-Internal-Codex-Responses-Lite",
		"Retry-After", "X-Request-Id", "Openai-Model",
		"X-Codex-Primary-Used-Percent", "X-Codex-Primary-Window-Minutes", "X-Codex-Primary-Reset-At",
		"X-Codex-Secondary-Used-Percent", "X-Codex-Secondary-Window-Minutes", "X-Codex-Secondary-Reset-At",
		"X-Codex-Credits-Has-Credits", "X-Codex-Credits-Unlimited", "X-Codex-Credits-Balance",
		"X-Codex-Rate-Limit-Reached-Type")...)
	// Openai-Organization is a vendor name the vendor list does not hold;
	// the rest are prefixes or a name the old prefix passed.
	for _, h := range []string{"Openai-Organization", "accept", "X-Api-Key", "X-Codex-*", "X-Codex-", "*", "X-Codex-Session-Token", "X-Codex-Bearer"} {
		if err := Name(h); err == nil || err.Error() != fmt.Sprintf("header %q is not on the allowlist", h) {
			t.Errorf("Name(%q) = %v, want it refused as not on the allowlist", h, err)
		}
	}
}

// Answer takes a listed name that holds no credential word, and refuses
// the rest saying why: a corpus name as not on the allowlist, a listed name
// holding a word (Session_id) as naming a credential (#5320, CLK-1). Every
// corpus credential name holds a word Credential finds, and each word is a
// corpus word, so the clerks, egress and the corpus hold one list. Catches a
// credential header reaching a guest, a dropped quota header, or a word the
// two filters do not share.
func TestAnswerRefusesCredentials(t *testing.T) {
	for _, h := range Names() {
		err := Answer(h)
		if w := Credential(h); w == "" && err != nil || w != "" && (err == nil || err.Error() != fmt.Sprintf("header %q names a credential (%q)", h, w)) {
			t.Errorf("Answer(%q) = %v with the word %q", h, err, w)
		}
	}
	if err := Answer("Session_id"); err == nil || err.Error() != `header "Session_id" names a credential ("session")` {
		t.Errorf(`Answer("Session_id") = %v, want it refused naming "session"`, err)
	}
	for _, h := range []string{"X-Codex-Primary-Used-Percent", "X-Codex-Credits-Balance", "X-Codex-Rate-Limit-Reached-Type", "Openai-Model", "Retry-After"} {
		if err := Answer(h); err != nil {
			t.Errorf("Answer(%q) = %v, want the header passed", h, err)
		}
	}
	corpus := map[string]bool{}
	for _, e := range hostiletext.HeaderNames() {
		if !strings.HasPrefix(e.Name, "credential ") {
			continue
		}
		corpus[e.Text] = true
		if err := Answer(e.Text); err == nil || err.Error() != fmt.Sprintf("header %q is not on the allowlist", e.Text) {
			t.Errorf("Answer(%q) = %v, want it refused as not on the allowlist", e.Text, err)
		}
		if Credential("X-Codex-"+e.Text) == "" {
			t.Errorf("Credential(%q) found no word", "X-Codex-"+e.Text)
		}
	}
	for _, w := range credentialWords {
		if !corpus[w] {
			t.Errorf("the credential word %q is not a corpus word", w)
		}
	}
	for h, w := range map[string]string{"X-Codex-Session-Token": "token", "X-Codex-Auth": "auth", "X-Codex-API-KEY": "key", "X-CSRF": "csrf", "X-Xsrf": "xsrf", "Signature": "signature", "X-Credential": "credential", "Accept": ""} {
		if got := Credential(h); got != w {
			t.Errorf("Credential(%q) = %q, want %q", h, got, w)
		}
	}
}

// Names hands out a copy: a caller that edits or appends to what it got
// does not change the next answer, so no importer can widen the list at
// run time (#5291).
func TestListsAreCopies(t *testing.T) {
	n := Names()
	n[0] = "Authorization"
	_ = append(n[:1], "Cookie")
	if Names()[0] != "Accept" || Names()[1] != "Content-Type" || Name("Authorization") == nil || Name("Cookie") == nil {
		t.Errorf("an edit of a returned list reached the list: Names() = %q", Names())
	}
}

// load reads the vendor list as data (CLK-14): the generic names always,
// then each vendor line's names, skipping blank lines, lines naming only a
// vendor, and every # comment, whole-line or inline, and dropping a name
// holding *, a lone * too, since nothing passes by prefix (#5291, #5320).
// load("") hands back its own copy of the generic names.
func TestLoadReadsTheVendorList(t *testing.T) {
	n := load("")
	if !slices.Equal(n, []string{"Accept", "Content-Type", "User-Agent", "Retry-After", "X-Request-Id"}) {
		t.Errorf(`load("") = %q, want only the generic names`, n)
	}
	n[0] = "X"
	if generic[0] != "Accept" {
		generic[0] = "Accept"
		t.Error(`load("") shares the generic list with its caller`)
	}
	n = load("# a B-C D-*\n\nv\n  v A-B E-* * F-G # H-J K-L\nw H-I#M-N\n#\nx *\n")
	if !slices.Equal(n[5:], []string{"A-B", "F-G", "H-I"}) {
		t.Errorf("load = %q, want [A-B F-G H-I]", n[5:])
	}
	n[0] = "X"
	if generic[0] != "Accept" {
		t.Error("load shares the generic list with its caller")
	}
}
