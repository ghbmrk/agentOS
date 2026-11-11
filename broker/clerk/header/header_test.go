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
// The request and answer lists are separate (#5346): each check runs the
// header corpus over its own list, and a name on only one list is refused
// by the other's check, so declaring a quota name for answers cannot make
// it a request header.
func TestPassHeadersRefuseTheCorpus(t *testing.T) {
	requests := hostiletext.Exactly(t, Requests(),
		"Accept", "Content-Type", "User-Agent", "Openai-Beta", "Originator", "Version",
		"Session_id", "Conversation_id", "Chatgpt-Account-Id", "X-Openai-Internal-Codex-Responses-Lite")
	answers := hostiletext.Exactly(t, Answers(),
		"Content-Type", "Retry-After", "X-Request-Id", "Openai-Model",
		"X-Codex-Primary-Used-Percent", "X-Codex-Primary-Window-Minutes", "X-Codex-Primary-Reset-At",
		"X-Codex-Secondary-Used-Percent", "X-Codex-Secondary-Window-Minutes", "X-Codex-Secondary-Reset-At",
		"X-Codex-Credits-Has-Credits", "X-Codex-Credits-Unlimited", "X-Codex-Credits-Balance",
		"X-Codex-Rate-Limit-Reached-Type")
	hostiletext.RunHeaders(t, func(h string) bool { return Request(h) == nil }, requests...)
	hostiletext.RunHeaders(t, func(h string) bool { return Answer(h) == nil }, answers...)
	for _, h := range []string{"Openai-Organization", "accept", "X-Api-Key", "X-Codex-*", "X-Codex-", "*", "X-Codex-Session-Token", "X-Codex-Bearer"} {
		if err := Request(h); err == nil || err.Error() != fmt.Sprintf("header %q is not on the request allowlist", h) {
			t.Errorf("Request(%q) = %v, want it refused as not on the request allowlist", h, err)
		}
		if err := Answer(h); err == nil || err.Error() != fmt.Sprintf("header %q is not on the answer allowlist", h) {
			t.Errorf("Answer(%q) = %v, want it refused as not on the answer allowlist", h, err)
		}
	}
	for _, h := range answers {
		if err := Request(h); slices.Contains(requests, h) != (err == nil) {
			t.Errorf("Request(%q) = %v: an answer-only name reaches the request side", h, err)
		}
	}
	for _, h := range requests {
		if err := Answer(h); slices.Contains(answers, h) != (err == nil) && Credential(h) == "" {
			t.Errorf("Answer(%q) = %v: a request-only name reaches the answer side", h, err)
		}
	}
	if err := Request("X-Codex-Primary-Used-Percent"); err == nil || err.Error() != `header "X-Codex-Primary-Used-Percent" is not on the request allowlist` {
		t.Errorf(`Request("X-Codex-Primary-Used-Percent") = %v, want the answer-only name refused`, err)
	}
	if err := Answer("Originator"); err == nil || err.Error() != `header "Originator" is not on the answer allowlist` {
		t.Errorf(`Answer("Originator") = %v, want the request-only name refused`, err)
	}
}

// A name on the answer list that holds a credential word is still refused
// as an answer: the list cannot override the word check (CLK-1).
func TestAnswerRefusesCredentials(t *testing.T) {
	kept := answers
	defer func() { answers = kept }()
	answers = append(Answers(), "Session_id", "X-Codex-Session-Token")
	for _, h := range Answers() {
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
	answers = kept
	corpus := map[string]bool{}
	for _, e := range hostiletext.HeaderNames() {
		if !strings.HasPrefix(e.Name, "credential ") {
			continue
		}
		corpus[e.Text] = true
		if err := Answer(e.Text); err == nil || err.Error() != fmt.Sprintf("header %q is not on the answer allowlist", e.Text) {
			t.Errorf("Answer(%q) = %v, want it refused as not on the answer allowlist", e.Text, err)
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

func TestListsAreCopies(t *testing.T) {
	r, a := Requests(), Answers()
	r[0], a[0] = "Authorization", "Authorization"
	_, _ = append(r[:1], "Cookie"), append(a[:1], "Cookie")
	if Requests()[0] != "Accept" || Requests()[1] != "Content-Type" || Request("Authorization") == nil || Request("Cookie") == nil {
		t.Errorf("an edit of a returned list reached the request list: Requests() = %q", Requests())
	}
	if Answers()[0] != "Content-Type" || Answers()[1] != "Retry-After" || Answer("Authorization") == nil || Answer("Cookie") == nil {
		t.Errorf("an edit of a returned list reached the answer list: Answers() = %q", Answers())
	}
}

func TestLoadReadsTheVendorList(t *testing.T) {
	g := []string{"Accept", "Retry-After"}
	n := load(g, "")
	if !slices.Equal(n, []string{"Accept", "Retry-After"}) {
		t.Errorf(`load(g, "") = %q, want only the generic names`, n)
	}
	n[0] = "X"
	if g[0] != "Accept" {
		t.Error(`load(g, "") shares the generic list with its caller`)
	}
	n = load(g, "# a B-C D-*\n\nv\n  v A-B E-* * F-G # H-J K-L\nw H-I#M-N\n#\nx *\ny !#$%&'+-.^_`|~09AZaz\n")
	if !slices.Equal(n[2:], []string{"A-B", "F-G", "H-I", "!"}) {
		t.Errorf("load = %q, want [A-B F-G H-I !]", n[2:])
	}
	n = load(g, "y $%&'+-.^_`|~09AZaz\n")
	if !slices.Equal(n[2:], []string{"$%&'+-.^_`|~09AZaz"}) {
		t.Errorf("load = %q, want every token byte taken", n[2:])
	}
	n[0] = "X"
	if g[0] != "Accept" {
		t.Error("load shares the generic list with its caller")
	}
	if !slices.Equal(genericRequests, []string{"Accept", "Content-Type", "User-Agent"}) || !slices.Equal(genericAnswers, []string{"Content-Type", "Retry-After", "X-Request-Id"}) {
		t.Errorf("the generic lists are %q and %q", genericRequests, genericAnswers)
	}
}

// A declared name holding a byte outside an RFC 9110 token (a non-ASCII
// look-alike, a control byte, a separator) stops the list loading (#5346).
func TestLoadRefusesNonTokenNames(t *testing.T) {
	for _, h := range []string{"X-Codex-Us\u0435d", "Acc\u0435pt", "X-\u00e9", "X-\xff", "X-\x00", "X-\x7f", "X:Y", "X\"Y", "X(Y)", "X/Y", "X@Y", "X;Y", "X,Y", "X=Y", "X[Y]", "X{Y}", "X\\Y", "X?Y", "X<Y>", "X-*-\u00e9"} {
		func() {
			defer func() {
				want := fmt.Sprintf("header: the name %q holds a byte outside an RFC 9110 token", h)
				if r := recover(); r != want {
					t.Errorf("load of %q: recovered %v, want %q", h, r, want)
				}
			}()
			load(nil, "v A-B "+h+"\n")
			t.Errorf("load took %q", h)
		}()
	}
	for _, list := range []string{requestList, answerList} {
		for _, r := range list {
			if r > '~' {
				t.Errorf("a vendor list holds the non-ASCII rune %q", r)
			}
		}
	}
}
