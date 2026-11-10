package plan

// REQ: CLK-7

import (
	"slices"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/clerk/header"
	"github.com/ghbmrk/agentos/broker/hostiletext"
)

// A declared refresh header's value refuses the header-value corpus (#4910,
// #5089, #5278): no line break, control character, DEL, non-ASCII byte,
// empty value or padding reaches a refresh as a header the clerk sets
// itself, and the refusal names the rule that fired.
func TestRefreshHeaderValuesRefuseTheCorpus(t *testing.T) {
	declare := func(v string) error {
		d := Codex(nil)
		d.RefreshHeaders = map[string]string{"User-Agent": v}
		return (&Login{d: d, token: map[string]*Field{}, refused: map[string]bool{}}).validate()
	}
	hostiletext.RunHeaderValues(t, func(v string) bool { return declare(v) == nil })
	for v, why := range map[string]string{
		"":        "is empty",
		" v":      "begins or ends with a space",
		"v ":      "begins or ends with a space",
		"v\t":     "control character",
		"v\u00e9": "outside visible ASCII",
	} {
		if err := declare(v); err == nil || !strings.HasPrefix(err.Error(), `clerk: refresh header "User-Agent": the value `) || !strings.Contains(err.Error(), why) {
			t.Errorf("the value %q: got %v, want a refusal saying %q", v, err, why)
		}
	}
}

// Each header a plan declaration passes is a name header.Names holds
// exactly, and the guest gets only the answer headers it declares: the
// header corpus's credential, request-reshaping, hop-by-hop and broken
// names, in any case, are refused on every list (#4914). Catches a route
// passing X-Original-Url, X-Api-Key or Forwarded, or a widened list.
func TestPassHeadersRefuseTheCorpus(t *testing.T) {
	takes := func(edit func(*Declaration)) bool {
		d := Codex(nil)
		edit(&d)
		return (&Login{d: d, token: map[string]*Field{}, refused: map[string]bool{}}).validate() == nil
	}
	// The names header.Names may hold, written out, not read from it.
	want := []string{
		"Accept", "Content-Type", "User-Agent", "Openai-Beta", "Originator", "Version",
		"Session_id", "Conversation_id", "Chatgpt-Account-Id", "X-Openai-Internal-Codex-Responses-Lite",
		"Retry-After", "X-Request-Id", "Openai-Model",
		"X-Codex-Primary-Used-Percent", "X-Codex-Primary-Window-Minutes", "X-Codex-Primary-Reset-At",
		"X-Codex-Secondary-Used-Percent", "X-Codex-Secondary-Window-Minutes", "X-Codex-Secondary-Reset-At",
		"X-Codex-Credits-Has-Credits", "X-Codex-Credits-Unlimited", "X-Codex-Credits-Balance",
		"X-Codex-Rate-Limit-Reached-Type",
	}
	// An answer may not name a credential, so Session_id never comes back.
	answers := slices.DeleteFunc(slices.Clone(want), func(h string) bool { return h == "Session_id" })
	for name, set := range map[string]func(d *Declaration, h string){
		"request":  func(d *Declaration, h string) { d.RequestHeaders = []string{h} },
		"sign-in":  func(d *Declaration, h string) { d.SignInHeaders = []string{h} },
		"response": func(d *Declaration, h string) { d.ResponseHeaders = []string{h} },
	} {
		t.Run(name, func(t *testing.T) {
			named := hostiletext.Exactly(t, header.Names(), want...)
			if name == "response" {
				named = answers
			}
			hostiletext.RunHeaders(t, func(h string) bool {
				return takes(func(d *Declaration) { set(d, h) })
			}, named...)
		})
	}
	t.Run("refresh", func(t *testing.T) {
		// The clerk sets a refresh's Content-Type itself.
		hostiletext.RunHeaders(t, func(h string) bool {
			return takes(func(d *Declaration) { d.RefreshHeaders = map[string]string{h: "v"} })
		}, slices.DeleteFunc(slices.Clone(hostiletext.Exactly(t, header.Names(), want...)), func(h string) bool { return h == "Content-Type" })...)
	})
	t.Run("answer", func(t *testing.T) {
		// The guest gets each declared answer header by its exact name, the
		// quota headers among them, and no other: a credential name the old
		// X-Codex- prefix passed is dropped (#5291, #5320, CLK-1).
		p := &Login{d: Codex(nil)}
		hostiletext.RunHeaders(t, (&Login{d: Codex(nil)}).answerHeader, hostiletext.Exactly(t, Codex(nil).ResponseHeaders,
			"Content-Type", "Retry-After", "X-Request-Id", "Openai-Model",
			"X-Codex-Primary-Used-Percent", "X-Codex-Primary-Window-Minutes", "X-Codex-Primary-Reset-At",
			"X-Codex-Secondary-Used-Percent", "X-Codex-Secondary-Window-Minutes", "X-Codex-Secondary-Reset-At",
			"X-Codex-Credits-Has-Credits", "X-Codex-Credits-Unlimited", "X-Codex-Credits-Balance",
			"X-Codex-Rate-Limit-Reached-Type")...)
		for _, e := range hostiletext.HeaderNames() {
			if strings.HasPrefix(e.Name, "credential ") && p.answerHeader("X-Codex-"+e.Text) {
				t.Errorf("the answer header %q reached the guest", "X-Codex-"+e.Text)
			}
		}
		for _, h := range []string{"X-Codex-Bearer", "X-Codex-Jwt", "X-Codex-Refresh", "X-Codex-Access", "X-Codex-Recovery-Code", "X-Codex-Passwd", "X-Codex-A"} {
			if p.answerHeader(h) {
				t.Errorf("the answer header %q reached the guest", h)
			}
		}
	})
	// Each refusal names its rule; Openai-Organization is a vendor name the
	// vendor list does not hold (#5291, CLK-14).
	validate := func(edit func(*Declaration)) error {
		d := Codex(nil)
		edit(&d)
		return (&Login{d: d, token: map[string]*Field{}, refused: map[string]bool{}}).validate()
	}
	for want, edit := range map[string]func(*Declaration){
		`clerk: header "Openai-Organization" is not on the allowlist`:               func(d *Declaration) { d.RequestHeaders = []string{"Openai-Organization"} },
		`clerk: answer header "X-Api-Key" is not on the allowlist`:                  func(d *Declaration) { d.ResponseHeaders = []string{"X-Api-Key"} },
		`clerk: answer header "Session_id" names a credential ("session")`:          func(d *Declaration) { d.ResponseHeaders = []string{"Session_id"} },
		`clerk: refresh header "Cookie" is not on the allowlist`:                    func(d *Declaration) { d.RefreshHeaders = map[string]string{"Cookie": "v"} },
		`clerk: refresh header "Content-Type" is the clerk's own`:                   func(d *Declaration) { d.RefreshHeaders = map[string]string{"Content-Type": "v"} },
		`clerk: refresh header "User-Agent": the value begins or ends with a space`: func(d *Declaration) { d.RefreshHeaders = map[string]string{"User-Agent": "v "} },
	} {
		if err := validate(edit); err == nil || err.Error() != want {
			t.Errorf("got %v, want %q", err, want)
		}
	}
}
