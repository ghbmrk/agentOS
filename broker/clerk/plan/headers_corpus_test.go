package plan

// REQ: CLK-7

import (
	"slices"
	"testing"

	"github.com/ghbmrk/agentos/broker/hostiletext"
)

// A declared refresh header's value refuses the header-value corpus (#4910,
// #5089): no line break, control character, DEL, non-ASCII byte or padding
// reaches a refresh as a header the clerk sets itself.
func TestRefreshHeaderValuesRefuseTheCorpus(t *testing.T) {
	hostiletext.RunHeaderValues(t, headerValue)
}

// Each header a plan declaration passes is a name passHeaders holds
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
	// The names passHeaders may hold, written out, not read from it.
	want := []string{
		"Accept", "Content-Type", "User-Agent", "Openai-Beta", "Originator", "Version",
		"Session_id", "Conversation_id", "Chatgpt-Account-Id", "X-Openai-Internal-Codex-Responses-Lite",
		"Retry-After", "X-Request-Id", "Openai-Model",
	}
	for name, set := range map[string]func(d *Declaration, h string){
		"request":  func(d *Declaration, h string) { d.RequestHeaders = []string{h} },
		"sign-in":  func(d *Declaration, h string) { d.SignInHeaders = []string{h} },
		"response": func(d *Declaration, h string) { d.ResponseHeaders = []string{h} },
	} {
		t.Run(name, func(t *testing.T) {
			hostiletext.RunHeaders(t, func(h string) bool {
				return takes(func(d *Declaration) { set(d, h) })
			}, hostiletext.Exactly(t, passHeaders, want...)...)
		})
	}
	t.Run("refresh", func(t *testing.T) {
		// The clerk sets a refresh's Content-Type itself.
		hostiletext.RunHeaders(t, func(h string) bool {
			return takes(func(d *Declaration) { d.RefreshHeaders = map[string]string{h: "v"} })
		}, slices.DeleteFunc(slices.Clone(hostiletext.Exactly(t, passHeaders, want...)), func(h string) bool { return h == "Content-Type" })...)
	})
	t.Run("answer", func(t *testing.T) {
		hostiletext.RunHeaders(t, (&Login{d: Codex(nil)}).answerHeader,
			hostiletext.Exactly(t, Codex(nil).ResponseHeaders, "Content-Type", "Retry-After", "X-Request-Id", "Openai-Model")...)
	})
	if !takes(func(d *Declaration) { d.ResponsePrefixes = []string{"X-Codex-"} }) {
		t.Error(`a declaration passing the prefix "X-Codex-" was refused`)
	}
	for _, pre := range []string{"X-", "x-codex-", "Set-", "Proxy-Auth", ""} {
		if takes(func(d *Declaration) { d.ResponsePrefixes = []string{pre} }) {
			t.Errorf("a declaration passing the prefix %q was taken", pre)
		}
	}
}
