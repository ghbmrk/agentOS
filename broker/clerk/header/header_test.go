package header

// REQ: CLK-3, CLK-7

import (
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

// PassHeaders is exactly the names review accepted, and a list check over
// it refuses the header-name corpus in every case (#4914, #5278): the plan
// clerk and egress both pass only these. Catches a widened list.
func TestPassHeadersRefuseTheCorpus(t *testing.T) {
	hostiletext.RunHeaders(t, func(h string) bool {
		for _, p := range PassHeaders {
			if h == p {
				return true
			}
		}
		return false
	}, hostiletext.Exactly(t, PassHeaders,
		"Accept", "Content-Type", "User-Agent", "Openai-Beta", "Originator", "Version",
		"Session_id", "Conversation_id", "Chatgpt-Account-Id", "X-Openai-Internal-Codex-Responses-Lite",
		"Retry-After", "X-Request-Id", "Openai-Model")...)
	if len(PassPrefixes) != 1 || PassPrefixes[0] != "X-Codex-" {
		t.Errorf("PassPrefixes = %q, review accepted [X-Codex-]", PassPrefixes)
	}
	for _, e := range hostiletext.HeaderNames() {
		for _, p := range PassPrefixes {
			if strings.HasPrefix(e.Text, p) {
				t.Errorf("the corpus name %q begins with the passed prefix %q", e.Text, p)
			}
		}
	}
}
