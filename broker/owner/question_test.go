package owner

import (
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/control"
	"github.com/ghbmrk/agentos/broker/question"
)

// REQ: CAP-10, CH-12

// TestQuestionTagsAndLengthFitTheChannel: a question's tag (Q100-Q999) is
// never an approval request ID, so "YES Q104" is no approval reply and
// "Q104 yes" no channel word; and the longest question the broker accepts
// fits one owner text behind the agent prefix, so Fit cuts nothing.
func TestQuestionTagsAndLengthFitTheChannel(t *testing.T) {
	for _, tag := range []string{"Q100", "Q104", "Q999"} {
		if isID(tag) {
			t.Errorf("%s is an approval ID", tag)
		}
		if r, ok := parseReply("YES " + tag); ok && r.id != "" {
			t.Errorf("YES %s parsed as a reply to %q", tag, r.id)
		}
		if _, ok := parseReply(tag + " yes"); ok {
			t.Errorf("%s yes parsed as a channel word", tag)
		}
	}
	if question.MaxRendered+len(AgentPrefix) > control.MaxText {
		t.Fatalf("MaxRendered %d + prefix %d > %d", question.MaxRendered, len(AgentPrefix), control.MaxText)
	}
	long := strings.Repeat("x", question.MaxRendered)
	if got := control.Fit(AgentPrefix + long); got != AgentPrefix+long {
		t.Fatal("Fit cut a text of MaxRendered")
	}
}
