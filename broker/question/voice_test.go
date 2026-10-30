package question

// REQ: CH-21

import (
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/owner"
)

// TestCH21QuestionTextsPassTheCheck: agent text carries no label, so the
// owner channel's CH-21 check reads a question's text as it is sent. Its
// frame must not take a shape the check holds, a line opening with the
// request ID and ":" among them, or every question would go as the held
// text and then default (#2189).
func TestCH21QuestionTextsPassTheCheck(t *testing.T) {
	r := newRig(t, nil)
	r.ask("lin1", "a", Spec{Text: "Ferry or train?", Default: "ferry", Choices: []string{"ferry", "train"}, Wait: time.Hour})
	r.ask("lin1", "b", short("Taxi home?"))
	got := r.texts()
	if len(got) == 0 {
		t.Fatal("no question texted")
	}
	for _, s := range got {
		if owner.AgentVoice(s) {
			t.Errorf("question text held by the CH-21 check: %q", s)
		}
	}
}
