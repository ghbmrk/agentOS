package page

// REQ: KRN-12, NET-2

import (
	"net/http"
	"strings"
	"testing"
)

// #6011 item 1 (KRN-12 Response): a red light goes off only when the cut
// lifts, so its line names the two lift steps and offers no clear.
func TestRedLightNamesTheLiftStep(t *testing.T) {
	g, _, _ := stateRig(t)
	h := g.homeHTML()
	for _, want := range []string{"The light is red", "It goes off only when the cut lifts", "lift the edge's cut", "resume the core's channel"} {
		if !strings.Contains(h, want) {
			t.Errorf("home lacks %q", want)
		}
	}
	if strings.Contains(h, "clear its alert") {
		t.Error("the red-light line offers a clear the page does not have")
	}
}

// #6011 item 2 (NET-2 Texts and calls): a clear drawn on an alert only a
// step closes names that step, whichever box the alert came from.
func TestFixedClearNamesBothSteps(t *testing.T) {
	g, al, _ := stateRig(t)
	code, res := g.tapState(g.a, ActClear, "9")
	msg, _ := res["error"].(string)
	if code != http.StatusConflict || len(al.resolved) != 0 {
		t.Fatalf("clear on a fixed alert: %d %v", code, al.resolved)
	}
	for _, want := range []string{"lift the edge's cut", "resume the core's channel"} {
		if !strings.Contains(msg, want) {
			t.Errorf("answer %q lacks %q", msg, want)
		}
	}
	if msg != errFixed.Error() {
		t.Errorf("answer %q is not errFixed", msg)
	}
}
