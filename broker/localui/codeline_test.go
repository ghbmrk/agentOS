package localui

// REQ: CH-21

import (
	"os"
	"strings"
	"testing"
)

// TestCodeLineIsTheSpecWording: the welcome text's code line is CH-21's,
// word for word, in both forms of the welcome text.
func TestCodeLineIsTheSpecWording(t *testing.T) {
	b, err := os.ReadFile("../../SPEC.md")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"`+CodeLine+`"`) {
		t.Fatalf("SPEC.md CH-21 does not quote %q", CodeLine)
	}
	for _, ok := range []bool{true, false} {
		if s := AllSetText([]string{"email"}, ok); strings.Count(s, CodeLine) != 1 {
			t.Fatalf("welcome text (private %v) lacks the code line once: %q", ok, s)
		}
	}
}
