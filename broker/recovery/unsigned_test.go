package recovery

// REQ: CH-21

import (
	"strings"
	"testing"
	"time"
)

// TestOwnerTextsAreUnsigned: texts to the owner carry no name or
// signature (CH-21); the restore notices speak as "I".
func TestOwnerTextsAreUnsigned(t *testing.T) {
	for _, n := range []string{
		RestoreNotice(Report{Source: "drive"}),
		RestoreNotice(Report{Created: time.Date(2026, 10, 5, 0, 0, 0, 0, time.UTC)}),
	} {
		if strings.Contains(strings.ToLower(n), "agentos") || !strings.HasPrefix(n, "I was restored") {
			t.Fatalf("signed or not first person: %q", n)
		}
	}
	nc := &NumberChange{Code: "12345678", Expires: time.Unix(100, 0)}
	_, texts, err := nc.Complete("+15550000777", "+15550000888", "12345678", time.Unix(50, 0))
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{texts.ToOld, texts.ToNew} {
		if strings.Contains(strings.ToLower(s), "agentos") {
			t.Fatalf("signed: %q", s)
		}
	}
}
