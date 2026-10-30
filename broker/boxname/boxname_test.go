package boxname

// REQ: CH-21

import (
	"bytes"
	"crypto/rand"
	"errors"
	"strings"
	"testing"
)

// TestNameCheck: a box name is 1 to 32 letters, spaces, hyphens, and
// apostrophes; not a control word; without "AgentOS" or "assistant"; and
// not the owner's name when it is known (SPEC CH-21).
func TestNameCheck(t *testing.T) {
	ok := []struct{ in, want string }{
		{"Dave Smith", "Dave Smith"},
		{"  Dave   Smith  ", "Dave Smith"},
		{"Mary-Jane O'Neil", "Mary-Jane O'Neil"},
		{"Zoë", "Zoë"},
		{"D", "D"},
		{strings.Repeat("a", 32), strings.Repeat("a", 32)},
		{"Stop Watson", "Stop Watson"}, // a control word inside a name is fine
	}
	for _, c := range ok {
		got, err := Check(c.in, "Mark Jones")
		if err != nil || got != c.want {
			t.Errorf("Check(%q) = %q, %v; want %q", c.in, got, err, c.want)
		}
	}
	bad := []struct {
		in, owner string
		want      error
	}{
		{"", "", ErrShape},
		{"   ", "", ErrShape},
		{"-'", "", ErrShape}, // no letter
		{strings.Repeat("a", 33), "", ErrShape},
		{"R2D2", "", ErrShape},
		{"dave@example.com", "", ErrShape},
		{"www.evil.example", "", ErrShape},
		{"Dave (Mark's AgentOS assistant)", "", ErrShape},
		{"Dave‮Smith", "", ErrShape}, // direction override
		{"Dave\tSmith", "", ErrShape},
		{"Dave\nSmith", "", ErrShape},
		{"Stop", "", ErrControlWord},
		{"s-t-o-p", "", ErrControlWord},
		{"Unlock", "", ErrControlWord},
		{"Name", "", ErrControlWord},
		{"No", "", ErrControlWord},
		{"Help", "", ErrControlWord},
		{"Agent OS", "", ErrReserved},
		{"AgentOS Dave", "", ErrReserved},
		{"Dave Assistant", "", ErrReserved},
		{"Assist-Ant", "", ErrReserved},
		{"Mark Jones", "Mark Jones", ErrOwnerName},
		{"mark  jones", "Mark Jones", ErrOwnerName},
		{"Mark-Jones", "Mark Jones", ErrOwnerName},
	}
	for _, c := range bad {
		if _, err := Check(c.in, c.owner); !errors.Is(err, c.want) {
			t.Errorf("Check(%q, %q) = %v; want %v", c.in, c.owner, err, c.want)
		}
	}
	// With the owner's name unknown, it cannot be matched.
	if _, err := Check("Mark Jones", ""); err != nil {
		t.Errorf("owner unknown: %v", err)
	}
}

// TestShapeIsTheSyntacticPart: Shape accepts exactly the names whose
// characters and length fit, whatever the other checks say, so the
// channel can tell a NAME command from chat that starts with "name".
func TestShapeIsTheSyntacticPart(t *testing.T) {
	for _, s := range []string{"Dave Smith", "Stop", "AgentOS", "it Bob"} {
		if !Shape(s) {
			t.Errorf("Shape(%q) = false", s)
		}
	}
	for _, s := range []string{"the file report.pdf", "R2D2", "", "a new name for the folder with my taxes"} {
		if Shape(s) {
			t.Errorf("Shape(%q) = true", s)
		}
	}
}

// TestSuggestPassesCheck: setup offers a made-up full name the owner keeps
// or overwrites (SPEC CH-21), so every name Suggest can return passes the
// name check, and a draw that is the owner's name is drawn again.
func TestSuggestPassesCheck(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 32; i++ {
		for j := 0; j < 32; j++ {
			n, err := Suggest(bytes.NewReader([]byte{byte(i), byte(j)}), "")
			if err != nil {
				t.Fatalf("Suggest(%d, %d): %v", i, j, err)
			}
			if got, err := Check(n, ""); err != nil || got != n || !strings.Contains(n, " ") {
				t.Errorf("Suggest gave %q, which Check reads as %q, %v", n, got, err)
			}
			seen[n] = true
		}
	}
	if len(seen) != 32*32 {
		t.Errorf("%d distinct names, want %d", len(seen), 32*32)
	}
	// The high bits are ignored, so each byte value picks one name.
	a, _ := Suggest(bytes.NewReader([]byte{3, 0}), "")
	b, _ := Suggest(bytes.NewReader([]byte{3 + 32, 0 + 64}), "")
	if a != "Dave Smith" || b != a {
		t.Errorf("Suggest(3, 0) = %q, Suggest(35, 64) = %q; want both Dave Smith", a, b)
	}
	if n, err := Suggest(rand.Reader, ""); err != nil || n == "" {
		t.Errorf("Suggest(rand.Reader) = %q, %v", n, err)
	}
}

// TestSuggestNotOwnerName: a suggestion is never the owner's own name.
func TestSuggestNotOwnerName(t *testing.T) {
	n, err := Suggest(bytes.NewReader([]byte{3, 0, 3, 0, 4, 1}), "dave  SMITH")
	if err != nil || n != "Ella Jones" {
		t.Errorf("Suggest = %q, %v; want the third draw, Ella Jones", n, err)
	}
	if _, err := Suggest(bytes.NewReader(bytes.Repeat([]byte{3, 0}, suggestTries)), "Dave Smith"); !errors.Is(err, ErrNoSuggestion) {
		t.Errorf("every draw the owner's name: %v, want ErrNoSuggestion", err)
	}
	if _, err := Suggest(bytes.NewReader([]byte{1}), ""); !errors.Is(err, ErrNoSuggestion) {
		t.Errorf("short reader: %v, want ErrNoSuggestion", err)
	}
}
