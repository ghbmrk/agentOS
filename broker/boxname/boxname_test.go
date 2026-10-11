package boxname

// REQ: CH-21

import (
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
