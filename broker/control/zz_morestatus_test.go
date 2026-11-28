package control

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"testing"
)

// REQ: CH-11, CH-12

func TestParseMoreForms(t *testing.T) {
	for s, want := range map[string][]string{
		"MORE K3":        {"K3"},
		"more k3, 12":    {"K3", "12"},
		"MORE STATUS":    {"STATUS"},
		"More status 4.": {"STATUS", "4"},
	} {
		c := Parse(s)
		if c.Word != WordMore || strings.Join(c.Args, " ") != strings.Join(want, " ") {
			t.Fatalf("%q: %+v", s, c)
		}
	}
	for _, s := range []string{"MORE", "MORE K3 0", "MORE K3 100", "MORE K3 1 2", "MORE STATUS X", "more status please", "MORE ABCD"} {
		if c := Parse(s); c.Word != WordNone {
			t.Fatalf("%q parsed as %+v", s, c)
		}
	}
}

var nextStatusRe = regexp.MustCompile(` Next: MORE STATUS ([0-9]+)\.$`)

// MORE STATUS pages the lines the texted STATUS left out, in order, each
// page within one text; every line is reachable, each page reads the
// same twice, and it needs the same proof as STATUS.
func TestMoreStatusPagesTheLeftOutLines(t *testing.T) {
	h, _ := newHandler(t, &fakeEngine{}, fakeAuth{unlocked: true}, nil)
	var notes []string
	for i := 0; i < 20; i++ {
		l := fmt.Sprintf("Note %02d: ", i) + strings.Repeat("x", 88) + "."
		notes = append(notes, l)
		h.Notes = append(h.Notes, func() string { return l })
	}
	s := one(t, h.Handle(context.Background(), owner, "STATUS"))
	shown := 0
	for _, l := range notes {
		if strings.Contains(s, l) {
			shown++
		}
	}
	if !strings.HasSuffix(s, fmt.Sprintf(" %d more lines: MORE STATUS.", len(notes)-shown)) {
		t.Fatalf("STATUS tail: %q", s)
	}
	var seen []string
	cmd := "MORE STATUS"
	for pages := 0; cmd != ""; pages++ {
		if pages > len(notes) {
			t.Fatal("too many pages")
		}
		p := one(t, h.Handle(context.Background(), owner, cmd))
		if again := one(t, h.Handle(context.Background(), owner, cmd)); again != p || len(p) > MaxText {
			t.Fatalf("%s: %q then %q", cmd, p, again)
		}
		if !strings.HasPrefix(p, "STATUS, more line") || !strings.Contains(p, fmt.Sprintf(" of %d:", len(notes)-shown)) {
			t.Fatalf("%s page: %q", cmd, p)
		}
		for _, l := range notes {
			if strings.Contains(p, l) {
				seen = append(seen, l)
			}
		}
		cmd = ""
		if m := nextStatusRe.FindStringSubmatch(p); m != nil {
			cmd = "MORE STATUS " + m[1]
		}
	}
	if strings.Join(seen, "|") != strings.Join(notes[shown:], "|") {
		t.Fatalf("MORE STATUS reached %d lines, want the %d left out", len(seen), len(notes)-shown)
	}
	if p := one(t, h.Handle(context.Background(), owner, "MORE STATUS 99")); !strings.Contains(p, "Reply MORE STATUS.") {
		t.Fatalf("past the end: %q", p)
	}
	h.Notes = h.Notes[:1]
	if p := one(t, h.Handle(context.Background(), owner, "MORE STATUS")); strings.Contains(p, "Note") {
		t.Fatalf("nothing left out: %q", p)
	}

	locked, _ := newHandler(t, &fakeEngine{}, fakeAuth{}, nil)
	locked.Notes = h.Notes
	if p := one(t, locked.Handle(context.Background(), owner, "MORE STATUS")); p != unlockText {
		t.Fatalf("locked MORE STATUS: %q", p)
	}
}
