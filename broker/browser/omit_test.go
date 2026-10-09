package browser

import (
	"strings"
	"testing"
)

// REQ: CRED-4

func TestCRED4PasswordValueIsOmitted(t *testing.T) {
	in := "- textbox \"Password\" [ref=e5]: hunter2"
	got := OmitValues(in, map[string]bool{"e5": true})
	if strings.Contains(got, "hunter2") || !strings.Contains(got, "[password omitted]") || !strings.Contains(got, "e5") {
		t.Fatalf("%q", got)
	}
	other := "- textbox \"Name\" [ref=e6]: ada"
	if OmitValues(other, map[string]bool{"e5": true}) != other {
		t.Fatal("a non-password value was removed")
	}
}

// The accessible name is page-controlled, so a [ref=...] token inside it is
// a decoy, at any indentation and with either YAML quoting.
func TestCRED4PasswordValueOmittedDespiteDecoyRefInName(t *testing.T) {
	refs := map[string]bool{"e5": true}
	for _, in := range []string{
		`- textbox "foo [ref=e1]" [ref=e5]: hunter2`,
		`- textbox "a [ref=e1]: b" [ref=e5]: hunter2`,
		`- textbox "q \" [ref=e1] " [ref=e5]: hunter2`,
		`  - textbox "x [ref=e1]" [ref=e5]: hunter2`,
		"\t\t- textbox \"x [ref=e1]\" [ref=e5]: hunter2",
		`    - 'textbox "x [ref=e1]" [ref=e5]: hunter2'`,
		`    - 'textbox "a: [ref=e1]" [ref=e5]': hunter2`,
	} {
		got := OmitValues(in, refs)
		if strings.Contains(got, "hunter2") || !strings.Contains(got, "[password omitted]") {
			t.Fatalf("%q -> %q", in, got)
		}
	}
	// A decoy naming the password ref on another element changes nothing.
	for _, in := range []string{
		`- textbox "foo [ref=e5]" [ref=e6]: ada`,
		`  - textbox "foo [ref=e5]" [ref=e6]: ada`,
	} {
		if got := OmitValues(in, refs); got != in {
			t.Fatalf("non-password changed: %q -> %q", in, got)
		}
	}
}

// A name whose quote never closes cannot be parsed. If any ref on the line is
// a password field, the value is omitted (fail closed).
func TestCRED4UnterminatedNameFailsClosed(t *testing.T) {
	refs := map[string]bool{"e5": true}
	for _, in := range []string{
		`- textbox "x [ref=e5]: hunter2`,
		`- textbox "x [ref=e1] [ref=e5]: hunter2`,
		`  - textbox "x \" [ref=e5]: hunter2`,
		`    - 'textbox "x [ref=e5]': hunter2`,
		`- textbox "x [ref=e5]: hunter2\`,
	} {
		got := OmitValues(in, refs)
		if strings.Contains(got, "hunter2") || !strings.Contains(got, "[password omitted]") || !strings.Contains(got, "[ref=e5]") {
			t.Fatalf("%q -> %q", in, got)
		}
	}
	other := `- textbox "x [ref=e6]: ada`
	if got := OmitValues(other, refs); got != other {
		t.Fatalf("non-password changed: %q", got)
	}
}

func TestCRED4OmitValuesKeepsOtherLines(t *testing.T) {
	in := "- form:\n  - textbox \"User\" [ref=e4]: ada\n  - textbox \"Password\" [ref=e5]: hunter2\n  - button \"Sign in\" [ref=e6]"
	want := "- form:\n  - textbox \"User\" [ref=e4]: ada\n  - textbox \"Password\" [ref=e5]: [password omitted]\n  - button \"Sign in\" [ref=e6]"
	if got := OmitValues(in, map[string]bool{"e5": true}); got != want {
		t.Fatalf("%q", got)
	}
}
