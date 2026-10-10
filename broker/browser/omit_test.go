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

// Any line shape other than the canonical `- role "name" [ref=…]` or
// `- role [ref=…]` cannot be parsed, so it fails closed too (L3 on 3f5687d).
func TestCRED4NonCanonicalLineFailsClosed(t *testing.T) {
	refs := map[string]bool{"e5": true}
	for _, in := range []string{
		`- textbox x [ref=e1] [ref=e5]: hunter2`,
		`- textbox /x [ref=e1]/ [ref=e5]: hunter2`,
		`- textbox  "x [ref=e1]" [ref=e5]: hunter2`,
		`-  textbox "x [ref=e1]" [ref=e5]: hunter2`,
		`- "textbox \"x [ref=e1]\" [ref=e5]: hunter2"`,
		`[ref=e1] [ref=e5]: hunter2`,
	} {
		got := OmitValues(in, refs)
		if strings.Contains(got, "hunter2") || !strings.Contains(got, "[password omitted]") || !strings.Contains(got, "[ref=e5]") {
			t.Fatalf("%q -> %q", in, got)
		}
	}
	for _, in := range []string{
		`- textbox x [ref=e1] [ref=e6]: ada`,
		`- /url: https://example.test/a`,
		`- text: plain`,
	} {
		if got := OmitValues(in, refs); got != in {
			t.Fatalf("non-password changed: %q -> %q", in, got)
		}
	}
}

// Shapes measured from Playwright 1.56.1 snapshots on Chromium (Security 4a
// on b6fa419). With a placeholder, the value is a child line of the password
// node.
func TestCRED4PasswordChildValueIsOmitted(t *testing.T) {
	in := "- form:\n  - textbox \"Password\" [ref=e5]:\n    - /placeholder: Enter password\n    - text: hunter2\n  - button \"Sign in\" [ref=e6]"
	want := "- form:\n  - textbox \"Password\" [ref=e5]:\n    - /placeholder: Enter password\n    - text: [password omitted]\n  - button \"Sign in\" [ref=e6]"
	if got := OmitValues(in, map[string]bool{"e5": true}); got != want {
		t.Fatalf("%q", got)
	}
}

// The accessible name of an element containing, or labelled by, the field
// includes its value, so every other copy of an omitted value is scrubbed.
func TestCRED4PasswordValueScrubbedFromOtherNames(t *testing.T) {
	refs := map[string]bool{"e5": true}
	for _, c := range []struct{ in, secret string }{
		{"- table [ref=e1]:\n  - rowgroup [ref=e2]:\n    - row \"Pass hunter2\" [ref=e3]:\n      - cell \"Pass\" [ref=e4]\n      - cell \"hunter2\" [ref=e6]:\n        - textbox [ref=e5]: hunter2", "hunter2"},
		{"- link \"hunter2\" [ref=e2] [cursor=pointer]:\n  - /url: \"#\"\n  - textbox [ref=e5]: hunter2", "hunter2"},
		{"- button \"Show hunter2\" [ref=e2]:\n  - textbox [ref=e5]: hunter2", "hunter2"},
		{"- textbox \"Password\" [ref=e5]: hunter2\n- button \"hunter2\" [ref=e6]", "hunter2"},
		{"- textbox \"Password\" [ref=e5]:\n  - text: hunter2\n- button \"hunter2\" [ref=e6]", "hunter2"},
		{"- textbox [ref=e5]: \"pa: ss\"\n- button \"pa: ss\" [ref=e6]", "pa: ss"},
		{"- textbox [ref=e5]: 'it''s'\n- button \"it's\" [ref=e6]", "it's"},
		{"- textbox [ref=e5]: q\"u\\o\n- button \"q\\\"u\\\\o\" [ref=e6]", `u\\o`},
		{"- textbox [ref=e5]: hun   ter2\n- button \"hun ter2\" [ref=e6]", "hun ter2"},
	} {
		got := OmitValues(c.in, refs)
		if strings.Contains(got, c.secret) || !strings.Contains(got, "[ref=e5]") {
			t.Fatalf("%q -> %q", c.in, got)
		}
	}
	other := "- textbox \"Password\" [ref=e5]: hunter2\n- button \"Sign in\" [ref=e6]"
	if got := OmitValues(other, refs); !strings.HasSuffix(got, "\n- button \"Sign in\" [ref=e6]") {
		t.Fatalf("unrelated name changed: %q", got)
	}
}
