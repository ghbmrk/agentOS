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

// The accessible name of an element containing the field includes its
// value, so a copy in the field's ancestors is scrubbed. A copy anywhere
// else, in an element labelled by the field or one that echoes it,
// withholds the snapshot: scrubbing it would point at the text that
// equals the value (#2245, comment 6239722241).
func TestCRED4PasswordValueScrubbedFromOtherNames(t *testing.T) {
	refs := map[string]bool{"e5": true}
	for _, c := range []struct {
		in, secret string
		held       bool
	}{
		{"- table [ref=e1]:\n  - rowgroup [ref=e2]:\n    - row \"Pass hunter2\" [ref=e3]:\n      - cell \"Pass\" [ref=e4]\n      - cell \"hunter2\" [ref=e6]:\n        - textbox [ref=e5]: hunter2", "hunter2", false},
		{"- link \"hunter2\" [ref=e2] [cursor=pointer]:\n  - /url: \"#\"\n  - textbox [ref=e5]: hunter2", "hunter2", false},
		{"- button \"Show hunter2\" [ref=e2]:\n  - textbox [ref=e5]: hunter2", "hunter2", false},
		{"- textbox \"Password\" [ref=e5]: hunter2\n- button \"hunter2\" [ref=e6]", "hunter2", true},
		{"- textbox \"Password\" [ref=e5]:\n  - text: hunter2\n- button \"hunter2\" [ref=e6]", "hunter2", true},
		{"- textbox [ref=e5]: \"pa: ss\"\n- button \"pa: ss\" [ref=e6]", "pa: ss", true},
		{"- textbox [ref=e5]: 'it''s'\n- button \"it's\" [ref=e6]", "it's", true},
		{"- textbox [ref=e5]: q\"u\\o\n- button \"q\\\"u\\\\o\" [ref=e6]", `u\\o`, true},
		{"- textbox [ref=e5]: hun   ter2\n- button \"hun ter2\" [ref=e6]", "hun ter2", true},
		{"- 'row \"Login: it''s\" [ref=e2]':\n  - textbox \"Password\" [ref=e5]: it's", "it''s", false},
		{"- textbox \"Password\" [ref=e5]: it's\n- 'button \"Show: it''s\" [ref=e7]'", "it''s", true},
		{"- textbox [ref=e5]: \"it's: x\"\n- 'cell \"it''s: x\" [ref=e8]'", "it''s: x", true},
		{"- 'row \"Password: pa''ss\" [ref=e3]':\n  - textbox \"Password\" [ref=e5]: pa'ss", "pa''ss", false},
		{"- textbox [ref=e5]: 'q\"u''s'\n- 'button \"Show: q\\\"u''s\" [ref=e7]'", "u''s", true},
		{"- heading \"Results for hunter2\" [level=1]\n- textbox [ref=e5]: hunter2", "hunter2", true},
		{"- textbox [ref=e5]: ab[ref=e9]hunter2\n- text: hunter2", "hunter2", true},
	} {
		got := OmitValues(c.in, refs)
		if strings.Contains(got, c.secret) || (got == withheldMark) != c.held || (!c.held && !strings.Contains(got, "[ref=e5]")) {
			t.Fatalf("%q -> %q", c.in, got)
		}
	}
	other := "- textbox \"Password\" [ref=e5]: hunter2\n- button \"Sign in\" [ref=e6]"
	if got := OmitValues(other, refs); !strings.HasSuffix(got, "\n- button \"Sign in\" [ref=e6]") {
		t.Fatalf("unrelated name changed: %q", got)
	}
}

// entryRefs is the gate's own password-ref set (K14): every entry field
// showing a value its ref was not given by the agent.
func TestEntryRefs(t *testing.T) {
	snap := strings.Join([]string{
		`- textbox "Email" [ref=e1]: a@example.test`,
		`- textbox "Empty" [ref=e2]`,
		`- searchbox "Find" [ref=e3]:`,
		`  - /placeholder: Search`,
		`  - text: lamp`,
		`- textbox "Typed" [active] [ref=e4]: kettle`,
		`- button "Go" [ref=e5]`,
		`- textbox Bad name [ref=e6] [ref=e7]: x`,
		`- spinbutton "Qty" [ref=e8]: "2"`,
		`- combobox "Size" [ref=e9]: M`,
	}, "\n")
	got, _ := entryRefs(snap, map[string]string{"e4": "kettle"})
	want := map[string]bool{"e1": true, "e3": true, "e6": true, "e7": true, "e8": true}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for r := range want {
		if !got[r] {
			t.Fatalf("got %v, want %v", got, want)
		}
	}
}

// Review comment 6239829840 on #2245: a field's ref is the one in the
// attribute run after its name, never a [ref=...] inside its value, so a
// value cannot borrow the ref of a field the agent typed into.
func TestCRED4RefOnlyInAttributePosition(t *testing.T) {
	snap := "- textbox \"Ed\" [ref=e4]: x\n- textbox \"K\": y[ref=e4]hunter2Canary"
	refs, _ := entryRefs(snap, map[string]string{"e4": "x"})
	if refs["e4"] || !refs[noRef] {
		t.Fatalf("refs = %v", refs)
	}
	got := omitValues(snap, refs, map[string]bool{"e4": true})
	want := "- textbox \"Ed\" [ref=e4]: x\n- textbox \"K\": " + omittedMark
	if got != want {
		t.Fatalf("got %q", got)
	}
}

// A rich-text editor (a contenteditable with role textbox) renders its
// draft as paragraph nodes: they are its structure, not a field value, so
// the draft is shown. Text children and lines that are not nodes still
// count (#2245).
func TestCRED4RichTextChildrenAreNotValues(t *testing.T) {
	draft := "- textbox \"Message\" [ref=e5]:\n  - paragraph: Hello team\n  - paragraph [ref=e6]\n  - generic: see you"
	if refs, _ := entryRefs(draft, nil); len(refs) != 0 {
		t.Fatalf("draft treated as a value: %v", refs)
	}
	for _, in := range []string{
		"- textbox \"M\" [ref=e5]:\n  - text: hunter2",
		"- textbox \"M\" [ref=e5]:\n  - 'text: hunter2'",
		"- textbox \"M\" [ref=e5]:\n    hunter2",
		"- textbox \"M\" [ref=e5]:\n  - /value: hunter2",
	} {
		if refs, _ := entryRefs(in, nil); !refs["e5"] {
			t.Fatalf("%q: value not flagged", in)
		}
	}
}

// A value shorter than minScrub (a CVV) is scrubbed from the field's
// ancestors, whose names carry it, but not from the rest of the page, and
// never from a role or ref (#2245).
func TestCRED4ShortValueScrubbedFromAncestors(t *testing.T) {
	in := "- row \"CVV 123\" [ref=e2]:\n  - cell \"CVV 123\":\n    - textbox \"CVV\" [ref=e5]: \"123\"\n- text: Order 1234"
	want := "- row \"CVV " + omittedMark + "\" [ref=e2]:\n  - cell \"CVV " + omittedMark + "\":\n    - textbox \"CVV\" [ref=e5]: " + omittedMark + "\n- text: Order 1234"
	if got := OmitValues(in, map[string]bool{"e5": true}); got != want {
		t.Fatalf("got %q", got)
	}
	in = "- row \"e2 row\" [ref=e2]:\n  - textbox [ref=e5]: row"
	if got := OmitValues(in, map[string]bool{"e5": true}); !strings.HasPrefix(got, "- row \"e2 "+omittedMark+"\" [ref=e2]:") {
		t.Fatalf("got %q", got)
	}
}

// A typed ref is stale once its field shows other text or is cleared, so
// the gate stops exempting it before the page can fill it again (#2245).
func TestEntryRefsStaleTyped(t *testing.T) {
	snap := "- textbox \"A\" [ref=e1]: kettle\n- textbox \"B\" [ref=e2]: other\n- textbox \"C\" [ref=e3]\n- textbox \"D\" [ref=e4]:\n  - /placeholder: Search"
	_, stale := entryRefs(snap, map[string]string{"e1": "kettle", "e2": "kettle", "e3": "kettle", "e4": "kettle", "e9": "kettle"})
	if len(stale) != 3 || !stale["e2"] || !stale["e3"] || !stale["e4"] {
		t.Fatalf("stale = %v", stale)
	}
}
