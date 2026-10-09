package browseract

import (
	"strings"
	"testing"
)

// REQ: CRED-4, CRED-10

func mustParse(t *testing.T, raw string) Request {
	t.Helper()
	r, err := Parse([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func refuse(t *testing.T, raw string) {
	t.Helper()
	if _, err := Parse([]byte(raw)); err == nil {
		t.Fatalf("accepted %s", raw)
	}
}

func TestCRED4OnlyTheClosedVerbs(t *testing.T) {
	r := mustParse(t, `{"v":0,"verb":"click","ref":"e12"}`)
	if r.Verb != "click" || r.Ref != "e12" {
		t.Fatal(r)
	}
	mustParse(t, `{"v":0,"verb":"snapshot"}`)
	mustParse(t, `{"v":0,"verb":"type","ref":"f1e3","text":"hi","submit":true}`)
	mustParse(t, `{"v":0,"verb":"navigate","url":"https://example.test/a"}`)
	for _, raw := range []string{
		`{"v":0,"verb":"evaluate","script":"1"}`,
		`{"v":0,"verb":"click","ref":"e1","cookies":true}`,
		`{"v":0,"verb":"click","ref":"#login"}`,
		`{"v":0,"verb":"navigate","url":"javascript:alert(1)"}`,
		`{"v":0,"verb":"navigate","url":"https://user:secret@example.test/"}`,
		`{"v":0,"verb":"click","ref":"e1","url":"https://example.test/"}`,
		`{"v":1,"verb":"snapshot"}`,
		`[]`,
		`{"v":0,"verb":"type","ref":"e1","text":"` + strings.Repeat("a", MaxText+1) + `"}`,
	} {
		refuse(t, raw)
	}
}

func TestCRED10DeclaredOrigin(t *testing.T) {
	if !OnDeclaredOrigin("https://app.example.test/inbox", []string{"https://app.example.test"}) {
		t.Fatal("same origin refused")
	}
	if OnDeclaredOrigin("https://evil.test/", []string{"https://app.example.test"}) {
		t.Fatal("other origin accepted")
	}
	if OnDeclaredOrigin("https://user:pw@app.example.test/", []string{"https://app.example.test"}) {
		t.Fatal("userinfo accepted")
	}
}

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

// REQ: CRED-4
func TestCRED4PasswordValueOmittedDespiteDecoyRefInName(t *testing.T) {
	refs := map[string]bool{"e5": true}
	for _, in := range []string{
		`- textbox "foo [ref=e1]" [ref=e5]: hunter2`,
		`- textbox "a [ref=e1]: b" [ref=e5]: hunter2`,
		`- textbox "q \" [ref=e1] " [ref=e5]: hunter2`,
		`- textbox "foo [ref=e5]" [ref=e6]: ada`,
		`  - textbox "x [ref=e1]" [ref=e5]: hunter2`,
		"\t\t- textbox \"x [ref=e1]\" [ref=e5]: hunter2",
		`    - 'textbox "x [ref=e1]" [ref=e5]: hunter2'`,
	} {
		got := OmitValues(in, refs)
		leaked := strings.Contains(got, "hunter2")
		if in[len(in)-3:] == "ada" {
			if got != in {
				t.Fatalf("non-password changed: %q", got)
			}
			continue
		}
		if leaked || !strings.Contains(got, "[password omitted]") {
			t.Fatalf("%q -> %q", in, got)
		}
	}
}
