package compact

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestWhitespaceGoesAndNothingElseDoes(t *testing.T) {
	in := "{\n  \"name\": \"Ada\",\n  \"n\": 10.50,\n  \"note\": \"keep  spaces\"\n}\n"
	got := JSON(in)
	if got == in || len(got) >= len(in) {
		t.Fatalf("not shorter: %q", got)
	}
	var a, b map[string]any
	if err := json.Unmarshal([]byte(in), &a); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal([]byte(got), &b); err != nil {
		t.Fatal(err)
	}
	if a["name"] != b["name"] || a["note"] != "keep  spaces" || b["note"] != "keep  spaces" {
		t.Fatalf("value changed: %#v %#v", a, b)
	}
	if !strings.Contains(got, "10.50") {
		t.Fatalf("number text changed: %s", got)
	}
	if !strings.Contains(got, `"name"`) || !strings.Contains(got, `"keep  spaces"`) {
		t.Fatalf("keys or string changed: %s", got)
	}
}

func TestPlainTextAndErrorsStay(t *testing.T) {
	for _, s := range []string{"", "results", "not json {", "[]", "0"} {
		if got := JSON(s); got != s {
			t.Fatalf("%q became %q", s, got)
		}
	}
}
