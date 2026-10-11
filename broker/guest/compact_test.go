package guest

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestWhitespaceGoesAndNothingElseDoes(t *testing.T) {
	in := "{\n  \"name\": \"Ada\",\n  \"n\": 10.50,\n  \"note\": \"keep  spaces\"\n}\n"
	got := compactJSON(in)
	if got == in || len(got) >= len(in) {
		t.Fatalf("not shorter: %q", got)
	}
	var a, b map[string]any
	if json.Unmarshal([]byte(in), &a) != nil || json.Unmarshal([]byte(got), &b) != nil {
		t.Fatal("unmarshal")
	}
	if a["name"] != b["name"] || b["note"] != "keep  spaces" {
		t.Fatalf("value changed: %#v %#v", a, b)
	}
	if !strings.Contains(got, "10.50") || !strings.Contains(got, `"name"`) {
		t.Fatalf("number or key changed: %s", got)
	}
}

func TestPlainTextStays(t *testing.T) {
	for _, s := range []string{"", "results", "not json {", "[]", "0"} {
		if got := compactJSON(s); got != s {
			t.Fatalf("%q became %q", s, got)
		}
	}
}
