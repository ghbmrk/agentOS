package route

import (
	"strings"
	"testing"
)

// REQ: OP-8, ARC-7

// TestObjectRefusesAmbiguousBodies: Object, moved from broker/meter
// (#2585), accepts one JSON object and refuses anything a case-folding
// decoder could read differently from the exact key checked.
func TestObjectRefusesAmbiguousBodies(t *testing.T) {
	canon := []string{"n", "max_tokens"}
	for _, c := range []struct {
		name, body string
		ok         bool
		why        string
	}{
		{"plain", `{"n":1,"max_tokens":5,"model":"m"}`, true, ""},
		{"empty object", `{}`, true, ""},
		{"not an object", `[1]`, false, "not a JSON object"},
		{"empty", ``, false, "not a JSON object"},
		{"truncated", `{"n":1`, false, "not a JSON object"},
		{"trailing data", `{"n":1} {}`, false, "trailing data"},
		{"repeated key", `{"model":"a","model":"b"}`, false, "repeated"},
		{"keys differ in case", `{"Model":"a","model":"b"}`, false, "repeated"},
		{"canon misspelt", `{"N":2}`, false, `must be spelled "n"`},
		{"canon misspelt nested case", `{"MAX_TOKENS":9}`, false, `must be spelled "max_tokens"`},
		{"kelvin sign folds to k", `{"max_toKens":9}`, false, `must be spelled "max_tokens"`},
		{"kelvin sign repeats a key", `{"K":1,"k":2}`, false, "repeated"},
	} {
		obj, err := Object([]byte(c.body), canon...)
		if c.ok {
			if err != nil {
				t.Errorf("%s: refused: %v", c.name, err)
			}
			continue
		}
		if err == nil || obj != nil {
			t.Errorf("%s: accepted %v", c.name, obj)
		} else if !strings.Contains(err.Error(), c.why) {
			t.Errorf("%s: error %q, want it to say %q", c.name, err, c.why)
		}
	}
	obj, err := Object([]byte(`{"n":1,"x":{"n":2,"n":3}}`), canon...)
	if err != nil || string(obj["n"]) != "1" {
		t.Fatalf("nested object: %v %v; only top-level keys are checked", obj, err)
	}
}
