package format

// REQ: CAP-5

import (
	"bytes"
	"strings"
	"testing"
)

func honest(t *testing.T) *Skill {
	t.Helper()
	s := &Skill{Version: Version, Kind: KindSkill, Runs: 3,
		Slots: []Slot{{Name: "to", Type: Email, Max: 64}, {Name: "n", Type: Number, Max: 1}},
		Steps: []Step{{Account: "mail", Action: "send",
			Params:     map[string]Node{"body": {Obj: map[string]Node{"size": {Slot: "n"}, "text": {Lit: []byte(`"hi"`)}}}},
			Recipients: []Node{{Slot: "to"}}}}}
	s.ID = "k" + s.Shape()
	if err := s.Validate(); err != nil {
		t.Fatal(err)
	}
	return s
}

// CAP-5 (P3-6e, #89 C2): only the canonical encoding decodes, and a file
// is accepted only under its own name: its ID, and the shape its steps
// give.
func TestDecodeFileTakesOnlyItsOwnCanonicalName(t *testing.T) {
	s := honest(t)
	b := s.Encode()
	if _, err := DecodeFile(s.Path(), b); err != nil {
		t.Fatal(err)
	}
	other := honest(t)
	other.Steps[0].Action = "draft" // another task's steps, under s's ID
	other.ID = s.ID
	for name, c := range map[string]struct{ path, file string }{
		"duplicate key":   {s.Path(), strings.Replace(string(b), `{"version":1,`, `{"version":1,"kind":"procedure",`, 1)},
		"trailing }":      {s.Path(), string(b) + "}"},
		"trailing ]":      {s.Path(), string(b) + "]"},
		"spacing":         {s.Path(), " " + string(b)},
		"other path":      {"procedures/p" + s.ID[1:] + ".json", string(b)},
		"other task":      {s.Path(), string(other.Encode())},
		"empty obj":       {s.Path(), strings.Replace(string(b), `"params":{`, `"params":{"zzz":{"obj":{}},`, 1)},
		"data param key":  {s.Path(), strings.Replace(string(b), `"params":{`, `"params":{"A/b":{"lit":1},`, 1)},
		"data object key": {s.Path(), strings.Replace(string(b), `{"obj":{`, `{"obj":{"A~b":{"lit":1},`, 1)},
	} {
		if bytes.Equal([]byte(c.file), b) && c.path == s.Path() {
			t.Fatalf("%s: fixture unchanged", name)
		}
		if _, err := DecodeFile(c.path, []byte(c.file)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
