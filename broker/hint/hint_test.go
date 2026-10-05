package hint

import (
	"errors"
	"testing"
)

// REQ: OSS-1, OSS-5

func good() Hint {
	return Hint{Kind: "skill_gap", Fields: map[string]string{"domain": "calendar", "format": "ics", "failure": "timezone"}}
}

// TestOSS1OnlyEnumeratedValues: a hint is valid only when its kind is in
// the schema and it carries exactly that kind's fields, each set to one of
// the listed values.
func TestOSS1OnlyEnumeratedValues(t *testing.T) {
	s := Default()
	if err := s.Validate(good()); err != nil {
		t.Fatalf("good hint: %v", err)
	}
	bad := map[string]Hint{
		"unknown kind":       {Kind: "note", Fields: map[string]string{"domain": "calendar"}},
		"missing field":      {Kind: "skill_gap", Fields: map[string]string{"domain": "calendar", "format": "ics"}},
		"extra field":        {Kind: "skill_gap", Fields: map[string]string{"domain": "calendar", "format": "ics", "failure": "timezone", "detail": "timezone"}},
		"free text":          {Kind: "skill_gap", Fields: map[string]string{"domain": "calendar", "format": "ics", "failure": "the 9am meeting with Ann"}},
		"number":             {Kind: "skill_gap", Fields: map[string]string{"domain": "calendar", "format": "ics", "failure": "42"}},
		"other field's list": {Kind: "skill_gap", Fields: map[string]string{"domain": "ics", "format": "ics", "failure": "timezone"}},
		"case variant":       {Kind: "skill_gap", Fields: map[string]string{"domain": "Calendar", "format": "ics", "failure": "timezone"}},
		"padded":             {Kind: "skill_gap", Fields: map[string]string{"domain": "calendar ", "format": "ics", "failure": "timezone"}},
		"nil fields":         {Kind: "skill_gap"},
	}
	for name, h := range bad {
		if err := s.Validate(h); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: got %v", name, err)
		}
	}
}

// TestOSS1StrictWireForm: the JSON form accepts only {"kind":..,"fields":{..}}
// with string values; anything else (numbers, nesting, unknown or repeated
// keys, trailing data) is refused before validation.
func TestOSS1StrictWireForm(t *testing.T) {
	s := Default()
	h, err := s.ParseJSON([]byte(` {"fields":{"failure":"timezone","format":"ics","domain":"calendar"},"kind":"skill_gap"} `))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if h.Kind != "skill_gap" || h.Fields["format"] != "ics" {
		t.Fatalf("parsed %+v", h)
	}
	for _, src := range []string{
		`{"kind":"skill_gap","fields":{"domain":"calendar","format":"ics","failure":7}}`,
		`{"kind":"skill_gap","fields":{"domain":"calendar","format":"ics","failure":["timezone"]}}`,
		`{"kind":"skill_gap","fields":{"domain":"calendar","format":"ics","failure":{"a":"b"}}}`,
		`{"kind":"skill_gap","fields":{"domain":"calendar","format":"ics","failure":null}}`,
		`{"kind":"skill_gap","fields":{"domain":"calendar","format":"ics","failure":"timezone"},"note":"hi"}`,
		`{"kind":"skill_gap","kind":"vuln","fields":{"domain":"calendar","format":"ics","failure":"timezone"}}`,
		`{"kind":"skill_gap","fields":{"domain":"calendar","domain":"email","format":"ics","failure":"timezone"}}`,
		`{"kind":"skill_gap","fields":{"domain":"calendar","format":"ics","failure":"timezone"}} {}`,
		`{"kind":"skill_gap","fields":{"domain":"calendar","format":"ics","failure":"timezone"}`,
		`["skill_gap"]`,
		`{"kind":1,"fields":{}}`,
		`{"fields":{"domain":"calendar","format":"ics","failure":"timezone"}}`,
		`{"kind":"skill_gap","fields":{"domain":"calendar","format":"ics","failure":"other"}}`,
	} {
		if _, err := s.ParseJSON([]byte(src)); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: got %v", src, err)
		}
	}
}

// TestOSS1CanonicalForm: what crosses the bridge is re-encoded from the
// validated values alone, so key order, spacing, and escapes in the
// submitted form cannot carry information. Vuln hints carry the embargo
// mark (OSS-5).
func TestOSS1CanonicalForm(t *testing.T) {
	s := Default()
	a, err := s.ParseJSON([]byte(`{"kind":"skill_gap","fields":{"domain":"calendar","format":"ics","failure":"timezone"}}`))
	if err != nil {
		t.Fatal(err)
	}
	b, err := s.ParseJSON([]byte("{\"fields\" : {\"failure\":\"time\\u007aone\",\n\"format\":\"ics\",\"domain\":\"calendar\"}, \"kind\":\"skill_gap\"}"))
	if err != nil {
		t.Fatal(err)
	}
	ca, err := s.Canonical(a)
	if err != nil {
		t.Fatal(err)
	}
	cb, _ := s.Canonical(b)
	want := `{"schema":1,"kind":"skill_gap","embargo":false,"fields":{"domain":"calendar","failure":"timezone","format":"ics"}}`
	if string(ca) != want || string(cb) != want {
		t.Fatalf("canonical\n%s\n%s", ca, cb)
	}
	v, err := s.Canonical(Hint{Kind: "vuln", Fields: map[string]string{"class": "prompt_injection", "vector": "email_html"}})
	if err != nil {
		t.Fatal(err)
	}
	if string(v) != `{"schema":1,"kind":"vuln","embargo":true,"fields":{"class":"prompt_injection","vector":"email_html"}}` {
		t.Fatalf("vuln canonical %s", v)
	}
	if _, err := s.Canonical(Hint{Kind: "vuln"}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("invalid canonical: %v", err)
	}
}
