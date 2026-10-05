package attest

// REQ: OSS-4

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

// TestOSS4PublicSchemaLoads: the schema the box ships is the embedded,
// public schema.json, and it passes every structural rule.
func TestOSS4PublicSchemaLoads(t *testing.T) {
	s := Default()
	if s.Version() != 1 {
		t.Fatalf("version %d", s.Version())
	}
	for _, r := range []string{"pass", "fail"} {
		if !s.Result(r) {
			t.Fatalf("result %s missing", r)
		}
	}
	for _, c := range []string{"stable", "fast"} {
		if !s.Channel(c) {
			t.Fatalf("channel %s missing", c)
		}
	}
	if err := s.CheckHardware(Hardware{Vendor: "geekom", Model: "air12_lite", Firmware: Unlisted}); err != nil {
		t.Fatal("the floor reference PC (HW-4):", err)
	}
	if err := s.CheckVersions(map[string]string{"openclaw": "2026.9.8"}); err != nil {
		t.Fatal("the qualified guest (S4):", err)
	}
}

var goodFields = [][2]string{
	{"version", `1`},
	{"results", `["pass", "fail"]`},
	{"channels", `["stable", "fast"]`},
	{"hardware", `{"acme": {"box_1": ["1.0.2", "v7"]}}`},
	{"versions", `{"openclaw": ["2026.9.8"]}`},
}

// doc is the good schema with the named top-level values replaced and any
// extra raw "key": value entries appended.
func doc(replace map[string]string, extra ...string) string {
	var parts []string
	for _, f := range goodFields {
		v := f[1]
		if r, ok := replace[f[0]]; ok {
			v = r
		}
		parts = append(parts, `"`+f[0]+`": `+v)
	}
	return "{" + strings.Join(append(parts, extra...), ", ") + "}"
}

var good = doc(nil)

func TestOSS4ParseRefusesAnythingButEnumeratedTokens(t *testing.T) {
	if _, err := Parse([]byte(good)); err != nil {
		t.Fatal(err)
	}
	bad := map[string]string{
		"space in a value":    doc(map[string]string{"versions": `{"openclaw": ["2026 9 8"]}`}),
		"upper case":          doc(map[string]string{"hardware": `{"Acme": {"box_1": ["v7"]}}`}),
		"free text model":     doc(map[string]string{"hardware": `{"acme": {"the box in my kitchen": ["v7"]}}`}),
		"long token":          doc(map[string]string{"hardware": `{"acme": {"` + strings.Repeat("a", 33) + `": ["v7"]}}`}),
		"unlisted vendor":     doc(map[string]string{"hardware": `{"unlisted": {"box_1": ["v7"]}}`}),
		"unlisted firmware":   doc(map[string]string{"hardware": `{"acme": {"box_1": ["unlisted"]}}`}),
		"vendor with none":    doc(map[string]string{"hardware": `{"acme": {}}`}),
		"repeated value":      doc(map[string]string{"versions": `{"openclaw": ["2026.9.8", "2026.9.8"]}`}),
		"empty version list":  doc(map[string]string{"versions": `{"openclaw": []}`}),
		"leading dot":         doc(map[string]string{"versions": `{"openclaw": [".9"]}`}),
		"no results":          doc(map[string]string{"results": `[]`}),
		"no channels":         doc(map[string]string{"channels": `[]`}),
		"bad result":          doc(map[string]string{"results": `["pass", "Fail!"]`}),
		"null hardware":       doc(map[string]string{"hardware": `null`}),
		"version 0":           doc(map[string]string{"version": `0`}),
		"unknown key":         doc(nil, `"notes": "x"`),
		"timestamp field":     doc(nil, `"day": "2026-10-05"`),
		"case-variant key":    doc(nil, `"Results": ["pass"]`),
		"duplicate key":       doc(nil, `"version": 1`),
		"duplicate inner key": doc(map[string]string{"hardware": `{"acme": {"box_1": ["v7"]}, "acme": {"box_2": ["v7"]}}`}),
		"trailing data":       good + "{}",
		"not an object":       `["pass"]`,
	}
	for name, d := range bad {
		if _, err := Parse([]byte(d)); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: parsed (%v)", name, err)
		}
	}
}

// TestOSS4HardwareIsAListedChoice: vendor, model and firmware are each a
// listed value or Unlisted, and Unlisted at one level forces it below, so
// a box on hardware the schema does not know yet says only that.
func TestOSS4HardwareIsAListedChoice(t *testing.T) {
	s, err := Parse([]byte(good))
	if err != nil {
		t.Fatal(err)
	}
	ok := []Hardware{
		{"acme", "box_1", "v7"},
		{"acme", "box_1", "1.0.2"},
		{"acme", "box_1", Unlisted},
		{"acme", Unlisted, Unlisted},
		{Unlisted, Unlisted, Unlisted},
	}
	for _, h := range ok {
		if err := s.CheckHardware(h); err != nil {
			t.Errorf("%+v: %v", h, err)
		}
	}
	bad := []Hardware{
		{},                                // every field is required
		{"acme", "box_1", ""},             // so is firmware
		{"acme", "box_2", Unlisted},       // model not listed under acme
		{"acme", "box_1", "v8"},           // firmware not listed
		{"other", Unlisted, Unlisted},     // vendor not listed
		{Unlisted, "box_1", Unlisted},     // a model under no vendor
		{"acme", Unlisted, "v7"},          // a firmware under no model
		{"acme", "box_1", "SN-4C1A92F07"}, // serial number
		{"acme", "box_1", "v7 (kitchen)"}, // free text
	}
	for _, h := range bad {
		if err := s.CheckHardware(h); !errors.Is(err, ErrInvalid) {
			t.Errorf("%+v accepted (%v)", h, err)
		}
	}
}

// TestOSS4ModelWithNoFirmwareYet: a model may be listed before any of its
// firmware versions; then its firmware can only be Unlisted.
func TestOSS4ModelWithNoFirmwareYet(t *testing.T) {
	s, err := Parse([]byte(doc(map[string]string{"hardware": `{"acme": {"box_1": []}}`})))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.CheckHardware(Hardware{"acme", "box_1", Unlisted}); err != nil {
		t.Fatal(err)
	}
	if err := s.CheckHardware(Hardware{"acme", "box_1", "v7"}); !errors.Is(err, ErrInvalid) {
		t.Fatal(err)
	}
}

func TestOSS4VersionsAreListedChoices(t *testing.T) {
	s, err := Parse([]byte(good))
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range []map[string]string{nil, {}, {"openclaw": "2026.9.8"}, {"openclaw": Unlisted}} {
		if err := s.CheckVersions(v); err != nil {
			t.Errorf("%v: %v", v, err)
		}
	}
	for _, v := range []map[string]string{
		{"openclaw": "2026.9.9"},
		{"openclaw": ""},
		{"kernel": "6.12.0"},
		{"openclaw": "2026.9.8", "note": "hello"},
	} {
		if err := s.CheckVersions(v); !errors.Is(err, ErrInvalid) {
			t.Errorf("%v accepted (%v)", v, err)
		}
	}
}

// TestOSS4HardwareDecodesStrictly: the wire object holds exactly vendor,
// model and firmware, spelled exactly so; encoding/json alone would take
// "Vendor" for "vendor" and ignore extra keys.
func TestOSS4HardwareDecodesStrictly(t *testing.T) {
	var h Hardware
	if err := json.Unmarshal([]byte(`{"vendor":"acme","model":"box_1","firmware":"v7"}`), &h); err != nil || h != (Hardware{"acme", "box_1", "v7"}) {
		t.Fatal(h, err)
	}
	for _, b := range []string{
		`{"vendor":"acme","model":"box_1"}`,
		`{"vendor":"acme","model":"box_1","firmware":"v7","serial":"x"}`,
		`{"Vendor":"acme","model":"box_1","firmware":"v7"}`,
		`{"vendor":1,"model":"box_1","firmware":"v7"}`,
		`"acme box_1 v7"`,
	} {
		var h Hardware
		if err := json.Unmarshal([]byte(b), &h); err == nil {
			t.Errorf("%s decoded as %+v", b, h)
		}
	}
	out, _ := json.Marshal(Hardware{"acme", "box_1", "v7"})
	if string(out) != `{"vendor":"acme","model":"box_1","firmware":"v7"}` {
		t.Fatal(string(out))
	}
}
