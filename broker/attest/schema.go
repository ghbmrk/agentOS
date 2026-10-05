// Package attest is the public attestation schema (SPEC v0.12 OSS-4).
//
// An attestation says that an installation reproduced something public
// and what happened: the result class, the channel it follows, the
// hardware it ran on, and the software versions involved (OSS-8). OSS-4
// bounds what that can say: every field is a value listed in the public
// schema.json, so a statement is a choice among published options. There
// is no free text, no serial number, and no timestamp at all (OSS-4 allows
// a day; nothing here needs one).
//
// Hardware is vendor, model and firmware version, each listed under the
// one above it. Unlisted stands for hardware the schema does not know
// yet, and once one level is Unlisted every level below it is too, so a
// box on new hardware says only that. Software versions are listed per
// component in the same way. The schema grows through reviewed changes to
// schema.json in the public repository and reaches boxes with releases.
//
// The hardware list is meant to be the hardware database's too (OSS-4's
// other half); that package is later.
//
// The package holds no key, reads no private store, and makes no network
// call. broker/update checks every statement it signs or parses here.
package attest

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"sort"
)

// ErrInvalid marks a schema, or a value, that breaks the rules.
var ErrInvalid = errors.New("attest: invalid")

// Unlisted is the value for hardware or a version the schema does not
// list. It is never listed itself.
const Unlisted = "unlisted"

//go:embed schema.json
var publicSchema []byte

// token is the only shape a listed value may take: lower-case letters,
// digits, and inner dots, underscores and hyphens, at most 32 characters.
// Listing is what bounds a value; the shape keeps listed values plain.
var token = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9._-]{0,30}[a-z0-9])?$`)

// Hardware is the hardware a statement ran on.
type Hardware struct {
	Vendor   string `json:"vendor"`
	Model    string `json:"model"`
	Firmware string `json:"firmware"`
}

// UnmarshalJSON takes exactly the keys vendor, model and firmware, each a
// string, spelled exactly so. encoding/json alone would match "Vendor"
// and skip unknown keys.
func (h *Hardware) UnmarshalJSON(b []byte) error {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(b, &m); err != nil || m == nil {
		return fmt.Errorf("%w: hardware is not an object", ErrInvalid)
	}
	if len(m) != 3 {
		return fmt.Errorf("%w: hardware holds exactly vendor, model and firmware", ErrInvalid)
	}
	var out Hardware
	for k, dst := range map[string]*string{"vendor": &out.Vendor, "model": &out.Model, "firmware": &out.Firmware} {
		raw, ok := m[k]
		if !ok {
			return fmt.Errorf("%w: hardware lacks %s", ErrInvalid, k)
		}
		if err := json.Unmarshal(raw, dst); err != nil {
			return fmt.Errorf("%w: hardware %s is not a string", ErrInvalid, k)
		}
	}
	*h = out
	return nil
}

// Schema is a parsed, checked public attestation schema.
type Schema struct {
	version  int
	results  map[string]bool
	channels map[string]bool
	hardware map[string]map[string]map[string]bool // vendor, model, firmware
	versions map[string]map[string]bool            // component, version
}

type schemaFile struct {
	Version  int                            `json:"version"`
	Results  []string                       `json:"results"`
	Channels []string                       `json:"channels"`
	Hardware map[string]map[string][]string `json:"hardware"`
	Versions map[string][]string            `json:"versions"`
}

var schemaKeys = []string{"version", "results", "channels", "hardware", "versions"}

var defaultSchema = func() *Schema {
	s, err := Parse(publicSchema)
	if err != nil {
		panic(err)
	}
	return s
}()

// Default returns the public schema embedded in the build.
func Default() *Schema { return defaultSchema }

// Version is the schema's version.
func (s *Schema) Version() int { return s.version }

// Result reports whether r is a listed result class.
func (s *Schema) Result(r string) bool { return s.results[r] }

// Channel reports whether c is a listed channel.
func (s *Schema) Channel(c string) bool { return s.channels[c] }

// Parse reads and checks a schema: exactly the known keys, no repeated
// key anywhere, every value a token, Unlisted never listed, no list
// with repeats, and every list non-empty except a model's firmware.
func Parse(data []byte) (*Schema, error) {
	if err := strictKeys(data); err != nil {
		return nil, err
	}
	var f schemaFile
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if err := d.Decode(&f); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	if _, err := d.Token(); err != io.EOF {
		return nil, fmt.Errorf("%w: trailing data", ErrInvalid)
	}
	if f.Version < 1 {
		return nil, fmt.Errorf("%w: schema version", ErrInvalid)
	}
	s := &Schema{version: f.Version, hardware: map[string]map[string]map[string]bool{}, versions: map[string]map[string]bool{}}
	var err error
	if s.results, err = list("results", f.Results); err != nil {
		return nil, err
	}
	if s.channels, err = list("channels", f.Channels); err != nil {
		return nil, err
	}
	if len(f.Hardware) == 0 {
		return nil, fmt.Errorf("%w: no hardware", ErrInvalid)
	}
	for vendor, models := range f.Hardware {
		if err := listed("vendor", vendor); err != nil {
			return nil, err
		}
		if len(models) == 0 {
			return nil, fmt.Errorf("%w: vendor %s lists no model", ErrInvalid, vendor)
		}
		s.hardware[vendor] = map[string]map[string]bool{}
		for model, firmware := range models {
			if err := listed("model", model); err != nil {
				return nil, err
			}
			// A model may list no firmware yet: then only Unlisted.
			if len(firmware) == 0 {
				s.hardware[vendor][model] = map[string]bool{}
			} else if s.hardware[vendor][model], err = list("firmware of "+vendor+"/"+model, firmware); err != nil {
				return nil, err
			}
		}
	}
	for comp, vs := range f.Versions {
		if err := listed("component", comp); err != nil {
			return nil, err
		}
		if s.versions[comp], err = list("versions of "+comp, vs); err != nil {
			return nil, err
		}
	}
	return s, nil
}

func listed(what, v string) error {
	if !token.MatchString(v) || v == Unlisted {
		return fmt.Errorf("%w: %s %q", ErrInvalid, what, v)
	}
	return nil
}

func list(what string, vs []string) (map[string]bool, error) {
	if len(vs) == 0 {
		return nil, fmt.Errorf("%w: %s is empty", ErrInvalid, what)
	}
	set := map[string]bool{}
	for _, v := range vs {
		if err := listed(what, v); err != nil {
			return nil, err
		}
		if set[v] {
			return nil, fmt.Errorf("%w: %s lists %q twice", ErrInvalid, what, v)
		}
		set[v] = true
	}
	return set, nil
}

// CheckHardware reports whether h is a listed choice: each level listed
// under the one above, or Unlisted with every level below it Unlisted.
func (s *Schema) CheckHardware(h Hardware) error {
	bad := fmt.Errorf("%w: hardware %q/%q/%q is not listed", ErrInvalid, h.Vendor, h.Model, h.Firmware)
	if h.Vendor == Unlisted {
		if h.Model != Unlisted || h.Firmware != Unlisted {
			return bad
		}
		return nil
	}
	models, ok := s.hardware[h.Vendor]
	if !ok {
		return bad
	}
	if h.Model == Unlisted {
		if h.Firmware != Unlisted {
			return bad
		}
		return nil
	}
	firmware, ok := models[h.Model]
	if !ok || (h.Firmware != Unlisted && !firmware[h.Firmware]) {
		return bad
	}
	return nil
}

// CheckVersions reports whether every component is listed and each
// version is listed for it or Unlisted. No versions is fine.
func (s *Schema) CheckVersions(vs map[string]string) error {
	comps := make([]string, 0, len(vs))
	for c := range vs {
		comps = append(comps, c)
	}
	sort.Strings(comps)
	for _, c := range comps {
		allowed, ok := s.versions[c]
		if !ok || (vs[c] != Unlisted && !allowed[vs[c]]) {
			return fmt.Errorf("%w: version %q of %q is not listed", ErrInvalid, vs[c], c)
		}
	}
	return nil
}

// Shape reports whether h could be a listed choice under some version of
// the schema: every level a token, and Unlisted at one level forcing it
// below.
func Shape(h Hardware) error {
	for _, v := range []string{h.Vendor, h.Model, h.Firmware} {
		if !token.MatchString(v) {
			return fmt.Errorf("%w: hardware %q/%q/%q is not tokens", ErrInvalid, h.Vendor, h.Model, h.Firmware)
		}
	}
	if (h.Vendor == Unlisted && h.Model != Unlisted) || (h.Model == Unlisted && h.Firmware != Unlisted) {
		return fmt.Errorf("%w: hardware %q/%q/%q lists a level under an unlisted one", ErrInvalid, h.Vendor, h.Model, h.Firmware)
	}
	return nil
}

// ReadHardware maps hardware from a statement signed under any version of
// the schema onto this one: a level this schema does not list becomes
// Unlisted, and so does every level below it. A box on an older schema
// thus still counts a statement written under a newer one, and keeps or
// shows only what it lists itself. A bad shape is refused.
func (s *Schema) ReadHardware(h Hardware) (Hardware, error) {
	if err := Shape(h); err != nil {
		return Hardware{}, err
	}
	models, ok := s.hardware[h.Vendor]
	if !ok {
		return Hardware{Unlisted, Unlisted, Unlisted}, nil
	}
	firmware, ok := models[h.Model]
	if !ok {
		return Hardware{h.Vendor, Unlisted, Unlisted}, nil
	}
	if !firmware[h.Firmware] {
		h.Firmware = Unlisted
	}
	return h, nil
}

// ReadVersions maps versions from a statement signed under any version of
// the schema onto this one: a version this schema does not list becomes
// Unlisted, and a component it does not list is dropped. A key or value
// that is not a token is refused.
func (s *Schema) ReadVersions(vs map[string]string) (map[string]string, error) {
	if vs == nil {
		return nil, nil
	}
	out := map[string]string{}
	for c, v := range vs {
		if !token.MatchString(c) || !token.MatchString(v) {
			return nil, fmt.Errorf("%w: version %q of %q is not tokens", ErrInvalid, v, c)
		}
		allowed, ok := s.versions[c]
		if !ok {
			continue
		}
		if !allowed[v] {
			v = Unlisted
		}
		out[c] = v
	}
	return out, nil
}

// strictKeys refuses JSON that is not one object with exactly the schema's
// top-level keys, or that repeats a key in any object.
func strictKeys(data []byte) error {
	d := json.NewDecoder(bytes.NewReader(data))
	top := map[string]bool{}
	for _, k := range schemaKeys {
		top[k] = true
	}
	depth := 0
	var walk func() error
	walk = func() error {
		t, err := d.Token()
		if err != nil {
			return fmt.Errorf("%w: %v", ErrInvalid, err)
		}
		if depth == 0 && t != json.Delim('{') {
			return fmt.Errorf("%w: not a JSON object", ErrInvalid)
		}
		switch t {
		case json.Delim('{'):
			depth++
			defer func() { depth-- }()
			seen := map[string]bool{}
			for d.More() {
				k, err := d.Token()
				if err != nil {
					return fmt.Errorf("%w: %v", ErrInvalid, err)
				}
				key, _ := k.(string)
				if seen[key] {
					return fmt.Errorf("%w: repeated key %q", ErrInvalid, key)
				}
				if depth == 1 && !top[key] {
					return fmt.Errorf("%w: unknown key %q", ErrInvalid, key)
				}
				seen[key] = true
				if err := walk(); err != nil {
					return err
				}
			}
			_, err = d.Token()
		case json.Delim('['):
			for d.More() {
				if err := walk(); err != nil {
					return err
				}
			}
			_, err = d.Token()
		}
		if err != nil {
			return fmt.Errorf("%w: %v", ErrInvalid, err)
		}
		return nil
	}
	return walk()
}
