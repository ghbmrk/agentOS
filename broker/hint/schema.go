// Package hint is the private side of the open-source bridge (SPEC v0.12
// OSS-1, OSS-5, OSS-7).
//
// The private side (journal, recall index, workspaces, real tasks) may tell
// the clean-room builder only a hint: a record whose kind and every field
// value are chosen from the public schema in schema.json. A hint carries no
// free text, numbers, names, identifiers, or content, so what crosses is
// bounded to a choice among publicly listed options. The schema's own rules
// (Parse) keep it that way: values are short lower-case words with no
// digits and no sensitive life domain, every field has at least two
// values, and no kind carries more than MaxBitsPerHint bits.
//
// The Emitter is the bridge's single exit. It validates each hint, logs it
// where the owner can read it, and applies the owner's per-category policy
// (automatic, ask each time, or never). Hints then cross only as one
// batch a day, released at a fixed time on a later day, deduplicated,
// capped, and sorted, so only the set crosses: not the order or time they
// were emitted. The outbox gets only canonical re-encodings built from the
// validated values. Hint kinds the schema marks embargo (vuln) have
// reserved slots in each batch and cross marked for the embargoed
// private-report path.
//
// The package holds no credential, reads no private store, and makes no
// network call.
package hint

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"regexp"
	"sort"
	"strings"
)

// MaxBitsPerHint caps the information one hint of any kind can carry:
// log2 of the number of distinct hints of that kind.
const MaxBitsPerHint = 16

// ErrInvalid marks a schema, wire form, or hint that breaks the rules.
var ErrInvalid = errors.New("hint: invalid")

//go:embed schema.json
var publicSchema []byte

// word is the only shape a category, kind, field, or value may take: lower
// case letters and inner underscores, at most 32 characters, no digits.
var word = regexp.MustCompile(`^[a-z](?:[a-z_]{0,30}[a-z])?$`)

// sensitive lists words that may not appear as any underscore-separated
// part of a category, kind, field, or value: even a bounded choice naming
// one of these domains would say the owner deals with it (ASSUMPTIONS H3).
// The list is a backstop; reviewers still check every schema diff.
var sensitive = map[string]bool{
	"health": true, "medical": true, "medicine": true, "doctor": true, "hospital": true,
	"pharmacy": true, "prescription": true, "therapy": true, "clinic": true, "insurance": true,
	"religion": true, "religious": true, "church": true, "mosque": true, "synagogue": true, "temple": true,
	"legal": true, "lawyer": true, "court": true, "police": true, "immigration": true, "visa": true,
	"benefits": true, "welfare": true, "unemployment": true, "tax": true, "debt": true,
	"dating": true, "sexual": true, "political": true, "union": true, "ethnicity": true,
}

func allowedWord(w string) bool {
	if !word.MatchString(w) {
		return false
	}
	for _, part := range strings.Split(w, "_") {
		if sensitive[part] {
			return false
		}
	}
	return true
}

// Schema is a parsed, checked public hint schema.
type Schema struct {
	version    int
	categories []string
	kinds      map[string]*kindDef
	edges      *frequencyEdges
}

// FrequencyField is the field whose value the broker computes from
// journaled counts (Frequency), with edges the schema declares.
const FrequencyField = "frequency"

var frequencyValues = []string{"once", "sometimes", "most_tasks"}

// frequencyEdges are the public bucket edges for FrequencyField: "once" at
// or under OnceMaxCount occurrences, "most_tasks" at or over
// MostTasksMinPercent of tasks, "sometimes" between.
type frequencyEdges struct {
	OnceMaxCount        int `json:"once_max_count"`
	MostTasksMinPercent int `json:"most_tasks_min_percent"`
}

type kindDef struct {
	Category string              `json:"category"`
	Embargo  bool                `json:"embargo"`
	Fields   map[string][]string `json:"fields"`

	names   []string // field names, sorted
	allowed map[string]map[string]bool
	bits    float64
}

type schemaFile struct {
	Version    int                 `json:"version"`
	Edges      *frequencyEdges     `json:"frequency_edges"`
	Categories []string            `json:"categories"`
	Kinds      map[string]*kindDef `json:"kinds"`
}

var defaultSchema = func() *Schema {
	s, err := Parse(publicSchema)
	if err != nil {
		panic(err)
	}
	return s
}()

// Default returns the public schema embedded in the build.
func Default() *Schema { return defaultSchema }

// Parse reads and checks a schema. It refuses anything that would let a
// hint carry more than a bounded choice among listed words.
func Parse(data []byte) (*Schema, error) {
	if err := noDupKeys(data); err != nil {
		return nil, err
	}
	var f schemaFile
	if err := decodeStrict(data, &f); err != nil {
		return nil, err
	}
	if f.Version < 1 {
		return nil, fmt.Errorf("%w: schema version", ErrInvalid)
	}
	if e := f.Edges; e != nil && (e.OnceMaxCount < 1 || e.MostTasksMinPercent < 1 || e.MostTasksMinPercent > 100) {
		return nil, fmt.Errorf("%w: frequency edges", ErrInvalid)
	}
	if len(f.Kinds) == 0 {
		return nil, fmt.Errorf("%w: no kinds", ErrInvalid)
	}
	used := map[string]bool{}
	cats := map[string]bool{}
	for _, c := range f.Categories {
		if !allowedWord(c) || cats[c] {
			return nil, fmt.Errorf("%w: category %q", ErrInvalid, c)
		}
		cats[c] = true
	}
	for name, k := range f.Kinds {
		if !allowedWord(name) || k == nil {
			return nil, fmt.Errorf("%w: kind %q", ErrInvalid, name)
		}
		if !cats[k.Category] {
			return nil, fmt.Errorf("%w: kind %s: category %q", ErrInvalid, name, k.Category)
		}
		used[k.Category] = true
		if len(k.Fields) == 0 {
			return nil, fmt.Errorf("%w: kind %s has no fields", ErrInvalid, name)
		}
		k.allowed = map[string]map[string]bool{}
		for field, values := range k.Fields {
			if !allowedWord(field) {
				return nil, fmt.Errorf("%w: kind %s: field %q", ErrInvalid, name, field)
			}
			if field == FrequencyField && (f.Edges == nil || strings.Join(values, ",") != strings.Join(frequencyValues, ",")) {
				return nil, fmt.Errorf("%w: kind %s: %s needs frequency_edges and the values %v", ErrInvalid, name, field, frequencyValues)
			}
			if len(values) < 2 {
				return nil, fmt.Errorf("%w: kind %s: field %s needs at least two values", ErrInvalid, name, field)
			}
			set := map[string]bool{}
			for _, v := range values {
				if !allowedWord(v) || set[v] {
					return nil, fmt.Errorf("%w: kind %s: field %s: value %q", ErrInvalid, name, field, v)
				}
				set[v] = true
			}
			k.allowed[field] = set
			k.names = append(k.names, field)
			k.bits += math.Log2(float64(len(values)))
		}
		sort.Strings(k.names)
		if k.bits > MaxBitsPerHint {
			return nil, fmt.Errorf("%w: kind %s carries %.1f bits, over %d", ErrInvalid, name, k.bits, MaxBitsPerHint)
		}
	}
	for _, c := range f.Categories {
		if !used[c] {
			return nil, fmt.Errorf("%w: category %s has no kinds", ErrInvalid, c)
		}
	}
	return &Schema{version: f.Version, categories: f.Categories, kinds: f.Kinds, edges: f.Edges}, nil
}

// Frequency is the only way a FrequencyField value is made: the broker
// passes how many of the window's journaled tasks showed the gap (n) and
// how many tasks there were, and the schema's edges pick the bucket. No
// machine chooses it (ASSUMPTIONS K1).
func (s *Schema) Frequency(n, tasks int) (string, error) {
	if s.edges == nil || n < 1 || n > tasks {
		return "", fmt.Errorf("%w: frequency of %d in %d tasks", ErrInvalid, n, tasks)
	}
	switch {
	case n <= s.edges.OnceMaxCount:
		return "once", nil
	case n*100 >= s.edges.MostTasksMinPercent*tasks:
		return "most_tasks", nil
	}
	return "sometimes", nil
}

// Version is the schema version stamped on every canonical hint.
func (s *Schema) Version() int { return s.version }

// Categories lists the policy categories (OSS-7).
func (s *Schema) Categories() []string { return append([]string(nil), s.categories...) }

// MaxBits is the most information any one hint of this schema can carry.
func (s *Schema) MaxBits() float64 {
	var m float64
	for _, k := range s.kinds {
		m = math.Max(m, k.bits)
	}
	return m
}

func (s *Schema) hasCategory(c string) bool {
	for _, x := range s.categories {
		if x == c {
			return true
		}
	}
	return false
}

// decodeStrict decodes one JSON value, refusing unknown keys and trailing
// data.
func decodeStrict(data []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	if _, err := dec.Token(); err != io.EOF {
		return fmt.Errorf("%w: trailing data", ErrInvalid)
	}
	return nil
}

// noDupKeys refuses a JSON document in which any object repeats a key;
// encoding/json would silently keep the last.
func noDupKeys(data []byte) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	var walk func() error
	walk = func() error {
		t, err := dec.Token()
		if err != nil {
			return fmt.Errorf("%w: %v", ErrInvalid, err)
		}
		switch t {
		case json.Delim('{'):
			seen := map[string]bool{}
			for dec.More() {
				k, err := dec.Token()
				if err != nil {
					return fmt.Errorf("%w: %v", ErrInvalid, err)
				}
				key, _ := k.(string)
				if seen[key] {
					return fmt.Errorf("%w: repeated key %q", ErrInvalid, key)
				}
				seen[key] = true
				if err := walk(); err != nil {
					return err
				}
			}
			_, err = dec.Token()
		case json.Delim('['):
			for dec.More() {
				if err := walk(); err != nil {
					return err
				}
			}
			_, err = dec.Token()
		}
		if err != nil {
			return fmt.Errorf("%w: %v", ErrInvalid, err)
		}
		return nil
	}
	return walk()
}
