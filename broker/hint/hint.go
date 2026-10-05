package hint

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

// Hint is one record for the bridge: a kind and a value for each of that
// kind's fields.
type Hint struct {
	Kind   string
	Fields map[string]string
}

// Validate reports ErrInvalid unless h's kind is in the schema and h has
// exactly that kind's fields, each set to a listed value.
func (s *Schema) Validate(h Hint) error {
	_, err := s.check(h)
	return err
}

func (s *Schema) check(h Hint) (*kindDef, error) {
	k, ok := s.kinds[h.Kind]
	if !ok {
		return nil, fmt.Errorf("%w: unknown kind", ErrInvalid)
	}
	if len(h.Fields) != len(k.names) {
		return nil, fmt.Errorf("%w: %s needs fields %s", ErrInvalid, h.Kind, strings.Join(k.names, ", "))
	}
	for _, f := range k.names {
		v, ok := h.Fields[f]
		if !ok {
			return nil, fmt.Errorf("%w: %s needs field %s", ErrInvalid, h.Kind, f)
		}
		// The message names the field, never the value, which may be
		// private text.
		if !k.allowed[f][v] {
			return nil, fmt.Errorf("%w: %s.%s is not a listed value", ErrInvalid, h.Kind, f)
		}
	}
	return k, nil
}

// ParseJSON reads the wire form {"kind": "...", "fields": {"name": "value"}}
// and validates it. Values must be strings; unknown or repeated keys,
// nesting, and trailing data are refused.
func (s *Schema) ParseJSON(data []byte) (Hint, error) {
	if err := noDupKeys(data); err != nil {
		return Hint{}, err
	}
	var w struct {
		Kind   *string            `json:"kind"`
		Fields map[string]*string `json:"fields"`
	}
	if err := decodeStrict(data, &w); err != nil {
		return Hint{}, err
	}
	if w.Kind == nil {
		return Hint{}, fmt.Errorf("%w: no kind", ErrInvalid)
	}
	h := Hint{Kind: *w.Kind, Fields: make(map[string]string, len(w.Fields))}
	for k, v := range w.Fields {
		if v == nil {
			return Hint{}, fmt.Errorf("%w: %s is null", ErrInvalid, k)
		}
		h.Fields[k] = *v
	}
	if err := s.Validate(h); err != nil {
		return Hint{}, err
	}
	return h, nil
}

// Canonical is the only form that crosses the bridge: rebuilt from the
// validated values in fixed order, stamped with the schema version and the
// kind's embargo mark (OSS-5).
func (s *Schema) Canonical(h Hint) ([]byte, error) {
	k, err := s.check(h)
	if err != nil {
		return nil, err
	}
	var b strings.Builder
	b.WriteString(`{"schema":`)
	b.WriteString(strconv.Itoa(s.version))
	b.WriteString(`,"kind":`)
	b.Write(quote(h.Kind))
	b.WriteString(`,"embargo":`)
	b.WriteString(strconv.FormatBool(k.Embargo))
	b.WriteString(`,"fields":{`)
	for i, f := range k.names {
		if i > 0 {
			b.WriteByte(',')
		}
		b.Write(quote(f))
		b.WriteByte(':')
		b.Write(quote(h.Fields[f]))
	}
	b.WriteString(`}}`)
	return []byte(b.String()), nil
}

func quote(s string) []byte {
	q, _ := json.Marshal(s)
	return q
}
