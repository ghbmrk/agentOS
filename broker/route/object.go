package route

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"unicode"
)

// Object decodes body as exactly one JSON object, refusing trailing data,
// a key given twice, and two keys that differ only in case. encoding/json
// matches a struct field to a key case-insensitively (Unicode simple
// folding, so the KELVIN SIGN matches k) and the last match wins, so
// either would let a decoder downstream read a different value from the
// one checked here. A key that differs only in case from one of canon is
// refused too: a decoder would read it as that key, which a check on the
// exact key does not see. Moved unchanged from broker/meter
// (MIG-4-spend-m, #2585).
func Object(body []byte, canon ...string) (map[string]json.RawMessage, error) {
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	if t, err := dec.Token(); err != nil || t != json.Delim('{') {
		return nil, errors.New("body is not a JSON object")
	}
	want := make(map[string]string, len(canon))
	for _, k := range canon {
		want[fold(k)] = k
	}
	obj := map[string]json.RawMessage{}
	seen := map[string]bool{}
	for dec.More() {
		t, err := dec.Token()
		if err != nil {
			return nil, errors.New("body is not a JSON object")
		}
		k := t.(string)
		var v json.RawMessage
		if err := dec.Decode(&v); err != nil {
			return nil, errors.New("body is not a JSON object")
		}
		f := fold(k)
		if seen[f] {
			return nil, fmt.Errorf("key %q repeated or differs from another only in case", k)
		}
		if c, ok := want[f]; ok && c != k {
			return nil, fmt.Errorf("key %q must be spelled %q", k, c)
		}
		seen[f] = true
		obj[k] = v
	}
	if _, err := dec.Token(); err != nil {
		return nil, errors.New("body is not a JSON object")
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, errors.New("trailing data after JSON body")
	}
	return obj, nil
}

// fold maps s to one representative of its case-folding class: each rune
// becomes the least rune of its simple-folding orbit, the equivalence
// encoding/json and strings.EqualFold use.
func fold(s string) string {
	var b strings.Builder
	for _, r := range s {
		least := r
		for f := unicode.SimpleFold(r); f != r; f = unicode.SimpleFold(f) {
			least = min(least, f)
		}
		b.WriteRune(least)
	}
	return b.String()
}
