package update

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// Digest is the hex SHA-256 the pipeline and target files use for content.
func Digest(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// decodeStrict decodes one JSON object into v with exactly the top-level
// keys in top: no unknown, duplicate, or case-variant key, no duplicate key
// at any depth, and nothing after the object. encoding/json alone would
// resolve a duplicate silently (last wins) and match field names
// case-insensitively, so {"security":false,"Security":true} would decode
// as true. (#34's guarantee, kept for manifests and attestations.)
func decodeStrict(b []byte, v any, top map[string]bool) error {
	if err := noDuplicateKeys(b, top); err != nil {
		return err
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if err := d.Decode(v); err != nil {
		return err
	}
	if _, err := d.Token(); err != io.EOF {
		return errors.New("trailing data")
	}
	return nil
}

func fields(names ...string) map[string]bool {
	m := map[string]bool{}
	for _, n := range names {
		m[n] = true
	}
	return m
}

// noDuplicateKeys rejects JSON with a repeated key in any object, and a
// top-level key not exactly in top. The top level must be an object.
func noDuplicateKeys(b []byte, top map[string]bool) error {
	d := json.NewDecoder(bytes.NewReader(b))
	depth := 0
	var walk func() error
	walk = func() error {
		t, err := d.Token()
		if err != nil {
			return err
		}
		if depth == 0 && t != json.Delim('{') {
			return errors.New("not a JSON object")
		}
		switch t {
		case json.Delim('{'):
			depth++
			defer func() { depth-- }()
			keys := map[string]bool{}
			for d.More() {
				k, err := d.Token()
				if err != nil {
					return err
				}
				ks, _ := k.(string)
				if keys[ks] {
					return fmt.Errorf("duplicate key %q", ks)
				}
				if depth == 1 && !top[ks] {
					return fmt.Errorf("unknown key %q", ks)
				}
				keys[ks] = true
				if err := walk(); err != nil {
					return err
				}
			}
			_, err = d.Token()
			return err
		case json.Delim('['):
			for d.More() {
				if err := walk(); err != nil {
					return err
				}
			}
			_, err = d.Token()
			return err
		}
		return nil
	}
	return walk()
}

// noNull rejects JSON with a null anywhere, or that does not parse. TUF
// metadata never holds one, and go-tuf dereferences a null map entry while
// parsing, before it checks any signature.
func noNull(b []byte) error {
	d := json.NewDecoder(bytes.NewReader(b))
	for {
		t, err := d.Token()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		if t == nil {
			return errors.New("null value")
		}
	}
}
