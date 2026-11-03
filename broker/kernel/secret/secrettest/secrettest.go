// Package secrettest is the print probe for a holder of keys (CLK-1,
// DECOY-b-8): only tests link it.
package secrettest

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

// Verbs are the sixteen verbs a probe formats in, %w and %p included.
var Verbs = []string{"%v", "%+v", "%#v", "%s", "%q", "%d", "%x", "%X", "%t", "%e", "%c", "%U", "%o", "%b", "%w", "%p"}

// Shown reports whether any of vs, formatted in any of Verbs, holds one of
// secrets: raw, as hex, as decimal bytes, JSON-escaped or in the verb's own
// form of the bytes. Only a form of at least ten bytes counts, so a short
// match by chance does not.
func Shown(secrets [][]byte, vs ...any) bool {
	for _, v := range vs {
		for _, verb := range Verbs {
			out := strings.ToLower(fmt.Sprintf(verb, v))
			for _, s := range secrets {
				j, _ := json.Marshal(string(s))
				for _, f := range []string{string(s), hex.EncodeToString(s), strings.Trim(fmt.Sprint(s), "[]"), strings.Trim(string(j), `"`), strings.Trim(fmt.Sprintf(verb, s), "[]")} {
					if len(f) >= 10 && strings.Contains(out, strings.ToLower(f)) {
						return true
					}
				}
			}
		}
	}
	return false
}

type holder[T any] struct {
	p *T
	v T
	i any
}

type plain struct{ k []byte }

// Holders is v bare, by pointer, and in a holder with an unexported
// pointer, value and interface field, bare and by pointer.
func Holders[T any](v T) []any {
	h := holder[T]{&v, v, v}
	return []any{v, &v, h, &h}
}

// NoKey fails t if any of vs shows one of secrets; pass Holders of each
// value. It first checks that a plain-field holder of each secret shows
// it, so the probe can see a leak.
func NoKey(t testing.TB, secrets [][]byte, vs ...any) {
	t.Helper()
	for _, s := range secrets {
		if !Shown([][]byte{s}, &holder[any]{i: &plain{s}}) {
			t.Fatalf("no print showed %x in a plain field: the probe cannot see it", s[:min(4, len(s))])
		}
	}
	for n, v := range vs {
		if Shown(secrets, v) {
			t.Errorf("value %d (%T) prints a key", n, v)
		}
	}
}
