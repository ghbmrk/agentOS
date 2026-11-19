package proc

import (
	"encoding"
	"encoding/json"
	"reflect"
	"testing"

	"github.com/ghbmrk/agentos/broker/kernel/key"
)

// TestCallsAlwaysMarshal pins what the Mutant-equivalent proofs for
// kernelsock.go's Conn.Call and wire.go's remote.call rest on: json.Marshal
// of a kernelCall or a call cannot fail, so their `if err != nil` is never
// taken. Every type either reaches holds no kind json can refuse (float, for
// NaN; interface, chan, func), and its only marshalers are the ones whose
// errors are nil: key.PublicKey, key.ID and kernelCall's RawMessage, which
// mustRaw fills only from a Marshal that succeeded. A new field of another
// kind fails this test, so the proofs are read again (#6253).
func TestCallsAlwaysMarshal(t *testing.T) {
	known := map[reflect.Type]bool{
		reflect.TypeFor[key.PublicKey]():   true,
		reflect.TypeFor[key.ID]():          true,
		reflect.TypeFor[json.RawMessage](): true,
	}
	marshals := func(ty reflect.Type) bool {
		for _, m := range []reflect.Type{reflect.TypeFor[json.Marshaler](), reflect.TypeFor[encoding.TextMarshaler]()} {
			if ty.Implements(m) || reflect.PointerTo(ty).Implements(m) {
				return true
			}
		}
		return false
	}
	seen := map[reflect.Type]bool{}
	var walk func(ty reflect.Type, at string)
	walk = func(ty reflect.Type, at string) {
		if seen[ty] {
			return
		}
		seen[ty] = true
		if marshals(ty) {
			if !known[ty] {
				t.Errorf("%s (%s) has a marshaler no proof reads", at, ty)
			}
			return
		}
		switch ty.Kind() {
		case reflect.Struct:
			for i := range ty.NumField() {
				if f := ty.Field(i); f.IsExported() {
					walk(f.Type, at+"."+f.Name)
				}
			}
		case reflect.Pointer, reflect.Slice, reflect.Array:
			walk(ty.Elem(), at+"[]")
		case reflect.Map:
			walk(ty.Key(), at+"{key}")
			walk(ty.Elem(), at+"{}")
		case reflect.Bool, reflect.String, reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
			reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		default:
			t.Errorf("%s is a %s, which json.Marshal can refuse", at, ty.Kind())
		}
	}
	walk(reflect.TypeFor[call](), "call")
	walk(reflect.TypeFor[kernelCall](), "kernelCall")
	for ty := range known {
		if !seen[ty] {
			t.Errorf("%s is no longer reached: drop it from known", ty)
		}
	}
}
