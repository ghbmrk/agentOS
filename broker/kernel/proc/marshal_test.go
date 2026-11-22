package proc

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding"
	"encoding/json"
	"errors"
	"math"
	"reflect"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/kernel/key"
)

// marshalProblems walks the types json.Marshal reaches from each root (named
// by its key) and lists every reason a value of them could fail to marshal:
// a kind json refuses (float, for NaN; complex, interface, chan, func), a map
// key json refuses, a recursive type (a cyclic value fails), a marshaler
// other than the ones the proofs read, or a json.RawMessage anywhere but
// kernelCall.Args, which Conn.Call fills only from a Marshal that succeeded.
// Embedded fields are walked whether exported or not, since json promotes
// their fields.
func marshalProblems(roots map[string]reflect.Type) []string {
	raw := reflect.TypeFor[json.RawMessage]()
	known := map[reflect.Type]bool{reflect.TypeFor[key.PublicKey](): true, reflect.TypeFor[key.ID](): true}
	marshals := func(ty reflect.Type) bool {
		for _, m := range []reflect.Type{reflect.TypeFor[json.Marshaler](), reflect.TypeFor[encoding.TextMarshaler]()} {
			if ty.Implements(m) || reflect.PointerTo(ty).Implements(m) {
				return true
			}
		}
		return false
	}
	var out []string
	done, onStack := map[reflect.Type]bool{}, map[reflect.Type]bool{}
	var walk func(ty reflect.Type, at string)
	walk = func(ty reflect.Type, at string) {
		switch {
		case ty == raw:
			if at != "kernelCall.Args" {
				out = append(out, at+" is a json.RawMessage no Marshal filled")
			}
			return
		case onStack[ty]:
			out = append(out, at+" ("+ty.String()+") is recursive, so a value can be cyclic")
			return
		case done[ty]:
			return
		case marshals(ty):
			if !known[ty] {
				out = append(out, at+" ("+ty.String()+") has a marshaler no proof reads")
			}
			done[ty] = true
			return
		}
		onStack[ty] = true
		switch ty.Kind() {
		case reflect.Struct:
			for i := range ty.NumField() {
				if f := ty.Field(i); f.IsExported() || f.Anonymous {
					walk(f.Type, at+"."+f.Name)
				}
			}
		case reflect.Pointer, reflect.Slice, reflect.Array:
			walk(ty.Elem(), at+"[]")
		case reflect.Map:
			k := ty.Key()
			switch {
			case k.Kind() == reflect.String:
			case k.Implements(reflect.TypeFor[encoding.TextMarshaler]()):
				// json reads only a value receiver's MarshalText for a key, never MarshalJSON.
				if !known[k] {
					out = append(out, at+" has a map key ("+k.String()+") with a marshaler no proof reads")
				}
			case k.Kind() >= reflect.Int && k.Kind() <= reflect.Uint64:
			default:
				out = append(out, at+" has a map key ("+k.String()+") json refuses")
			}
			walk(ty.Elem(), at+"{}")
		case reflect.Bool, reflect.String, reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
			reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		default:
			out = append(out, at+" is a "+ty.Kind().String()+", which json.Marshal can refuse")
		}
		delete(onStack, ty)
		done[ty] = true
	}
	for name, ty := range roots {
		walk(ty, name)
	}
	return out
}

// TestCallsAlwaysMarshal pins what wire.go's remote.call Mutant-equivalent
// proof and kernelsock.go's Conn.Call dropping its second Marshal error rest
// on: json.Marshal of a call, or of a kernelCall whose Args a Marshal filled,
// cannot fail. A type change that could make it fail fails this test, so the
// proofs are read again (#6253).
func TestCallsAlwaysMarshal(t *testing.T) {
	if p := marshalProblems(map[string]reflect.Type{"call": reflect.TypeFor[call](), "kernelCall": reflect.TypeFor[kernelCall]()}); len(p) > 0 {
		t.Errorf("json.Marshal of a call can fail:\n%s", strings.Join(p, "\n"))
	}
	// The marshalers the walk stops at, on zero and filled values.
	var id key.ID
	id[0] = 1
	ec, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	es, err := key.ES256("example.org", ec.PublicKey().Bytes())
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range []any{key.PublicKey{}, key.Ed25519(make([]byte, 32)), es, map[key.ID]int{id: 1, {}: 2}} {
		if _, err := json.Marshal(v); err != nil {
			t.Errorf("json.Marshal(%T): %v", v, err)
		}
	}
}

type (
	marshalNaN    struct{ F float64 }
	marshalInner  struct{ marshalNaN }
	marshalNode   struct{ Next *marshalNode }
	marshalRaw    struct{ R json.RawMessage }
	marshalBool   struct{ M map[bool]int }
	marshalArrKey struct{ M map[[2]byte]int }
	marshalPtrKey struct{ M map[*string]int }
	marshalStrKey struct{ M map[struct{ A string }]int }
	marshalText   struct{ M map[marshalOdd]int }
	marshalOdd    int
	marshalIface  struct{ V any }
	marshalPKKey  struct{ M map[key.PublicKey]int }
)

func (marshalOdd) MarshalText() ([]byte, error) { return nil, errors.New("refused") }

// TestMarshalProblemsFindsEachFailure runs the walk on a type of each kind
// that makes json.Marshal fail, and checks a value of each does fail it, so
// the pin's own claim is tested.
func TestMarshalProblemsFindsEachFailure(t *testing.T) {
	s := "x"
	n := &marshalNode{}
	n.Next = n
	for _, v := range []any{
		marshalNaN{math.NaN()}, marshalInner{marshalNaN{math.NaN()}}, n, marshalRaw{json.RawMessage("{")},
		marshalBool{map[bool]int{true: 1}}, marshalArrKey{map[[2]byte]int{{}: 1}}, marshalPtrKey{map[*string]int{&s: 1}},
		marshalStrKey{map[struct{ A string }]int{{}: 1}}, marshalText{map[marshalOdd]int{1: 1}}, marshalIface{func() {}}, marshalPKKey{map[key.PublicKey]int{{}: 1}},
	} {
		ty := reflect.TypeOf(v)
		if len(marshalProblems(map[string]reflect.Type{"root": ty})) == 0 {
			t.Errorf("%s passes the walk", ty)
		}
		if _, err := json.Marshal(v); err == nil {
			t.Errorf("json.Marshal of a %s value succeeds, so it shows no gap", ty)
		}
	}
	if p := marshalProblems(map[string]reflect.Type{"ok": reflect.TypeFor[struct {
		A map[int8]string
		B map[key.ID][]byte
		C *struct{ D []uint16 }
	}]()}); len(p) > 0 {
		t.Errorf("a type json always marshals fails the walk: %v", p)
	}
}
