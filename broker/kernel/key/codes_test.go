package key_test

// KEY-refusal-code (#6023): a refusal code is a closed key.Code. Only key
// makes one (its one field is unexported), every one is declared in
// codes.go, and a name not declared there does not decode, so neither a
// package, a log entry nor a socket message can introduce a code.
//
// REQ: KRN-5, PLN-4

import (
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"maps"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/kernel"
	"github.com/ghbmrk/agentos/broker/kernel/key"
)

// wireNames is every declared code by the name the log and the sockets carry
// today. A code renamed or dropped breaks the replay of entries already
// written, so this list changes only with a migration.
var wireNames = map[string]key.Code{
	"malformed": key.RMalformed, "stopped": key.RStopped, "revoked": key.RRevoked,
	"paused": key.RPaused, "expired": key.RExpired, "clerk": key.RClerk, "verb": key.RVerb,
	"arg": key.RArg, "content": key.RContent, "labels": key.RLabels,
	"spend-task": key.RSpendTask, "spend-day": key.RSpendDay, "rate": key.RRate,
	"uses": key.RUses, "task": key.RTask, "rung": key.RRung,

	"key": kernel.CKey, "not-granted": kernel.CUngranted, "grant-held": kernel.CGrantHeld,
	"cut-off": kernel.CCutOff, "plan": kernel.CPlan, "duplicate": kernel.CDuplicate,
	"no-clerk": kernel.CClerk, "pool": kernel.CPool, "not-held": kernel.CNotHeld,
	"extension": kernel.CExtension, "held": kernel.CHeld, "log-broken": kernel.CBroken,
	"erased": kernel.CErased, "trip": kernel.CTrip, "tripped": kernel.CTripped,
	"needs-cosign": kernel.CCosign, "in-flight": kernel.CInFlight, "owner": key.COwner,

	"claim": key.RClaim, "dispatch": key.RDispatch, "hold": key.RHold,
	"plan-unknown": key.DPlanUnknown,
}

// Every declared code marshals to its current name and back, alone and in
// a Refusal, and the table is exactly the names above. Catches a renamed or
// dropped wire name, which would fail the replay of existing log entries.
func TestEveryCodeRoundTripsByName(t *testing.T) {
	if got, want := slices.Sorted(maps.Keys(key.Codes())), slices.Sorted(maps.Keys(wireNames)); !slices.Equal(got, want) {
		t.Fatalf("declared codes %v, want %v", got, want)
	}
	if kernel.CTask != key.RTask {
		t.Fatalf("CTask and RTask share the name %q, so they are one code", "task")
	}
	for name, c := range wireNames {
		if c.String() != name || key.Codes()[name] != c {
			t.Errorf("%q: the value is named %q", name, c)
		}
		b, err := json.Marshal(c)
		if err != nil || string(b) != strconv.Quote(name) {
			t.Errorf("%q marshals to %s (%v)", name, b, err)
		}
		var back key.Code
		if err := json.Unmarshal(b, &back); err != nil || back != c {
			t.Errorf("%q does not decode back: %v %v", name, back, err)
		}
		r := key.Refuse(c, "d")
		b, err = json.Marshal(r)
		if want := `{"Code":` + strconv.Quote(name) + `,"Detail":"d"}`; err != nil || string(b) != want {
			t.Errorf("a %q refusal marshals to %s, want %s (%v)", name, b, want, err)
		}
		var rb key.Refusal
		if err := json.Unmarshal(b, &rb); err != nil || rb.Code() != c || rb.Detail != "d" {
			t.Errorf("a %q refusal does not decode back: %+v %v", name, rb, err)
		}
		if r.Error() != name+": d" {
			t.Errorf("a %q refusal reads %q", name, r.Error())
		}
	}
	// The zero Code is no code: "" both ways, and omitted where the field
	// was omitempty before.
	if b, _ := json.Marshal(kernel.PlanView{Status: kernel.SActive}); string(b) != `{"status":"active"}` {
		t.Errorf("a view with no codes marshals to %s", b)
	}
	if b, _ := json.Marshal(kernel.PlanView{Status: kernel.SRejected, Reject: kernel.CPlan}); string(b) != `{"status":"rejected","reject":"plan"}` {
		t.Errorf("a rejected view marshals to %s", b)
	}
}

// A name no code declares does not decode: not as a Code, not in a Refusal
// (with either key case, as encoding/json matches field names), and not in
// the kernel's plan state, view or spend hold. Catches the json routes from
// #6021, by which a log entry or socket message could carry a new code. The
// owner socket's reply is held to the same in owner/kernelsock
// (TestAnUndeclaredCodeDoesNotDecode there).
func TestAnUndeclaredCodeDoesNotDecode(t *testing.T) {
	for _, tc := range []struct {
		into any
		js   string
	}{
		{new(key.Code), `"new-check"`},
		{new(key.Code), `"Plan"`}, // names match exactly, not by case
		{new(key.Refusal), `{"code":"new-check","detail":"x"}`},
		{new(key.Refusal), `{"Code":"new-check","Detail":"x"}`},
		{new(kernel.PlanState), `{"Reject":"new-check"}`},
		{new(kernel.PlanState), `{"Cancel":"new-check"}`},
		{new(kernel.PlanState), `{"Ended":"new-check"}`},
		{new(kernel.PlanView), `{"status":"rejected","reject":"new-check"}`},
		{new(kernel.PlanView), `{"status":"cancelled","cancel":"new-check"}`},
		{new(kernel.SpendHold), `{"Code":"new-check"}`},
		{new(kernel.Unsettled), `{"Cancel":"new-check"}`},
	} {
		if err := json.Unmarshal([]byte(tc.js), tc.into); err == nil {
			t.Errorf("%s decoded into %T: %+v", tc.js, tc.into, tc.into)
		}
	}
	if _, err := key.ParseCode("new-check"); err == nil {
		t.Error("ParseCode accepted an undeclared name")
	}
	// A declared name decodes in the same places.
	var ps kernel.PlanState
	if err := json.Unmarshal([]byte(`{"Reject":"plan","Cancel":"owner","Ended":"stopped"}`), &ps); err != nil ||
		ps.Reject != kernel.CPlan || ps.Cancel != key.COwner || ps.Ended != key.RStopped {
		t.Fatalf("declared names: %+v %v", ps, err)
	}
}

// codesFile is the one file in key that may write a Code literal.
const codesFile = "codes.go"

// No two declared codes share a name, and no file of key's but codes.go
// writes a Code literal with a name, so the table is the only place a code is made.
// Catches a duplicate table entry aliasing another code, and a code made
// outside the table.
func TestCodeNamesAreUnique(t *testing.T) {
	fset := token.NewFileSet()
	names := map[string]string{}
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		af, err := parser.ParseFile(fset, f, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(af, func(n ast.Node) bool {
			cl, ok := n.(*ast.CompositeLit)
			if !ok {
				return true
			}
			if id, ok := cl.Type.(*ast.Ident); !ok || id.Name != "Code" {
				return true
			}
			if len(cl.Elts) == 0 {
				return true // the zero Code, which names no code
			}
			if f != codesFile {
				t.Errorf("%s: a Code is made outside %s", fset.Position(cl.Pos()), codesFile)
				return true
			}
			if len(cl.Elts) != 1 {
				t.Errorf("%s: a Code literal with %d elements", fset.Position(cl.Pos()), len(cl.Elts))
				return true
			}
			lit, ok := cl.Elts[0].(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				t.Errorf("%s: a Code's name is not a string literal", fset.Position(cl.Pos()))
				return true
			}
			name, _ := strconv.Unquote(lit.Value)
			if prev, dup := names[name]; dup {
				t.Errorf("%s: code %q is declared again (first at %s)", fset.Position(cl.Pos()), name, prev)
			}
			names[name] = fset.Position(cl.Pos()).String()
			return true
		})
	}
	if len(names) != len(key.Codes()) {
		t.Fatalf("%d Code literals, %d declared codes", len(names), len(key.Codes()))
	}
}

// Outside key, a Code cannot be set by reflect, and a Refusal's code cannot
// be set by reflect or json: the fields are unexported. (A composite literal,
// an identical unnamed struct and a ~struct constraint do not compile; the
// PR shows those.)
func TestReflectCannotSetACode(t *testing.T) {
	var c key.Code
	if reflect.ValueOf(&c).Elem().Field(0).CanSet() {
		t.Fatal("reflect can set a Code's name")
	}
	r := key.Refuse(key.RVerb, "x")
	if reflect.ValueOf(r).Elem().FieldByName("code").CanSet() {
		t.Fatal("reflect can set a Refusal's code")
	}
}

// key and kernel import no unsafe, the one route left to write an
// unexported field.
func TestKernelAndKeyImportNoUnsafe(t *testing.T) {
	for _, dir := range []string{".", ".."} {
		ents, err := os.ReadDir(dir)
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range ents {
			if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") {
				continue
			}
			p := filepath.Join(dir, e.Name())
			af, err := parser.ParseFile(token.NewFileSet(), p, nil, parser.ImportsOnly)
			if err != nil {
				t.Fatal(err)
			}
			for _, im := range af.Imports {
				if im.Path.Value == `"unsafe"` {
					t.Errorf("%s imports unsafe", p)
				}
			}
		}
	}
}
