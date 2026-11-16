package driver

// REQ: PLN-4, EVL-3

import (
	"fmt"
	"go/ast"
	"go/build"
	"go/constant"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"testing"
)

// The kernel's sources, read from this package's directory (UPD-5r-b7f-1).
const (
	modulePath     = "github.com/ghbmrk/agentos/broker"
	moduleRoot     = "../../.."
	kernelDir      = "../../../kernel"
	keyDir         = "../../../kernel/key"
	assumptionsMD  = "../ASSUMPTIONS.md"
	stepCodesStart = "`kernel.Admit` checks the steps in order"
	stepCodesEnd   = "(`duplicate`)."
)

// notStepCodes are the refusal codes kernel and key write that row
// UPD-5r-b7f-1 does not name, because kernel.Admit's loop over the steps
// never refuses a step with them: they refuse a plan before the loop, a send,
// a dispatch, a fold or a call outside Admit. A code the kernel gains is in
// neither this list nor the row, so the pin fails until someone classes it.
// The limit: which codes are step codes is classed by hand. stepBodies fails
// a listed code named in the loop or in key.Authorize, but a listed code that
// a callee of the loop starts to write would stay green.
var notStepCodes = []string{
	"needs-cosign", // CCosign: a co-signed send's total (cosign.go)
	"cut-off",      // CCutOff: a key narrowed by a cut-off passkey: Live, before the loop with no step, and at dispatch
	"extension",    // CExtension: a held key's extension
	"grant-held",   // CGrantHeld: a grant not yet live: Live, before the loop with no step, and at dispatch
	"held",         // CHeld: a held task, at dispatch
	"in-flight",    // CInFlight: a step already in flight, at dispatch
	"key",          // CKey: a plan whose key does not verify, before the loop
	"log-broken",   // CBroken: a failed write
	"not-held",     // CNotHeld: releasing a plan that is not held
	"pool",         // CPool: a pool call
	"trip",         // CTrip: a tripped plan, before the loop
	"tripped",      // CTripped: planning stopped after a trip, before the loop
	"not-granted",  // CUngranted: a key with no grant: Live, before the loop with no step, and at dispatch
}

// externalWriters are the calls out of kernel and key that are handed
// something reaching a refusal code, and why none writes a code this scan has
// not checked. A key is a callee (any call) or "callee in caller" (that call
// only); every "in" entry must still be met. Any other such call fails.
var externalWriters = map[string]string{
	"fmt.Errorf":            "formats only",
	"fmt.Sprintf":           "formats only",
	"fmt.Sprint":            "formats only",
	"errors.Is":             "compares only",
	"errors.Join":           "wraps only",
	"reflect.DeepEqual":     "compares only",
	"encoding/json.Marshal": "reads only",
	"encoding/json.Unmarshal in kernel.body": "decodes an Entry's Body, which only the log's append and decode write " +
		"(guardedFields), from values this scan checks; an Entry another package builds is a log it read, data and not kernel code",
	"slices.EqualFunc": "compares only",
	"encoding/json.Unmarshal in kernel.Open": "decodes a log frame the log's AEAD opened, so an Entry append sealed; " +
		"Entry's Body is guarded (guardedFields)",
	"encoding/json.Unmarshal in kernel.LoggedAnchors": "decodes the setup frame the log's AEAD opened, as kernel.Open does",
	"encoding/json.Unmarshal in kernel.asLogged":      "round-trips a value the kernel is about to log, so out holds v's codes",
	// The scan's boundary: code outside kernel and key that the kernel hands
	// its state. A clerk sees it as the read-only View (CLK-2); a Backups is
	// handed *State. A code such code writes is not one kernel or key declares.
	"(kernel.Clerk).Do in (*kernel.Kernel).Tick":           "a clerk, outside kernel and key, handed the View",
	"(kernel.Clerk).Probe in (*kernel.Kernel).Tick":        "a clerk, outside kernel and key, handed the View",
	"(kernel.Backups).Prepare in (*kernel.Kernel).Reseals": "a backup target, outside kernel and key, handed the state",
}

// TestTheAssumptionNamesTheKernelsStepChecks pins row UPD-5r-b7f-1's list of
// step-level refusals to the code as a closed set (L3 6924376062 on #5997).
// Every write of a refusal code anywhere in kernel and key must be a declared
// package-level string constant, or a copy from another code-carrying field or
// a code parameter whose own writes and callers obey the same rule; any other
// form fails, so no helper shape or sentinel variable can hide a code; nor can a
// struct of the same shape, a generic literal, the log decoder, a type
// assertion out of an interface, or a value returned from a package that
// imports key. The
// constants so used must then equal the row's codes plus notStepCodes.
func TestTheAssumptionNamesTheKernelsStepChecks(t *testing.T) {
	row := rowStepCodes(t, readFile(t, assumptionsMD))
	used, errs := scanCodes(t, nil)
	if len(errs) > 0 {
		t.Fatalf("refusal codes written in a form that is not a declared constant:\n%s", strings.Join(errs, "\n"))
	}
	if err := classify(row, used); err != nil {
		t.Fatal(err)
	}
}

// classify says how the codes kernel and key write differ from the row's codes
// plus the codes classed as not step codes.
func classify(row, used []string) error {
	var both, stale, unclassed []string
	for _, c := range row {
		if slices.Contains(notStepCodes, c) {
			both = append(both, c)
		}
	}
	want := sortedSet(append(slices.Clone(row), notStepCodes...))
	for _, c := range want {
		if !slices.Contains(used, c) {
			stale = append(stale, c)
		}
	}
	for _, c := range used {
		if !slices.Contains(want, c) {
			unclassed = append(unclassed, c)
		}
	}
	if len(both)+len(stale)+len(unclassed) == 0 {
		return nil
	}
	return fmt.Errorf("row UPD-5r-b7f-1 and notStepCodes disagree with the codes kernel and key write: "+
		"in both %v; named but never written %v; written but in neither (a step code goes in the row, any other in notStepCodes) %v",
		both, stale, unclassed)
}

// TestTheStepCheckPinCatchesDrift is the pin's mutant test. Each mutant either
// fails the scan or adds the code "new-check", which neither list names. It
// holds every route past the earlier reachability walk that L3 found on #5997
// (6923594464, 6923997232, 6924376062), and the row's own edits.
func TestTheStepCheckPinCatchesDrift(t *testing.T) {
	md := readFile(t, assumptionsMD)
	row := rowStepCodes(t, md)
	used, errs := scanCodes(t, nil)
	if len(errs) > 0 || classify(row, used) != nil {
		t.Fatal("the pin fails on the unchanged sources; see TestTheAssumptionNamesTheKernelsStepChecks")
	}
	extra := strings.Replace(md, stepCodesEnd, "(`extra-check`) or "+stepCodesEnd, 1)
	if classify(rowStepCodes(t, extra), used) == nil {
		t.Fatal("a code added to the row was not caught")
	}
	fewer := strings.Replace(md, "(`spend-task`, `spend-day`, `rate`, `uses`)", "(`spend-task`, `spend-day`, `rate`)", 1)
	if classify(rowStepCodes(t, fewer), used) == nil {
		t.Fatal("a code dropped from the row was not caught")
	}

	kernelGo := filepath.Join(kernelDir, "kernel.go")
	authGo := filepath.Join(keyDir, "authorize.go")
	const loopAt = "\t\tif c.Irreversible() {"
	const authAt = "\treturn v.caps(s, c, false)\n}"
	const refuseAt = "\treturn &Refusal{Code: code, Detail: fmt.Sprintf(f, a...)}"
	inLoop := func(body string) (string, string, string) {
		return kernelGo, loopAt, "\t\tif st.Amount > 1<<40 {\n" + body + "\n\t\t}\n" + loopAt
	}
	inRefuse := func(body string) (string, string, string) { return authGo, refuseAt, body + "\n" + refuseAt }
	inAuth := func(body string) (string, string, string) { return authGo, authAt, body + "\n" + authAt }
	type mutant struct {
		file, anchor, rep string
		tail              string            // appended to the file
		read              bool              // adds new-check to the codes, rather than failing the scan
		imp               string            // an import added to the file
		files             map[string]string // new files
	}
	m := func(file, anchor, rep string) mutant { return mutant{file: file, anchor: anchor, rep: rep} }
	withTail := func(mu mutant, tail string, read bool) mutant { mu.tail, mu.read = tail, read; return mu }
	const newConst = "\nconst CNewCheck = \"new-check\"\n"
	const newKeyConst = "\nconst RNewCheck = \"new-check\"\n"
	for name, c := range map[string]mutant{
		// Round 1 and 2 (6923594464, 6923997232).
		"a code literal":                  m(inLoop(`			return key.ID{}, nil, on(&key.Refusal{Code: "new-check"}, &i)`)),
		"a local variable":                m(inLoop(`			nc := CPlan; return key.ID{}, nil, on(&key.Refusal{Code: nc, Detail: "x"}, &i)`)),
		"an assigned Code field":          m(inLoop(`			r := &key.Refusal{Detail: "x"}; r.Code = "new-check"; return key.ID{}, nil, on(r, &i)`)),
		"a Code field appended to":        m(inLoop(`			r := &key.Refusal{Code: key.RRate}; r.Code += "x"; return key.ID{}, nil, on(r, &i)`)),
		"an unkeyed literal":              m(inLoop(`			return key.ID{}, nil, on(&key.Refusal{"new-check", "x"}, &i)`)),
		"a local shadowing a constant":    m(inRefuse("\tif len(a) > 99 {\n\t\tRRate := \"new-check\"\n\t\treturn &Refusal{Code: RRate}\n\t}")),
		"a local const":                   m(inLoop(`			const nc = "new-check"; return key.ID{}, nil, on(&key.Refusal{Code: nc}, &i)`)),
		"a reassigned code parameter":     m(inRefuse("\tif code == RRate && len(a) > 99 {\n\t\tcode = \"new-check\"\n\t}")),
		"a code parameter by address":     m(inRefuse("\t_ = &code")),
		"a code parameter at a variable":  m(inAuth("\tif nc := RRate + \"x\"; s.Amount > 1<<40 {\n\t\treturn refuse(nc, \"x\")\n\t}")),
		"a code from a call":              withTail(m(inLoop(`			return key.ID{}, nil, on(&key.Refusal{Code: newCode()}, &i)`)), "\nfunc newCode() string { return CNewCheck }\n"+newConst, false),
		"a code concatenated":             m(inLoop(`			return key.ID{}, nil, on(&key.Refusal{Code: CPlan + "x"}, &i)`)),
		"a code from a map":               m(inLoop(`			return key.ID{}, nil, on(&key.Refusal{Code: map[int]string{0: CPlan}[0]}, &i)`)),
		"a closure parameter":             m(inLoop(`			mk := func(c string) *key.Refusal { return &key.Refusal{Code: c} }; return key.ID{}, nil, on(mk(CPlan), &i)`)),
		"a helper returning a value":      withTail(m(inLoop(`			r := newCheck(); return key.ID{}, nil, on(&r, &i)`)), "\nfunc newCheck() key.Refusal { return key.Refusal{Code: CNewCheck, Detail: \"x\"} }\n"+newConst, true),
		"a helper assigning the field":    withTail(m(inLoop(`			var r key.Refusal; setCheck(&r); return key.ID{}, nil, on(&r, &i)`)), "\nfunc setCheck(r *key.Refusal) { r.Code = CNewCheck }\n"+newConst, true),
		"a closure bound in the loop":     withTail(m(inLoop(`			mk := func() *key.Refusal { return &key.Refusal{Code: CNewCheck} }; return key.ID{}, nil, on(mk(), &i)`)), newConst, true),
		"a func value of unknown binding": withTail(m(inLoop(`			var mk func(*key.Refusal); r := &key.Refusal{Code: CPlan}; mk(r); return key.ID{}, nil, on(r, &i)`)), "", false),
		// Round 3 (6924376062): a helper returning error, and a sentinel.
		"a helper returning error (key)": withTail(m(authGo, authAt,
			"\tif err := v.extra(s); err != nil {\n\t\treturn err.(*Refusal)\n\t}\n"+authAt),
			"\nfunc (v *Verified) extra(s Step) error {\n\tif s.Amount > 1<<40 {\n\t\treturn refuse(RNewCheck, \"x\")\n\t}\n\treturn nil\n}\n"+newKeyConst, false),
		"a helper returning error (kernel)": withTail(m(inLoop(`			if e := chkNew(); e != nil { return key.ID{}, nil, on(e.(*key.Refusal), &i) }`)),
			"\nfunc mkNew() *key.Refusal { return &key.Refusal{Code: CNewCheck, Detail: \"x\"} }\nfunc chkNew() error { return mkNew() }\n"+newConst, false),
		"a sentinel variable":         withTail(m(inLoop(`			return key.ID{}, nil, on(errNew, &i)`)), "\nvar errNew = &key.Refusal{Code: \"new-check\", Detail: \"x\"}\n", false),
		"a sentinel of a constant":    withTail(m(inLoop(`			return key.ID{}, nil, on(errNew, &i)`)), "\nvar errNew = &key.Refusal{Code: CNewCheck, Detail: \"x\"}\n"+newConst, true),
		"a sentinel copied":           withTail(m(inLoop(`			r := &key.Refusal{Detail: "x"}; *r = *errNew; return key.ID{}, nil, on(r, &i)`)), "\nvar errNew = &key.Refusal{Code: CNewCheck, Detail: \"x\"}\n"+newConst, true),
		"a sentinel in a dead helper": withTail(m(inLoop(`			_ = 0`)), "\nvar errNew = key.Refusal{Code: CNewCheck}\n"+newConst, true),
		// Round 3 release items R1 and R2.
		"the field by address":   m(inLoop(`			r := &key.Refusal{Code: CPlan}; p := &r.Code; *p = "new-check"; return key.ID{}, nil, on(r, &i)`)),
		"the field scanned into": m(inLoop(`			r := &key.Refusal{Code: CPlan}; fmt.Sscan("new-check", &r.Code); return key.ID{}, nil, on(r, &i)`)),
		"the field in a range":   m(inLoop(`			r := &key.Refusal{Code: CPlan}; for _, r.Code = range []string{"new-check"} {}; return key.ID{}, nil, on(r, &i)`)),
		"a refusal decoded": m(filepath.Join(kernelDir, "state.go"), "\tif p.Ended != \"\" {",
			"\tif r := (&key.Refusal{}); json.Unmarshal([]byte(`{\"Code\":\"new-check\"}`), r) == nil {\n\t\treturn r\n\t}\n\tif p.Ended != \"\" {"),
		"a refusal converted":       m(inLoop(`			type alt struct{ Code, Detail string }; r := key.Refusal(alt{Code: "new-check"}); return key.ID{}, nil, on(&r, &i)`)),
		"a tuple from a call":       m(inLoop(`			r := &key.Refusal{}; r.Code, r.Detail = fmt.Sprint("new-check"), "x"; return key.ID{}, nil, on(r, &i)`)),
		"a copied field written":    withTail(m(inLoop(`			h := holder{c: "new-check"}; return key.ID{}, nil, on(&key.Refusal{Code: h.c}, &i)`)), "\ntype holder struct{ c string }\n", false),
		"a copied field from const": withTail(m(inLoop(`			h := holder{c: CNewCheck}; return key.ID{}, nil, on(&key.Refusal{Code: h.c}, &i)`)), "\ntype holder struct{ c string }\n"+newConst, true),
		// Round 2 of #6021 (L3 6924923773, Security 6924966358).
		"an identical unnamed struct": m(inLoop(`			var r key.Refusal = struct{ Code, Detail string }{"new-check", "x"}; return key.ID{}, nil, on(&r, &i)`)),
		"an identical struct written": m(inLoop(`			var u struct{ Code, Detail string }; u.Code = "new-check"; var r key.Refusal = u; return key.ID{}, nil, on(&r, &i)`)),
		"an identical struct sent":    m(inLoop(`			ch := make(chan key.Refusal, 1); ch <- struct{ Code, Detail string }{Code: "new-check"}; r := <-ch; return key.ID{}, nil, on(&r, &i)`)),
		"an identical struct returned": withTail(m(inLoop(`			r := mkU(); return key.ID{}, nil, on(&r, &i)`)),
			"\nfunc mkU() key.Refusal { return struct{ Code, Detail string }{\"new-check\", \"x\"} }\n", false),
		"a generic literal": withTail(m(inLoop(`			r := mkR[key.Refusal](); return key.ID{}, nil, on(&r, &i)`)),
			"\nfunc mkR[T ~struct{ Code, Detail string }]() T { return T{Code: CPlan} }\n", false),
		"the log decoder on a built entry": m(inLoop("\t\t\tr, _ := body[key.Refusal](Entry{Body: []byte(`{\"Code\":\"new-check\"}`)}); return key.ID{}, nil, on(&r, &i)")),
		"the log decoder on a set body":    m(inLoop("\t\t\tvar e Entry; e.Body = []byte(`{\"Code\":\"new-check\"}`); r, _ := body[key.Refusal](e); return key.ID{}, nil, on(&r, &i)")),
		"a refusal from an imported package": {file: kernelGo, anchor: loopAt,
			rep: "\t\tif r := ipform.CheckNew(st.Amount); r != nil {\n\t\t\treturn key.ID{}, nil, on(r, &i)\n\t\t}\n" + loopAt,
			imp: modulePath + "/kernel/ipform",
			files: map[string]string{filepath.Join(kernelDir, "ipform", "checknew.go"): "package ipform\n\nimport \"" + modulePath + "/kernel/key\"\n\n" +
				"func CheckNew(a int64) *key.Refusal {\n\tif a > 1<<40 {\n\t\treturn &key.Refusal{Code: \"new-check\", Detail: \"x\"}\n\t}\n\treturn nil\n}\n"}},
		"a step refusal with a non-step code": m(inLoop(`			return key.ID{}, nil, on(&key.Refusal{Code: CCutOff, Detail: "x"}, &i)`)),
		"a new constant code":                 withTail(m(inLoop(`			return key.ID{}, nil, on(&key.Refusal{Code: CNewCheck}, &i)`)), newConst, true),
	} {
		t.Run(name, func(t *testing.T) {
			src := readFile(t, c.file)
			mut := strings.Replace(src, c.anchor, c.rep, 1)
			if mut == src {
				t.Fatalf("the mutant did not apply to %s", c.file)
			}
			mut += c.tail
			if c.imp != "" {
				mut = strings.Replace(mut, "import (", "import (\n\t\""+c.imp+"\"", 1)
			}
			over := map[string]string{c.file: mut}
			maps.Copy(over, c.files)
			got, errs := scanCodes(t, over)
			switch {
			case c.read && len(errs) > 0:
				t.Fatalf("want new-check read, got scan errors:\n%s", strings.Join(errs, "\n"))
			case c.read && !slices.Contains(got, "new-check"):
				t.Fatalf("new-check was not read: %v", got)
			case c.read && classify(row, got) == nil:
				t.Fatal("new-check was read but not caught as unclassed")
			case !c.read && len(errs) == 0:
				t.Fatalf("want the scan to fail; it read %v", got)
			case !c.read && strings.HasPrefix(errs[0], "type-check: "):
				t.Fatalf("the mutant does not compile: %s", errs[0])
			}
		})
	}
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// rowStepCodes is the sorted set of codes row UPD-5r-b7f-1's sentence on
// kernel.Admit names, each in backticks.
func rowStepCodes(t *testing.T, md string) []string {
	t.Helper()
	var row string
	for _, l := range strings.Split(md, "\n") {
		if strings.HasPrefix(l, "| UPD-5r-b7f-1 |") {
			row = l
		}
	}
	i := strings.Index(row, stepCodesStart)
	j := strings.Index(row, stepCodesEnd)
	if row == "" || i < 0 || j < i {
		t.Fatalf("row UPD-5r-b7f-1 has no sentence from %q to %q", stepCodesStart, stepCodesEnd)
	}
	seg := row[i+len(stepCodesStart) : j+len(stepCodesEnd)]
	var codes []string
	for _, m := range regexp.MustCompile("`([^`]+)`").FindAllStringSubmatch(seg, -1) {
		codes = append(codes, m[1])
	}
	return sortedSet(codes)
}

func sortedSet(s []string) []string {
	slices.Sort(s)
	return slices.Compact(s)
}

// loaded is one type-checked package of the scan.
type loaded struct {
	pkg   *types.Package
	files []*ast.File
	info  *types.Info
}

// loader type-checks module packages from source, with files overridden for
// the mutants, and the standard library from export data.
type loader struct {
	t        *testing.T
	fset     *token.FileSet
	override map[string]string // absolute path -> source
	std      types.Importer
	done     map[string]*loaded
	scan     map[string]bool // the import paths the scan reads: kernel and key
}

func (l *loader) Import(path string) (*types.Package, error) {
	if path == modulePath || strings.HasPrefix(path, modulePath+"/") {
		p, err := l.load(filepath.Join(moduleRoot, strings.TrimPrefix(path, modulePath)), path)
		if err != nil {
			return nil, err
		}
		return p.pkg, nil
	}
	return l.std.Import(path)
}

func (l *loader) load(dir, path string) (*loaded, error) {
	if p, ok := l.done[path]; ok {
		return p, nil
	}
	bp, err := build.Default.ImportDir(dir, 0)
	if err != nil {
		return nil, err
	}
	// A file left out for its build constraints, a cgo file, or an assembly
	// or object file (a bodyless function's body) is code the scan would not
	// read.
	var skipped []string
	for _, f := range slices.Concat(bp.IgnoredGoFiles, bp.InvalidGoFiles, bp.CgoFiles, bp.SFiles, bp.SysoFiles) {
		if !strings.HasSuffix(f, "_test.go") {
			skipped = append(skipped, f)
		}
	}
	if len(skipped) > 0 && l.scan[path] {
		return nil, fmt.Errorf("%s has files the scan cannot read: %v", path, skipped)
	}
	names := slices.Clone(bp.GoFiles)
	for f := range l.override { // a mutant's new file
		absDir, _ := filepath.Abs(dir)
		if filepath.Dir(f) == absDir && !slices.Contains(names, filepath.Base(f)) {
			names = append(names, filepath.Base(f))
		}
	}
	var files []*ast.File
	for _, name := range names {
		f := filepath.Join(dir, name)
		abs, _ := filepath.Abs(f)
		var src any
		if s, ok := l.override[abs]; ok {
			src = s
		}
		af, err := parser.ParseFile(l.fset, f, src, 0)
		if err != nil {
			return nil, err
		}
		files = append(files, af)
	}
	info := &types.Info{
		Types:      map[ast.Expr]types.TypeAndValue{},
		Defs:       map[*ast.Ident]types.Object{},
		Uses:       map[*ast.Ident]types.Object{},
		Selections: map[*ast.SelectorExpr]*types.Selection{},
	}
	conf := types.Config{Importer: l}
	pkg, err := conf.Check(path, l.fset, files, info)
	if err != nil {
		return nil, err
	}
	p := &loaded{pkg, files, info}
	l.done[path] = p
	return p, nil
}

// scanCodes type-checks kernel and key, with override's files in place of
// theirs, and returns the constants written as refusal codes and every write
// of a code that is not one (UPD-5r-b7f-1).
func scanCodes(t *testing.T, override map[string]string) ([]string, []string) {
	t.Helper()
	abs := map[string]string{}
	for f, s := range override {
		a, err := filepath.Abs(f)
		if err != nil {
			t.Fatal(err)
		}
		abs[a] = s
	}
	fset := token.NewFileSet()
	l := &loader{t: t, fset: fset, override: abs, std: importer.Default(), done: map[string]*loaded{},
		scan: map[string]bool{modulePath + "/kernel": true, modulePath + "/kernel/key": true}}
	var pkgs []*loaded
	for _, d := range []string{keyDir, kernelDir} {
		rel, err := filepath.Rel(moduleRoot, d)
		if err != nil {
			t.Fatal(err)
		}
		p, err := l.load(d, modulePath+"/"+filepath.ToSlash(rel))
		if err != nil {
			return nil, []string{"type-check: " + err.Error()}
		}
		pkgs = append(pkgs, p)
	}
	codeField := fieldNamed(pkgs[0].pkg, "Refusal", "Code")
	if codeField == nil {
		t.Fatal("key.Refusal has no Code field")
	}
	s := &scanner{fset: fset, pkgs: pkgs, fields: map[*types.Var]bool{codeField: true}, params: map[*types.Var]bool{}, guarded: map[*types.Var]map[string]bool{}}
	for typ, g := range guardedFields {
		v := fieldNamed(pkgs[1].pkg, typ, g.field)
		if v == nil {
			t.Fatalf("kernel.%s has no field %s", typ, g.field)
		}
		s.guarded[v] = map[string]bool{}
		for _, w := range g.writers {
			s.guarded[v][w] = true
		}
	}
	for {
		nf, np, ng := len(s.fields), len(s.params), len(s.guarded)
		s.used, s.errs, s.sites = map[string]bool{}, map[string]bool{}, map[string]bool{}
		s.run()
		if len(s.fields) == nf && len(s.params) == np && len(s.guarded) == ng {
			break
		}
	}
	s.stepBodies()
	for k := range externalWriters {
		if strings.Contains(k, " in ") && !s.sites[k] {
			s.errs["externalWriters: "+k+" is no longer called; drop it"] = true
		}
	}
	var used, errs []string
	for c := range s.used {
		used = append(used, c)
	}
	for e := range s.errs {
		errs = append(errs, e)
	}
	sort.Strings(used)
	sort.Strings(errs)
	return used, errs
}

// stepBodies fails a code in notStepCodes named in admit's loop over the
// steps or in key's (*Verified).Authorize, where a code is a step code by
// definition. It is a partial check: a code a callee of either writes is
// classed by hand (L3 6924923773 R1, Security 6924966358 R1).
func (s *scanner) stepBodies() {
	var loop, auth ast.Node
	for _, l := range s.pkgs {
		for _, f := range l.files {
			for _, d := range f.Decls {
				fd, ok := d.(*ast.FuncDecl)
				if !ok || fd.Body == nil {
					continue
				}
				switch fn, _ := l.info.Defs[fd.Name].(*types.Func); {
				case fn == nil:
				case shortName(fn) == "kernel.admit":
					for _, st := range fd.Body.List {
						if r, ok := st.(*ast.RangeStmt); ok && loop == nil {
							loop = r.Body
						}
					}
				case shortName(fn) == "(*kernel/key.Verified).Authorize":
					auth = fd.Body
				}
			}
		}
	}
	if loop == nil || auth == nil {
		s.errs["admit's loop over the steps or key's (*Verified).Authorize was not found"] = true
		return
	}
	for _, body := range []ast.Node{loop, auth} {
		ast.Inspect(body, func(n ast.Node) bool {
			id, ok := n.(*ast.Ident)
			if !ok {
				return true
			}
			for _, l := range s.pkgs {
				if c, ok := l.info.Uses[id].(*types.Const); ok && c.Val().Kind() == constant.String && slices.Contains(notStepCodes, constant.StringVal(c.Val())) {
					s.fail(id, "%s, a code in notStepCodes, is named where a step is refused", c.Name())
				}
			}
			return true
		})
	}
}

// guardedFields are kernel's fields a code could enter through without a
// checked write, and the only functions that may write them. kernel.Entry's
// Body is what the exempt json.Unmarshal in kernel.body decodes (L3
// 6924923773 point 2): written only by the log's append, from a body the
// kernel marshals from values this scan checks, and by the log's own decode
// of what append sealed, it holds no code the scan has not read.
var guardedFields = map[string]struct {
	field   string
	writers []string
}{
	"Entry": {"Body", []string{"(*kernel.Log).append"}},
}

// fieldNamed is the field of package p's struct type typ named name.
func fieldNamed(p *types.Package, typ, name string) *types.Var {
	if obj, ok := p.Scope().Lookup(typ).(*types.TypeName); ok {
		if st, ok := obj.Type().Underlying().(*types.Struct); ok {
			for i := range st.NumFields() {
				if st.Field(i).Name() == name {
					return st.Field(i)
				}
			}
		}
	}
	return nil
}

// scanner checks every write of a code-carrying field in kernel and key. A
// code-carrying field is key.Refusal's Code, or any field a code is copied
// from; a code parameter is a function parameter a code is copied from. The
// two sets grow until they are closed, and each write into either must be a
// declared package-level string constant of kernel or key, or a read of
// another member.
type scanner struct {
	fset   *token.FileSet
	pkgs   []*loaded
	fields map[*types.Var]bool // code-carrying fields
	params map[*types.Var]bool // code parameters
	// guarded are fields a code can enter through unchecked (kernel.Entry's
	// Body, which the exempt json.Unmarshal in kernel.body decodes), with
	// the only functions that may write them.
	guarded map[*types.Var]map[string]bool
	used    map[string]bool
	errs    map[string]bool
	sites   map[string]bool // externalWriters sites the scan met
}

func (s *scanner) scanned(p *types.Package) bool {
	return p != nil && slices.ContainsFunc(s.pkgs, func(l *loaded) bool { return l.pkg == p })
}

func (s *scanner) fail(n ast.Node, f string, a ...any) {
	p := s.fset.Position(n.Pos())
	s.errs[fmt.Sprintf("%s:%d: %s", filepath.Base(p.Filename), p.Line, fmt.Sprintf(f, a...))] = true
}

func (s *scanner) run() {
	s.identical()
	for _, p := range s.pkgs {
		for _, imp := range p.pkg.Imports() {
			if imp.Path() == "unsafe" {
				s.fail(p.files[0], "package %s imports unsafe, which can write a code unseen", p.pkg.Name())
			}
		}
		fl := funcLitVars(s, p)
		for _, f := range p.files {
			for _, d := range f.Decls {
				var fn *types.Func
				if fd, ok := d.(*ast.FuncDecl); ok {
					fn, _ = p.info.Defs[fd.Name].(*types.Func)
				}
				ast.Inspect(d, func(n ast.Node) bool { s.node(p, fl, fn, n); return true })
			}
		}
		s.checkParams(p)
	}
}

// fieldOf is the field e selects, if e is a field selection.
func fieldOf(p *loaded, e ast.Expr) *types.Var {
	if se, ok := ast.Unparen(e).(*ast.SelectorExpr); ok {
		if sel := p.info.Selections[se]; sel != nil && sel.Kind() == types.FieldVal {
			return sel.Obj().(*types.Var)
		}
	}
	return nil
}

func (s *scanner) node(p *loaded, fl map[*types.Var]bool, fn *types.Func, n ast.Node) {
	switch n := n.(type) {
	case *ast.CompositeLit:
		t := p.info.TypeOf(n)
		if _, ok := t.(*types.TypeParam); ok {
			s.fail(n, "a composite literal of a type parameter, whose fields the scan cannot tell")
			return
		}
		st, ok := t.Underlying().(*types.Struct)
		if !ok {
			return
		}
		for i, el := range n.Elts {
			if kv, ok := el.(*ast.KeyValueExpr); ok {
				if k, ok := kv.Key.(*ast.Ident); ok {
					if v, ok := p.info.Uses[k].(*types.Var); ok {
						s.write(p, fn, el, v, kv.Value)
					}
				}
			} else if i < st.NumFields() {
				s.write(p, fn, el, st.Field(i), el)
			}
		}
	case *ast.AssignStmt:
		for i, lhs := range n.Lhs {
			v := fieldOf(p, lhs)
			if v == nil || !s.fields[v] && s.guarded[v] == nil {
				continue
			}
			switch {
			case s.guarded[v] != nil:
				s.write(p, fn, n, v, nil)
			case n.Tok != token.ASSIGN:
				s.fail(n, "a code written with %s", n.Tok)
			case len(n.Lhs) != len(n.Rhs):
				s.fail(n, "a code written from a multi-value call")
			default:
				s.code(p, fn, n.Rhs[i])
			}
		}
	case *ast.UnaryExpr:
		if v := fieldOf(p, n.X); n.Op == token.AND && v != nil {
			s.write(p, fn, n, v, nil)
		}
	case *ast.RangeStmt:
		for _, e := range []ast.Expr{n.Key, n.Value} {
			if v := fieldOf(p, e); e != nil && v != nil && n.Tok == token.ASSIGN {
				s.write(p, fn, n, v, nil)
			}
		}
	case *ast.CallExpr:
		s.call(p, fl, fn, n)
	case *ast.TypeAssertExpr:
		if n.Type != nil && s.holds(p.info.TypeOf(n.Type)) {
			s.fail(n, "a type assertion to %s takes a code out of an interface, where it could have come from anywhere", p.info.TypeOf(n.Type))
		}
	case *ast.CaseClause:
		for _, e := range n.List {
			if tv := p.info.Types[e]; tv.IsType() && s.holds(tv.Type) {
				s.fail(e, "a type switch case %s takes a code out of an interface, where it could have come from anywhere", tv.Type)
			}
		}
	}
}

// write checks a write of field v at n, in fn: a code-carrying field takes
// only a code (value, or nil for a write whose value the scan cannot read);
// a guarded field is written only in its own writers.
func (s *scanner) write(p *loaded, fn *types.Func, n ast.Node, v *types.Var, value ast.Expr) {
	if w := s.guarded[v]; w != nil {
		if fn == nil || !w[shortName(fn)] {
			s.fail(n, "guarded field %s written outside its writers", v.Name())
		}
		return
	}
	if !s.fields[v] {
		return
	}
	if value == nil {
		s.fail(n, "a code field written by address or as a range variable")
		return
	}
	s.code(p, fn, value)
}

// identical makes a field code-carrying, or guarded, when its struct type is
// identical, tags aside, to the struct of one that is: Go assigns a value of
// an unnamed struct type to a named type of the same underlying struct with
// no conversion, so such a literal's fields are the code fields by another
// name (L3 6924923773 and Security 6924966358, point 1).
func (s *scanner) identical() {
	var structs []*types.Struct
	seen := map[types.Type]bool{}
	var walk func(t types.Type)
	walk = func(t types.Type) {
		if t == nil || seen[t] {
			return
		}
		seen[t] = true
		switch u := t.(type) {
		case *types.Named:
			walk(u.Underlying())
			for i := range u.TypeArgs().Len() {
				walk(u.TypeArgs().At(i))
			}
		case *types.Alias:
			walk(types.Unalias(u))
		case *types.Pointer:
			walk(u.Elem())
		case *types.Slice:
			walk(u.Elem())
		case *types.Array:
			walk(u.Elem())
		case *types.Map:
			walk(u.Key())
			walk(u.Elem())
		case *types.Chan:
			walk(u.Elem())
		case *types.Signature:
			for _, tup := range []*types.Tuple{u.Params(), u.Results()} {
				for i := range tup.Len() {
					walk(tup.At(i).Type())
				}
			}
		case *types.TypeParam:
			walk(u.Constraint())
		case *types.Interface:
			for i := range u.NumEmbeddeds() {
				walk(u.EmbeddedType(i))
			}
		case *types.Union:
			for i := range u.Len() {
				walk(u.Term(i).Type())
			}
		case *types.Struct:
			structs = append(structs, u)
			for i := range u.NumFields() {
				walk(u.Field(i).Type())
			}
		}
	}
	for _, l := range s.pkgs {
		for _, tv := range l.info.Types {
			walk(tv.Type)
		}
		for _, o := range l.info.Defs {
			if o != nil {
				walk(o.Type())
			}
		}
	}
	var marked []*types.Struct
	for _, st := range structs {
		for i := range st.NumFields() {
			if s.fields[st.Field(i)] || s.guarded[st.Field(i)] != nil {
				marked = append(marked, st)
				break
			}
		}
	}
	for _, st := range structs {
		for _, m := range marked {
			if st == m || st.NumFields() != m.NumFields() || !types.IdenticalIgnoreTags(st, m) {
				continue
			}
			for i := range m.NumFields() {
				if s.fields[m.Field(i)] {
					s.fields[st.Field(i)] = true
				}
				if w := s.guarded[m.Field(i)]; w != nil && s.guarded[st.Field(i)] == nil {
					s.guarded[st.Field(i)] = w
				}
			}
		}
	}
}

// code checks e, written into a code-carrying field or passed at a code
// parameter.
func (s *scanner) code(p *loaded, fn *types.Func, e ast.Expr) {
	e = ast.Unparen(e)
	var id *ast.Ident
	switch x := e.(type) {
	case *ast.Ident:
		id = x
	case *ast.SelectorExpr:
		if v := fieldOf(p, x); v != nil {
			if !s.scanned(v.Pkg()) {
				s.fail(e, "a code copied from field %s outside kernel and key", v.Name())
			}
			s.fields[v] = true
			return
		}
		id = x.Sel
	default:
		s.fail(e, "a code that is not a declared constant: %s", types.ExprString(e))
		return
	}
	switch o := p.info.Uses[id].(type) {
	case *types.Const:
		b, ok := o.Type().Underlying().(*types.Basic)
		if ok && b.Info()&types.IsString != 0 && s.scanned(o.Pkg()) && o.Parent() == o.Pkg().Scope() {
			s.used[constant.StringVal(o.Val())] = true
			return
		}
		s.fail(e, "a code from constant %s, which is not a package-level string constant of kernel or key", o.Name())
	case *types.Var:
		if fn != nil && isParam(fn, o) {
			s.params[o] = true
			return
		}
		s.fail(e, "a code from variable %s, which is not a code parameter", o.Name())
	default:
		s.fail(e, "a code that is not a declared constant: %s", types.ExprString(e))
	}
}

// isParam says whether v is one of fn's own parameters.
func isParam(fn *types.Func, v *types.Var) bool {
	ps := fn.Type().(*types.Signature).Params()
	for i := range ps.Len() {
		if ps.At(i) == v {
			return true
		}
	}
	return false
}

// callee is the function a call statically names, if any.
// callee is the function or method a call names, and whether the call is
// dynamic (an interface method); nil for a call through a function value.
func callee(p *loaded, c *ast.CallExpr) (*types.Func, bool) {
	switch f := ast.Unparen(c.Fun).(type) {
	case *ast.Ident:
		fn, _ := p.info.Uses[f].(*types.Func)
		return fn, false
	case *ast.SelectorExpr:
		if sel := p.info.Selections[f]; sel != nil {
			if sel.Kind() != types.MethodVal {
				return nil, false
			}
			return sel.Obj().(*types.Func), types.IsInterface(sel.Recv())
		}
		fn, _ := p.info.Uses[f.Sel].(*types.Func)
		return fn, false
	case *ast.IndexExpr, *ast.IndexListExpr: // an explicit instantiation
		var x ast.Expr
		if ie, ok := f.(*ast.IndexExpr); ok {
			x = ie.X
		} else {
			x = f.(*ast.IndexListExpr).X
		}
		if id, ok := ast.Unparen(x).(*ast.Ident); ok {
			fn, _ := p.info.Uses[id].(*types.Func)
			return fn, false
		}
	}
	return nil, false
}

// shortName is fn's full name without the module path.
func shortName(fn *types.Func) string {
	return strings.ReplaceAll(fn.FullName(), modulePath+"/", "")
}

func (s *scanner) call(p *loaded, fl map[*types.Var]bool, encl *types.Func, c *ast.CallExpr) {
	if tv := p.info.Types[c.Fun]; tv.IsType() {
		if len(c.Args) == 1 && s.reaches(tv.Type, true) && !types.Identical(tv.Type, p.info.TypeOf(c.Args[0])) {
			s.fail(c, "a conversion to %s, which holds a code", tv.Type)
		}
		return
	} else if tv.IsBuiltin() {
		if id, ok := ast.Unparen(c.Fun).(*ast.Ident); ok && id.Name == "copy" && len(c.Args) > 0 && s.reaches(p.info.TypeOf(c.Args[0]), false) {
			s.fail(c, "copy into a value that holds a code")
		}
		return
	}
	fn, dynamic := callee(p, c)
	if fn != nil && !dynamic && s.scanned(fn.Pkg()) {
		sig := fn.Origin().Type().(*types.Signature)
		n := sig.Params().Len()
		for i := range n {
			if !s.params[sig.Params().At(i)] {
				continue
			}
			if sig.Variadic() && i == n-1 || i >= len(c.Args) || len(c.Args) == 1 && n > 1 {
				s.fail(c, "a code parameter of %s passed variadically or from a multi-value call", fn.Name())
				continue
			}
			s.code(p, encl, c.Args[i])
		}
		return
	}
	if fn == nil {
		if id, ok := ast.Unparen(c.Fun).(*ast.Ident); ok {
			if v, ok := p.info.Uses[id].(*types.Var); ok && fl[v] {
				return // bound only to function literals or kernel and key functions, which the scan reads
			}
		}
	}
	name := "a function value"
	if fn != nil {
		name = shortName(fn)
	}
	site := name
	if encl != nil {
		site += " in " + shortName(encl)
	}
	if _, ok := externalWriters[name]; ok {
		return
	}
	if _, ok := externalWriters[site]; ok {
		s.sites[site] = true
		return
	}
	for _, a := range c.Args {
		if s.reaches(p.info.TypeOf(a), false) {
			s.fail(a, "%s is handed %s, which reaches a code it could write", site, types.ExprString(a))
		}
	}
	// What such a call returns was built where the scan cannot read: a
	// result that holds or reaches a code fails, unless the callee is in a
	// package that cannot name key's types (the standard library, or a
	// module package that does not import key), so its result holds only
	// codes it was handed (L3 6924923773 point 3, Security 6924966358 point 2).
	if fn != nil && !dynamic && !s.namesKey(fn.Pkg()) {
		return
	}
	if res, ok := p.info.TypeOf(c).(*types.Tuple); ok {
		for i := range res.Len() {
			if s.holds(res.At(i).Type()) {
				s.fail(c, "%s returns %s, which holds a code built where the scan cannot read", site, res.At(i).Type())
			}
		}
	} else if t := p.info.TypeOf(c); t != nil && s.holds(t) {
		s.fail(c, "%s returns %s, which holds a code built where the scan cannot read", site, t)
	}
}

// namesKey says whether package p can name key's types: it is a module
// package that imports key, directly or through others.
func (s *scanner) namesKey(p *types.Package) bool {
	if p == nil || !strings.HasPrefix(p.Path(), modulePath+"/") {
		return false
	}
	seen := map[*types.Package]bool{}
	var imports func(q *types.Package) bool
	imports = func(q *types.Package) bool {
		if seen[q] {
			return false
		}
		seen[q] = true
		if q == s.pkgs[0].pkg {
			return true
		}
		return slices.ContainsFunc(q.Imports(), imports)
	}
	return imports(p)
}

// reaches says whether a value of type t lets its holder write a code: t
// reaches a code-carrying field through a pointer, slice or map, or is an
// interface such a pointer could be held in.
func (s *scanner) reaches(t types.Type, indirect bool) bool {
	return s.reach(t, indirect, true, map[types.Type]bool{})
}

// holds says whether a value of type t holds or reaches a code other than
// through an interface: a code inside an interface value is of no use to
// kernel or key until a type assertion takes it out, and the scan fails
// every such assertion.
func (s *scanner) holds(t types.Type) bool {
	return s.reach(t, true, false, map[types.Type]bool{})
}

func (s *scanner) reach(t types.Type, indirect, iface bool, seen map[types.Type]bool) bool {
	if t == nil || seen[t] {
		return false
	}
	seen[t] = true
	switch u := t.Underlying().(type) {
	case *types.Pointer:
		return s.reach(u.Elem(), true, iface, seen)
	case *types.Slice:
		return s.reach(u.Elem(), true, iface, seen)
	case *types.Map:
		return s.reach(u.Key(), true, iface, seen) || s.reach(u.Elem(), true, iface, seen)
	case *types.Array:
		return s.reach(u.Elem(), indirect, iface, seen)
	case *types.Chan:
		return s.reach(u.Elem(), true, iface, seen)
	case *types.Struct:
		for i := range u.NumFields() {
			if indirect && (s.fields[u.Field(i)] || s.guarded[u.Field(i)] != nil) || s.reach(u.Field(i).Type(), indirect, iface, seen) {
				return true
			}
		}
	case *types.Interface:
		if !iface {
			return false
		}
		if u.Empty() {
			return true
		}
		for _, l := range s.pkgs {
			for _, name := range l.pkg.Scope().Names() {
				tn, ok := l.pkg.Scope().Lookup(name).(*types.TypeName)
				if !ok || types.IsInterface(tn.Type()) {
					continue
				}
				for _, h := range []types.Type{tn.Type(), types.NewPointer(tn.Type())} {
					if types.Implements(h, u) && s.reaches(h, false) {
						return true
					}
				}
			}
		}
	}
	return false
}

// funcLitVars are p's variables of function type that the scan can follow:
// a local whose every binding is a function literal or a kernel or key
// function, and whose address is never taken; and a parameter of an
// unexported function that every call binds the same way.
func funcLitVars(s *scanner, p *loaded) map[*types.Var]bool {
	ok, bad := map[*types.Var]bool{}, map[*types.Var]bool{}
	follows := func(e ast.Expr) bool {
		switch x := ast.Unparen(e).(type) {
		case *ast.FuncLit:
			return true
		case *ast.Ident:
			fn, isFn := p.info.Uses[x].(*types.Func)
			return isFn && s.scanned(fn.Pkg())
		case *ast.SelectorExpr:
			fn, isFn := p.info.Uses[x.Sel].(*types.Func)
			sel := p.info.Selections[x]
			return isFn && s.scanned(fn.Pkg()) && (sel == nil || !types.IsInterface(sel.Recv()))
		}
		return false
	}
	bind := func(v *types.Var, rhs ast.Expr) {
		if v == nil {
			return
		}
		if rhs != nil && follows(rhs) {
			ok[v] = true
		} else {
			bad[v] = true
		}
	}
	varOf := func(id *ast.Ident) *types.Var {
		obj := p.info.Defs[id]
		if obj == nil {
			obj = p.info.Uses[id]
		}
		v, _ := obj.(*types.Var)
		if v != nil && v.Parent() == v.Pkg().Scope() {
			bad[v] = true // a package variable: any package may rebind an exported one
		}
		return v
	}
	for _, f := range p.files {
		ast.Inspect(f, func(n ast.Node) bool {
			switch n := n.(type) {
			case *ast.AssignStmt:
				for i, l := range n.Lhs {
					if id, isID := ast.Unparen(l).(*ast.Ident); isID {
						if len(n.Lhs) == len(n.Rhs) {
							bind(varOf(id), n.Rhs[i])
						} else {
							bind(varOf(id), nil)
						}
					}
				}
			case *ast.ValueSpec:
				for i, id := range n.Names {
					if len(n.Names) == len(n.Values) {
						bind(varOf(id), n.Values[i])
					} else {
						bind(varOf(id), nil)
					}
				}
			case *ast.UnaryExpr:
				if id, isID := ast.Unparen(n.X).(*ast.Ident); isID && n.Op == token.AND {
					bind(varOf(id), nil)
				}
			case *ast.FuncDecl:
				fn, _ := p.info.Defs[n.Name].(*types.Func)
				if fn == nil {
					return true
				}
				ps := fn.Type().(*types.Signature).Params()
				for i := range ps.Len() {
					if _, isFunc := ps.At(i).Type().Underlying().(*types.Signature); isFunc {
						if fn.Exported() {
							bad[ps.At(i)] = true
						} else {
							ok[ps.At(i)] = true
						}
					}
				}
			case *ast.CallExpr:
				fn, dynamic := callee(p, n)
				if fn == nil || dynamic || !s.scanned(fn.Pkg()) {
					return true
				}
				ps := fn.Origin().Type().(*types.Signature).Params()
				for i := range ps.Len() {
					if _, isFunc := ps.At(i).Type().Underlying().(*types.Signature); isFunc && (i >= len(n.Args) || !follows(n.Args[i])) {
						bad[ps.At(i)] = true
					}
				}
			}
			return true
		})
	}
	for v := range bad {
		delete(ok, v)
	}
	return ok
}

// checkParams fails a code parameter that its function writes, takes the
// address of or is variadic at, and a function with one that is used other
// than by a direct call, or is a method an interface could call.
func (s *scanner) checkParams(p *loaded) {
	owner := map[*types.Var]*types.Func{}
	for _, f := range p.files {
		for _, d := range f.Decls {
			fd, ok := d.(*ast.FuncDecl)
			if !ok {
				continue
			}
			fn, _ := p.info.Defs[fd.Name].(*types.Func)
			if fn == nil {
				continue
			}
			ps := fn.Type().(*types.Signature).Params()
			for i := range ps.Len() {
				if s.params[ps.At(i)] {
					owner[ps.At(i)] = fn
				}
			}
			isCP := func(e ast.Expr) bool {
				id, ok := ast.Unparen(e).(*ast.Ident)
				if !ok {
					return false
				}
				v, _ := p.info.Uses[id].(*types.Var)
				return v != nil && s.params[v] && owner[v] == fn
			}
			if fd.Body == nil {
				continue
			}
			ast.Inspect(fd.Body, func(n ast.Node) bool {
				switch n := n.(type) {
				case *ast.AssignStmt:
					for _, l := range n.Lhs {
						if isCP(l) {
							s.fail(n, "code parameter %s is reassigned", types.ExprString(l))
						}
					}
				case *ast.UnaryExpr:
					if n.Op == token.AND && isCP(n.X) {
						s.fail(n, "code parameter %s has its address taken", types.ExprString(n.X))
					}
				case *ast.RangeStmt:
					if n.Tok == token.ASSIGN && (n.Key != nil && isCP(n.Key) || n.Value != nil && isCP(n.Value)) {
						s.fail(n, "a code parameter is a range variable")
					}
				}
				return true
			})
		}
	}
	fns := map[*types.Func]bool{}
	for v, fn := range owner {
		fns[fn] = true
		sig := fn.Type().(*types.Signature)
		if sig.Variadic() && sig.Params().At(sig.Params().Len()-1) == v {
			s.fail(p.files[0], "%s's code parameter is variadic", fn.Name())
		}
		if sig.Recv() != nil && fn.Exported() {
			s.fail(p.files[0], "exported method %s takes a code parameter, and an interface outside kernel and key could call it", fn.Name())
		}
	}
	// Every use of such a function is a direct call, and no interface in
	// kernel or key has a method of a code-parameter method's name.
	called := map[*ast.Ident]bool{}
	for _, l := range s.pkgs {
		for _, f := range l.files {
			ast.Inspect(f, func(n ast.Node) bool {
				if c, ok := n.(*ast.CallExpr); ok {
					switch x := ast.Unparen(c.Fun).(type) {
					case *ast.Ident:
						called[x] = true
					case *ast.SelectorExpr:
						called[x.Sel] = true
					case *ast.IndexExpr:
						if id, ok := x.X.(*ast.Ident); ok {
							called[id] = true
						}
					}
				}
				if it, ok := n.(*ast.InterfaceType); ok {
					for _, m := range it.Methods.List {
						for _, name := range m.Names {
							for fn := range fns {
								if fn.Type().(*types.Signature).Recv() != nil && fn.Name() == name.Name {
									s.fail(it, "interface method %s shares a code-parameter method's name", name.Name)
								}
							}
						}
					}
				}
				return true
			})
		}
	}
	for _, l := range s.pkgs {
		for id, obj := range l.info.Uses {
			if fn, ok := obj.(*types.Func); ok && fns[fn.Origin()] && !called[id] {
				s.fail(id, "%s, which takes a code parameter, is used as a value", fn.Name())
			}
		}
	}
}
