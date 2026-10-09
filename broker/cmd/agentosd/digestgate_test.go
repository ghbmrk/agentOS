package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// deliverAllowed are the broker's Deliver selectors that are not the
// digest transport's, by file and enclosing function: the corpus check's
// field, the control handler's agent and lateAgent's own. Only
// digestqueue's Sender calls a digest Transport (DC-6).
var deliverAllowed = map[string]string{
	"loops/corpus.go":      "ClosedCheck.hit",
	"control/handler.go":   "Handler.deliver",
	"cmd/agentosd/main.go": "lateAgent.Deliver",
}

// digestGate checks the digest's send paths structurally (DC-5, DC-6,
// DC-8, OP-2), so a second path from a batch to the modem fails CI:
//   - SendReceipt is used only in newDigestTransport, and Deliver is
//     selected only in digestqueue's sender.go (bar deliverAllowed);
//   - digestTransport is named only by newDigestTransport and its own
//     type and methods in digest.go, and newDigestTransport is called
//     only in main;
//   - in cmd/agentosd, cfg.Transport is only assigned in main and passed
//     to digestqueue.NewSender in openLocked; a cfg is never copied or
//     aliased, only selected through; reflect is not imported and
//     Method/MethodByName are not selected;
//   - cfg.Inform is only assigned in main and called in sendOutage, which
//     takes no parameters and calls it once with digestOutageLine, the
//     line no other function names (bar digestLineTexts);
//   - a batch's Snapshots and Lines are read only in digest.go's render,
//     carrier and refersTo (Lines in render only).
//
// files maps a broker-relative path to its source.
func digestGate(files map[string]string) []string {
	var bad []string
	fset := token.NewFileSet()
	for path, src := range files {
		f, err := parser.ParseFile(fset, path, src, 0)
		if err != nil {
			bad = append(bad, path+": "+err.Error())
			continue
		}
		agentosd := strings.HasPrefix(path, "cmd/agentosd/")
		digest := path == "cmd/agentosd/digest.go"
		if agentosd {
			for _, im := range f.Imports {
				if p, _ := strconv.Unquote(im.Path.Value); p == "reflect" {
					bad = append(bad, path+": reflect imported")
				}
			}
		}
		for _, decl := range f.Decls {
			fn, _ := decl.(*ast.FuncDecl)
			name, full := "", ""
			if fn != nil {
				name, full = fn.Name.Name, funcName(fn)
			}
			if gd, ok := decl.(*ast.GenDecl); ok && digest && gd.Tok == token.TYPE {
				if len(gd.Specs) == 1 && gd.Specs[0].(*ast.TypeSpec).Name.Name == "digestTransport" {
					continue // its own declaration
				}
			}
			if digest && name == "sendOutage" {
				bad = append(bad, checkSendOutage(fn)...)
			}
			var stack []ast.Node
			ast.Inspect(decl, func(n ast.Node) bool {
				if n == nil {
					stack = stack[:len(stack)-1]
					return true
				}
				var parent ast.Node
				if len(stack) > 0 {
					parent = stack[len(stack)-1]
				}
				stack = append(stack, n)
				switch n := n.(type) {
				case *ast.SelectorExpr:
					sel := n.Sel.Name
					switch {
					case sel == "SendReceipt" && (!digest || name != "newDigestTransport"):
						bad = append(bad, path+": SendReceipt in "+full)
					case sel == "Deliver" && path != "digestqueue/sender.go" && deliverAllowed[path] != full:
						bad = append(bad, path+": Deliver in "+full)
					case agentosd && (sel == "MethodByName" || sel == "Method"):
						bad = append(bad, path+": "+sel+" in "+full)
					case agentosd && sel == "cfg" && !isSelectorX(parent, n):
						bad = append(bad, path+": cfg copied in "+full)
					case agentosd && sel == "Transport" && isCfg(n.X) &&
						!(path == "cmd/agentosd/main.go" && name == "main" && isAssigned(parent, n)) &&
						!(digest && name == "openLocked" && isNewSenderArg(parent, n)):
						bad = append(bad, path+": digest transport in "+full)
					case agentosd && sel == "Inform" && isCfg(n.X) &&
						!(path == "cmd/agentosd/main.go" && name == "main" && isAssigned(parent, n)) &&
						!(digest && name == "sendOutage"):
						bad = append(bad, path+": Inform in "+full)
					case agentosd && sel == "Snapshots" && !(digest && (name == "render" || name == "carrier" || name == "refersTo")):
						bad = append(bad, path+": Snapshots in "+full)
					case agentosd && sel == "Lines" && !(digest && name == "render"):
						bad = append(bad, path+": Lines in "+full)
					}
				case *ast.Ident:
					switch {
					case n.Name == "newDigestTransport" && fn != nil && name != "newDigestTransport" &&
						!(path == "cmd/agentosd/main.go" && name == "main"):
						bad = append(bad, path+": newDigestTransport in "+full)
					case n.Name == "digestTransport" && !(digest && (name == "newDigestTransport" || recvIs(fn, "digestTransport"))):
						bad = append(bad, path+": digestTransport in "+full)
					case n.Name == "digestOutageLine" && fn != nil && name != "sendOutage" && name != "digestLineTexts":
						bad = append(bad, path+": outage line in "+full)
					}
				}
				return true
			})
		}
	}
	return bad
}

// checkSendOutage holds sendOutage to DC-8's shape: no parameters and one
// Inform call whose one argument is the identifier digestOutageLine.
func checkSendOutage(fn *ast.FuncDecl) []string {
	var bad []string
	if fn.Type.Params.NumFields() != 0 {
		bad = append(bad, "sendOutage takes parameters")
	}
	calls := 0
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		c, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		if s, ok := c.Fun.(*ast.SelectorExpr); ok && s.Sel.Name == "Inform" {
			calls++
			if len(c.Args) != 1 || !isIdent(c.Args[0], "digestOutageLine") {
				bad = append(bad, "sendOutage informs more than digestOutageLine")
			}
		}
		return true
	})
	if calls != 1 {
		bad = append(bad, "sendOutage does not call Inform exactly once")
	}
	return bad
}

// funcName is fn's name, with its receiver type for a method.
func funcName(fn *ast.FuncDecl) string {
	if r := recvName(fn); r != "" {
		return r + "." + fn.Name.Name
	}
	return fn.Name.Name
}

func recvName(fn *ast.FuncDecl) string {
	if fn == nil || fn.Recv == nil || len(fn.Recv.List) == 0 {
		return ""
	}
	t := fn.Recv.List[0].Type
	if s, ok := t.(*ast.StarExpr); ok {
		t = s.X
	}
	if id, ok := t.(*ast.Ident); ok {
		return id.Name
	}
	return ""
}

func isIdent(x ast.Expr, name string) bool {
	id, ok := x.(*ast.Ident)
	return ok && id.Name == name
}

func recvIs(fn *ast.FuncDecl, typ string) bool { return recvName(fn) == typ }

// isCfg reports whether x is a selector ending in .cfg (d.cfg, dg.cfg).
func isCfg(x ast.Expr) bool {
	s, ok := x.(*ast.SelectorExpr)
	return ok && s.Sel.Name == "cfg"
}

// isSelectorX reports whether n is selected through (n.Field), not used
// as a value.
func isSelectorX(parent ast.Node, n ast.Expr) bool {
	s, ok := parent.(*ast.SelectorExpr)
	return ok && s.X == n
}

// isAssigned reports whether n is the left side of an assignment.
func isAssigned(parent ast.Node, n ast.Expr) bool {
	a, ok := parent.(*ast.AssignStmt)
	return ok && a.Tok == token.ASSIGN && len(a.Lhs) == 1 && a.Lhs[0] == n
}

// isNewSenderArg reports whether n is an argument to
// digestqueue.NewSender.
func isNewSenderArg(parent ast.Node, n ast.Expr) bool {
	c, ok := parent.(*ast.CallExpr)
	if !ok {
		return false
	}
	s, ok := c.Fun.(*ast.SelectorExpr)
	if !ok || s.Sel.Name != "NewSender" {
		return false
	}
	if id, ok := s.X.(*ast.Ident); !ok || id.Name != "digestqueue" {
		return false
	}
	for _, a := range c.Args {
		if a == n {
			return true
		}
	}
	return false
}

func brokerSources(t *testing.T) map[string]string {
	t.Helper()
	root := filepath.Join("..", "..")
	files := map[string]string{}
	err := filepath.WalkDir(root, func(p string, e fs.DirEntry, err error) error {
		if err != nil || e.IsDir() || !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
			return err
		}
		rel, _ := filepath.Rel(root, p)
		if strings.HasPrefix(rel, "modemlink"+string(filepath.Separator)) {
			return nil // SendReceipt's own package
		}
		b, err := os.ReadFile(p)
		files[filepath.ToSlash(rel)] = string(b)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return files
}

// REQ: OP-2, OP-9
func TestDigestGate(t *testing.T) {
	files := brokerSources(t)
	if _, ok := files["cmd/agentosd/digest.go"]; !ok {
		t.Fatal("digest.go not found")
	}
	if bad := digestGate(files); len(bad) != 0 {
		t.Fatalf("digest gate: %q", bad)
	}
}

// Each case is a bypass the gate must catch, including every mutant from
// security 4a (6079804454, M1-M4) and L3 (6079813426, M1-M5) on #592.
// REQ: OP-2, OP-9
func TestDigestGateCatchesViolations(t *testing.T) {
	const pre = "package main\n"
	cases := map[string]map[string]string{
		"second file":     {"cmd/agentosd/other.go": pre + "func f(l *L) { l.SendReceipt(\"o\", \"t\") }\n"},
		"second func":     {"cmd/agentosd/digest.go": pre + "func g(l *L) { _ = l.SendReceipt }\n"},
		"inform":          {"cmd/agentosd/digest.go": pre + "func (d *D) daily() { d.cfg.Inform(\"x\") }\n"},
		"outage line":     {"cmd/agentosd/learn.go": pre + "func h() string { return digestOutageLine }\n"},
		"transport read":  {"cmd/agentosd/digest.go": pre + "func (d *D) daily() { _ = d.cfg.Transport }\n"},
		"transport built": {"cmd/agentosd/learn.go": pre + "func h() { _ = newDigestTransport(nil, \"o\") }\n"},
		"sec M1 deliver in main": {"cmd/agentosd/main.go": pre +
			"func main() { newDigestTransport(link, cfg.OwnerNumber).Deliver(context.Background(), \"leak\") }\n"},
		"sec M2, L3 M3 cfg alias": {"cmd/agentosd/digest.go": pre +
			"func (d *D) daily(ctx C) { c := d.cfg; c.Transport.Deliver(ctx, \"leak\") }\n"},
		"sec M3 reflect": {"cmd/agentosd/digest.go": pre + "import \"reflect\"\n" +
			"func (d *D) daily() { reflect.ValueOf(&modemlink.Link{}).MethodByName(\"Send\" + \"Receipt\") }\n"},
		"sec M4 snapshot leak": {"cmd/agentosd/leak.go": pre +
			"func leak(d *D, o *O) { bs, _ := d.q.List(); for _, s := range bs[0].Snapshots { o.Inform(s.Lines[0]) } }\n"},
		"L3 M1 deliver after set": {"cmd/agentosd/main.go": pre +
			"func main() { dg.cfg.Transport = t; dg.cfg.Transport.Deliver(ctx, \"bypass\") }\n"},
		"L3 M2 deliver in openLocked": {"cmd/agentosd/digest.go": pre +
			"func (d *D) openLocked(ctx C) { d.cfg.Transport.Deliver(ctx, \"bypass\") }\n"},
		"L3 M2 transport passed elsewhere": {"cmd/agentosd/digest.go": pre +
			"func (d *D) openLocked() { other(d.cfg.Transport) }\n"},
		"L3 M4 outage with batch": {"cmd/agentosd/digest.go": pre +
			"func (d *D) sendOutage(b digestqueue.Batch) { d.cfg.Inform(digestOutageLine + strings.Join(b.Snapshots[0].Lines, \" \")) }\n"},
		"outage line grown": {"cmd/agentosd/digest.go": pre +
			"func (d *D) sendOutage() { d.cfg.Inform(digestOutageLine + d.note) }\n"},
		"L3 M5 inform in another file": {"cmd/agentosd/leak.go": pre + "func (d *D) leak(t string) { d.cfg.Inform(t) }\n"},
		"transport asserted": {"cmd/agentosd/leak.go": pre +
			"func (d *D) leak(t T) { t.(digestTransport).send(\"o\", \"t\") }\n"},
		"deliver method value": {"cmd/agentosd/leak.go": pre + "func leak(t T) { f := t.Deliver; _ = f }\n"},
	}
	for name, files := range cases {
		if bad := digestGate(files); len(bad) == 0 {
			t.Errorf("%s: not caught", name)
		}
	}
}
