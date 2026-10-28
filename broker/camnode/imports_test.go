package camnode

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// REQ: NET-2, DEV-3

// TestNoOutboundDial (link half; the binary's socket half is part b2): no
// source file of the server opens a connection. It imports no client
// package and calls no dialer: the node only answers on the listener the
// binary hands it. Revert mutant: a net.Dial or an "net/http" import in a
// non-test file.
func TestNoOutboundDial(t *testing.T) {
	banned := map[string]bool{
		"net/http": true, "net/rpc": true, "net/smtp": true, "net/mail": true,
		"net/http/httptrace": true, "os/exec": true, "syscall": true, "unsafe": true,
	}
	dialers := map[string]bool{
		"Dial": true, "DialContext": true, "DialTCP": true, "DialUDP": true, "DialIP": true,
		"DialUnix": true, "DialTimeout": true, "DialWithDialer": true, "Dialer": true,
		"ListenPacket": true, "ListenUDP": true, "ListenMulticastUDP": true, "Listen": true,
	}
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	fs := token.NewFileSet()
	seen := 0
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fs, name, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		seen++
		for _, im := range f.Imports {
			if p, _ := strconv.Unquote(im.Path.Value); banned[p] {
				t.Errorf("%s imports %s", name, p)
			}
		}
		ast.Inspect(f, func(n ast.Node) bool {
			if s, ok := n.(*ast.SelectorExpr); ok && dialers[s.Sel.Name] {
				t.Errorf("%s: %s uses %s", name, fs.Position(s.Pos()), s.Sel.Name)
			}
			return true
		})
	}
	if seen == 0 {
		t.Fatal("no source files read")
	}
}
