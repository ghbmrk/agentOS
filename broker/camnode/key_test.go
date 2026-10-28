package camnode

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/base64"
	"encoding/hex"
	"go/ast"
	"go/parser"
	"go/token"
	"math/big"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/ghbmrk/agentos/broker/camnode/se"
	"github.com/ghbmrk/agentos/broker/camnode/se/setest"
	"github.com/ghbmrk/agentos/broker/camwire"
)

// REQ: KRN-2, A16, NET-2

// TestDeviceKeyNeverExported: the element interface is exactly its seven
// methods, none of which returns key material; and a node whose element
// holds a canary key runs provisioning, a bundle, a refused bundle and a
// stream without the canary scalar in any log line, error or frame.
// Revert mutant: an Export method on se.Element.
func TestDeviceKeyNeverExported(t *testing.T) {
	typ := reflect.TypeFor[se.Element]()
	var names []string
	for i := range typ.NumMethod() {
		m := typ.Method(i)
		names = append(names, m.Name)
		for j := range m.Type.NumOut() {
			if out := m.Type.Out(j); strings.Contains(out.String(), "Private") {
				t.Errorf("%s returns %s", m.Name, out)
			}
		}
	}
	want := []string{"ClearOwnerPin", "Counter", "OwnerPin", "Public", "Raise", "SetOwnerPin", "Sign"}
	if !slices.Equal(names, want) {
		t.Fatalf("se.Element methods %v, want %v: a new method needs this test's review", names, want)
	}

	// The canary: a fixed synthetic scalar, never a real key.
	d, _ := new(big.Int).SetString("4c414e4152592d63616d6e6f64652d6465766963652d6b65792d3030303031", 16)
	k := &ecdsa.PrivateKey{D: d}
	k.Curve = elliptic.P256()
	k.X, k.Y = k.Curve.ScalarBaseMult(d.Bytes())
	raw := d.FillBytes(make([]byte, 32))
	canaries := [][]byte{raw, []byte(hex.EncodeToString(raw)), []byte(strings.ToUpper(hex.EncodeToString(raw))),
		[]byte(base64.StdEncoding.EncodeToString(raw)), []byte(d.String())}

	n := newNode(t)
	n.el = setest.NewMemoryKey(k)
	n.provision()
	var seen recorder
	if _, err := n.send(n.enforcer, n.owner.sign(t, n.bundle(2, goodSettings))); err != nil {
		t.Fatal(err)
	}
	_, err := n.send(n.enforcer, n.owner.sign(t, n.bundle(2, goodSettings)))
	seen.add([]byte(errString(err)))
	c, err := n.dial(n.core)
	if err != nil {
		t.Fatal(err)
	}
	for range 4 {
		f, err := camwire.ReadFrame(c, camwire.ToCore, testRanges.Thermal)
		if err != nil {
			t.Fatal(err)
		}
		seen.add(f.Payload)
	}
	seen.add([]byte(n.logs.all()))
	for _, name := range []string{currentName, pendingName} {
		p, _ := n.dir.Read(name)
		seen.add(p)
	}
	for _, c := range canaries {
		if seen.contains(c) {
			t.Fatalf("the device key's canary %q leaked", c)
		}
	}
	if seen.empty() {
		t.Fatal("nothing recorded")
	}
}

type recorder struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (r *recorder) add(p []byte) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.buf.Write(p)
	r.buf.WriteByte('\n')
}

func (r *recorder) contains(p []byte) bool { return bytes.Contains(r.buf.Bytes(), p) }
func (r *recorder) empty() bool            { return r.buf.Len() == 0 }

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// sources is every non-test Go file of the server and its element driver.
func sources(t *testing.T) []*ast.File {
	t.Helper()
	var out []*ast.File
	fs := token.NewFileSet()
	for _, dir := range []string{".", "se"} {
		files, err := filepath.Glob(filepath.Join(dir, "*.go"))
		if err != nil {
			t.Fatal(err)
		}
		for _, name := range files {
			if strings.HasSuffix(name, "_test.go") {
				continue
			}
			f, err := parser.ParseFile(fs, name, nil, 0)
			if err != nil {
				t.Fatal(err)
			}
			out = append(out, f)
		}
	}
	if len(out) < 5 {
		t.Fatalf("read %d files", len(out))
	}
	return out
}

// TestNoOutboundDial: the server and the element driver name no dialer
// (net.Dial*, tls.Dial*, a Dialer) and import no client package, so the
// node's code can only accept on the listener it is handed. The binary's
// run under a network namespace is part b2's, with the binary.
// Revert mutant: a net.Dial call in server.go.
func TestNoOutboundDial(t *testing.T) {
	banned := map[string]bool{
		"net/http": true, "net/rpc": true, "net/smtp": true, "net/mail": true, "os/exec": true,
		"net/http/httptrace": true,
	}
	for _, f := range sources(t) {
		for _, im := range f.Imports {
			p, _ := strconv.Unquote(im.Path.Value)
			if banned[p] {
				t.Errorf("%s imports %s", f.Name.Name, p)
			}
		}
		ast.Inspect(f, func(n ast.Node) bool {
			if id, ok := n.(*ast.Ident); ok && strings.HasPrefix(id.Name, "Dial") {
				t.Errorf("%s names %s", f.Name.Name, id.Name)
			}
			return true
		})
	}
}

// TestServerImportsNoTestElement: no production file imports the
// in-memory element.
func TestServerImportsNoTestElement(t *testing.T) {
	for _, f := range sources(t) {
		for _, im := range f.Imports {
			if strings.Contains(im.Path.Value, "setest") {
				t.Errorf("%s imports %s", f.Name.Name, im.Path.Value)
			}
		}
	}
}
