package drone

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"log"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

// canaryKey is a synthetic secret, distinctive in every encoding.
var canaryKey = []byte("DRONE-CANARY-KEY-7c1e9f02b4d6a8!")

// spills reports whether s holds the canary in any encoding a careless
// format or log line would produce.
func spills(s string) bool {
	forms := []string{string(canaryKey), hex.EncodeToString(canaryKey), strings.ToUpper(hex.EncodeToString(canaryKey)),
		base64.StdEncoding.EncodeToString(canaryKey), base64.RawURLEncoding.EncodeToString(canaryKey),
		fmt.Sprint([]byte(canaryKey)), fmt.Sprintf("%#v", [32]byte(canaryKey)), fmt.Sprintf("%v", [32]byte(canaryKey)),
		string(canaryKey[:12])}
	for _, f := range forms {
		if strings.Contains(s, f) {
			return true
		}
	}
	return false
}

// REQ: NET-2
// TestKeyNeverLeaves (brief acceptance test 5, P2): a canary key loaded by
// every path (drawn and written, read from its file, provisioned, used to
// sign) never appears in a log line, an error, any format of any exported
// type, the environment or the arguments; the key file is refused unless it
// is a regular file of mode 0600 owned by this process's user.
func TestKeyNeverLeaves(t *testing.T) {
	var logs bytes.Buffer
	logger := log.New(&logs, "", 0)
	var errs []error
	note := func(err error) {
		if err != nil {
			errs = append(errs, err)
			logger.Printf("%v", err)
		}
	}

	// Drawn from a reader and written.
	k, err := NewKey(bytes.NewReader(canaryKey))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "drone.key")
	if err := WriteKeyFile(path, k); err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Stat(path); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("written key file: %v, %v", fi, err)
	}

	// Read from its file.
	k2, err := LoadKeyFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if *k2.s() != *k.s() {
		t.Fatal("the key read back differs")
	}

	// Refused files, each with an error that names no byte of the key.
	for _, mode := range []os.FileMode{0o644, 0o640, 0o604, 0o400, 0o700, 0o660} {
		p := filepath.Join(dir, fmt.Sprintf("mode-%o.key", mode))
		if err := os.WriteFile(p, canaryKey, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(p, mode); err != nil {
			t.Fatal(err)
		}
		_, err := LoadKeyFile(p)
		if err == nil {
			t.Errorf("mode %#o accepted", mode)
		}
		note(err)
	}
	long := filepath.Join(dir, "long.key")
	os.WriteFile(long, append(append([]byte(nil), canaryKey...), canaryKey...), 0o600)
	short := filepath.Join(dir, "short.key")
	os.WriteFile(short, canaryKey[:31], 0o600)
	link := filepath.Join(dir, "link.key")
	os.Symlink(path, link)
	zero := filepath.Join(dir, "zero.key")
	os.WriteFile(zero, make([]byte, KeySize), 0o600)
	for _, p := range []string{long, short, link, zero, dir, filepath.Join(dir, "absent.key")} {
		_, err := LoadKeyFile(p)
		if err == nil {
			t.Errorf("%s accepted", filepath.Base(p))
		}
		note(err)
	}
	if os.Getuid() == 0 {
		other := filepath.Join(dir, "other.key")
		os.WriteFile(other, canaryKey, 0o600)
		if err := os.Chown(other, 65534, 65534); err != nil {
			t.Fatal(err)
		}
		_, err := LoadKeyFile(other)
		if err == nil {
			t.Error("a key file owned by another user was accepted")
		}
		note(err)
	} else {
		// Not root, so no file of another owner can be made: the owner check is
		// code-read here (ASSUMPTIONS.md row DRONE-sim-11).
		t.Log("owner check not exercised: not root")
	}
	_, err = NewKey(bytes.NewReader(make([]byte, KeySize)))
	note(err)
	_, err = NewKey(bytes.NewReader(canaryKey[:5]))
	note(err)
	note(WriteKeyFile(filepath.Join(dir, "absent-dir", "k"), k))

	// Provisioned: the frame carries the key to the aircraft, by design; the
	// key appears on that wire and nowhere else.
	var wire bytes.Buffer
	if err := Provision(&wire, k2, time.Now()); err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(wire.Bytes(), canaryKey) {
		t.Fatal("the provisioning frame does not carry the key; the canary check would be vacuous")
	}

	// Used to sign: a signed frame carries a signature, never the key.
	near, far := net.Pipe()
	defer far.Close()
	got := make(chan []byte, 1)
	go func() {
		b := make([]byte, 4096)
		n, _ := far.Read(b)
		got <- b[:n]
	}()
	l, err := Dial(near, k2)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	if err := l.SendHeartbeat(); err != nil {
		t.Fatal(err)
	}
	if frame := <-got; len(frame) == 0 || spills(string(frame)) {
		t.Errorf("a signed frame (%d bytes) carries the key", len(frame))
	}

	// A holder over that link logs a refused policy.
	owner := testOwner(t, 1)
	h, err := NewHolder(l, owner.Public().(ed25519.PublicKey), t.TempDir(), logger)
	if err != nil {
		t.Fatal(err)
	}
	note(h.Load([]byte(`{"policy":{},"sig":""}`)))
	plan := Plan{Params: []Param{{"FENCE_ENABLE", 1}}, Fence: []Item{{Command: 1}}}
	hb := Heartbeat{}

	// Formatting reads every field by reflection: stop the link's reader first.
	l.Close()
	<-l.done

	// Every exported type, by value and by pointer, under every verb.
	values := map[string]any{
		"Key": k2, "Link": l, "Holder": h, "Policy": testPolicy(), "Plan": plan, "Param": plan.Params[0],
		"Item": plan.Fence[0], "Point": testDock, "Waypoint": wp(0, 0, 1), "Route": testPolicy().Routes[0],
		"Dock": testPolicy().Dock, "Heartbeat": hb,
	}
	for _, name := range exportedTypes(t) {
		if _, ok := values[name]; !ok {
			t.Errorf("exported type %s is not in this test's table", name)
		}
	}
	var formatted strings.Builder
	for name, v := range values {
		for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%x", "%X", "%q", "%d"} {
			fmt.Fprintf(&formatted, "%s "+verb+"\n", name, v)
			ptr := reflect.New(reflect.TypeOf(v))
			ptr.Elem().Set(reflect.ValueOf(v))
			fmt.Fprintf(&formatted, "%s "+verb+"\n", name, ptr.Interface())
		}
	}
	fmt.Fprintf(&formatted, "%v %+v %#v %x\n", *k2.s() == *k.s(), k, &k, []Key{k, k2})
	for _, line := range strings.Split(formatted.String(), "\n") {
		if spills(line) {
			t.Errorf("a formatted exported value carries the key: %.80s", line)
		}
	}
	for _, err := range errs {
		if spills(err.Error()) || spills(fmt.Sprintf("%+v %#v", err, err)) {
			t.Errorf("an error carries the key: %v", err)
		}
	}
	if len(errs) < 14 {
		t.Errorf("only %d refusals were checked", len(errs))
	}
	if spills(logs.String()) {
		t.Error("the log carries the key")
	}
	if spills(strings.Join(os.Environ(), "\n")) || spills(strings.Join(os.Args, " ")) {
		t.Error("the environment or the arguments carry the key")
	}
	if !spills(string(canaryKey)) {
		t.Fatal("spills misses the raw key; the checks above are vacuous")
	}
}

// exportedTypes lists the package's exported type names from its sources.
func exportedTypes(t *testing.T) []string {
	t.Helper()
	fset := token.NewFileSet()
	files, _ := filepath.Glob("*.go")
	var out []string
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		af, err := parser.ParseFile(fset, f, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, d := range af.Decls {
			g, ok := d.(*ast.GenDecl)
			if !ok || g.Tok != token.TYPE {
				continue
			}
			for _, s := range g.Specs {
				if ts := s.(*ast.TypeSpec); ts.Name.IsExported() {
					out = append(out, ts.Name.Name)
				}
			}
		}
	}
	if len(out) == 0 {
		t.Fatal("no exported types found")
	}
	return out
}
