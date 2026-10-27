package main

import (
	"bytes"
	"crypto/rand"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/card"
	"github.com/ghbmrk/agentos/broker/clerk"
	"github.com/ghbmrk/agentos/broker/clerk/seal"
)

// REQ: A8, STO-2, CRED-8, CLK-1, ARC-2
// Acceptance: A8 (the scan tool for the owner session)

type drive struct {
	dir, store string
	rk         []byte
	rkText     string
	secret     []byte
}

// newDrive makes a sealed store with a recovery slot and one sealed secret,
// next to a plaintext partition holding nothing secret.
func newDrive(t *testing.T) drive {
	t.Helper()
	d := drive{dir: t.TempDir(), secret: []byte("synthetic-sealed-secret-0123456789")}
	var bits [20]byte
	rand.Read(bits[:])
	d.rkText = card.RecoveryKeyText(bits)
	var err error
	if d.rk, err = card.StoreRecoveryKey(d.rkText); err != nil {
		t.Fatal(err)
	}
	d.store = filepath.Join(d.dir, "state", "store")
	os.Mkdir(filepath.Dir(d.store), 0o700)
	st, err := seal.Create(d.store, seal.Recovery{Key: d.rk})
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Put("canary/secret", d.secret); err != nil {
		t.Fatal(err)
	}
	st.Close()
	esp := filepath.Join(d.dir, "esp")
	os.Mkdir(esp, 0o700)
	os.WriteFile(filepath.Join(esp, "loader.conf"), []byte("timeout 0\n"), 0o600)
	return d
}

func (d drive) esp() string { return filepath.Join(d.dir, "esp") }

// storeKey is the store's data key, checked against the store itself: the
// log key the store hands out is derived from it.
func (d drive) storeKey(t *testing.T) []byte {
	t.Helper()
	raw, _ := os.ReadFile(d.store)
	key, id, err := unwrapRecovery(raw, d.rk)
	if err != nil {
		t.Fatal(err)
	}
	st, err := seal.Unlock(d.store, seal.Recovery{Key: d.rk})
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	lk, _ := st.LogKey()
	if !bytes.Equal(derive(key, id, "log"), lk[:]) {
		t.Fatal("unwrapped a key that is not the store's")
	}
	return key
}

// The store's data key, not the old vault's, is a needle: planted on the
// drive in each encoding at an odd offset, it is found and named, never
// printed. So are the log key and a sealed secret.
func TestFindsSealedStoreKeyInEveryEncoding(t *testing.T) {
	d := newDrive(t)
	var out bytes.Buffer
	if n, err := run(d.store, d.rk, d.rkText, "", shippedClerks, []string{d.dir}, &out); err != nil || n != 0 {
		t.Fatalf("clean drive (the store file itself included): %d findings, %v\n%s", n, err, out.String())
	}
	key := d.storeKey(t)
	crock := base32.NewEncoding("0123456789ABCDEFGHJKMNPQRSTVWXYZ").WithPadding(base32.NoPadding)
	forms := map[string][]byte{
		"raw":          key,
		"hex":          []byte(hex.EncodeToString(key)),
		"HEX":          []byte(strings.ToUpper(hex.EncodeToString(key))),
		"base64":       []byte(base64.StdEncoding.EncodeToString(append([]byte("ab"), key...))),
		"base64url":    []byte(base64.URLEncoding.EncodeToString(append([]byte("a"), key...))),
		"base32":       []byte(base32.StdEncoding.EncodeToString(append([]byte("abc"), key...))),
		"crockford":    []byte(strings.ToLower(crock.EncodeToString(append([]byte("a"), key...)))),
		"raw fragment": key[3:19],
	}
	for name, form := range forms {
		os.WriteFile(filepath.Join(d.esp(), "leak.bin"), append(append([]byte("xyz"), form...), 'q'), 0o600)
		out.Reset()
		n, err := run(d.store, d.rk, d.rkText, "", shippedClerks, []string{d.esp()}, &out)
		if err != nil || n == 0 || !strings.Contains(out.String(), "FIND store data key") {
			t.Errorf("%s: %d findings, %v\n%s", name, n, err, out.String())
		}
		if bytes.Contains(out.Bytes(), key) || strings.Contains(out.String(), hex.EncodeToString(key)) {
			t.Errorf("%s: the output carries the key", name)
		}
	}
	st, _ := seal.Unlock(d.store, seal.Recovery{Key: d.rk})
	lk, _ := st.LogKey()
	st.Close()
	for want, leak := range map[string][]byte{"log key": lk[:], "store entry canary/secret": d.secret} {
		os.WriteFile(filepath.Join(d.esp(), "leak.bin"), append([]byte("x"), leak...), 0o600)
		out.Reset()
		if n, err := run(d.store, d.rk, d.rkText, "", shippedClerks, []string{d.esp()}, &out); err != nil || !strings.Contains(out.String(), "FIND "+want) {
			t.Errorf("%s: %d, %v\n%s", want, n, err, out.String())
		}
		if strings.Contains(out.String(), string(d.secret)) {
			t.Error("the output carries the sealed secret")
		}
	}
	// The recovery key as the slot takes it and a typed passphrase, which
	// the store does not hold, are needles too.
	pass := "synthetic passphrase words here"
	os.WriteFile(filepath.Join(d.esp(), "leak.bin"), []byte("x"+strings.ToUpper(hex.EncodeToString(d.rk))+" "+pass), 0o600)
	out.Reset()
	if _, err := run(d.store, d.rk, d.rkText, pass, shippedClerks, []string{d.esp()}, &out); err != nil ||
		!strings.Contains(out.String(), "FIND recovery key") || !strings.Contains(out.String(), "FIND passphrase") {
		t.Fatalf("typed factors: %v\n%s", err, out.String())
	}
	// Another store's recovery key opens nothing, so nothing is scanned.
	other := make([]byte, seal.RecoveryLen)
	if _, err := run(d.store, other, d.rkText, "", shippedClerks, []string{d.esp()}, &out); err == nil {
		t.Fatal("a wrong recovery key scanned")
	}
}

// The self-check refuses to report a clean scan unless every needle
// planted in a scratch blob is found.
func TestSelfCheckStopsOnMissedNeedle(t *testing.T) {
	needles := []Needle{{Name: "a", Value: []byte("needle-a-0123456789")}, {Name: "b", Value: []byte("needle-b-0123456789")}}
	s, err := NewScanner(needles[:1])
	if err != nil {
		t.Fatal(err)
	}
	if err := control(s, needles); err == nil || !strings.Contains(err.Error(), "missed b") {
		t.Fatalf("a scanner blind to b passed the self-check: %v", err)
	}
	if s, _ = NewScanner(needles); control(s, needles) != nil {
		t.Fatal("a full scanner failed the self-check")
	}
}

// The scan reads the sealed store, not the old core's vault.
func TestLinksNoVault(t *testing.T) {
	out, err := exec.Command("go", "list", "-deps", ".").CombinedOutput()
	if err != nil {
		t.Fatalf("go list: %v\n%s", err, out)
	}
	for _, dep := range strings.Fields(string(out)) {
		if dep == "github.com/ghbmrk/agentos/broker/vault" || dep == "github.com/ghbmrk/agentos/broker/recovery" {
			t.Errorf("agentos-a8scan links %s", dep)
		}
	}
	if !strings.Contains(string(out), "github.com/ghbmrk/agentos/broker/clerk/seal") {
		t.Error("agentos-a8scan does not link the sealed store")
	}
}

// The sealed store links the TPM seal (tpmseal's import test lists this
// binary), but the scan opens the store with the recovery factor alone. Its
// source imports no go-tpm or tpmseal package and dot-imports nothing, and
// names no TPM factor of clerk/seal under whatever name it imports seal
// (an alias included). The built binary holds no code that opens a TPM
// device: the linker drops what nothing reaches, so a device opener in the
// symbol table is one the binary can reach, through any package.
func TestTakesNoTPMFactor(t *testing.T) {
	src, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range src {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		for _, bad := range tpmNames(t, f) {
			t.Errorf("%s: %s", f, bad)
		}
	}
	bin := filepath.Join(t.TempDir(), "a8scan")
	if out, err := exec.Command("go", "build", "-o", bin, ".").CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, out)
	}
	for _, s := range tpmOpeners(t, bin) {
		t.Errorf("agentos-a8scan links the TPM device opener %s", s)
	}
}

// tpmNames lists what in the Go file f reaches for a TPM: an import of
// go-tpm or tpmseal, a dot import, or a selector naming clerk/seal's TPM or
// Pinned through the name the file imports seal under.
func tpmNames(t *testing.T, f string) []string {
	t.Helper()
	fs := token.NewFileSet()
	file, err := parser.ParseFile(fs, f, nil, parser.SkipObjectResolution)
	if err != nil {
		t.Fatal(err)
	}
	var bad []string
	sealAs := map[string]bool{}
	for _, im := range file.Imports {
		path, _ := strconv.Unquote(im.Path.Value)
		if strings.HasPrefix(path, "github.com/google/go-tpm") || strings.HasSuffix(path, "/broker/tpmseal") {
			bad = append(bad, "imports "+path)
		}
		if im.Name != nil && im.Name.Name == "." {
			bad = append(bad, "dot-imports "+path)
		}
		if path == "github.com/ghbmrk/agentos/broker/clerk/seal" {
			name := "seal"
			if im.Name != nil {
				name = im.Name.Name
			}
			sealAs[name] = true
		}
	}
	ast.Inspect(file, func(n ast.Node) bool {
		if sel, ok := n.(*ast.SelectorExpr); ok {
			if x, ok := sel.X.(*ast.Ident); ok && sealAs[x.Name] && (sel.Sel.Name == "TPM" || sel.Sel.Name == "Pinned") {
				bad = append(bad, "names seal."+sel.Sel.Name+" at "+fs.Position(sel.Pos()).String())
			}
		}
		return true
	})
	return bad
}

// tpmOpener matches the symbols of go-tpm's device openers: transport's
// OpenTPM (the base package, always linked with tpm2), the linux and
// unix-socket transports, and the legacy tpm2 and tpmutil OpenTPM.
var tpmOpener = regexp.MustCompile(`go-tpm/.*(\.OpenTPM|linuxtpm|linuxudstpm)`)

func tpmOpeners(t *testing.T, bin string) []string {
	t.Helper()
	out, err := exec.Command("go", "tool", "nm", bin).CombinedOutput()
	if err != nil {
		t.Fatalf("go tool nm: %v\n%s", err, out)
	}
	var got []string
	for _, l := range strings.Split(string(out), "\n") {
		if f := strings.Fields(l); len(f) >= 3 && tpmOpener.MatchString(f[len(f)-1]) {
			got = append(got, f[len(f)-1])
		}
	}
	return got
}

// The checks catch what the old text match missed (#3435's L3 delta and
// Security reviews): an aliased seal import naming the TPM factor, and a
// call to the base transport's OpenTPM, which no transport/ subpackage
// import shows.
func TestTPMChecksCatchAliasAndBaseOpener(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "x.go")
	os.WriteFile(f, []byte(`package main

import sl "github.com/ghbmrk/agentos/broker/clerk/seal"

type dev struct{}

func (dev) Send([]byte) ([]byte, error) { return nil, nil }

var _, _ = sl.Unlock("x", sl.TPM{TPM: dev{}})
`), 0o600)
	if got := tpmNames(t, f); len(got) != 1 || !strings.Contains(got[0], "seal.TPM") {
		t.Fatalf("aliased seal.TPM: %q", got)
	}
	// A binary that reaches transport.OpenTPM through the base package,
	// overlaid into this module (whose go.mod requires go-tpm) so it
	// builds with this module's dependencies and leaves no file behind.
	wd, _ := os.Getwd()
	mainGo := filepath.Join(dir, "main.go")
	os.WriteFile(mainGo, []byte(`package main

import "github.com/google/go-tpm/tpm2/transport"

func main() { transport.OpenTPM() }
`), 0o600)
	ov := filepath.Join(dir, "overlay.json")
	os.WriteFile(ov, []byte(`{"Replace":{`+strconv.Quote(filepath.Join(wd, "openermutant", "main.go"))+`:`+strconv.Quote(mainGo)+`}}`), 0o600)
	bin := filepath.Join(dir, "opener.bin")
	if out, err := exec.Command("go", "build", "-overlay", ov, "-o", bin, "./openermutant").CombinedOutput(); err != nil {
		t.Fatalf("go build of the opener mutant: %v\n%s", err, out)
	}
	if got := tpmOpeners(t, bin); len(got) == 0 {
		t.Fatal("a binary calling transport.OpenTPM passed the symbol check")
	}
}

// The typed card key opens the store as card.StoreRecoveryKey reads it,
// however it is typed, and its printed text and its 160 bits are needles
// in every form the card's text and a binary value take.
func TestTakesTheCardsTypedKey(t *testing.T) {
	d := newDrive(t)
	typed := strings.ToLower(strings.ReplaceAll(d.rkText, "-", " "))
	rk, err := card.StoreRecoveryKey(typed)
	if err != nil || !bytes.Equal(rk, d.rk) {
		t.Fatalf("the typed key reads as another key: %v", err)
	}
	var out bytes.Buffer
	if n, err := run(d.store, rk, typed, "", shippedClerks, []string{d.dir}, &out); err != nil || n != 0 {
		t.Fatalf("clean drive opened by the typed key: %d, %v\n%s", n, err, out.String())
	}
	_, bits, err := cardKey(typed)
	if err != nil {
		t.Fatal(err)
	}
	gs := strings.Split(d.rkText, "-")
	for form, leak := range map[string][]byte{
		"printed":        []byte(d.rkText),
		"undashed lower": []byte(strings.ToLower(strings.ReplaceAll(d.rkText, "-", ""))),
		"utf-16":         utf16le(d.rkText),
		// #3500 Security blocker 1: spaced, and in part.
		"spaced upper":       []byte(strings.ReplaceAll(d.rkText, "-", " ")),
		"spaced lower":       []byte(strings.ToLower(strings.ReplaceAll(d.rkText, "-", " "))),
		"seven groups":       []byte(strings.Join(gs[:7], "-")),
		"last seven spaced":  []byte(strings.Join(gs[1:], " ")),
		"three groups lower": []byte(strings.ToLower(strings.Join(gs[3:6], " "))),
		"three groups bare":  []byte(strings.Join(gs[5:], "")),
		"three groups utf16": utf16le(strings.Join(gs[2:5], " ")),
	} {
		os.WriteFile(filepath.Join(d.esp(), "leak.bin"), append([]byte("x"), leak...), 0o600)
		out.Reset()
		if _, err := run(d.store, rk, typed, "", shippedClerks, []string{d.esp()}, &out); err != nil || !strings.Contains(out.String(), "FIND recovery key text") {
			t.Errorf("%s card text: %v\n%s", form, err, out.String())
		}
	}
	for form, leak := range map[string][]byte{"raw": bits, "hex": []byte(hex.EncodeToString(bits)), "fragment": bits[2:17]} {
		os.WriteFile(filepath.Join(d.esp(), "leak.bin"), append([]byte("x"), leak...), 0o600)
		out.Reset()
		if _, err := run(d.store, rk, typed, "", shippedClerks, []string{d.esp()}, &out); err != nil || !strings.Contains(out.String(), "FIND recovery key bits") {
			t.Errorf("%s card bits: %v\n%s", form, err, out.String())
		}
		if strings.Contains(out.String(), hex.EncodeToString(bits)) {
			t.Errorf("%s: the output carries the card's bits", form)
		}
	}
	// The old 64-hex form is not the card's key.
	if _, err := card.StoreRecoveryKey(hex.EncodeToString(d.rk)); err == nil {
		t.Fatal("64 hex digits read as a card key")
	}
	// Text whose bits do not print back as itself is refused.
	if _, _, err := cardKey(d.rkText[:len(d.rkText)-1] + "A"); err == nil && !strings.HasSuffix(d.rkText, "A") {
		t.Fatal("cardKey took text whose last check symbol is wrong")
	}
}

// Each clerk's sealer key is a needle (#3435 Security release 1, CLK-1):
// the shipped clerks' without a flag and any other named by -clerk. The
// needle is the key seal's Sealer seals under.
func TestFindsClerkSealerKeys(t *testing.T) {
	d := newDrive(t)
	key := d.storeKey(t)
	raw, _ := os.ReadFile(d.store)
	_, id, _ := unwrapRecovery(raw, d.rk)
	st, err := seal.Unlock(d.store, seal.Recovery{Key: d.rk})
	if err != nil {
		t.Fatal(err)
	}
	sl, err := st.Sealer("bank")
	st.Close()
	if err != nil {
		t.Fatal(err)
	}
	blob, _ := sl.Seal([]byte("x"), nil)
	mine, _ := clerk.NewAESSealer(derive(key, id, "sealer/bank"))
	if p, err := mine.Open(blob, nil); err != nil || string(p) != "x" {
		t.Fatal("derive(sealer/bank) is not the key seal's Sealer uses")
	}
	var out bytes.Buffer
	for _, c := range []struct {
		clerk  string
		clerks []string
	}{{"mail", shippedClerks}, {"bank", append([]string{"bank"}, shippedClerks...)}} {
		os.WriteFile(filepath.Join(d.esp(), "leak.bin"), append([]byte("x"), derive(key, id, "sealer/"+c.clerk)...), 0o600)
		out.Reset()
		if n, err := run(d.store, d.rk, d.rkText, "", c.clerks, []string{d.esp()}, &out); err != nil || n == 0 || !strings.Contains(out.String(), "FIND sealer key of clerk "+c.clerk) {
			t.Errorf("sealer key of %s: %d, %v\n%s", c.clerk, n, err, out.String())
		}
	}
}

// Every purpose seal.go derives a key for under the store key is in
// storePurposes, and every non-secret-free entry there names a needle the
// scan plants; so a key seal starts deriving fails this test until the
// scan looks for it.
func TestEveryStorePurposeIsANeedle(t *testing.T) {
	fs := token.NewFileSet()
	file, err := parser.ParseFile(fs, "../../clerk/seal/seal.go", nil, parser.SkipObjectResolution)
	if err != nil {
		t.Fatal(err)
	}
	inSeal := map[string]bool{}
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok {
			continue
		}
		ast.Inspect(fn, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			var arg ast.Expr
			switch f := call.Fun.(type) {
			case *ast.Ident:
				if f.Name == "derive" && len(call.Args) >= 3 {
					arg = call.Args[2]
				}
			case *ast.SelectorExpr:
				if f.Sel.Name == "derived" && len(call.Args) == 1 {
					arg = call.Args[0]
				}
			}
			if arg == nil {
				return true
			}
			if b, ok := arg.(*ast.BinaryExpr); ok && b.Op == token.ADD {
				arg = b.X // a prefix and a name: "sealer/" + clerkID
			}
			switch a := arg.(type) {
			case *ast.BasicLit:
				p, _ := strconv.Unquote(a.Value)
				inSeal[p] = true
			case *ast.Ident:
				if fn.Name.Name != "derived" || a.Name != "purpose" {
					t.Errorf("%s: a purpose this test cannot read", fs.Position(a.Pos()))
				}
			default:
				t.Errorf("%s: a purpose this test cannot read", fs.Position(arg.Pos()))
			}
			return true
		})
	}
	for p := range inSeal {
		if _, ok := storePurposes[p]; !ok {
			t.Errorf("seal derives a %q key that the scan does not look for (storePurposes)", p)
		}
	}
	d := newDrive(t)
	st, err := seal.Unlock(d.store, seal.Recovery{Key: d.rk})
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ns, err := storeNeedles(d.store, st, d.rk, d.rkText, "", shippedClerks, &bytes.Buffer{})
	if err != nil {
		t.Fatal(err)
	}
	for p, name := range storePurposes {
		if !inSeal[p] {
			t.Errorf("storePurposes lists %q, which seal no longer derives", p)
		}
		if name == "" {
			continue
		}
		hit := false
		for _, n := range ns {
			hit = hit || strings.HasPrefix(n.Name, name)
		}
		if !hit {
			t.Errorf("purpose %q: no needle named %q", p, name)
		}
	}
}

// A binary sealed entry gets fragment patterns (#3435 Security later 2),
// and a passphrase too short to be a needle is reported, not dropped
// silently (later 3).
func TestBinaryEntryFragmentsAndShortPassphrase(t *testing.T) {
	d := newDrive(t)
	bin := make([]byte, 32)
	rand.Read(bin)
	bin[0] = 0 // not text
	st, err := seal.Unlock(d.store, seal.Recovery{Key: d.rk})
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Put("canary/binary", bin); err != nil {
		t.Fatal(err)
	}
	st.Close()
	os.WriteFile(filepath.Join(d.esp(), "leak.bin"), append([]byte("x"), bin[5:22]...), 0o600)
	var out bytes.Buffer
	if n, err := run(d.store, d.rk, d.rkText, "hunter2", shippedClerks, []string{d.esp()}, &out); err != nil || !strings.Contains(out.String(), "FIND store entry canary/binary") {
		t.Errorf("17-byte slice of a binary entry: %d, %v\n%s", n, err, out.String())
	}
	if !strings.Contains(out.String(), "skip passphrase (shorter than") {
		t.Errorf("a short passphrase was dropped silently\n%s", out.String())
	}
}

// A passphrase is found as the store reads it (card.NormalizePassphrase)
// and with other spacing (#3500 Security release 2), and the slots'
// key-wrapping keys are needles (release 4): with the store file, either
// unwraps the data key.
func TestPassphraseFormsAndSlotKeys(t *testing.T) {
	d := newDrive(t)
	pass := "Synthetic  Passphrase words HERE"
	st, err := seal.Unlock(d.store, seal.Recovery{Key: d.rk})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.AddSlot(seal.Passphrase{Phrase: []byte(pass)}); err != nil {
		t.Fatal(err)
	}
	st.Close()
	raw, _ := os.ReadFile(d.store)
	key, _, rkek, err := unwrapSlot(raw, seal.KindRecovery, recoveryKEK(d.rk))
	if err != nil {
		t.Fatal(err)
	}
	pk, _, pkek, err := unwrapSlot(raw, seal.KindPassphrase, passphraseKEK([]byte(pass)))
	if err != nil || !bytes.Equal(pk, key) {
		t.Fatalf("the passphrase slot does not unwrap the store key: %v", err)
	}
	for _, c := range []struct {
		want string
		leak []byte
	}{
		{"passphrase", []byte("synthetic passphrase words here")},
		{"passphrase", []byte("SYNTHETIC-PASSPHRASE-WORDS-HERE")},
		{"passphrase", []byte("syntheticpassphrasewordshere")},
		{"recovery slot key", rkek},
		{"passphrase slot key", []byte(hex.EncodeToString(pkek))},
	} {
		os.WriteFile(filepath.Join(d.esp(), "leak.bin"), append([]byte("x"), c.leak...), 0o600)
		var out bytes.Buffer
		if n, err := run(d.store, d.rk, d.rkText, pass, shippedClerks, []string{d.esp()}, &out); err != nil || n == 0 || !strings.Contains(out.String(), "FIND "+c.want+" at") {
			t.Errorf("%s (%q): %d, %v\n%s", c.want, c.leak, n, err, out.String())
		}
	}
	// A passphrase that opens no slot is reported, not used.
	var out bytes.Buffer
	os.Remove(filepath.Join(d.esp(), "leak.bin"))
	if _, err := run(d.store, d.rk, d.rkText, "another synthetic passphrase", shippedClerks, []string{d.esp()}, &out); err != nil || !strings.Contains(out.String(), "skip passphrase slot key") {
		t.Errorf("a wrong passphrase: %v\n%s", err, out.String())
	}
}

// The tool's own reading of the card format gives the key card gives, for
// any key and however it is typed; a mistyped group is refused by both and
// named the same; a passphrase splits into the words card's normal form
// holds.
func TestCardFormatMatchesCard(t *testing.T) {
	for i := 0; i < 200; i++ {
		var b [20]byte
		rand.Read(b[:])
		text := card.RecoveryKeyText(b)
		for _, typed := range []string{text, strings.ToLower(strings.ReplaceAll(text, "-", " ")), strings.ReplaceAll(text, "-", "")} {
			want, err := card.StoreRecoveryKey(typed)
			if err != nil {
				t.Fatal(err)
			}
			got, err := storeRecoveryKey(typed)
			if err != nil || !bytes.Equal(got, want) {
				t.Fatalf("%q: a8scan reads %x, card %x (%v)", typed, got, want, err)
			}
			printed, bits, _ := cardKey(typed)
			if printed != text || !bytes.Equal(bits, b[:]) {
				t.Fatalf("%q: printed %q, bits %x", typed, printed, bits)
			}
		}
		// One symbol changed in group g.
		g := i % 8
		pos := g*6 + i%5
		sym := strings.IndexByte(cardAlphabet, text[pos])
		bad := text[:pos] + string(cardAlphabet[(sym+1+i%31)%32]) + text[pos+1:]
		_, cerr := card.StoreRecoveryKey(bad)
		var me *card.MistypedError
		_, err := storeRecoveryKey(bad)
		if !errors.As(cerr, &me) || err == nil || !strings.Contains(err.Error(), fmt.Sprintf("group %d ", me.Group)) {
			t.Fatalf("%q: card %v, a8scan %v", bad, cerr, err)
		}
	}
	if cardAlphabet != card.Alphabet {
		t.Fatal("the card alphabet differs")
	}
	for _, p := range []string{"Synthetic  Passphrase\twords HERE", " a  b "} {
		if strings.Join(strings.Fields(strings.ToLower(p)), " ") != card.NormalizePassphrase(p) {
			t.Fatalf("%q: passphrase words differ from card's normal form", p)
		}
	}
	if _, err := storeRecoveryKey(strings.Repeat("A", 64)); err == nil {
		t.Fatal("64 symbols read as a card key")
	}
}
