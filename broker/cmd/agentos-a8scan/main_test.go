package main

import (
	"bytes"
	"crypto/rand"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/clerk/seal"
)

// REQ: A8, STO-2, CRED-8
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
	d := drive{dir: t.TempDir(), rk: make([]byte, seal.RecoveryLen), secret: []byte("synthetic-sealed-secret-0123456789")}
	rand.Read(d.rk)
	d.rkText = hex.EncodeToString(d.rk)
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
	if n, err := run(d.store, d.rk, d.rkText, "", []string{d.dir}, &out); err != nil || n != 0 {
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
		n, err := run(d.store, d.rk, d.rkText, "", []string{d.esp()}, &out)
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
		if n, err := run(d.store, d.rk, d.rkText, "", []string{d.esp()}, &out); err != nil || !strings.Contains(out.String(), "FIND "+want) {
			t.Errorf("%s: %d, %v\n%s", want, n, err, out.String())
		}
		if strings.Contains(out.String(), string(d.secret)) {
			t.Error("the output carries the sealed secret")
		}
	}
	// The recovery key as typed and a typed passphrase, which the store
	// does not hold, are needles too.
	pass := "synthetic passphrase words here"
	os.WriteFile(filepath.Join(d.esp(), "leak.bin"), []byte("x"+strings.ToUpper(d.rkText)+" "+pass), 0o600)
	out.Reset()
	if _, err := run(d.store, d.rk, d.rkText, pass, []string{d.esp()}, &out); err != nil ||
		!strings.Contains(out.String(), "FIND recovery key") || !strings.Contains(out.String(), "FIND passphrase") {
		t.Fatalf("typed factors: %v\n%s", err, out.String())
	}
	// Another store's recovery key opens nothing, so nothing is scanned.
	other := make([]byte, seal.RecoveryLen)
	if _, err := run(d.store, other, hex.EncodeToString(other), "", []string{d.esp()}, &out); err == nil {
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
