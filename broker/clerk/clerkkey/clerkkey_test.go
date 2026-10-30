package clerkkey

// REQ: CLK-1

import (
	"bytes"
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"
)

func keyPipe(t *testing.T, b []byte) *os.File {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(b); err != nil {
		t.Fatal(err)
	}
	w.Close()
	return r
}

func testKey(name string) Key {
	k := Key{Name: name}
	for i := range k.Key {
		k.Key[i] = byte(i + 1)
	}
	return k
}

func TestClerkKeyRoundTrip(t *testing.T) {
	k := testKey("mail")
	b, err := Marshal(k)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Read(keyPipe(t, b), "mail")
	if err != nil || got != k {
		t.Fatalf("Read = %+v, %v; want the key handed", got, err)
	}
	if _, err := Read(keyPipe(t, b), "model"); !errors.Is(err, ErrKey) {
		t.Fatalf("the mail clerk's key read as the model clerk's: %v", err)
	}
	bad := map[string][]byte{
		"empty":    nil,
		"short":    b[:len(b)-1],
		"trailing": append(bytes.Clone(b), 0),
		"tag":      append([]byte("agentos-clerk-key/v2\n"), b[len(clerkKeyTag):]...),
		"kernel's": append([]byte("agentos-kernel-keys/v6\n"), b[len(clerkKeyTag):]...),
		"too long": bytes.Repeat([]byte{'a'}, maxClerkKey+10),
	}
	for name, b := range bad {
		if _, err := Read(keyPipe(t, b), "mail"); !errors.Is(err, ErrKey) {
			t.Errorf("%s hand-off read: %v", name, err)
		}
	}
	for _, name := range []string{"", "Mail", "-mail", "mail/x", string(bytes.Repeat([]byte{'a'}, 65))} {
		if _, err := Marshal(testKey(name)); !errors.Is(err, ErrKey) {
			t.Errorf("clerk name %q marshalled: %v", name, err)
		}
	}
}

// A file on the drive never stands in for the kernel's hand-off; a
// connected socket does, as systemd's OpenFile= hands one (MAIL-keys).
func TestClerkKeyComesOnlyFromAPipeOrSocket(t *testing.T) {
	b, err := Marshal(testKey("mail"))
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "key")
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(p)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Read(f, "mail"); !errors.Is(err, ErrKey) {
		t.Fatalf("a regular file read as the hand-off: %v", err)
	}
	a, c := socketPair(t)
	if _, err := a.Write(b); err != nil {
		t.Fatal(err)
	}
	a.Close()
	if got, err := Read(c, "mail"); err != nil || got.Name != "mail" {
		t.Fatalf("a socket's hand-off: %+v, %v", got, err)
	}
}

func socketPair(t *testing.T) (net.Conn, *os.File) {
	t.Helper()
	ln, err := net.Listen("unix", filepath.Join(t.TempDir(), "s"))
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	a, err := net.Dial("unix", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	c, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	f, err := c.(*net.UnixConn).File()
	c.Close()
	if err != nil {
		t.Fatal(err)
	}
	return a, f
}

func TestClerkKeysDeriveApart(t *testing.T) {
	k := testKey("mail")
	s, err := k.Sealer()
	if err != nil {
		t.Fatal(err)
	}
	h, err := k.HandleSecret()
	if err != nil {
		t.Fatal(err)
	}
	other := testKey("model")
	o, err := other.Sealer()
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range [][2][]byte{{s, h}, {s, k.Key[:]}, {h, k.Key[:]}, {s, o}} {
		if bytes.Equal(p[0], p[1]) {
			t.Fatal("two of a clerk's keys, or two clerks' sealer keys, are the same")
		}
	}
	if len(s) != 32 || len(h) != 32 {
		t.Fatalf("derived keys of %d and %d bytes", len(s), len(h))
	}
	k.Wipe()
	if k.Key != ([Len]byte{}) {
		t.Fatal("Wipe left the key")
	}
}

// REQ: CLK-1
// The kernel's per-clerk key (MAIL-keys): the same root and name give the
// same key at every start, two clerks' keys differ, neither is the root,
// and a bad name or an empty root derives nothing. Fails if one clerk's key
// could open another's slots.
func TestDeriveGivesEachClerkItsOwnStableKey(t *testing.T) {
	var root [Len]byte
	for i := range root {
		root[i] = byte(0x40 + i)
	}
	mail, err := Derive(&root, "mail")
	if err != nil || mail.Name != "mail" {
		t.Fatalf("Derive(mail) = %+v, %v", mail, err)
	}
	again, _ := Derive(&root, "mail")
	model, _ := Derive(&root, "model")
	if again != mail {
		t.Fatal("the same root and name gave two keys: a restart would open nothing")
	}
	if model.Key == mail.Key || mail.Key == root {
		t.Fatal("two clerks share a key, or a clerk holds the root")
	}
	other := root
	other[0] ^= 1
	if o, _ := Derive(&other, "mail"); o.Key == mail.Key {
		t.Fatal("another root gave the same clerk key")
	}
	for _, name := range []string{"", "Mail", "mail/x"} {
		if _, err := Derive(&root, name); !errors.Is(err, ErrKey) {
			t.Errorf("Derive(%q): %v", name, err)
		}
	}
	if _, err := Derive(&[Len]byte{}, "mail"); !errors.Is(err, ErrKey) {
		t.Errorf("an empty root derived a key: %v", err)
	}
}

// REQ: CLK-1
// A clerk's signing key (MIG-4-exit-c2): stable for one key, apart from its
// sealer and from another clerk's signer, so the kernel's pin of the
// checker's key matches no other clerk's.
func TestSignerIsStableAndApart(t *testing.T) {
	k := testKey("checker")
	a, err := k.Signer()
	if err != nil {
		t.Fatal(err)
	}
	b, _ := k.Signer()
	s, _ := k.Sealer()
	o, _ := testKey("mail").Signer()
	if !a.Equal(b) {
		t.Fatal("one key gave two signers: the kernel's pin would not match after a restart")
	}
	if bytes.Equal(a.Seed(), s) || a.Equal(o) {
		t.Fatal("the signer is the sealer, or two clerks share a signer")
	}
	if _, err := (Key{Name: "Bad"}).Signer(); !errors.Is(err, ErrKey) {
		t.Fatalf("a bad name signed: %v", err)
	}
}
