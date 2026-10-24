package anchor

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/ghbmrk/agentos/broker/clerk/handoff"
	"github.com/ghbmrk/agentos/broker/kernel"
	"github.com/ghbmrk/agentos/broker/kernel/proc"
	"github.com/ghbmrk/agentos/broker/tpmseal"
	"github.com/ghbmrk/agentos/broker/tpmseal/swtpm"
)

// REQ: LOG-2, STO-1

// box is a software TPM with the log anchor's counter defined and its head
// file started, as enrollment leaves them (STO-2c).
type box struct {
	t    *testing.T
	sw   *swtpm.TPM
	dir  string
	keys handoff.KernelKeys
}

func newBox(t *testing.T) *box {
	t.Helper()
	b := &box{t: t, sw: swtpm.Start(t), dir: filepath.Join(t.TempDir(), "anchor")}
	must(t, os.Mkdir(b.dir, 0o700))
	srk, err := tpmseal.Identity(b.sw.TPM())
	must(t, err)
	auth := []byte("0123456789abcdef0123456789abcdef")
	ref, err := tpmseal.DefineCounter(b.sw.TPM(), srk, []byte("store id"), auth)
	must(t, err)
	b.keys = handoff.KernelKeys{
		Head:    ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, 32)),
		Counter: handoff.Counter{SRK: srk, Handle: ref.Handle, Name: ref.Name, Auth: auth},
	}
	c := tpmseal.Counter{TPM: b.sw.TPM(), SRK: srk, Ref: ref, Auth: auth}
	must(t, proc.InitCounterAnchor(b.dir, filepath.Join(t.TempDir(), "log"), c, b.keys.Head))
	return b
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

// conn is the kernel's connection, as the unlock step hands it over: one
// stream to the software TPM, which serves one connection at a time, so no
// other caller reaches it until conn is closed.
func (b *box) conn() *os.File {
	b.t.Helper()
	c, err := net.Dial("unix", b.sw.Socket())
	must(b.t, err)
	defer c.Close()
	f, err := c.(*net.UnixConn).File()
	must(b.t, err)
	return f
}

// open opens the anchor over a fresh connection and closes the connection.
func (b *box) open(keys handoff.KernelKeys) (kernel.Anchor, error) {
	f := b.conn()
	defer f.Close()
	return Open(b.dir, keys, f)
}

// LOG-2, STO-1: the kernel opens enrollment's counter anchor over the TPM
// connection it was handed, and each open moves the counter on, so a head
// file copied before an open is refused after it: a drive rolled back, log
// and anchor together, starts no kernel.
func TestTheKernelOpensTheCounterAnchor(t *testing.T) {
	b := newBox(t)
	a, err := b.open(b.keys)
	must(t, err)
	if _, ok := a.Latest(); ok {
		t.Fatal("a fresh anchor has a head")
	}
	n := a.(*proc.CounterAnchor).Number()
	old, err := os.ReadFile(filepath.Join(b.dir, "anchor"))
	must(t, err)
	a, err = b.open(b.keys)
	must(t, err)
	if got := a.(*proc.CounterAnchor).Number(); got != n+2 {
		t.Fatalf("the second open left the counter at %d, want %d", got, n+2)
	}
	must(t, os.WriteFile(filepath.Join(b.dir, "anchor"), old, 0o600))
	if _, err := b.open(b.keys); !errors.Is(err, proc.ErrAnchorRolledBack) {
		t.Fatalf("a rolled-back head file: got %v, want ErrAnchorRolledBack", err)
	}
}

// The counter is the TPM's to check: a wrong auth value, another index's
// name or another TPM's storage root key opens no anchor.
func TestTheCounterMustBeTheEnrolledOne(t *testing.T) {
	b := newBox(t)
	for name, mut := range map[string]func(*handoff.Counter){
		"auth": func(c *handoff.Counter) { c.Auth = []byte("fedcba9876543210fedcba9876543210") },
		"name": func(c *handoff.Counter) { c.Name = bytes.Clone(c.Name); c.Name[len(c.Name)-1] ^= 1 },
		"srk":  func(c *handoff.Counter) { c.SRK = bytes.Clone(c.SRK); c.SRK[len(c.SRK)-1] ^= 1 },
	} {
		k := b.keys
		mut(&k.Counter)
		if _, err := b.open(k); err == nil {
			t.Errorf("%s: the anchor opened", name)
		}
	}
	if _, err := b.open(b.keys); err != nil {
		t.Fatalf("the refusals spent the anchor: %v", err)
	}
}

// The kernel's TPM connection is one stream, read whole by each response's
// size: commands after the first still answer, so the counter can be
// advanced for as long as the kernel runs.
func TestTheKernelsTPMConnectionCarriesManyCommands(t *testing.T) {
	b := newBox(t)
	want := b.keys.Counter.SRK
	f := b.conn()
	defer f.Close()
	tpm, err := tpmConn(f)
	must(t, err)
	for i := range 3 {
		got, err := tpmseal.Identity(tpm)
		if err != nil || !bytes.Equal(got, want) {
			t.Fatalf("command %d over the kernel's connection: %x, %v", i, got, err)
		}
	}
}
