package proc

// REQ: LOG-1, KRN-7
//
// MUT-kill-6305-proc (#6367): the kernel process's start refusals and an
// erase the kernel refuses, each checked by what they leave and return.

import (
	"errors"
	"path/filepath"
	"testing"

	"github.com/ghbmrk/agentos/broker/kernel"
)

// A start refused for backups or content without a key table releases the
// log, so the next start can take it.
func TestAStartWithoutAKeyTableReleasesTheLog(t *testing.T) {
	dir := t.TempDir()
	for _, cfg := range []KernelConfig{{BackupDir: filepath.Join(dir, "b")}, {ContentDir: filepath.Join(dir, "c")}} {
		cfg.Log, cfg.Anchor, cfg.Pub, cfg.Sign = filepath.Join(dir, "log"), &kernel.MemAnchor{}, headPub, headPriv
		if _, err := OpenKernel(cfg, 0); err == nil {
			t.Fatal("a start with no key table was taken")
		}
		s, err := OpenFileStore(cfg.Log)
		if err != nil {
			t.Fatalf("the refused start kept the log: %v", err)
		}
		s.Close()
	}
}

// An erase the kernel refuses returns its refusal alone: nothing is
// re-sealed nor confirmed after it.
func TestAnEraseTheKernelRefusesReturnsAtOnce(t *testing.T) {
	b := newBBox(t, recipientWire(t, testRK))
	sub := b.subject()
	b.h.Close()
	c, err := b.h.Erase(b.now, sub)
	if err == nil || err.Error() != "run: kernel closed" || c.Subject != "" {
		t.Fatalf("an erase on a closed kernel: %+v, %q; want the refusal alone", c, err)
	}
	var joined interface{ Unwrap() []error }
	if errors.As(err, &joined) {
		t.Fatalf("the refusal is joined with another: %q", err)
	}
}

// An erase re-seals every backup due, the ones it does not name too, and
// replies only once those re-seals are over (#3338).
func TestAnEraseWaitsForTheResealsItStarts(t *testing.T) {
	b, gone, _, dir, id, h := hungBox(t)
	later := b.subject() // opened after the backup, so the erase names none
	if err := b.h.With(func(k *kernel.Kernel) error { _, err := k.Erase(b.now, gone); return err }); err != nil {
		t.Fatal(err)
	}
	cs, _ := erasing(t, b, later)
	waiting(t, "the erase", cs)
	h.hang.Store(false)
	h.free()
	if c := reply(t, cs); len(c.Resealed)+len(c.StillHeld) != 0 {
		t.Fatalf("the erase's confirmation names a backup without the subject: %+v", c)
	}
	if gives(t, dir, id, gone) {
		t.Fatal("the re-seal the erase waited for left the erased key")
	}
}
