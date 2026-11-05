package main

// REQ: HW-8

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// host is a scratch tree laid out as agentos-mor reads the box: efivarfs,
// the kernel command line and the page-cache knob. mor nil means the
// firmware has no MOR variable.
type host struct {
	t      *testing.T
	s      *sys
	events []string
}

func newHost(t *testing.T, cmdline string, mor []byte) *host {
	t.Helper()
	root := t.TempDir()
	for rel, b := range map[string][]byte{
		"proc/cmdline":            []byte(cmdline + "\n"),
		"proc/sys/vm/drop_caches": nil,
	} {
		p := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	vars := filepath.Join(root, "sys/firmware/efi/efivars")
	if err := os.MkdirAll(vars, 0o755); err != nil {
		t.Fatal(err)
	}
	h := &host{t: t, s: newSys(root)}
	if mor != nil {
		if err := os.WriteFile(h.s.morPath(), mor, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	immutable := uint32(fsImmutable | 0x80000) // and FS_EXTENT_FL, kept
	h.s.getFlags = func(int) (uint32, error) { return immutable, nil }
	h.s.setFlags = func(_ int, f uint32) error {
		// The wipe comes first: by the time MOR is touched the cache is
		// dropped and MOR is still set.
		h.events = append(h.events, "unlock")
		if string(h.file("proc/sys/vm/drop_caches")) != "3" {
			t.Error("MOR unlocked before the page cache was dropped")
		}
		if f != 0x80000 {
			t.Errorf("set flags %#x, want only the immutable bit dropped", f)
		}
		immutable = f
		return nil
	}
	h.s.sync = func() { h.events = append(h.events, "sync") }
	return h
}

func (h *host) file(rel string) []byte {
	b, err := os.ReadFile(filepath.Join(h.s.root, rel))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		h.t.Fatal(err)
	}
	return b
}

func (h *host) run(args ...string) (int, string, string) {
	var out, errOut bytes.Buffer
	rc := run(args, h.s, &out, &errOut)
	return rc, out.String(), errOut.String()
}

const wipe = "console=ttyS0 rw quiet init_on_free=1 usrhash=00"

var (
	morSet   = []byte{7, 0, 0, 0, 1}
	morClear = []byte{7, 0, 0, 0, 0}
	morPath  = "sys/firmware/efi/efivars/" + morName
)

// HW-8: an orderly shutdown wipes, then clears the bit the kernel set, so
// the host's next start does not wipe memory and its MOR is as it was.
func TestClearWipesThenClears(t *testing.T) {
	h := newHost(t, wipe, morSet)
	rc, out, errOut := h.run("clear")
	if rc != 0 || out != "agentos-mor: mor=cleared\n" {
		t.Fatalf("rc %d, %q, %q", rc, out, errOut)
	}
	if got := h.file(morPath); !bytes.Equal(got, morClear) {
		t.Fatalf("MOR %x, want %x", got, morClear)
	}
	if strings.Join(h.events, ",") != "sync,unlock" {
		t.Fatalf("events %v, want sync then unlock", h.events)
	}
}

// Only the ClearMemory bit changes: DisableAutoDetect (bit 4) and any
// other bit the firmware or owner set stays.
func TestClearKeepsOtherBits(t *testing.T) {
	h := newHost(t, wipe, []byte{7, 0, 0, 0, 0x11})
	if rc, _, errOut := h.run("clear"); rc != 0 {
		t.Fatal(errOut)
	}
	if got := h.file(morPath); !bytes.Equal(got, []byte{7, 0, 0, 0, 0x10}) {
		t.Fatalf("MOR %x", got)
	}
}

// A firmware without MOR (Ubuntu 24.04's OVMF) gets no variable, and a
// clear bit is not rewritten: neither writes anything.
func TestNothingToClearWritesNothing(t *testing.T) {
	for name, c := range map[string]struct {
		mor  []byte
		want string
	}{
		"absent": {nil, "mor=absent"},
		"clear":  {morClear, "mor=clear"},
	} {
		t.Run(name, func(t *testing.T) {
			h := newHost(t, wipe, c.mor)
			rc, out, _ := h.run("clear")
			if rc != 0 || out != "agentos-mor: "+c.want+"\n" {
				t.Fatalf("rc %d, %q", rc, out)
			}
			if len(h.events) != 0 || len(h.file("proc/sys/vm/drop_caches")) != 0 {
				t.Fatalf("events %v", h.events)
			}
			if got := h.file(morPath); !bytes.Equal(got, c.mor) {
				t.Fatalf("MOR %x, want %x", got, c.mor)
			}
		})
	}
}

// Without the kernel's zeroing on free there is no wipe, so MOR stays set
// and the firmware wipes at the next start. Only the last init_on_free=
// counts, as in the kernel, and only "1" counts as on.
func TestNoWipeLeavesMORSet(t *testing.T) {
	for _, cmdline := range []string{
		"console=ttyS0 rw",
		"init_on_free=1 init_on_free=0",
		"init_on_free=on",
		"xinit_on_free=1",
		"init_on_free=11",
	} {
		t.Run(cmdline, func(t *testing.T) {
			h := newHost(t, cmdline, morSet)
			rc, _, errOut := h.run("clear")
			if rc != 1 || !strings.Contains(errOut, "MOR left set") {
				t.Fatalf("rc %d, %q", rc, errOut)
			}
			if got := h.file(morPath); !bytes.Equal(got, morSet) {
				t.Fatalf("MOR %x, want it left set", got)
			}
			if len(h.events) != 0 {
				t.Fatalf("events %v", h.events)
			}
		})
	}
}

// Whatever fails, MOR is left set, never half-written or created.
func TestFailuresLeaveMORSet(t *testing.T) {
	t.Run("drop_caches", func(t *testing.T) {
		h := newHost(t, wipe, morSet)
		if err := os.Remove(filepath.Join(h.s.root, "proc/sys/vm/drop_caches")); err != nil {
			t.Fatal(err)
		}
		if rc, _, errOut := h.run("clear"); rc != 1 || !strings.Contains(errOut, "page cache") {
			t.Fatalf("rc %d, %q", rc, errOut)
		}
		if got := h.file(morPath); !bytes.Equal(got, morSet) {
			t.Fatalf("MOR %x", got)
		}
	})
	t.Run("unlock", func(t *testing.T) {
		h := newHost(t, wipe, morSet)
		h.s.setFlags = func(int, uint32) error { return errors.New("EPERM") }
		if rc, _, _ := h.run("clear"); rc != 1 {
			t.Fatal("cleared through a failed unlock")
		}
		if got := h.file(morPath); !bytes.Equal(got, morSet) {
			t.Fatalf("MOR %x", got)
		}
	})
	for name, mor := range map[string][]byte{
		"other attributes": {0x27, 0, 0, 0, 1},
		"long":             {7, 0, 0, 0, 1, 0},
		"short":            {7, 0, 0, 1},
	} {
		t.Run(name, func(t *testing.T) {
			h := newHost(t, wipe, mor)
			if rc, _, _ := h.run("clear"); rc != 1 {
				t.Fatal("cleared an unexpected variable")
			}
			if got := h.file(morPath); !bytes.Equal(got, mor) || len(h.events) != 0 {
				t.Fatalf("MOR %x, events %v", got, h.events)
			}
		})
	}
	t.Run("a link", func(t *testing.T) {
		h := newHost(t, wipe, nil)
		target := filepath.Join(h.s.root, "elsewhere")
		if err := os.WriteFile(target, morSet, 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, h.s.morPath()); err != nil {
			t.Fatal(err)
		}
		if rc, _, _ := h.run("clear"); rc != 1 {
			t.Fatal("followed a link")
		}
		if b, _ := os.ReadFile(target); !bytes.Equal(b, morSet) {
			t.Fatalf("target %x", b)
		}
	})
}

func TestStatusReadsOnly(t *testing.T) {
	for want, c := range map[string]struct {
		cmdline string
		mor     []byte
	}{
		"mor=set wipe=on":    {wipe, morSet},
		"mor=clear wipe=off": {"rw", morClear},
		"mor=absent wipe=on": {wipe, nil},
	} {
		h := newHost(t, c.cmdline, c.mor)
		rc, out, errOut := h.run("status")
		if rc != 0 || out != "agentos-mor: "+want+"\n" {
			t.Fatalf("rc %d, %q, %q, want %q", rc, out, errOut, want)
		}
		if got := h.file(morPath); !bytes.Equal(got, c.mor) || len(h.events) != 0 {
			t.Fatalf("status wrote: MOR %x, events %v", got, h.events)
		}
	}
	h := newHost(t, wipe, morSet)
	if rc, _, _ := h.run(); rc != 2 {
		t.Fatal("no usage error")
	}
}

// Files on /run and /dev/shm are never freed, so init_on_free never zeroes
// them: while a secret-holding directory there holds anything (the Owner
// Card's factors after a failed or pending enrollment, the first edge's
// capture, shared memory), MOR stays set (Security on #5009, 1).
func TestHeldTmpfsLeavesMORSet(t *testing.T) {
	for _, rel := range []string{"run/agentos-setup/passphrase", "run/agentos-setup/.x",
		"run/agentos-link-capture/first-edge", "dev/shm/seg", "run/agentos-setup/sub/"} {
		t.Run(rel, func(t *testing.T) {
			h := newHost(t, wipe, morSet)
			p := filepath.Join(h.s.root, rel)
			if strings.HasSuffix(rel, "/") {
				if err := os.MkdirAll(p, 0o700); err != nil {
					t.Fatal(err)
				}
			} else {
				if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(p, []byte("synthetic-canary"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			rc, _, errOut := h.run("clear")
			if rc != 1 || !strings.Contains(errOut, "MOR left set") {
				t.Fatalf("rc %d, %q", rc, errOut)
			}
			if got := h.file(morPath); !bytes.Equal(got, morSet) || len(h.events) != 0 {
				t.Fatalf("MOR %x, events %v", got, h.events)
			}
		})
	}
	t.Run("empty directories", func(t *testing.T) {
		h := newHost(t, wipe, morSet)
		for _, d := range holdDirs {
			if err := os.MkdirAll(filepath.Join(h.s.root, d), 0o700); err != nil {
				t.Fatal(err)
			}
		}
		if rc, out, errOut := h.run("clear"); rc != 0 || out != "agentos-mor: mor=cleared\n" {
			t.Fatalf("rc %d, %q, %q", rc, out, errOut)
		}
	})
	t.Run("a link in place of the directory", func(t *testing.T) {
		h := newHost(t, wipe, morSet)
		if err := os.MkdirAll(filepath.Join(h.s.root, "run"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(t.TempDir(), filepath.Join(h.s.root, "run/agentos-setup")); err != nil {
			t.Fatal(err)
		}
		if rc, _, _ := h.run("clear"); rc != 1 {
			t.Fatal("cleared through a link it could not read")
		}
	})
}

// The kernel splits its command line at blanks outside double quotes and
// takes nothing after "--" (Security on #5009, 2).
func TestWipeOnReadsAsTheKernel(t *testing.T) {
	for cmdline, want := range map[string]bool{
		"quiet -- init_on_free=1":          false,
		`quiet x="a init_on_free=1 b"`:     false,
		`quiet init_on_free="1"`:           false,
		"quiet\tinit_on_free=1\n":          true,
		`x="a b" init_on_free=1 -- y`:      true,
		"init_on_free=1 -- init_on_free=0": true,
		`x="unterminated init_on_free=1`:   false,
	} {
		h := newHost(t, cmdline, morSet)
		if on, err := h.s.wipeOn(); err != nil || on != want {
			t.Errorf("%q: on %v (%v), want %v", cmdline, on, err, want)
		}
	}
}
