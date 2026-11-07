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

// openFDs counts this process's open descriptors.
func openFDs(t *testing.T) int {
	t.Helper()
	ents, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	return len(ents)
}

// A clear closes every descriptor it opens: the variable, each held
// directory and the immutable-flag handle.
func TestClearLeaksNoDescriptor(t *testing.T) {
	clearOnce := func() {
		h := newHost(t, wipe, morSet)
		for _, d := range holdDirs {
			if err := os.MkdirAll(filepath.Join(h.s.root, d), 0o700); err != nil {
				t.Fatal(err)
			}
		}
		if rc, _, errOut := h.run("clear"); rc != 0 {
			t.Fatal(errOut)
		}
	}
	clearOnce()
	before := openFDs(t)
	for i := 0; i < 5; i++ {
		clearOnce()
	}
	if after := openFDs(t); after != before {
		t.Fatalf("%d descriptors open after five clears, %d before", after, before)
	}
}

// Each failure is reported as itself, not as a later step's.
func TestFailuresNameTheirCause(t *testing.T) {
	const loop = "too many levels of symbolic links"
	t.Run("MOR a link", func(t *testing.T) {
		for _, cmd := range []string{"clear", "status"} {
			h := newHost(t, wipe, nil)
			if err := os.Symlink(filepath.Join(h.s.root, "elsewhere"), h.s.morPath()); err != nil {
				t.Fatal(err)
			}
			if rc, _, errOut := h.run(cmd); rc != 1 || !strings.Contains(errOut, loop) {
				t.Fatalf("%s: rc %d, %q", cmd, rc, errOut)
			}
		}
	})
	t.Run("no command line", func(t *testing.T) {
		for _, cmd := range []string{"clear", "status"} {
			h := newHost(t, wipe, morSet)
			if err := os.Remove(filepath.Join(h.s.root, "proc/cmdline")); err != nil {
				t.Fatal(err)
			}
			if rc, _, errOut := h.run(cmd); rc != 1 || !strings.Contains(errOut, "no such file") {
				t.Fatalf("%s: rc %d, %q", cmd, rc, errOut)
			}
			if got := h.file(morPath); !bytes.Equal(got, morSet) {
				t.Fatalf("MOR %x", got)
			}
		}
	})
	t.Run("held directory a link", func(t *testing.T) {
		h := newHost(t, wipe, morSet)
		if err := os.MkdirAll(filepath.Join(h.s.root, "run"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(t.TempDir(), filepath.Join(h.s.root, "run/agentos-setup")); err != nil {
			t.Fatal(err)
		}
		if rc, _, errOut := h.run("clear"); rc != 1 || !strings.Contains(errOut, "not a directory") {
			t.Fatalf("rc %d, %q", rc, errOut)
		}
	})
	t.Run("usage", func(t *testing.T) {
		h := newHost(t, wipe, morSet)
		if rc, _, errOut := h.run("wipe"); rc != 2 || !strings.Contains(errOut, "usage: agentos-mor status|clear") {
			t.Fatalf("rc %d, %q", rc, errOut)
		}
	})
}

// The immutable flag is dropped only when it is set, and only once it was
// read: a failed read leaves MOR set.
func TestUnlockReadsTheFlagFirst(t *testing.T) {
	t.Run("read fails", func(t *testing.T) {
		h := newHost(t, wipe, morSet)
		h.s.getFlags = func(int) (uint32, error) { return 0, errors.New("ENOTTY") }
		if rc, _, errOut := h.run("clear"); rc != 1 || !strings.Contains(errOut, "ENOTTY") {
			t.Fatalf("rc %d, %q", rc, errOut)
		}
		if got := h.file(morPath); !bytes.Equal(got, morSet) || strings.Contains(strings.Join(h.events, ","), "unlock") {
			t.Fatalf("MOR %x, events %v", got, h.events)
		}
	})
	t.Run("not immutable", func(t *testing.T) {
		h := newHost(t, wipe, morSet)
		h.s.getFlags = func(int) (uint32, error) { return 0x80000, nil }
		if rc, _, errOut := h.run("clear"); rc != 0 {
			t.Fatal(errOut)
		}
		if strings.Join(h.events, ",") != "sync" {
			t.Fatalf("events %v, want no unlock", h.events)
		}
	})
	t.Run("no file", func(t *testing.T) {
		h := newHost(t, wipe, nil)
		if err := h.s.clearImmutable(h.s.morPath()); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("%v", err)
		}
		if len(h.events) != 0 {
			t.Fatalf("events %v", h.events)
		}
	})
}

// The write is read back: a variable the firmware did not take as written,
// or that cannot be read back, is a failure.
func TestClearReadsTheWriteBack(t *testing.T) {
	for name, put := range map[string]func(string, []byte) error{
		"firmware kept the bit": func(p string, b []byte) error { return write(p, morSet) },
		"gone after the write": func(p string, b []byte) error {
			return errors.Join(write(p, b), os.Remove(p))
		},
	} {
		t.Run(name, func(t *testing.T) {
			h := newHost(t, wipe, morSet)
			h.s.put = put
			if rc, out, errOut := h.run("clear"); rc != 1 || !strings.Contains(errOut, "after the write") {
				t.Fatalf("rc %d, %q, %q", rc, out, errOut)
			}
		})
	}
	t.Run("write fails", func(t *testing.T) {
		h := newHost(t, wipe, morSet)
		h.s.put = func(string, []byte) error { return errors.New("EIO") }
		if rc, _, errOut := h.run("clear"); rc != 1 || !strings.Contains(errOut, "writing MOR: EIO") {
			t.Fatalf("rc %d, %q", rc, errOut)
		}
	})
}

// clear mounts efivarfs first when it has a mount to make, and stops if
// that fails.
func TestClearMountsEFIVarsFirst(t *testing.T) {
	h := newHost(t, wipe, morSet)
	h.s.mount = func() error { h.events = append(h.events, "mount"); return errors.New("EPERM") }
	if rc, _, errOut := h.run("clear"); rc != 1 || !strings.Contains(errOut, "mounting efivarfs: EPERM") {
		t.Fatalf("rc %d, %q", rc, errOut)
	}
	if got := h.file(morPath); !bytes.Equal(got, morSet) || strings.Join(h.events, ",") != "mount" {
		t.Fatalf("MOR %x, events %v", got, h.events)
	}
	h = newHost(t, wipe, morSet)
	h.s.mount = func() error { h.events = append(h.events, "mount"); return nil }
	if rc, _, errOut := h.run("clear"); rc != 0 || strings.Join(h.events, ",") != "mount,sync,unlock" {
		t.Fatalf("rc %d, %q, events %v", rc, errOut, h.events)
	}
	h = newHost(t, wipe, morSet)
	h.s.mount = func() error { t.Error("status mounted efivarfs"); return nil }
	h.run("status")
}

// read refuses a file over its bound; write never creates one.
func TestReadAndWriteBounds(t *testing.T) {
	p := filepath.Join(t.TempDir(), "v")
	if err := write(p, morSet); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("write to a missing file: %v", err)
	}
	if _, err := os.Stat(p); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("write created the file")
	}
	if err := os.WriteFile(p, morSet, 0o600); err != nil {
		t.Fatal(err)
	}
	if b, err := read(p, 5); err != nil || !bytes.Equal(b, morSet) {
		t.Fatalf("%x, %v", b, err)
	}
	if _, err := read(p, 4); err == nil || !strings.Contains(err.Error(), "over 4 bytes") {
		t.Fatalf("read past its bound: %v", err)
	}
}

// Words split as the kernel's next_arg: runs of blanks give no empty word,
// and the last word needs no blank after it.
func TestCmdlineWords(t *testing.T) {
	for line, want := range map[string]string{
		"a  b\n":         "a|b",
		"a b":            "a|b",
		` x="1 2"  y `:   `x="1 2"|y`,
		"":               "",
		"\t\n":           "",
		"init_on_free=1": "init_on_free=1",
	} {
		if got := strings.Join(cmdlineWords(line), "|"); got != want {
			t.Errorf("%q: %q, want %q", line, got, want)
		}
	}
}
