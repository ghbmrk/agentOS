// Command agentos-mor clears the memory-overwrite request (MOR) on an
// orderly shutdown, after the image's secrets are wiped (HW-8, P2-1).
//
// The kernel's EFI stub sets MemoryOverwriteRequestControl's ClearMemory
// bit at every boot on a firmware that has the variable, so that after a
// power cut or forced reset the firmware wipes memory before anything else
// runs. On an orderly shutdown the OS clears it, or the host's next boot
// wipes memory for nothing and HW-8's host-untouched check sees the
// variable changed.
//
//	agentos-mor status   print mor=absent|clear|set and wipe=on|off
//	agentos-mor clear    wipe, then clear the ClearMemory bit
//
// agentos-mor.service runs clear as its ExecStop, which systemd reaches
// after every unit ordered after sysinit.target has stopped, so every
// process that held a secret has exited. The wipe rests on the kernel's
// init_on_free=1 (mkosi.conf), which zeroes each page and slab object as it
// is freed: clear refuses to touch MOR without it, and before clearing it
// syncs and drops the page cache, so cached file pages are freed and
// zeroed too. Files on the /run and /dev/shm tmpfs mounts are never freed
// (systemd-shutdown never unmounts them), so clear also refuses while a
// secret-holding directory there (holdDirs) or /dev/shm holds anything.
// Every refusal leaves MOR set, which errs safe: the firmware then wipes
// memory at the next start, which HW-8 discloses.
//
// It never creates the variable, writes only when the bit is set, keeps
// every other bit and the variable's attributes, and checks the result.
package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

// morName is the variable and vendor GUID the TCG Platform Reset Attack
// Mitigation specification defines (the Linux EFI stub's
// MEMORY_ONLY_RESET_CONTROL_GUID).
const morName = "MemoryOverwriteRequestControl-e20939be-32d4-41be-a150-897f85d49829"

const (
	clearMemory   = 0x01       // bit 0: wipe memory at the next start
	efiAttrs      = 0x7        // NV | BS | RT, the only attributes the variable has
	fsImmutable   = 0x10       // FS_IMMUTABLE_FL, which efivarfs sets on the file
	efivarfsMagic = 0xde5e81e4 // EFIVARFS_MAGIC
)

// holdDirs are the tmpfs directories that can hold a secret past its unit's
// stop: the Owner Card's passphrase, recovery key and staged page authority
// between the confirm and a successful enrollment (agentos-keeper-enroll
// keeps them for a retry on failure), the first edge's capture, and any
// POSIX shared memory. Each is on a mount systemd never unmounts, so its
// pages are never freed and never zeroed. image/ASSUMPTIONS.md P2-1-mor-1
// lists the audit of /run.
var holdDirs = []string{"run/agentos-setup", "run/agentos-link-capture", "dev/shm"}

// sys is the host, rooted at root ("/" on the box; a scratch tree in tests).
type sys struct {
	root     string
	getFlags func(fd int) (uint32, error)
	setFlags func(fd int, flags uint32) error
	sync     func()
}

func newSys(root string) *sys {
	return &sys{
		root:     root,
		getFlags: func(fd int) (uint32, error) { return unix.IoctlGetUint32(fd, unix.FS_IOC_GETFLAGS) },
		setFlags: func(fd int, f uint32) error { return unix.IoctlSetPointerInt(fd, unix.FS_IOC_SETFLAGS, int(f)) },
		sync:     unix.Sync,
	}
}

func (s *sys) path(rel string) string { return filepath.Join(s.root, rel) }

func (s *sys) morPath() string { return s.path("sys/firmware/efi/efivars/" + morName) }

// read reads a small file without following a link at its last step.
func read(path string, max int64) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, max+1))
	if err == nil && int64(len(b)) > max {
		err = fmt.Errorf("%s is over %d bytes", path, max)
	}
	return b, err
}

// write writes b to an existing file in one write, as efivarfs and procfs
// require; it never creates the file.
func write(path string, b []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	_, err = f.Write(b)
	return errors.Join(err, f.Close())
}

// mor returns the variable's attributes and data byte; ok is false when the
// firmware has no such variable.
func (s *sys) mor() (attrs uint32, data byte, ok bool, err error) {
	b, err := read(s.morPath(), 64)
	if errors.Is(err, os.ErrNotExist) {
		return 0, 0, false, nil
	}
	if err != nil {
		return 0, 0, false, err
	}
	if len(b) != 5 {
		return 0, 0, false, fmt.Errorf("MOR is %d bytes, not 4 of attributes and 1 of data", len(b))
	}
	return binary.LittleEndian.Uint32(b), b[4], true, nil
}

// wipeOn reports whether the running kernel zeroes memory as it is freed:
// the last init_on_free= on its command line is 1. Words split as the
// kernel's next_arg splits them: blanks inside double quotes do not split,
// and the kernel takes nothing after a bare "--" (init gets it). Only the
// exact word init_on_free=1 counts as on; a quoted or other spelling
// counts as off, which errs safe.
func (s *sys) wipeOn() (bool, error) {
	b, err := read(s.path("proc/cmdline"), 4096)
	if err != nil {
		return false, err
	}
	on := false
	for _, w := range cmdlineWords(string(b)) {
		if w == "--" {
			break
		}
		if v, ok := strings.CutPrefix(w, "init_on_free="); ok {
			on = v == "1"
		}
	}
	return on, nil
}

// cmdlineWords splits a kernel command line at blanks outside double
// quotes, keeping the quotes in each word.
func cmdlineWords(line string) []string {
	var out []string
	var w strings.Builder
	quoted, in := false, false
	for _, r := range line {
		if r == '"' {
			quoted = !quoted
		}
		if !quoted && (r == ' ' || r == '\t' || r == '\n' || r == '\r' || r == '\v' || r == '\f') {
			if in {
				out = append(out, w.String())
				w.Reset()
				in = false
			}
			continue
		}
		w.WriteRune(r)
		in = true
	}
	if in {
		out = append(out, w.String())
	}
	return out
}

// held names the first holdDirs entry that is not empty; a directory that
// is absent is empty, and one that cannot be read counts as held.
func (s *sys) held() (string, error) {
	for _, d := range holdDirs {
		f, err := os.OpenFile(s.path(d), os.O_RDONLY|unix.O_NOFOLLOW|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return "", fmt.Errorf("reading /%s: %w; MOR left set", d, err)
		}
		names, err := f.Readdirnames(1)
		f.Close()
		if err != nil && !errors.Is(err, io.EOF) {
			return "", fmt.Errorf("reading /%s: %w; MOR left set", d, err)
		}
		if len(names) > 0 {
			return "/" + d, nil
		}
	}
	return "", nil
}

// clearImmutable drops efivarfs's immutable flag, as bootctl does before a
// write (broker/apply/bootab does the same).
func (s *sys) clearImmutable(path string) error {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	flags, err := s.getFlags(fd)
	if err != nil || flags&fsImmutable == 0 {
		return err
	}
	return s.setFlags(fd, flags&^fsImmutable)
}

// clear wipes, then clears the ClearMemory bit. It returns what it did.
func (s *sys) clear() (string, error) {
	attrs, data, ok, err := s.mor()
	if err != nil {
		return "", err
	}
	if !ok {
		return "mor=absent", nil
	}
	if data&clearMemory == 0 {
		return "mor=clear", nil
	}
	if attrs != efiAttrs {
		return "", fmt.Errorf("MOR has attributes %#x, not %#x; left set", attrs, efiAttrs)
	}
	on, err := s.wipeOn()
	if err != nil {
		return "", err
	}
	if !on {
		return "", errors.New("the kernel does not zero freed memory (no init_on_free=1); MOR left set, so the firmware wipes memory at the next start")
	}
	if d, err := s.held(); err != nil {
		return "", err
	} else if d != "" {
		return "", fmt.Errorf("%s still holds files, which are never freed or zeroed; MOR left set, so the firmware wipes memory at the next start", d)
	}
	// The wipe: every secret-holding process has exited, so its pages are
	// free and zeroed; the page cache's clean pages are freed (and zeroed)
	// here, after writing back the dirty ones.
	s.sync()
	if err := write(s.path("proc/sys/vm/drop_caches"), []byte("3")); err != nil {
		return "", fmt.Errorf("dropping the page cache: %w; MOR left set", err)
	}
	path := s.morPath()
	if err := s.clearImmutable(path); err != nil {
		return "", fmt.Errorf("MOR: %w; left set", err)
	}
	b := binary.LittleEndian.AppendUint32(nil, attrs)
	if err := write(path, append(b, data&^clearMemory)); err != nil {
		return "", fmt.Errorf("writing MOR: %w; left set", err)
	}
	got, err := read(path, 64)
	if err != nil {
		return "", err
	}
	if want := append(b, data&^clearMemory); !bytes.Equal(got, want) {
		return "", fmt.Errorf("MOR reads %x after the write, not %x", got, want)
	}
	return "mor=cleared", nil
}

func (s *sys) status() (string, error) {
	_, data, ok, err := s.mor()
	if err != nil {
		return "", err
	}
	on, err := s.wipeOn()
	if err != nil {
		return "", err
	}
	st := map[bool]string{true: "set", false: "clear"}[data&clearMemory != 0]
	if !ok {
		st = "absent"
	}
	return fmt.Sprintf("mor=%s wipe=%s", st, map[bool]string{true: "on", false: "off"}[on]), nil
}

// mountEFIVars mounts efivarfs if it is not mounted and the firmware is
// UEFI; a host booted another way has no MOR.
func mountEFIVars() error {
	dir := "/sys/firmware/efi/efivars"
	var st unix.Statfs_t
	if err := unix.Statfs(dir, &st); err == nil && uint32(st.Type) == efivarfsMagic {
		return nil
	} else if errors.Is(err, unix.ENOENT) {
		return nil
	}
	return unix.Mount("efivarfs", dir, "efivarfs", unix.MS_NOSUID|unix.MS_NODEV|unix.MS_NOEXEC, "")
}

func main() {
	os.Exit(run(os.Args[1:], newSys("/"), os.Stdout, os.Stderr))
}

func run(args []string, s *sys, stdout, stderr io.Writer) int {
	var out string
	var err error
	switch {
	case len(args) == 1 && args[0] == "status":
		out, err = s.status()
	case len(args) == 1 && args[0] == "clear":
		if s.root == "/" {
			if err = mountEFIVars(); err != nil {
				err = fmt.Errorf("mounting efivarfs: %w", err)
				break
			}
		}
		out, err = s.clear()
	default:
		fmt.Fprintln(stderr, "usage: agentos-mor status|clear")
		return 2
	}
	if err != nil {
		fmt.Fprintln(stderr, "agentos-mor:", err)
		return 1
	}
	fmt.Fprintln(stdout, "agentos-mor:", out)
	return 0
}
