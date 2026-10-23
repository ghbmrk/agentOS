// Command agentos-unlock is the one-shot unlock step at boot (STO-2b). Run
// as root, it opens the sealed store's tpm slot, derives the kernel's keys,
// closes the store, and becomes the kernel process: it drops to the kernel's
// uid and gid and execs the kernel main, with the keys on an inherited pipe
// (descriptor 3):
//
//	agentos-unlock -store /var/lib/agentos-store/store -uid 980 -gid 980 \
//	    -exec /usr/lib/agentos/agentos-kernel -- -log ... -owner-sock ...
//
// No process lives on with the store key (STO-2a-e, CLK-1): this one wipes
// it before the exec, and the kernel gets only the log key, the head key and
// the owner's anchors. The box's policy key and the store's anchor must come
// from somewhere the drive's writer cannot change (STO-2a-k); until that
// source lands (STO-pins, #2682) this step unlocks nothing.
package main

import (
	"crypto/ecdsa"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"

	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/linuxtpm"
	"github.com/google/go-tpm/tpm2/transport/linuxudstpm"

	"github.com/ghbmrk/agentos/broker/clerk/handoff"
	"github.com/ghbmrk/agentos/broker/clerk/seal"
)

func main() {
	log.SetFlags(0)
	c, err := parse(os.Args[1:], os.Stderr)
	if err == nil {
		err = unlockAndExec(c, noPins)
	}
	log.Fatal(err)
}

// pinSource gives the box's policy key and the store's anchor, read from
// somewhere the drive's writer cannot change (STO-2a-k). It fails closed:
// an error unlocks nothing.
type pinSource func(transport.TPM) (policyKey *ecdsa.PublicKey, anchor []byte, err error)

var errNoPins = errors.New("agentos-unlock: no place off the drive holds my policy key and store anchor yet (STO-pins); I unlock nothing")

// noPins is the production source until the TPM NV index lands.
func noPins(transport.TPM) (*ecdsa.PublicKey, []byte, error) { return nil, nil, errNoPins }

type config struct {
	store, tpm, exec string
	uid, gid         int
	args             []string // the kernel main's, after --
}

func parse(args []string, stderr io.Writer) (config, error) {
	fs := flag.NewFlagSet("agentos-unlock", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var c config
	fs.StringVar(&c.store, "store", "", "the sealed store file")
	fs.StringVar(&c.tpm, "tpm", "/dev/tpmrm0", "the TPM: the kernel's resource manager, or a software TPM's socket")
	fs.StringVar(&c.exec, "exec", "", "the kernel main, an absolute path")
	fs.IntVar(&c.uid, "uid", -1, "the kernel's uid")
	fs.IntVar(&c.gid, "gid", -1, "the kernel's gid")
	if err := fs.Parse(args); err != nil {
		return c, err
	}
	c.args = fs.Args()
	switch {
	case c.store == "" || !filepath.IsAbs(c.exec):
		return c, errors.New("-store and an absolute -exec are required")
	case c.uid <= 0 || c.gid <= 0:
		return c, errors.New("-uid and -gid are required, and never root")
	}
	return c, nil
}

// unlockAndExec returns only on failure, having exec'd nothing.
func unlockAndExec(c config, pins pinSource) error {
	if c.uid <= 0 || c.gid <= 0 {
		return errors.New("agentos-unlock: the kernel never runs as root")
	}
	b, err := unlock(c, pins)
	if err != nil {
		return err
	}
	defer clear(b)
	return handOff(b, c)
}

// unlock opens the store through this PC's tpm slot and returns the
// kernel's hand-off. The store is closed, its key wiped, before it returns.
func unlock(c config, pins pinSource) ([]byte, error) {
	t, err := openTPM(c.tpm)
	if err != nil {
		return nil, err
	}
	defer t.Close()
	pk, anchor, err := pins(t)
	if err != nil {
		return nil, err
	}
	st, err := seal.Unlock(c.store, seal.TPM{TPM: t, PolicyKey: pk, Anchor: anchor})
	if err != nil {
		return nil, fmt.Errorf("agentos-unlock: %w", err)
	}
	defer st.Close()
	var k handoff.KernelKeys
	defer k.Wipe()
	if k.Log, err = st.LogKey(); err != nil {
		return nil, err
	}
	if k.Head, err = st.HeadKey(); err != nil {
		return nil, err
	}
	raw, ok, err := st.Get(handoff.AnchorsEntry)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, errors.New("agentos-unlock: my store holds none of your hardware keys; set me up again")
	}
	if k.Anchors, err = handoff.ParseAnchors(raw); err != nil {
		return nil, fmt.Errorf("agentos-unlock: your hardware keys in my store: %w", err)
	}
	return k.Marshal()
}

// openTPM opens the TPM at path: the kernel's resource manager on the box,
// or a socket for a software TPM.
func openTPM(path string) (transport.TPMCloser, error) {
	if fi, err := os.Stat(path); err == nil && fi.Mode()&os.ModeSocket != 0 {
		return linuxudstpm.Open(path)
	}
	return linuxtpm.Open(path)
}

// handOff writes b to a pipe, drops to the kernel's ids and execs the
// kernel main with the pipe's read end as handoff.KeyFD. b is far below a
// pipe's buffer, so the write completes with no reader yet.
func handOff(b []byte, c config) error {
	r, w, err := os.Pipe()
	if err != nil {
		return err
	}
	defer r.Close()
	_, err = w.Write(b)
	if cerr := w.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	if err := drop(c.uid, c.gid); err != nil {
		return err
	}
	if err := inherit(int(r.Fd()), handoff.KeyFD); err != nil {
		return err
	}
	return syscall.Exec(c.exec, append([]string{c.exec}, c.args...), kernelEnv)
}

// kernelEnv is the kernel process's whole environment. It reads no
// variable, so nothing of the unlock step's environment, a root unit's,
// reaches it (cmd/agentosd ASSUMPTIONS L7-2).
var kernelEnv = []string{}

// drop makes uid and gid this process's every id, with no supplementary
// groups, and checks that root cannot be taken back. A step not running as
// root must already be exactly those ids (a test, or a unit that started it
// as the kernel's user).
func drop(uid, gid int) error {
	if uid <= 0 || gid <= 0 {
		return errors.New("agentos-unlock: the kernel never runs as root")
	}
	if os.Geteuid() == 0 {
		if err := syscall.Setgroups(nil); err != nil {
			return fmt.Errorf("agentos-unlock: drop groups: %w", err)
		}
		// Go applies these to every thread of the process.
		if err := syscall.Setresgid(gid, gid, gid); err != nil {
			return fmt.Errorf("agentos-unlock: set gid: %w", err)
		}
		if err := syscall.Setresuid(uid, uid, uid); err != nil {
			return fmt.Errorf("agentos-unlock: set uid: %w", err)
		}
		if syscall.Setresuid(0, 0, 0) == nil {
			return errors.New("agentos-unlock: root came back after the drop")
		}
	}
	gs, err := syscall.Getgroups()
	if err != nil {
		return err
	}
	ru, eu, su := getresuid()
	rg, eg, sg := getresgid()
	if ru != uid || eu != uid || su != uid || rg != gid || eg != gid || sg != gid {
		return fmt.Errorf("agentos-unlock: running as uid %d/%d/%d gid %d/%d/%d, not the kernel's %d:%d", ru, eu, su, rg, eg, sg, uid, gid)
	}
	for _, g := range gs {
		if g != gid {
			return fmt.Errorf("agentos-unlock: still in group %d", g)
		}
	}
	return noCaps()
}

// noCaps checks that no capability survived the drop: a unit with
// no-setuid-fixup securebits or ambient capabilities would otherwise carry
// some through setresuid and the exec (#2896 L3 item 3).
func noCaps() error {
	b, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return err
	}
	seen := 0
	for _, l := range strings.Split(string(b), "\n") {
		name, v, ok := strings.Cut(l, ":")
		if !ok || name != "CapPrm" && name != "CapEff" && name != "CapAmb" {
			continue
		}
		seen++
		if strings.Trim(strings.TrimSpace(v), "0") != "" {
			return fmt.Errorf("agentos-unlock: %s is %s after the drop, not empty", name, strings.TrimSpace(v))
		}
	}
	if seen != 3 {
		return errors.New("agentos-unlock: cannot read my capability sets")
	}
	return nil
}

// getresuid and getresgid read the real, effective and saved ids, which the
// syscall package does not export.
func getresuid() (r, e, s int) { return getres(syscall.SYS_GETRESUID) }
func getresgid() (r, e, s int) { return getres(syscall.SYS_GETRESGID) }

func getres(trap uintptr) (r, e, s int) {
	var a, b, c uint32
	if _, _, errno := syscall.RawSyscall(trap, uintptr(unsafe.Pointer(&a)), uintptr(unsafe.Pointer(&b)), uintptr(unsafe.Pointer(&c))); errno != 0 {
		return -1, -1, -1
	}
	return int(a), int(b), int(c)
}

// inherit makes fd survive the exec as want; every other descriptor Go
// opened is close-on-exec.
func inherit(fd, want int) error {
	if fd == want {
		_, _, e := syscall.RawSyscall(syscall.SYS_FCNTL, uintptr(fd), syscall.F_SETFD, 0)
		if e != 0 {
			return e
		}
		return nil
	}
	return syscall.Dup3(fd, want, 0)
}
