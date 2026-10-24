// Command agentos-enroll is enrollment (STO-2c): the one-shot step at first
// boot on a trusted host that makes the box's sealed store. Run as root:
//
//	agentos-enroll -state /var/lib/agentos-store \
//	    -anchor-dir /var/lib/agentos-kernel/anchor -log /var/lib/agentos-kernel/log \
//	    -kernel-uid 980 -kernel-gid 980 \
//	    -passphrase-file /run/agentos-setup/passphrase -recovery-file /run/agentos-setup/recovery
//
// It generates the box's own PCR-policy signing key (HW-5a) and creates the
// store with three slots: tpm, sealed to this PC's TPM under boot paths that
// key signs, and the passphrase and recovery slots from the Owner Card's
// factors (STO-2). The private key is kept only inside the store. It defines
// the TPM counter that anchors the log (LOG-2, STO-1) and starts the anchor's
// head file beside a log that does not exist yet, then writes the store's
// pins (the policy public key and Store.Anchor) to the TPM, where the unlock
// step reads them (STO-2a-k).
//
// The store is built at a staging path and renamed into place last, so the
// store at -state exists only once its pins, counter and slots agree. A rerun
// after a crash finishes a staged store whose pins are locked (only the
// rename was left), and otherwise frees the staged store's NV indexes and
// starts again. It never runs over a store, a log, or another store's locked
// pins on this TPM: it refuses with fixed words and changes nothing.
//
// -rotate re-seals the tpm slot under a new policy key, re-signing the boot
// paths the slot was enrolled with (never this boot's PCRs, which the unlock
// step capped), and rewrites the pins (ASSUMPTIONS STO-2c-b); -delete frees a store's NV indexes and removes it.
//
// Enrollment runs as root, and -anchor-dir's parent may be the kernel uid's
// to write. So the anchor's directory is removed, made and handed to the
// kernel through descriptors on that parent, never by path: a symlink
// swapped in between the steps cannot redirect root's writes or chown.
package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"

	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/linuxtpm"
	"github.com/google/go-tpm/tpm2/transport/linuxudstpm"
	"golang.org/x/sys/unix"

	"github.com/ghbmrk/agentos/broker/clerk/seal"
	"github.com/ghbmrk/agentos/broker/kernel/proc"
	"github.com/ghbmrk/agentos/broker/tpmseal"
)

func main() {
	log.SetFlags(0)
	c, err := parse(os.Args[1:], os.Stderr)
	if err == nil {
		err = runMode(c)
	}
	if err != nil {
		log.Fatal(err)
	}
}

const (
	storeName  = "store"
	stagedName = "store.enrolling"
	anchorFile = "anchor" // proc.CounterAnchor's head file in -anchor-dir

	// Store entries enrollment writes. counterEntry is the kernel's: the
	// counter's reference and auth value, which a kernel that opens the
	// counter anchor needs.
	policyKeyEntry = "tpm/policy-key"
	nextKeyEntry   = "tpm/policy-key-next"
	counterEntry   = "kernel/counter"

	defaultPCRs = "4,7,9,12"
)

// The fixed refusals. Each leaves everything as it was.
var (
	errEnrolled  = errors.New("agentos-enroll: I already have a sealed store; I change nothing")
	errLogExists = errors.New("agentos-enroll: I already have a log; I change nothing")
	errOtherPins = errors.New("agentos-enroll: this PC's TPM already holds another store's pins; I change nothing")
	errStaged    = errors.New("agentos-enroll: my unfinished store does not read; I change nothing")
	errCapped    = errors.New("agentos-enroll: my tpm slot is locked until the next boot, since this boot has unlocked it; give me -passphrase-file")
	errPCRs      = errors.New("agentos-enroll: -pcrs is not the selection my tpm slot was enrolled with; I change nothing")
)

// errCrash is what a test's stop returns, as a crash would end the run.
var errCrash = errors.New("agentos-enroll: stopped (test crash)")

type config struct {
	state, anchorDir, log, tpm, host string
	passphrase, recovery             string // root-only files
	pcrs                             []uint // nil on -rotate: keep the slot's
	kernelUID, kernelGID             int
	rotate, delete                   bool
	// stop, for tests only, ends the run after the named step as a crash
	// would; nil runs every step.
	stop func(step string) bool
}

func parse(args []string, stderr io.Writer) (config, error) {
	fs := flag.NewFlagSet("agentos-enroll", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var c config
	pcrs := fs.String("pcrs", "", "PCRs the boot path is measured into (SHA-256 bank); enrollment's default is "+defaultPCRs+", and -rotate keeps the enrolled selection")
	fs.StringVar(&c.state, "state", "", "the store's directory")
	fs.StringVar(&c.anchorDir, "anchor-dir", "", "the log anchor's directory, the kernel's")
	fs.StringVar(&c.log, "log", "", "the kernel's log file, which must not exist yet")
	fs.StringVar(&c.tpm, "tpm", "/dev/tpmrm0", "the TPM: the kernel's resource manager, or a software TPM's socket")
	fs.StringVar(&c.host, "host", "this PC", "the PC's name on its tpm slot")
	fs.StringVar(&c.passphrase, "passphrase-file", "", "a root-only file holding the Owner Card's store passphrase")
	fs.StringVar(&c.recovery, "recovery-file", "", "a root-only file holding the recovery key, hex")
	fs.IntVar(&c.kernelUID, "kernel-uid", -1, "the kernel's uid, which owns the anchor")
	fs.IntVar(&c.kernelGID, "kernel-gid", -1, "the kernel's gid")
	fs.BoolVar(&c.rotate, "rotate", false, "rotate my policy key")
	fs.BoolVar(&c.delete, "delete", false, "free the store's NV indexes and remove it")
	if err := fs.Parse(args); err != nil {
		return c, err
	}
	if *pcrs == "" && !c.rotate {
		*pcrs = defaultPCRs
	}
	if *pcrs != "" {
		var err error
		if c.pcrs, err = parsePCRs(*pcrs); err != nil {
			return c, err
		}
	}
	switch {
	case fs.NArg() != 0:
		return c, fmt.Errorf("unexpected arguments: %q", fs.Args())
	case !filepath.IsAbs(c.state):
		return c, errors.New("an absolute -state is required")
	case c.rotate && c.delete:
		return c, errors.New("-rotate and -delete are separate runs")
	case c.rotate || c.delete:
	case !filepath.IsAbs(c.anchorDir) || !filepath.IsAbs(c.log):
		return c, errors.New("absolute -anchor-dir and -log are required")
	case c.kernelUID <= 0 || c.kernelGID <= 0:
		return c, errors.New("-kernel-uid and -kernel-gid are required, and never root")
	case c.passphrase == "" || c.recovery == "":
		return c, errors.New("-passphrase-file and -recovery-file are required: a store never has only its tpm slot")
	}
	return c, nil
}

func parsePCRs(s string) ([]uint, error) {
	var out []uint
	for _, f := range strings.Split(s, ",") {
		n, err := strconv.ParseUint(strings.TrimSpace(f), 10, 8)
		if err != nil || n > 23 {
			return nil, fmt.Errorf("-pcrs: bad PCR %q", f)
		}
		out = append(out, uint(n))
	}
	if len(out) == 0 || len(out) > tpmseal.MaxPCRs {
		return nil, fmt.Errorf("-pcrs: select 1 to %d PCRs", tpmseal.MaxPCRs)
	}
	// The unlock step caps the slot by extending one of these (#2977).
	if _, err := tpmseal.CapPCR(out); err != nil {
		return nil, fmt.Errorf("-pcrs: %w", err)
	}
	return out, nil
}

func runMode(c config) error {
	t, err := openTPM(c.tpm)
	if err != nil {
		return err
	}
	defer t.Close()
	switch {
	case c.rotate:
		return rotate(c, t)
	case c.delete:
		return deleteStore(c, t)
	}
	return enroll(c, t)
}

func openTPM(path string) (transport.TPMCloser, error) {
	if fi, err := os.Stat(path); err == nil && fi.Mode()&os.ModeSocket != 0 {
		return linuxudstpm.Open(path)
	}
	return linuxtpm.Open(path)
}

func (c config) step(name string) error {
	if c.stop != nil && c.stop(name) {
		return errCrash
	}
	return nil
}

func (c config) storePath() string  { return filepath.Join(c.state, storeName) }
func (c config) stagedPath() string { return filepath.Join(c.state, stagedName) }

func exists(path string) (bool, error) {
	_, err := os.Lstat(path)
	if err == nil {
		return true, nil
	}
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	return false, err
}

// enroll makes the box's store. Steps, each named for a test's stop:
// "cleaned", "created", "slots", "counter", "head-file", "anchor", "pins",
// then the rename.
func enroll(c config, t transport.TPM) error {
	for _, r := range []struct {
		path string
		err  error
	}{{c.storePath(), errEnrolled}, {c.log, errLogExists}} {
		if ok, err := exists(r.path); err != nil {
			return err
		} else if ok {
			return r.err
		}
	}
	srk, err := tpmseal.Identity(t)
	if err != nil {
		return err
	}
	var stagedID []byte
	if ok, err := exists(c.stagedPath()); err != nil {
		return err
	} else if ok {
		if stagedID, err = seal.ReadID(c.stagedPath()); err != nil {
			return fmt.Errorf("%w: %w", errStaged, err)
		}
	}
	if other, err := tpmseal.OtherPins(t, stagedID); err != nil {
		return err
	} else if other {
		return errOtherPins
	}
	if stagedID != nil {
		// Locked pins are the last TPM step: only the rename was left.
		if _, err := tpmseal.ReadPins(t, srk, stagedID); err == nil {
			return commit(c)
		} else if !errors.Is(err, tpmseal.ErrNoPins) {
			return err
		}
		if err := forget(t, srk, stagedID); err != nil {
			return err
		}
		if err := os.Remove(c.stagedPath()); err != nil {
			return err
		}
	}
	parent, err := unix.Open(filepath.Dir(c.anchorDir), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return &os.PathError{Op: "open", Path: filepath.Dir(c.anchorDir), Err: err}
	}
	defer unix.Close(parent)
	base := filepath.Base(c.anchorDir)
	// No store and no log, so any head file here is a dead enrollment's.
	if err := removeAnchor(parent, base); err != nil {
		return err
	}
	if err := c.step("cleaned"); err != nil {
		return err
	}
	pass, rec, err := factors(c)
	if err != nil {
		return err
	}
	defer clear(pass)
	defer clear(rec)

	key, err := tpmseal.NewPolicyKey()
	if err != nil {
		return err
	}
	// This boot's PCRs are the boot path only before the unlock step has
	// capped them (#2977); the units run enrollment before the kernel.
	pol, err := tpmseal.SignCurrent(t, key, c.pcrs)
	if err != nil {
		return err
	}
	st, err := seal.Create(c.stagedPath(), seal.TPM{TPM: t, PolicyKey: &key.PublicKey, Policies: []tpmseal.Policy{pol}, Host: c.host})
	if err != nil {
		return err
	}
	defer st.Close()
	if err := c.step("created"); err != nil {
		return err
	}
	if _, err := st.AddSlot(seal.Passphrase{Phrase: pass}); err != nil {
		return err
	}
	if _, err := st.AddSlot(seal.Recovery{Key: rec}); err != nil {
		return err
	}
	der, err := tpmseal.MarshalPolicyKey(key)
	if err != nil {
		return err
	}
	defer clear(der)
	if err := st.Put(policyKeyEntry, der); err != nil {
		return err
	}
	if err := c.step("slots"); err != nil {
		return err
	}
	ctr, err := newCounter(t, srk, st.ID())
	if err != nil {
		return err
	}
	b, _ := json.Marshal(ctr)
	defer clear(b)
	if err := st.Put(counterEntry, b); err != nil {
		return err
	}
	if err := c.step("counter"); err != nil {
		return err
	}
	head, err := st.HeadKey()
	if err != nil {
		return err
	}
	defer clear(head)
	if err := makeAnchor(c, parent, base, ctr.Counter(t, srk), head); err != nil {
		return err
	}
	if err := c.step("anchor"); err != nil {
		return err
	}
	anchor, err := st.Anchor()
	if err != nil {
		return err
	}
	if err := tpmseal.WritePins(t, srk, st.ID(), tpmseal.Pins{PolicyKey: &key.PublicKey, Anchor: anchor}); err != nil {
		return err
	}
	if err := c.step("pins"); err != nil {
		return err
	}
	st.Close()
	return commit(c)
}

// commit renames the staged store into place: from here the unlock step
// finds it.
func commit(c config) error {
	if err := os.Rename(c.stagedPath(), c.storePath()); err != nil { // durable:exempt lifecycle:exempt the store's one commit point; the directory is synced next
		return err
	}
	d, err := os.Open(c.state)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

// openDir opens the directory name in dirfd, never through a symlink.
func openDir(dirfd int, name string) (int, error) {
	fd, err := unix.Openat(dirfd, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, &os.PathError{Op: "open", Path: name, Err: err}
	}
	return fd, nil
}

// removeAnchor removes a dead enrollment's head file and its directory,
// name in parent. A symlink there is refused, not followed.
func removeAnchor(parent int, name string) error {
	dir, err := openDir(parent, name)
	if errors.Is(err, unix.ENOENT) {
		return nil
	} else if err != nil {
		return err
	}
	defer unix.Close(dir)
	for _, n := range []string{anchorFile, anchorFile + ".tmp"} {
		if err := unix.Unlinkat(dir, n, 0); err != nil && !errors.Is(err, unix.ENOENT) {
			return &os.PathError{Op: "remove", Path: n, Err: err}
		}
	}
	if err := unix.Unlinkat(parent, name, unix.AT_REMOVEDIR); err != nil && !errors.Is(err, unix.ENOENT) {
		return &os.PathError{Op: "remove", Path: name, Err: err}
	}
	return nil
}

// makeAnchor makes the anchor's directory, name in parent, starts its head
// file and hands both to the kernel uid, all through the directory's
// descriptor. proc.InitCounterAnchor takes a path, so it gets the
// descriptor's /proc path, which names this directory wherever it is
// moved; and it refuses a directory that is not root's alone, so one
// swapped in after the mkdir fails there.
func makeAnchor(c config, parent int, name string, ctr proc.Counter, head []byte) error {
	if err := unix.Mkdirat(parent, name, 0o700); err != nil {
		return &os.PathError{Op: "mkdir", Path: name, Err: err}
	}
	dir, err := openDir(parent, name)
	if err != nil {
		return err
	}
	defer unix.Close(dir)
	if err := proc.InitCounterAnchor(fmt.Sprintf("/proc/self/fd/%d/.", dir), c.log, ctr, head); err != nil {
		return err
	}
	if err := c.step("head-file"); err != nil {
		return err
	}
	if err := unix.Fchownat(dir, anchorFile, c.kernelUID, c.kernelGID, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return &os.PathError{Op: "chown", Path: anchorFile, Err: err}
	}
	if err := unix.Fchown(dir, c.kernelUID, c.kernelGID); err != nil {
		return &os.PathError{Op: "chown", Path: name, Err: err}
	}
	return nil
}

// forget frees store id's pins and counter on this TPM.
func forget(t transport.TPM, srk, id []byte) error {
	if err := tpmseal.FreePins(t, srk, id); err != nil {
		return err
	}
	return tpmseal.FreeCounter(t, srk, id)
}

// factors reads the passphrase and the recovery key from their files, which
// must be root-only.
func factors(c config) (pass, rec []byte, err error) {
	if pass, err = readSecret(c.passphrase); err != nil {
		return nil, nil, err
	}
	pass = bytes.TrimRight(pass, "\n")
	h, err := readSecret(c.recovery)
	if err != nil {
		clear(pass)
		return nil, nil, err
	}
	defer clear(h)
	rec, err = hex.DecodeString(strings.TrimSpace(string(h)))
	if err != nil || len(rec) != seal.RecoveryLen {
		clear(pass)
		return nil, nil, fmt.Errorf("agentos-enroll: the recovery key is not %d bytes of hex", seal.RecoveryLen)
	}
	return pass, rec, nil
}

func readSecret(path string) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || !fi.Mode().IsRegular() || int(st.Uid) != os.Geteuid() || fi.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("agentos-enroll: %s is not a file only I can read", path)
	}
	return io.ReadAll(io.LimitReader(f, 4<<10))
}

// counterRec is counterEntry's value.
type counterRec struct {
	Ref  tpmseal.CounterRef `json:"ref"`
	Auth []byte             `json:"auth"`
}

func (r counterRec) Counter(t transport.TPM, srk []byte) tpmseal.Counter {
	return tpmseal.Counter{TPM: t, SRK: srk, Ref: r.Ref, Auth: r.Auth}
}

// newCounter defines store id's counter. A define that reports an error
// may still have made the index (the TPM defined it and then failed the
// first increment, or the answer was lost), and a counter the store does
// not record would later read as a rollback (#2905, from #2907). So after
// an error it asks the TPM: a counter that exists, partly made or not, is
// finished and adopted in this call; none, or a TPM that does not answer,
// returns the error, and nothing records the counter. The staged store is
// then never committed, and the rerun frees whatever the ID holds.
func newCounter(t transport.TPM, srk, id []byte) (counterRec, error) {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return counterRec{}, err
	}
	// Hex, so the auth value has no zero byte (T7).
	r := counterRec{Auth: []byte(hex.EncodeToString(raw))}
	ref, err := tpmseal.DefineCounter(t, srk, id, r.Auth)
	if err != nil {
		found, ferr := tpmseal.FindCounter(t, id)
		if ferr != nil || !found {
			return counterRec{}, err
		}
		if ref, err = tpmseal.DefineCounter(t, srk, id, r.Auth); err != nil {
			return counterRec{}, err
		}
	}
	r.Ref = ref
	return r, nil
}

// open unlocks the store at -state through its pins on this TPM, or,
// through the passphrase in -passphrase-file, when the TPM holds none (a
// rotation stopped between freeing the old pins and writing the new) or the
// tpm slot is capped for the rest of this boot (the unlock step has run,
// #2977).
func open(c config, t transport.TPM) (*seal.Store, error) {
	f, err := seal.Pinned(t, c.storePath())
	if err == nil {
		st, err := seal.Unlock(c.storePath(), f)
		if !errors.Is(err, tpmseal.ErrNoPolicy) {
			return st, err
		}
		if c.passphrase == "" {
			return nil, errCapped
		}
	} else if !errors.Is(err, tpmseal.ErrNoPins) || c.passphrase == "" {
		return nil, err
	}
	pass, err := readSecret(c.passphrase)
	if err != nil {
		return nil, err
	}
	defer clear(pass)
	return seal.Unlock(c.storePath(), seal.Passphrase{Phrase: bytes.TrimRight(pass, "\n")})
}

// rotate moves the store's tpm slot to a new policy key. Steps, each named
// for a test's stop: "next-key", "new-slot", "pins-freed", "pins-new",
// "old-slot", then the entries. Until "pins-freed" the old pins and slot
// unlock; between it and "pins-new" only the passphrase and recovery slots
// do; after, the new pins and slot. A rerun resumes where a crash stopped,
// with the same next key.
func rotate(c config, t transport.TPM) error {
	st, err := open(c, t)
	if err != nil {
		return err
	}
	defer st.Close()
	srk, err := tpmseal.Identity(t)
	if err != nil {
		return err
	}
	oldDER, ok, err := st.Get(policyKeyEntry)
	if err != nil || !ok {
		return fmt.Errorf("agentos-enroll: my store holds no policy key: %v", err)
	}
	old, err := tpmseal.ParsePolicyKey(oldDER)
	if err != nil {
		return err
	}
	nextDER, ok, err := st.Get(nextKeyEntry)
	if err != nil {
		return err
	}
	defer func() { clear(nextDER) }()
	var next *ecdsa.PrivateKey
	if ok {
		if next, err = tpmseal.ParsePolicyKey(nextDER); err != nil {
			return err
		}
	}
	// The new slot re-signs the old slot's boot paths over its PCR
	// selection, so a rotation keeps what enrollment measured (HW-5a). It
	// never reads the PCRs: the unlock step capped one of them after its
	// unseal (#2977), so values read now would open nothing on the next
	// boot. They are read before anything changes; a rerun that finds the
	// new slot made needs none.
	var pols []tpmseal.Policy
	if next == nil || !hasSlot(st, &next.PublicKey) {
		if pols, err = slotPolicies(st, &old.PublicKey, c.pcrs); err != nil {
			return err
		}
	}
	if next == nil {
		if next, err = tpmseal.NewPolicyKey(); err != nil {
			return err
		}
		if nextDER, err = tpmseal.MarshalPolicyKey(next); err != nil {
			return err
		}
		if err := st.Put(nextKeyEntry, nextDER); err != nil {
			return err
		}
	}
	if err := c.step("next-key"); err != nil {
		return err
	}
	if !hasSlot(st, &next.PublicKey) {
		signed := make([]tpmseal.Policy, 0, len(pols))
		for _, p := range pols {
			q, err := tpmseal.Resign(next, p)
			if err != nil {
				return err
			}
			signed = append(signed, q)
		}
		if _, err := st.AddSlot(seal.TPM{TPM: t, PolicyKey: &next.PublicKey, Policies: signed, Host: c.host}); err != nil {
			return err
		}
	}
	if err := c.step("new-slot"); err != nil {
		return err
	}
	p, err := tpmseal.ReadPins(t, srk, st.ID())
	if err != nil && !errors.Is(err, tpmseal.ErrNoPins) {
		return err
	}
	if err != nil || !p.PolicyKey.Equal(&next.PublicKey) {
		if err := tpmseal.FreePins(t, srk, st.ID()); err != nil {
			return err
		}
		if err := c.step("pins-freed"); err != nil {
			return err
		}
		anchor, err := st.Anchor()
		if err != nil {
			return err
		}
		if err := tpmseal.WritePins(t, srk, st.ID(), tpmseal.Pins{PolicyKey: &next.PublicKey, Anchor: anchor}); err != nil {
			return err
		}
	}
	if err := c.step("pins-new"); err != nil {
		return err
	}
	for _, sl := range st.Slots() {
		if sl.Kind == seal.KindTPM && sl.PolicyKey != nil && sl.PolicyKey.Equal(&old.PublicKey) && !old.PublicKey.Equal(&next.PublicKey) {
			if err := st.RemoveSlot(sl.ID); err != nil {
				return err
			}
		}
	}
	if err := c.step("old-slot"); err != nil {
		return err
	}
	if err := st.Put(policyKeyEntry, nextDER); err != nil {
		return err
	}
	return st.Delete(nextKeyEntry)
}

func hasSlot(st *seal.Store, key *ecdsa.PublicKey) bool {
	for _, sl := range st.Slots() {
		if sl.Kind == seal.KindTPM && sl.PolicyKey != nil && sl.PolicyKey.Equal(key) {
			return true
		}
	}
	return false
}

// slotPolicies is the boot paths, of one PCR selection, of the tpm slot
// sealed under key; the store holds only boot paths a slot's key signed
// (seal.SetPolicies), so a rotation re-signs nothing the box did not
// already approve. With no -pcrs the slot must use one selection; -pcrs must
// name one of the slot's selections, and errPCRs refuses any other.
func slotPolicies(st *seal.Store, key *ecdsa.PublicKey, asked []uint) ([]tpmseal.Policy, error) {
	var pols []tpmseal.Policy
	var sels [][]uint
	for _, sl := range st.Slots() {
		if sl.Kind != seal.KindTPM || sl.PolicyKey == nil || !sl.PolicyKey.Equal(key) {
			continue
		}
		for _, p := range sl.Policies {
			pols = append(pols, p)
			if !slices.ContainsFunc(sels, func(s []uint) bool { return slices.Equal(s, p.PCRs) }) {
				sels = append(sels, p.PCRs)
			}
		}
	}
	var sel []uint
	switch {
	case len(sels) == 0:
		return nil, errors.New("agentos-enroll: my store has no tpm slot under its policy key")
	case asked == nil && len(sels) == 1:
		sel = sels[0]
	case asked == nil:
		return nil, fmt.Errorf("agentos-enroll: my tpm slot's boot paths use the selections %v; name one with -pcrs", sels)
	default:
		sel = slices.Sorted(slices.Values(asked))
		if !slices.ContainsFunc(sels, func(s []uint) bool { return slices.Equal(s, sel) }) {
			return nil, fmt.Errorf("%w (it is %v)", errPCRs, sels)
		}
	}
	return slices.DeleteFunc(pols, func(p tpmseal.Policy) bool { return !slices.Equal(p.PCRs, sel) }), nil
}

// deleteStore frees the store's pins and counter on this TPM, then removes
// it. The store must open first, so only its owner's box deletes it. A crash
// between the two leaves a store with no pins, which opens only by the
// passphrase or recovery slot, and a rerun finishes.
func deleteStore(c config, t transport.TPM) error {
	st, err := open(c, t)
	if err != nil {
		return err
	}
	id := st.ID()
	st.Close()
	srk, err := tpmseal.Identity(t)
	if err != nil {
		return err
	}
	if err := forget(t, srk, id); err != nil {
		return err
	}
	if err := c.step("freed"); err != nil {
		return err
	}
	return os.Remove(c.storePath())
}
