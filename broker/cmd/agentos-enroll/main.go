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
// It also keeps the page authority (CH-9) in the store, for the unlock step
// to hand the kernel, which certifies the owner page's serving keys and
// writes it into every backup (MIG-4-recovery-f1). At first boot that is the
// authority -stage-page-ca staged before the Owner Card was shown, whose
// fingerprint the card printed (-page-ca-file, -page-ca-cert; stage.go).
//
// -take-factors is the Owner Card confirm's hand-off: the keeper's setup
// socket runs it once per connection, as root, with no TPM, and it writes
// the card's factors where enrollment reads them (take.go).
//
// It makes the core's link key (HW-15) and keeps it only in the store, for
// the unlock step to hand the kernel; it is never backed up (BAK-1). With
// -first-edge it takes the edge key the link port captured before the
// Owner Card confirm from that file, stores it for the kernel's setup step
// to log, and removes the file once the store is in place; with -restore
// (a restore's enrollment, REC-2) it stores none and only removes the file.
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
// -rotate-recovery replaces the recovery key on a running box (REC-4, route
// A of D-201). The keeper's socket unit runs it once per connection, as
// root, with no TPM: it reads one request on stdin, opens the store with the
// Owner Card factor the request carries, checks the kernel's head-signed
// approval, puts the new key's slot and backup recipient in place in one
// write, and answers one word on stdout (rotateWord). A store that already
// holds the approved key and recipient answers ok and is left as it is.
//
// Enrollment runs as root, and -anchor-dir's parent may be the kernel uid's
// to write. So the anchor's directory is removed, made and handed to the
// kernel through descriptors on that parent, never by path: a symlink
// swapped in between the steps cannot redirect root's writes or chown.
package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
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
	"runtime/debug"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/linuxtpm"
	"github.com/google/go-tpm/tpm2/transport/linuxudstpm"
	"golang.org/x/sys/unix"

	"github.com/ghbmrk/agentos/broker/backup"
	"github.com/ghbmrk/agentos/broker/clerk/handoff"
	"github.com/ghbmrk/agentos/broker/clerk/seal"
	"github.com/ghbmrk/agentos/broker/kernel"
	"github.com/ghbmrk/agentos/broker/kernel/proc"
	"github.com/ghbmrk/agentos/broker/pageca"
	"github.com/ghbmrk/agentos/broker/tpmseal"
)

func main() {
	log.SetFlags(0)
	c, err := parse(os.Args[1:], os.Stderr)
	if err == nil && c.rotateRecovery {
		os.Exit(rotateRecoveryMain(c, os.Stdin, os.Stdout))
	}
	if err == nil && c.takeFactors {
		os.Exit(takeFactorsMain(c, os.Stdin, os.Stdout, os.Stderr))
	}
	if err == nil && c.stagePageCA {
		err = stagePageCA(c.pageCAFile, c.pageCACert, c.built)
	} else if err == nil {
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
	errCapped    = errors.New("agentos-enroll: my tpm slot does not open on this boot (locked after this boot's unlock, or a boot path I never approved); give me -passphrase-file")
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
	rotateRecovery                   bool
	stagePageCA, takeFactors         bool
	// pageCAFile is the staged page authority (-stage-page-ca writes it,
	// enrollment stores it), "" for enrollment to make its own;
	// pageCACert is its published certificate. setupDir is where
	// -take-factors writes the Owner Card's factors.
	pageCAFile, pageCACert, setupDir string
	// firstEdge is the link port's capture file (agentos-link's pre-store
	// mode), "" for none; restore takes no first key from it.
	firstEdge string
	restore   bool
	// built is the image's build time, the page authority's NotBefore
	// plus a day (pageca.New): never the first boot's clock.
	built time.Time
	// stop, for tests only, ends the run after the named step as a crash
	// would; nil runs every step.
	stop func(step string) bool
	// now, for tests only, is the clock -rotate-recovery checks an
	// approval's expiry by; nil is the system's.
	now func() time.Time
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
	fs.BoolVar(&c.rotateRecovery, "rotate-recovery", false, "replace the recovery key: one request on stdin, one word on stdout")
	fs.StringVar(&c.firstEdge, "first-edge", "", "the link port's capture file of the first edge's hello, which I remove")
	fs.BoolVar(&c.restore, "restore", false, "a restore's enrollment: take no first edge key")
	fs.BoolVar(&c.stagePageCA, "stage-page-ca", false, "make the first-boot page authority: -page-ca-file and -page-ca-cert")
	fs.BoolVar(&c.takeFactors, "take-factors", false, "take the confirmed Owner Card's factors: one request on stdin, one word on stdout")
	fs.StringVar(&c.pageCAFile, "page-ca-file", "", "the staged page authority, a root-only file")
	fs.StringVar(&c.pageCACert, "page-ca-cert", "", "the staged page authority's published certificate")
	fs.StringVar(&c.setupDir, "setup-dir", "", "the directory -take-factors writes the Owner Card's factors in")
	if err := fs.Parse(args); err != nil {
		return c, err
	}
	c.built = buildTime()
	if *pcrs == "" && !c.rotate {
		*pcrs = defaultPCRs
	}
	if *pcrs != "" {
		var err error
		if c.pcrs, err = parsePCRs(*pcrs); err != nil {
			return c, err
		}
	}
	modes := 0
	for _, m := range []bool{c.rotate, c.delete, c.rotateRecovery, c.stagePageCA, c.takeFactors} {
		if m {
			modes++
		}
	}
	switch {
	case fs.NArg() != 0:
		return c, fmt.Errorf("unexpected arguments: %q", fs.Args())
	case modes > 1:
		return c, errors.New("-rotate, -rotate-recovery, -delete, -stage-page-ca and -take-factors are separate runs")
	case c.stagePageCA:
		if !filepath.IsAbs(c.pageCAFile) || !filepath.IsAbs(c.pageCACert) {
			return c, errors.New("-stage-page-ca needs absolute -page-ca-file and -page-ca-cert")
		}
		return c, nil
	case !filepath.IsAbs(c.state):
		return c, errors.New("an absolute -state is required")
	case c.takeFactors && (!filepath.IsAbs(c.setupDir) || !filepath.IsAbs(c.pageCACert)):
		return c, errors.New("-take-factors needs absolute -setup-dir and -page-ca-cert")
	case c.rotate || c.delete || c.rotateRecovery || c.takeFactors:
	case !filepath.IsAbs(c.anchorDir) || !filepath.IsAbs(c.log):
		return c, errors.New("absolute -anchor-dir and -log are required")
	case c.kernelUID <= 0 || c.kernelGID <= 0:
		return c, errors.New("-kernel-uid and -kernel-gid are required, and never root")
	case c.passphrase == "" || c.recovery == "":
		return c, errors.New("-passphrase-file and -recovery-file are required: a store never has only its tpm slot")
	case c.firstEdge != "" && !filepath.IsAbs(c.firstEdge):
		return c, errors.New("-first-edge must be absolute")
	case (c.pageCAFile == "") != (c.pageCACert == ""),
		c.pageCAFile != "" && (!filepath.IsAbs(c.pageCAFile) || !filepath.IsAbs(c.pageCACert)):
		return c, errors.New("-page-ca-file and -page-ca-cert go together, both absolute")
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
	// The staged authority binds before anything changes: a refusal leaves
	// the TPM and the state as they were.
	var pca []byte
	if c.pageCAFile != "" {
		var err error
		if pca, err = readStaged(c.pageCAFile, c.pageCACert); err != nil {
			return err
		}
		defer clear(pca)
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
			return c.commitAndDrop()
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
	if err := putRecipient(st, rec); err != nil {
		return err
	}
	if err := putPageCA(st, c.built, pca); err != nil {
		return err
	}
	if err := putLinkKeys(c, st); err != nil {
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
	return c.commitAndDrop()
}

// commitAndDrop puts the store in place, then removes the link port's
// capture file, whose key the store now holds (or, at a restore, never
// will). A crash between the two leaves the file, which no later
// enrollment of this store reads: one never reruns over a store.
func (c config) commitAndDrop() error {
	if err := commit(c); err != nil {
		return err
	}
	if c.firstEdge == "" {
		return nil
	}
	if err := os.Remove(c.firstEdge); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("agentos-enroll: remove the first edge's capture: %w", err)
	}
	return nil
}

// putLinkKeys makes the core's link key and stores it, and stores the
// first edge key from the link port's capture, unless this is a restore's
// enrollment or there is no capture (HW-15, brief EDGE-link-core decisions
// 3 and 4). A capture that does not read stores no first key and
// enrollment goes on: the owner adds the edge in the page step.
func putLinkKeys(c config, st *seal.Store) error {
	seed := make([]byte, ed25519.SeedSize)
	defer clear(seed)
	if _, err := rand.Read(seed); err != nil {
		return err
	}
	if err := st.Put(handoff.LinkKeyEntry, seed); err != nil {
		return err
	}
	if c.firstEdge == "" || c.restore {
		return nil
	}
	edge, err := readCapture(c.firstEdge, os.Geteuid())
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "agentos-enroll: I take no first edge key: %v\n", err)
		return nil
	}
	return st.Put(handoff.FirstEdgeEntry, edge)
}

// captureLen is the capture file: the edge's Ed25519 public key, the
// hello's 32-byte nonce (the connection's exporter value), and the key's
// signature over kernel.HelloMsg(nonce), as agentos-link's pre-store mode
// writes the first valid hello (decision 3).
const captureLen = ed25519.PublicKeySize + 32 + ed25519.SignatureSize

var errCapture = errors.New("the first edge's capture is not one valid hello in a file only I can write")

// readCapture reads the capture file at path and returns its key, once its
// hello verifies and the key is not of small order (kernel.SmallOrder:
// anyone can sign for one). The file must be a regular file of owner's
// (root: this process's euid) that no one else can write, and exactly
// captureLen bytes.
func readCapture(path string, owner int) (ed25519.PublicKey, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if err != nil {
		return nil, errCapture
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, errCapture
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || !fi.Mode().IsRegular() || int(st.Uid) != owner || fi.Mode().Perm()&0o022 != 0 {
		return nil, errCapture
	}
	b, err := io.ReadAll(io.LimitReader(f, captureLen+1))
	if err != nil || len(b) != captureLen {
		return nil, errCapture
	}
	edge := ed25519.PublicKey(b[:ed25519.PublicKeySize])
	nonce, sig := b[ed25519.PublicKeySize:ed25519.PublicKeySize+32], b[ed25519.PublicKeySize+32:]
	if kernel.SmallOrder(edge) || !ed25519.Verify(edge, kernel.HelloMsg(nonce), sig) {
		return nil, errCapture
	}
	return edge, nil
}

// putRecipient keeps the backup recipient the recovery key derives in the
// store, for the unlock step to hand the kernel (BAK-1). Only its public
// half: the recovery key itself stays in the recovery slot's wrap.
func putRecipient(st *seal.Store, rk []byte) error {
	r, err := backup.RecipientFor(rk)
	if err != nil {
		return err
	}
	v, err := handoff.EncodeRecipient(r.X, r.EK)
	if err != nil {
		return err
	}
	return st.Put(handoff.RecipientEntry, v)
}

// putPageCA keeps the page authority in the store, for the unlock step to
// hand the kernel (CH-9, MIG-4-recovery-f1). At first boot it is staged,
// the authority whose fingerprint the Owner Card printed (brief
// OWN-card-flow decision 7): enrollment stores those bytes as read, after
// readStaged's checks, so a rerun after a crash stores the same authority.
// With none staged (a restore's enrollment, whose authority the backup
// brings), it makes one, and the store is the only place it is written.
func putPageCA(st *seal.Store, built time.Time, staged []byte) error {
	if staged != nil {
		return st.Put(handoff.PageCAEntry, staged)
	}
	a, err := pageca.New(pageca.DefaultName, built, nil)
	if err != nil {
		return err
	}
	v, err := pageca.Marshal(a)
	if err != nil {
		return err
	}
	defer clear(v)
	return st.Put(handoff.PageCAEntry, v)
}

// buildTime is this binary's build time: its commit's time, which go build
// stamps from the image build's checkout (image/build.sh takes
// SOURCE_DATE_EPOCH from the same commit), or else the binary's own
// modification time. Zero when neither reads, and enrollment then refuses
// (pageca.New), changing nothing the rerun cannot redo.
func buildTime() time.Time {
	if bi, ok := debug.ReadBuildInfo(); ok {
		for _, s := range bi.Settings {
			if s.Key == "vcs.time" {
				if t, err := time.Parse(time.RFC3339, s.Value); err == nil {
					return t
				}
			}
		}
	}
	if p, err := os.Executable(); err == nil {
		if fi, err := os.Stat(p); err == nil {
			return fi.ModTime()
		}
	}
	return time.Time{}
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

func readSecret(path string) ([]byte, error) { return readSecretMax(path, 4<<10) }

// readSecretMax reads path as readSecret does, and refuses a file over max
// bytes rather than reading part of it.
func readSecretMax(path string, max int) ([]byte, error) {
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
	b, err := io.ReadAll(io.LimitReader(f, int64(max)+1))
	if err != nil {
		return nil, err
	}
	if len(b) > max {
		clear(b)
		return nil, fmt.Errorf("agentos-enroll: %s is over %d bytes", path, max)
	}
	return b, nil
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
	// The runs that rewrite a running box's store (-rotate,
	// -rotate-recovery) take its lock, so neither writes back what the
	// other just replaced.
	unlock, err := lockStore(c, true)
	if err != nil {
		return err
	}
	defer unlock()
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

// maxRotateRequest bounds -rotate-recovery's request (brief decision 7).
const maxRotateRequest = 8 << 10

// rotateWords are -rotate-recovery's refusals, each a fixed word that the
// owner side reads; any other error answers "store". Each changed nothing.
var rotateWords = []struct {
	err  error
	word string
}{
	{errRequest, "request"},
	{errFactor, "factor"},
	{errApproval, "approval"},
	{errStale, "stale"},
	{errBusy, "busy"},
}

// rotateWord is the answer for rotateRecovery's err.
func rotateWord(err error) string {
	if err == nil {
		return "ok"
	}
	for _, w := range rotateWords {
		if errors.Is(err, w.err) {
			return w.word
		}
	}
	return "store"
}

var (
	errRequest   = errors.New("agentos-enroll: the request does not read")
	errFactor    = errors.New("agentos-enroll: the factor does not open my store")
	errApproval  = errors.New("agentos-enroll: the approval is not my kernel's for this key on the card route, or has expired")
	errStale     = errors.New("agentos-enroll: the approval is for a recipient my store no longer holds")
	errBusy      = errors.New("agentos-enroll: another rotation is running")
	errStoreOpen = errors.New("agentos-enroll: my store does not take the new key")
)

// rotateRequest is -rotate-recovery's request, read to the end of stdin:
// the owner side ends its write half once it has sent it. Secret is the factor's
// bytes: the store passphrase, or the current recovery key's 32 bytes. Next
// is the new recovery key, hex; Approval is the kernel's (handoff.Approval).
type rotateRequest struct {
	Factor   string `json:"factor"` // "passphrase" or "recovery"
	Secret   []byte `json:"secret"`
	Next     hexKey `json:"next"`
	Approval []byte `json:"approval"`
}

// hexKey decodes a hex string into bytes the caller can wipe: json hands
// UnmarshalJSON a slice of the request, which rotateRecoveryMain wipes too,
// and no string copy is made.
type hexKey []byte

func (k *hexKey) UnmarshalJSON(b []byte) error {
	if len(b) < 2 || b[0] != '"' || b[len(b)-1] != '"' {
		return errRequest
	}
	b = b[1 : len(b)-1]
	*k = make([]byte, hex.DecodedLen(len(b)))
	if _, err := hex.Decode(*k, b); err != nil {
		return errRequest
	}
	return nil
}

func (r *rotateRequest) wipe() {
	clear(r.Secret)
	clear(r.Next)
}

// rotateRecoveryMain runs -rotate-recovery on in and out and returns the
// exit status. The word goes to out; the reason, which never holds a
// secret, to stderr (the unit's journal).
func rotateRecoveryMain(c config, in io.Reader, out io.Writer) int {
	err := rotateRecovery(c, in)
	fmt.Fprintln(out, rotateWord(err))
	if err != nil {
		log.Print(err)
		return 1
	}
	return 0
}

// rotateRecovery replaces the store's recovery slot with the request's new
// key and its backup recipient with that key's, in one write, under the
// kernel's approval (brief MIG-4-recovery-r, r2). It opens the store with
// the request's factor only: on a running box nothing else opens it. Every
// refusal is a rotateWords error and changes nothing.
func rotateRecovery(c config, in io.Reader) error {
	raw, err := io.ReadAll(io.LimitReader(in, maxRotateRequest+1))
	defer clear(raw)
	if err != nil || len(raw) > maxRotateRequest {
		return errRequest
	}
	var r rotateRequest
	defer r.wipe()
	if json.Unmarshal(raw, &r) != nil || len(r.Next) != seal.RecoveryLen || len(r.Approval) > handoff.MaxApproval {
		return errRequest
	}
	var f seal.Factor
	switch r.Factor {
	case "passphrase":
		f = seal.Passphrase{Phrase: r.Secret}
	case "recovery":
		if len(r.Secret) != seal.RecoveryLen {
			return errFactor
		}
		f = seal.Recovery{Key: r.Secret}
	default:
		return errRequest
	}
	unlock, err := lockStore(c, false)
	if err != nil {
		return err
	}
	defer unlock()
	st, err := seal.Unlock(c.storePath(), f)
	// A retry after the owner side lost an earlier ok (MIG-4-recovery-r4c):
	// that run made next the recovery key, so the old card's key opens
	// nothing now. If next opens the store, the request can only be
	// answered as already done; anything else is still the factor's
	// refusal.
	applied := false
	if errors.Is(err, seal.ErrWrongFactor) || errors.Is(err, seal.ErrNoSlot) {
		if st, err = seal.Unlock(c.storePath(), seal.Recovery{Key: r.Next}); err != nil {
			return errFactor
		}
		applied = true
	} else if err != nil {
		return fmt.Errorf("%w: %w", errStoreOpen, err)
	}
	defer st.Close()
	head, err := st.HeadKey()
	if err != nil {
		return fmt.Errorf("%w: %w", errStoreOpen, err)
	}
	pub := head.Public().(ed25519.PublicKey)
	clear(head)
	now := time.Now
	if c.now != nil {
		now = c.now
	}
	a, err := handoff.VerifyApproval(pub, r.Approval, now().UnixMilli())
	if err != nil || a.Route != handoff.RouteCard {
		return errApproval
	}
	old, err := storeRecipientID(st)
	if err != nil {
		return fmt.Errorf("%w: %w", errStoreOpen, err)
	}
	next, err := backup.RecipientFor(r.Next)
	if err != nil {
		return fmt.Errorf("%w: %w", errStoreOpen, err)
	}
	// The store already holds the approved key's recipient, which every
	// writer puts with that key's recovery slot: the rotation is done,
	// so the answer is ok and nothing is written. The owner side then asks
	// the kernel to switch, as after the first ok (BAK-1).
	if old == a.Next && next.ID() == a.Next {
		log.Print("agentos-enroll: the store already holds the approved key and recipient; nothing to write")
		return nil
	}
	if applied {
		return errFactor
	}
	if a.Old != old {
		return errStale
	}
	if next.ID() != a.Next {
		return errApproval
	}
	v, err := handoff.EncodeRecipient(next.X, next.EK)
	if err != nil {
		return fmt.Errorf("%w: %w", errStoreOpen, err)
	}
	var slot []string
	for _, sl := range st.Slots() {
		if sl.Kind == seal.KindRecovery {
			slot = append(slot, sl.ID)
		}
	}
	if len(slot) != 1 {
		return fmt.Errorf("%w: it holds %d recovery slots, not one", errStoreOpen, len(slot))
	}
	// A directory sync that fails after the rename still leaves the new
	// slot and recipient in place (seal.Store.commit): the store opens only
	// with the new key, so the answer is ok, and the reason goes to the
	// journal.
	id, err := st.ReplaceAndPut(slot[0], seal.Recovery{Key: r.Next}, handoff.RecipientEntry, v)
	if id == "" {
		return fmt.Errorf("%w: %w", errStoreOpen, err)
	}
	if err != nil {
		log.Printf("agentos-enroll: the new key is in place; the store's directory sync failed: %v", err)
	}
	return nil
}

// storeRecipientID is the ID of the backup recipient st holds, or "" for a
// store enrolled before MIG-4-recovery-e1, which holds none.
func storeRecipientID(st *seal.Store) (string, error) {
	v, ok, err := st.Get(handoff.RecipientEntry)
	if err != nil || !ok {
		return "", err
	}
	w, err := handoff.ParseRecipient(v)
	if err != nil {
		return "", err
	}
	x, ek, err := handoff.SplitRecipient(w)
	if err != nil {
		return "", err
	}
	return backup.Recipient{X: x, EK: ek}.ID(), nil
}

// lockStore takes the store's write lock, a lock on the -state directory
// itself, so it leaves nothing on disk: it waits for it, or, unless wait,
// answers errBusy while another run holds it.
func lockStore(c config, wait bool) (func(), error) {
	fd, err := unix.Open(c.state, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errStoreOpen, &os.PathError{Op: "open", Path: c.state, Err: err})
	}
	how := unix.LOCK_EX
	if !wait {
		how |= unix.LOCK_NB
	}
	if err := unix.Flock(fd, how); err != nil {
		unix.Close(fd)
		if errors.Is(err, unix.EWOULDBLOCK) {
			return nil, errBusy
		}
		return nil, fmt.Errorf("%w: %w", errStoreOpen, err)
	}
	return func() { unix.Close(fd) }, nil
}
