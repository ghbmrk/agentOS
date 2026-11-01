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
// it before the exec, and the kernel gets only the log key, the head key,
// the clerk root key, the log anchor's counter and the owner's anchors on
// descriptor 3, and one connection to the TPM on descriptor 4 for that
// counter (LOG-2, STO-1), since the kernel's uid can open no TPM itself. Before that hand-off it caps
// the slot's boot path (#2977), so that connection unseals nothing for the
// rest of the boot. The box's policy key and the store's anchor come
// from the store's pins index on this PC's TPM, which enrollment wrote
// (STO-2a-k, STO-2c), never from the drive.
//
// With -clerk-anchors and -log, it also writes the owner's hardware keys for
// the clerks (clerkAnchors; D-146, #2995); with -recovery-request, it carries
// out the owner's lost-card request (lostCard; REC-4, route B of D-201); with
// -checker-seed, it writes the checker's sealed code seed (writeCheckerSeed;
// CH-4, MIG-4-exit-c2). Each function's comment says how.
//
//go:debug containermaxprocs=0
package main

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/linuxtpm"
	"github.com/google/go-tpm/tpm2/transport/linuxudstpm"
	"golang.org/x/sys/unix"

	"github.com/ghbmrk/agentos/broker/backup"
	"github.com/ghbmrk/agentos/broker/card/words"
	"github.com/ghbmrk/agentos/broker/clerk/clerkkey"
	"github.com/ghbmrk/agentos/broker/clerk/handoff"
	"github.com/ghbmrk/agentos/broker/clerk/seal"
	"github.com/ghbmrk/agentos/broker/kernel"
	"github.com/ghbmrk/agentos/broker/kernel/key"
	"github.com/ghbmrk/agentos/broker/kernel/privfile"
	"github.com/ghbmrk/agentos/broker/tpmseal"
)

func main() {
	log.SetFlags(0)
	c, err := parse(os.Args[1:], os.Stderr)
	if err == nil {
		if err = reserve(); err == nil {
			err = unlockAndExec(c, storePins(c.store))
		}
	}
	log.Fatal(err)
}

// pinSource gives the box's policy key and the store's anchor, read from
// somewhere the drive's writer cannot change (STO-2a-k). It fails closed:
// an error unlocks nothing.
type pinSource func(transport.TPM) (policyKey *ecdsa.PublicKey, anchor []byte, err error)

// storePins is the production source: the pins index on this TPM for the
// store at path (seal.Pinned). No pins there unlocks nothing.
func storePins(path string) pinSource {
	return func(t transport.TPM) (*ecdsa.PublicKey, []byte, error) {
		f, err := seal.Pinned(t, path)
		if err != nil {
			return nil, nil, fmt.Errorf("agentos-unlock: my policy key and store anchor on this PC's TPM: %w", err)
		}
		return f.PolicyKey, f.Anchor, nil
	}
}

type config struct {
	store, tpm, exec string
	uid, gid         int
	// clerkAnchors is the clerks' anchors file and log the kernel's log
	// file, from whose first entry the step pins the anchors (#2995); ""
	// for both writes no file.
	clerkAnchors, log string
	// checkerSeed is the checker's sealed seed file (MIG-4-exit-c2), an
	// absolute path; "" writes none.
	checkerSeed string
	// request is the owner's lost-card request file (D-201 route B), an
	// absolute path; "" reads none.
	request string
	args    []string // the kernel main's, after --
	// dropTo replaces drop in tests that run as a plain user, who cannot
	// shed supplementary groups; the command line never sets it.
	dropTo func(uid, gid int) error
	// passphrase, when set, opens the store by its passphrase slot instead
	// of this PC's tpm slot, and the hand-off names that slot, so the
	// kernel cuts the edge (§12.2, HW-15 "move"). Only tests set it: no
	// flag takes it until the unknown-host unlock is built (ASSUMPTIONS
	// EDGE-link-core-b-3).
	passphrase []byte
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
	fs.StringVar(&c.clerkAnchors, "clerk-anchors", "", "the clerks' anchors file, an absolute path; none without it")
	fs.StringVar(&c.log, "log", "", "the kernel's log file, an absolute path, with -clerk-anchors")
	fs.StringVar(&c.checkerSeed, "checker-seed", "", "the checker's sealed code seed file, an absolute path; none without it")
	fs.StringVar(&c.request, "recovery-request", "", "the owner's lost-card request file, an absolute path; none without it")
	if err := fs.Parse(args); err != nil {
		return c, err
	}
	c.args = fs.Args()
	switch {
	case c.store == "" || !filepath.IsAbs(c.exec):
		return c, errors.New("-store and an absolute -exec are required")
	case c.uid <= 0 || c.gid <= 0:
		return c, errors.New("-uid and -gid are required, and never root")
	case (c.clerkAnchors == "") != (c.log == ""):
		return c, errors.New("-clerk-anchors and -log come together")
	case c.clerkAnchors != "" && (!filepath.IsAbs(c.clerkAnchors) || !filepath.IsAbs(c.log)):
		return c, errors.New("-clerk-anchors and -log are absolute paths")
	case c.checkerSeed != "" && !filepath.IsAbs(c.checkerSeed):
		return c, errors.New("-checker-seed is an absolute path")
	case c.request != "" && !filepath.IsAbs(c.request):
		return c, errors.New("-recovery-request is an absolute path")
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
	tpm, err := kernelTPM(c.tpm)
	if err != nil {
		return fmt.Errorf("agentos-unlock: the kernel's TPM connection: %w", err)
	}
	defer tpm.Close()
	return handOff(b, tpm, c)
}

// unlock opens the store through this PC's tpm slot and returns the
// kernel's hand-off, which names the slot that opened it. The store is
// closed, its key wiped, before it returns.
func unlock(c config, pins pinSource) ([]byte, error) {
	t, err := openTPM(c.tpm)
	if err != nil {
		return nil, err
	}
	defer t.Close()
	var k handoff.KernelKeys
	defer k.Wipe()
	var f seal.Factor = seal.Passphrase{Phrase: c.passphrase}
	k.Slot = handoff.SlotPassphrase
	if c.passphrase == nil {
		pk, anchor, err := pins(t)
		if err != nil {
			return nil, err
		}
		f, k.Slot = seal.TPM{TPM: t, PolicyKey: pk, Anchor: anchor}, handoff.SlotTPM
	}
	// The lost-card route only on a boot that opened this PC's tpm slot:
	// one opened by a card factor has the card (route A).
	var request []byte
	if k.Slot == handoff.SlotTPM && c.request != "" {
		var release func()
		request, release = takeRequest(c)
		defer release()
	}
	st, err := seal.Unlock(c.store, f)
	if err != nil {
		return nil, fmt.Errorf("agentos-unlock: %w", err)
	}
	defer st.Close()
	// Lock after use (#2977, K6): with the store open, cap every boot path
	// of its tpm slots, so for the rest of this boot no connection to this
	// TPM, the kernel's on handoff.TPMFD included, unseals them again. A
	// cap that fails hands the kernel nothing.
	if err := tpmseal.Cap(t, tpmSelections(st)); err != nil {
		return nil, fmt.Errorf("agentos-unlock: lock my tpm slot for the rest of this boot: %w", err)
	}
	if k.Log, err = st.LogKey(); err != nil {
		return nil, err
	}
	if k.Head, err = st.HeadKey(); err != nil {
		return nil, err
	}
	if request != nil {
		k.NewRecovery, err = lostCard(st, request, k.Head.Public().(ed25519.PublicKey), time.Now().UnixMilli())
		if err != nil {
			fmt.Fprintf(os.Stderr, "agentos-unlock: I start on the card you hold: your lost-card request: %v\n", err)
		} else if err := os.Remove(c.request); err != nil {
			fmt.Fprintf(os.Stderr, "agentos-unlock: remove the lost-card request I carried out: %v\n", err)
		}
	}
	// A store with no anchors hands over none: the kernel starts setup-only
	// and takes the owner's hardware keys as its log's first entry (#2905
	// open point 2). An entry that is there must read.
	raw, ok, err := st.Get(handoff.AnchorsEntry)
	if err != nil {
		return nil, err
	}
	if ok {
		if k.Anchors, err = handoff.ParseAnchors(raw); err != nil {
			return nil, fmt.Errorf("agentos-unlock: your hardware keys in my store: %w", err)
		}
	}
	// The backup recipient (BAK-1). A store enrolled before
	// MIG-4-recovery-e1 has none and hands none: its kernel still starts,
	// and takes no backup until the owner rotates the recovery key. An
	// entry that is there must read.
	raw, ok, err = st.Get(handoff.RecipientEntry)
	if err != nil {
		return nil, err
	}
	if ok {
		if k.Recipient, err = handoff.ParseRecipient(raw); err != nil {
			return nil, fmt.Errorf("agentos-unlock: the backup recipient in my store: %w", err)
		}
	}
	// The page authority (CH-9). A store enrolled before
	// MIG-4-recovery-f1 has none and hands none: its kernel still starts,
	// and certifies no page key. An entry that is there must read.
	raw, ok, err = st.Get(handoff.PageCAEntry)
	if err != nil {
		return nil, err
	}
	if ok {
		k.PageCA, err = handoff.ParsePageCA(raw)
		clear(raw)
		if err != nil {
			return nil, fmt.Errorf("agentos-unlock: the page authority in my store: %w", err)
		}
	}
	if k.LinkKey, k.FirstEdge, err = linkKeys(st); err != nil {
		return nil, err
	}
	if k.ClerkRoot, err = st.ClerkRoot(); err != nil {
		return nil, err
	}
	if c.checkerSeed != "" {
		writeCheckerSeed(c.checkerSeed, st, &k.ClerkRoot)
	}
	if c.clerkAnchors != "" {
		ca, err := clerkAnchors(st, k, c.log)
		if err != nil {
			return nil, err
		}
		writeClerkAnchors(c.clerkAnchors, ca)
	}
	if k.Counter, err = counter(st); err != nil {
		return nil, err
	}
	// seal.Unlock opened the tpm slot, which is sealed under this SRK's
	// name, so this name is the PC's, not the drive's.
	if k.Counter.SRK, err = tpmseal.Identity(t); err != nil {
		return nil, err
	}
	return k.Marshal()
}

// maxRequest bounds the lost-card request file, which holds one
// handoff.Approval (handoff.MaxApproval bytes).
const maxRequest = 4 << 10

// The reasons a lost-card request is not carried out, for stderr. None
// changes the store.
var (
	errNotLost = errors.New("the kernel approved it for the card route, not the lost-card route")
	errStale   = errors.New("it is for another backup recipient than my store's; ask again")
)

// takeRequest reads the lost-card request at c.request and, if there is
// one, takes the store's write lock, the lock agentos-enroll takes on the
// store's directory (ASSUMPTIONS MIG-4-recovery-r2-2), so no other writer
// changes the store between this step's open and its write. The caller
// releases it after closing the store. No request, or one that does not
// read, is nil, said on stderr unless the file is not there.
func takeRequest(c config) ([]byte, func()) {
	b, err := readRequest(c.request)
	if errors.Is(err, os.ErrNotExist) {
		return nil, func() {}
	}
	if err == nil {
		var release func()
		if release, err = lockStore(filepath.Dir(c.store)); err == nil {
			return b, release
		}
	}
	fmt.Fprintf(os.Stderr, "agentos-unlock: I start on the card you hold: your lost-card request: %v\n", err)
	return nil, func() {}
}

// readRequest reads path: a regular file, never through a link, nor a FIFO
// put there to hold this root step, of at most maxRequest bytes. Its
// integrity is the head key's signature, which lostCard checks.
func readRequest(path string) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a file", path)
	}
	b, err := io.ReadAll(io.LimitReader(f, maxRequest+1))
	if err == nil && len(b) > maxRequest {
		err = fmt.Errorf("%s is over %d bytes", path, maxRequest)
	}
	return b, err
}

// lockStore takes an exclusive flock on dir, waiting for it, and returns
// its release.
func lockStore(dir string) (func(), error) {
	fd, err := syscall.Open(dir, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: dir, Err: err}
	}
	if err := syscall.Flock(fd, syscall.LOCK_EX); err != nil {
		syscall.Close(fd)
		return nil, &os.PathError{Op: "lock", Path: dir, Err: err}
	}
	return func() { syscall.Close(fd) }, nil
}

// lostCard carries out request, a lost-card approval (handoff.Approval,
// route B) the kernel signed with head, the store's head key, for the
// backup recipient st holds now ("" for none): it makes a new card, puts
// its recovery key in st's one recovery slot, its passphrase in st's one
// passphrase slot (MIG-4-recovery-r4d) and its recipient in RecipientEntry,
// in one write (seal.Store.ReplaceAndPut), and returns the new card
// (handoff.MadeCardLen): the bits that key derives from, then the seed the
// passphrase derives from. So the lost card's passphrase stops opening the
// store with its recovery key, and the two stay independent: a recovery
// key replaced later (route A) derives nothing still in the store.
// Any error changes nothing. Once the recipient has changed the request no
// longer matches, so it is carried out at most once.
func lostCard(st *seal.Store, request []byte, head ed25519.PublicKey, now int64) ([]byte, error) {
	a, err := handoff.VerifyApproval(head, request, now)
	if err != nil {
		return nil, err
	}
	if a.Route != handoff.RouteLost {
		return nil, errNotLost
	}
	old, err := storeRecipientID(st)
	if err != nil {
		return nil, err
	}
	if a.Old != old {
		return nil, errStale
	}
	slot := map[seal.Kind][]string{}
	for _, sl := range st.Slots() {
		slot[sl.Kind] = append(slot[sl.Kind], sl.ID)
	}
	if len(slot[seal.KindRecovery]) != 1 || len(slot[seal.KindPassphrase]) != 1 {
		return nil, fmt.Errorf("my store holds %d recovery and %d passphrase slots, not one of each", len(slot[seal.KindRecovery]), len(slot[seal.KindPassphrase]))
	}
	// The new card's 160 bits, which the page prints, and its passphrase's
	// seed, drawn apart; the slots and the recipient take the key derived
	// from the bits, as from any card (#3406), and the passphrase from the
	// seed (words.FromSeed).
	bits := make([]byte, handoff.MadeCardLen)
	rand.Read(bits)
	rec, err := handoff.StoreRecoveryKey(bits[:handoff.CardKeyLen])
	defer clear(rec)
	var pass []byte
	if err == nil {
		pass, err = words.FromSeed(bits[handoff.CardKeyLen:])
	}
	defer clear(pass)
	var next backup.Recipient
	if err == nil {
		next, err = backup.RecipientFor(rec)
	}
	var v []byte
	if err == nil {
		v, err = handoff.EncodeRecipient(next.X, next.EK)
	}
	if err != nil {
		clear(bits)
		return nil, err
	}
	// A directory sync that fails after the rename still leaves the new
	// slots and recipient in place (seal.Store.commit): only the new card
	// opens the store, so it is handed on.
	id, err := st.ReplaceAndPut(handoff.RecipientEntry, v,
		seal.Swap{ID: slot[seal.KindRecovery][0], F: seal.Recovery{Key: rec}},
		seal.Swap{ID: slot[seal.KindPassphrase][0], F: seal.Passphrase{Phrase: pass}})
	if id == nil {
		clear(bits)
		return nil, err
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "agentos-unlock: the new card is in place; my store's directory sync failed: %v\n", err)
	}
	return bits, nil
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
		return "", fmt.Errorf("the backup recipient in my store: %w", err)
	}
	x, ek, err := handoff.SplitRecipient(w)
	if err != nil {
		return "", fmt.Errorf("the backup recipient in my store: %w", err)
	}
	return backup.Recipient{X: x, EK: ek}.ID(), nil
}

// linkKeys reads the core's link key and the first edge key from the store
// (HW-15). A store enrolled before EDGE-link-core-b holds neither, and a
// restore's holds no first key: each missing entry hands none, and the
// kernel still starts. An entry that is there must read.
func linkKeys(st *seal.Store) (ed25519.PrivateKey, ed25519.PublicKey, error) {
	var link ed25519.PrivateKey
	raw, ok, err := st.Get(handoff.LinkKeyEntry)
	if err != nil {
		return nil, nil, err
	}
	if ok {
		link, err = handoff.ParseLinkKey(raw)
		clear(raw)
		if err != nil {
			return nil, nil, fmt.Errorf("agentos-unlock: the link key in my store: %w", err)
		}
	}
	var edge ed25519.PublicKey
	if raw, ok, err = st.Get(handoff.FirstEdgeEntry); err != nil {
		clear(link)
		return nil, nil, err
	}
	if ok {
		if edge, err = handoff.ParseFirstEdge(raw); err != nil {
			clear(link)
			return nil, nil, fmt.Errorf("agentos-unlock: the first edge key in my store: %w", err)
		}
	}
	return link, edge, nil
}

// clerkAnchors is the owner's hardware keys for the clerks, from the store
// alone: the kernel's anchors if the store holds them, else its
// clerks/anchors entry. A store with neither, on a box whose setup put the
// keys in the kernel's log, gets that entry now from the log's first entry,
// read under the log key and checked against this box's head key, and keeps
// it: from then on a kernel taken over cannot change what the clerks check
// it by (D-146, #2995). None, with the reason on stderr, when the log holds
// no setup or the store cannot keep it: the clerks then refuse to start,
// and the kernel starts as ever. An entry that is there must read.
func clerkAnchors(st *seal.Store, k handoff.KernelKeys, logPath string) ([]key.PublicKey, error) {
	if len(k.Anchors) != 0 {
		return k.Anchors, nil
	}
	raw, ok, err := st.Get(handoff.ClerkAnchorsEntry)
	if err != nil {
		return nil, err
	}
	if ok {
		a, err := handoff.ParseAnchors(raw)
		if err != nil {
			return nil, fmt.Errorf("agentos-unlock: the clerks' copy of your hardware keys in my store: %w", err)
		}
		return a, nil
	}
	first, err := logStart(logPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "agentos-unlock: the clerks get no hardware keys: my log: %v\n", err)
		return nil, nil
	}
	a, ok, err := kernel.LoggedAnchors(first, k.Log, k.Head.Public().(ed25519.PublicKey))
	if err != nil || !ok {
		if err != nil {
			fmt.Fprintf(os.Stderr, "agentos-unlock: the clerks get no hardware keys: my log's first entry: %v\n", err)
		}
		return nil, nil
	}
	b, err := handoff.EncodeAnchors(a)
	if err == nil {
		err = st.Put(handoff.ClerkAnchorsEntry, b)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "agentos-unlock: the clerks get no hardware keys: keep them in my store: %v\n", err)
		return nil, nil
	}
	return a, nil
}

// logStart reads the start of the kernel's log, as far as its first frame
// can reach: a regular file, never through a link, nor a FIFO the kernel's
// uid put there to hold this root step. None yet is an empty start.
func logStart(path string) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a file", path)
	}
	b := make([]byte, 4+kernel.MaxSetupFrame)
	n, err := io.ReadFull(f, b)
	if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
		return nil, err
	}
	return b[:n], nil
}

// writeClerkAnchors makes path hold anchors in handoff.EncodeAnchors' form,
// world-readable and written only by this step's uid (root on the box), in a
// directory of that uid's that no one else can write: the form and owner
// the clerk mains require (MAIL-main-a-3). No anchors removes it, so a
// clerk never starts on an earlier boot's. A failure is said, the file is
// removed, and the kernel still starts: only the clerks go without.
func writeClerkAnchors(path string, anchors []key.PublicKey) {
	if err := putClerkAnchors(path, anchors); err != nil {
		fmt.Fprintf(os.Stderr, "agentos-unlock: the clerks' hardware keys: %v\n", err)
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			fmt.Fprintf(os.Stderr, "agentos-unlock: remove %s: %v\n", path, err)
		}
	}
}

func putClerkAnchors(path string, anchors []key.PublicKey) error {
	dir := filepath.Dir(path)
	if err := os.Mkdir(dir, 0o755); err != nil && !errors.Is(err, os.ErrExist) {
		return err
	}
	fi, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || !fi.IsDir() || fi.Mode().Perm()&0o022 != 0 || int(st.Uid) != os.Geteuid() {
		return fmt.Errorf("%s is not a directory of mine alone", dir)
	}
	if len(anchors) == 0 {
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		return nil
	}
	b, err := handoff.EncodeAnchors(anchors)
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, ".anchors-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	_, err = f.Write(b)
	if err == nil {
		err = f.Chmod(0o644)
	}
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	return os.Rename(f.Name(), path) // durable:exempt lifecycle:exempt durable is old core (tools/old_core.txt), so the trusted unlock step cannot link it; the anchors are public, rewritten each boot, and pinned in the store
}

// writeCheckerSeed makes path hold the store's code seed sealed under the
// checker's clerk key (handoff.SealCodeSeed, MIG-4-exit-c2): a file only
// this step's uid (root on the box) reads, in a directory of that uid's
// alone, for the checker's unit to load at each start. The kernel hands the
// checker the key, so neither the kernel, which cannot read the file, nor
// a reader of the file holds the seed. A store with no seed removes it, so
// a checker never starts on an earlier boot's. A failure is said, the file
// is removed, and the kernel still starts: only the codes go without.
func writeCheckerSeed(path string, st *seal.Store, root *[32]byte) {
	if err := putCheckerSeed(path, st, root); err != nil {
		fmt.Fprintf(os.Stderr, "agentos-unlock: the checker's code seed: %v\n", err)
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			fmt.Fprintf(os.Stderr, "agentos-unlock: remove %s: %v\n", path, err)
		}
	}
}

func putCheckerSeed(path string, st *seal.Store, root *[32]byte) error {
	dir := filepath.Dir(path)
	if err := os.Mkdir(dir, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
		return err
	}
	fi, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	ds, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || !fi.IsDir() || fi.Mode().Perm()&0o077 != 0 || int(ds.Uid) != os.Geteuid() {
		return fmt.Errorf("%s is not a directory of mine alone", dir)
	}
	raw, ok, err := st.Get(handoff.CheckerSeedEntry)
	if err != nil {
		return err
	}
	if !ok {
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		return nil
	}
	s, err := handoff.ParseCodeSeed(raw)
	clear(raw)
	if err != nil {
		return fmt.Errorf("in my store: %w", err)
	}
	defer s.Wipe()
	k, err := clerkkey.Derive(root, handoff.CheckerName)
	if err != nil {
		return err
	}
	sealer, err := k.Sealer()
	k.Wipe()
	if err != nil {
		return err
	}
	defer clear(sealer)
	blob, err := handoff.SealCodeSeed(sealer, s)
	if err != nil {
		return err
	}
	return privfile.WriteAtomic(dir, filepath.Base(path), blob, nil)
}

// tpmSelections is every PCR selection of the store's tpm slots' boot
// paths: a rotation cut short leaves two slots, and either would unseal.
func tpmSelections(st *seal.Store) [][]uint {
	var out [][]uint
	for _, sl := range st.Slots() {
		if sl.Kind != seal.KindTPM {
			continue
		}
		for _, p := range sl.Policies {
			out = append(out, p.PCRs)
		}
	}
	return out
}

// counterRec is handoff.CounterEntry's value, as enrollment writes it.
type counterRec struct {
	Ref  json.RawMessage `json:"ref"`
	Auth []byte          `json:"auth"`
}

// counter reads the log anchor's counter from the store. A store without
// one was never enrolled whole: the kernel would have no anchor.
func counter(st *seal.Store) (handoff.Counter, error) {
	raw, ok, err := st.Get(handoff.CounterEntry)
	if err != nil {
		return handoff.Counter{}, err
	}
	if !ok {
		return handoff.Counter{}, errors.New("agentos-unlock: my store holds no counter for my log; set me up again")
	}
	defer clear(raw)
	var r counterRec
	if err := json.Unmarshal(raw, &r); err != nil {
		return handoff.Counter{}, fmt.Errorf("agentos-unlock: my log's counter in my store: %w", err)
	}
	ref, err := tpmseal.ParseCounterRef(r.Ref)
	if err != nil || len(r.Auth) == 0 {
		clear(r.Auth)
		return handoff.Counter{}, fmt.Errorf("agentos-unlock: my log's counter in my store does not read")
	}
	return handoff.Counter{Handle: ref.Handle, Name: ref.Name, Auth: r.Auth}, nil
}

// kernelTPM opens the kernel's own connection to the TPM at path: the
// resource manager's device, or one stream to a software TPM's socket.
func kernelTPM(path string) (*os.File, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if fi.Mode()&os.ModeSocket == 0 {
		if fi.Mode()&os.ModeCharDevice == 0 {
			return nil, fmt.Errorf("%s is no TPM", path)
		}
		return os.OpenFile(path, os.O_RDWR, 0)
	}
	conn, err := net.Dial("unix", path)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	return conn.(*net.UnixConn).File()
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
// kernel main with the pipe's read end as handoff.KeyFD and tpm as
// handoff.TPMFD. b is far below a pipe's buffer, so the write completes with
// no reader yet.
func handOff(b []byte, tpm *os.File, c config) error {
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
	dropTo := drop
	if c.dropTo != nil {
		dropTo = c.dropTo
	}
	if err := dropTo(c.uid, c.gid); err != nil {
		return err
	}
	if err := inherit(map[int]int{int(r.Fd()): handoff.KeyFD, int(tpm.Fd()): handoff.TPMFD}); err != nil {
		return err
	}
	return syscall.Exec(c.exec, append([]string{c.exec}, c.args...), kernelEnv)
}

// kernelEnv is the kernel process's whole environment. It reads no
// variable, so nothing of the unlock step's environment, a root unit's,
// reaches it (reviews/security/README.md, the row on a child inheriting
// the daemon's whole environment).
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
	if err := noCaps(); err != nil {
		return err
	}
	// Last, so a test that cannot shed its own groups (below) has had
	// every other check.
	for _, g := range gs {
		if g != gid {
			return fmt.Errorf("%w %d", errExtraGroup, g)
		}
	}
	return nil
}

// errExtraGroup: the step keeps a supplementary group. Only root can drop
// one, so a step not started as root with extra groups is refused: they
// would reach the kernel, a tss group with it the TPM.
var errExtraGroup = errors.New("agentos-unlock: still in group")

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

// reserve holds handoff.KeyFD and handoff.TPMFD from the start, so no runtime
// descriptor (the poller's; go:debug above shuts its cgroup file) is there for
// inherit to overwrite: a poll on it before the exec kills the step (#4474).
func reserve() error {
	var p [2]int
	if err := syscall.Pipe2(p[:], syscall.O_CLOEXEC); err != nil || p != [2]int{handoff.KeyFD, handoff.TPMFD} {
		return fmt.Errorf("agentos-unlock: descriptors %d and %d are not free at my start (got %v, %v)", handoff.KeyFD, handoff.TPMFD, p, err)
	}
	return nil
}

// inherit moves each descriptor onto the number it maps to, over reserve's
// placeholders, and makes every descriptor above them close-on-exec (Linux
// 5.11), so only those and 0 to 2 reach the exec, none a parent left open.
func inherit(fds map[int]int) error {
	for fd, want := range fds {
		if err := syscall.Dup3(fd, want, 0); err != nil {
			return err
		}
	}
	return unix.CloseRange(handoff.TPMFD+1, ^uint(0), unix.CLOSE_RANGE_CLOEXEC)
}
