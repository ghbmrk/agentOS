package proc

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"maps"
	"net"
	"os"
	"slices"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/ghbmrk/agentos/broker/clerk/handoff"
	"github.com/ghbmrk/agentos/broker/kernel"
	"github.com/ghbmrk/agentos/broker/pageca"
	"github.com/ghbmrk/agentos/broker/procguard"
)

// MainConfig is the kernel process's command line (cmd/agentos-kernel).
type MainConfig struct {
	Log       string // the log file
	OwnerSock string // OwnerSide's socket
	OwnerUID  int    // the owner side's uid, its only peer
	MeterSock string // MeterSide's socket
	MeterUID  int    // the model clerk's uid, its only peer
	// LinkSock is LinkSide's socket, "" for none (a box with no edge
	// link); LinkUID is agentos-link's uid, its only peer.
	LinkSock string
	LinkUID  int
	Clerks   map[string]Remote
	// Content are the content clerks, by the store each seals into: each
	// one's ContentSide socket and uid, its only peer.
	Content map[string]Remote
	// ClerkKeys are the clerks the kernel hands their keys to, at each
	// start of their units, by name (MAIL-keys): none without the flag.
	ClerkKeys  map[string]KeyClerk
	KeyDir     string // the subject-key table's directory (KernelConfig.KeyDir)
	ContentDir string // the content stores' directory (KernelConfig.ContentDir)
	BackupDir  string // the backups' records (KernelConfig.BackupDir)
	// Peers are the uids this process must not run as: every peer above
	// (procguard.Isolate). The main fills it from the uids it was given.
	Peers []int
	Tick  time.Duration // how often plans run; 0 is one second
	// Up is a file made once every socket listens, so the unit can tell a
	// kernel that came up and then failed, which a reboot may cure, from
	// one refused at its start, which every boot repeats (#2998). "" makes
	// none.
	Up string
}

// markUp makes path, empty. It never follows a link nor replaces what is
// there. A failure is said and the kernel runs on: the file only lets a
// later failure reboot the box (#2998), so its lack keeps nothing down.
func markUp(path string) {
	if path == "" {
		return
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600)
	if err == nil {
		err = f.Close()
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "run: mark that I am up, so a later failure of mine reboots me: %v\n", err)
	}
}

// ErrLogKey: the log on the drive does not open under the key the unlock
// step gave. It is never read as a fresh box (STO-2a-b): the kernel starts
// nothing until the owner says what to do.
var ErrLogKey = errors.New("run: the log does not open under my store's key; I start nothing until you choose what to do")

// ErrNoRecipient: the unlock step handed no backup recipient, so no backup
// can be sealed (BAK-1). The kernel runs on; the fix is a recovery-key
// rotation, which stores one (REC-4).
var ErrNoRecipient = errors.New("run: my store holds no backup recipient, so I take no backup until you rotate your recovery key")

// ErrNoAuthority: the unlock step handed no page authority, so the kernel
// certifies no page key and the page serves HTTP only (CH-9). On a box not
// yet set up the fix is a new enrollment; on a claimed one, ErrPageRestore.
var ErrNoAuthority = errors.New("run: my store holds no page authority, so I certify no page key")

// ErrPageRestore: a claimed box has no page authority. A new one is never
// made, since the Owner Card carries the old fingerprint: the box must be
// restored from a backup, which carries it (CH-9, BAK-1).
var ErrPageRestore = errors.New("run: I am claimed but hold no page authority; restore me from a backup")

// maxPageKey bounds a page key to certify: a P-256 key in PKIX DER is 91
// bytes.
const maxPageKey = 128

// Certified is the certify call's answer: the page's serving certificate
// and the authority's, both DER.
type Certified struct {
	Leaf      []byte `json:"leaf"`
	Authority []byte `json:"authority"`
}

// Certify signs the page's serving key (PKIX DER, ECDSA P-256 only) for the
// page name only (pageca.Authority.Issue) at now, Unix milliseconds. With
// no authority it answers ErrNoAuthority, or ErrPageRestore once setup has
// logged the owner's keys. The key the authority signs with never leaves
// the kernel process; the call takes the lock only to read the claim.
func (h *Kernel) Certify(now int64, pub []byte) (Certified, error) {
	if h.page == nil {
		claimed := false
		h.With(func(k *kernel.Kernel) error { claimed = len(k.State().Anchors) > 0; return nil })
		if claimed {
			return Certified{}, ErrPageRestore
		}
		return Certified{}, ErrNoAuthority
	}
	if len(pub) == 0 || len(pub) > maxPageKey {
		return Certified{}, pageca.ErrKey
	}
	leaf, err := h.page.Issue(pub, time.UnixMilli(now), nil)
	if err != nil {
		return Certified{}, err
	}
	return Certified{Leaf: leaf, Authority: h.page.Certificate()}, nil
}

// ErrNoLinkKey: the unlock step handed no link key (a store enrolled
// before it), so the kernel signs no edge handshake; a new enrollment makes
// one (EDGE-link-core decision 4).
var ErrNoLinkKey = errors.New("run: my store holds no link key, so I sign no edge handshake")

// ErrLinkSign refuses anything the link key is asked to sign but a TLS 1.3
// server CertificateVerify input.
var ErrLinkSign = errors.New("run: the link key signs a TLS 1.3 server CertificateVerify only")

// certificateVerify is what every TLS 1.3 server CertificateVerify input
// starts with (RFC 8446 section 4.4.3): 64 spaces, the server's context
// string and a zero byte. The transcript hash follows.
var certificateVerify = []byte(strings.Repeat(" ", 64) + "TLS 1.3, server CertificateVerify\x00")

// LinkKey is the public half of the core's link key, which agentos-link's
// TLS certificate names.
func (h *Kernel) LinkKey() (ed25519.PublicKey, error) {
	if len(h.link) != ed25519.PrivateKeySize {
		return nil, ErrNoLinkKey
	}
	return h.link.Public().(ed25519.PublicKey), nil
}

// LinkSign signs msg with the link key when it is a TLS 1.3 server
// CertificateVerify input over a SHA-256 or SHA-384 transcript hash, and
// refuses anything else, so a compromised link process can complete
// handshakes while it runs but can neither copy the key nor have it sign
// another message (EDGE-link-core decision 4).
func (h *Kernel) LinkSign(msg []byte) ([]byte, error) {
	if len(h.link) != ed25519.PrivateKeySize {
		return nil, ErrNoLinkKey
	}
	n := len(msg) - len(certificateVerify)
	if !bytes.HasPrefix(msg, certificateVerify) || n != 32 && n != 48 {
		return nil, ErrLinkSign
	}
	return ed25519.Sign(h.link, msg), nil
}

// Setup is the setup step (kernel.Setup) on this box: it logs the owner's
// first anchors and, right after them, the first edge key the store
// handed, if any (HW-15, brief EDGE-link-core decision 3).
func (h *Kernel) Setup(now int64, f kernel.FirstAnchors) error {
	return h.With(func(k *kernel.Kernel) error { return k.SetupWithEdge(now, f, h.firstEdge) })
}

// ErrNoKeyTable: the kernel process never starts with its content closed.
var ErrNoKeyTable = errors.New("run: a kernel needs its subject-key table's directory")

// ErrNoContentDir: nor with nowhere to keep sealed items.
var ErrNoContentDir = errors.New("run: a kernel needs its content stores' directory")

// RunKernel is the kernel process (STO-2b): hardened against its peers, it
// opens the log, the subject-key table and the content stores under keys,
// serves OwnerSide, MeterSide, LinkSide given its socket and each content
// clerk's ContentSide, hands each of ClerkKeys its key at each start of its
// unit, and runs plans every Tick until ctx ends. anchor is where
// signed heads go (LOG-2).
func RunKernel(ctx context.Context, cfg MainConfig, keys handoff.KernelKeys, anchor kernel.Anchor) error {
	if cfg.KeyDir == "" {
		return ErrNoKeyTable
	}
	if cfg.BackupDir == "" {
		return ErrNoBackupDir
	}
	if cfg.ContentDir == "" {
		return ErrNoContentDir
	}
	if len(cfg.ClerkKeys) > 0 && keys.ClerkRoot == ([32]byte{}) {
		return errors.New("run: I hand clerks their keys, but the unlock step handed me no clerk root key")
	}
	if os.Geteuid() == 0 {
		return errors.New("run: the kernel never runs as root")
	}
	if err := procguard.Isolate(cfg.Peers...); err != nil {
		return err
	}
	if anchor == nil || len(keys.Head) != ed25519.PrivateKeySize {
		return errors.New("run: a kernel needs an anchor and the unlock step's keys")
	}
	if err := checkLogKey(cfg.Log, keys.Log); err != nil {
		return err
	}
	// A store enrolled before the backup recipient holds none, and the
	// backup call refuses (MIG-4-recovery-e3).
	if len(keys.Recipient) == 0 {
		fmt.Fprintln(os.Stderr, ErrNoRecipient)
	}
	// One enrolled before the page authority holds none, and certify
	// refuses (MIG-4-recovery-f1).
	if len(keys.PageCA) == 0 {
		fmt.Fprintln(os.Stderr, ErrNoAuthority)
	}
	// A start not by this PC's tpm slot trusts no edge (§12.2, HW-15
	// "move"): not a first key setup would log, nor the live one, which it
	// cuts below.
	moved := keys.Slot != handoff.SlotTPM
	first := keys.FirstEdge
	if moved {
		first = nil
	}
	clock := func() int64 { return time.Now().UnixMilli() }
	h, err := OpenKernel(KernelConfig{
		Log: cfg.Log, Anchor: anchor, Key: keys.Log,
		Pub: keys.Head.Public().(ed25519.PublicKey), Sign: keys.Head,
		Anchors: keys.Anchors, Clerks: cfg.Clerks, KeyDir: cfg.KeyDir,
		ContentDir: cfg.ContentDir, Stores: slices.Sorted(maps.Keys(cfg.Content)),
		BackupDir: cfg.BackupDir, Recipient: keys.Recipient, PageCA: keys.PageCA,
		FirstEdge: first, LinkKey: keys.LinkKey, Clock: clock,
	}, clock())
	if err != nil {
		return err
	}
	defer h.Close()
	if moved {
		if err := h.With(func(k *kernel.Kernel) error { return k.EdgeCut(clock(), keys.Slot) }); err != nil {
			return fmt.Errorf("run: cut the edge at a start by my %s slot: %w", keys.Slot, err)
		}
	}
	// Counts only, on stderr: no owner call reports the subjects yet.
	if r := h.Content(); len(r.Missing)+len(r.Unnamed) > 0 {
		fmt.Fprintf(os.Stderr, "run: the subject-key table lacks %d open subjects' keys and holds %d keys no subject names\n", len(r.Missing), len(r.Unnamed))
	}
	type served struct {
		path string
		uid  int
		side Side
	}
	sides := []served{{cfg.OwnerSock, cfg.OwnerUID, OwnerSide}, {cfg.MeterSock, cfg.MeterUID, MeterSide}}
	if cfg.LinkSock != "" {
		sides = append(sides, served{cfg.LinkSock, cfg.LinkUID, LinkSide})
	}
	for _, store := range slices.Sorted(maps.Keys(cfg.Content)) {
		r := cfg.Content[store]
		sides = append(sides, served{r.Socket, r.UID, ContentSide(store)})
	}
	errs := make(chan error, len(sides)+len(cfg.ClerkKeys))
	if len(cfg.ClerkKeys) > 0 {
		root := keys.ClerkRoot // the kernel's copy, for its whole life
		// Cleared only once every key socket's server, and so every
		// hand-off, has returned; the listeners close first (defers run
		// last-in, first-out).
		var serving sync.WaitGroup
		defer func() {
			serving.Wait()
			clear(root[:])
		}()
		for name, kc := range cfg.ClerkKeys {
			ln, err := ListenClerkKey(kc.Socket)
			if err != nil {
				return err
			}
			defer ln.Close()
			serving.Add(1)
			go func() {
				defer serving.Done()
				errs <- fmt.Errorf("run: clerk %s's key socket: %w", name, ServeClerkKey(ln, name, kc.Cgroup, &root))
			}()
		}
	}
	for _, s := range sides {
		ln, err := ListenKernel(s.path, s.uid)
		if err != nil {
			return err
		}
		defer ln.Close()
		go func(ln net.Listener, side Side) {
			errs <- fmt.Errorf("run: %s socket: %w", side.name, ServeKernel(ln, h, side, clock))
		}(ln, s.side)
	}
	markUp(cfg.Up)
	every := cfg.Tick
	if every <= 0 {
		every = time.Second
	}
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case err := <-errs:
			return err
		case <-t.C:
			if err := h.Tick(clock()); err != nil {
				return err
			}
		}
	}
}

// checkLogKey refuses a log whose first whole frame does not open under
// key. kernel.Open trims a final frame it cannot open as torn, so a log of
// one entry under another key would otherwise come back empty, a fresh box
// on keys the owner never gave it (STO-2a-b). A missing or empty log, or a
// first frame torn by a crash, is left to kernel.Open. The frame is the
// kernel's: a 4-byte length, then AES-256-GCM's nonce and sealed entry
// under seq 1 (TestCheckLogKeyReadsTheKernelsFrames ties the two).
func checkLogKey(path string, key [32]byte) error {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer f.Close()
	var n [4]byte
	if _, err := io.ReadFull(f, n[:]); err != nil {
		return nil // empty, or a torn length
	}
	fi, err := f.Stat()
	if err != nil {
		return err
	}
	size := int64(binary.BigEndian.Uint32(n[:]))
	if 4+size > fi.Size() {
		return nil // a torn first frame
	}
	fr := make([]byte, size)
	if _, err := io.ReadFull(f, fr); err != nil {
		return err
	}
	b, err := aes.NewCipher(key[:])
	if err != nil {
		return err
	}
	a, err := cipher.NewGCM(b)
	if err != nil {
		return err
	}
	if len(fr) < a.NonceSize()+a.Overhead() {
		return ErrLogKey
	}
	pt, err := a.Open(nil, fr[:a.NonceSize()], fr[a.NonceSize():], binary.BigEndian.AppendUint64(nil, 1))
	clear(pt)
	if err != nil {
		return ErrLogKey
	}
	return nil
}
