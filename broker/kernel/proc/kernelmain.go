package proc

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"syscall"
	"time"

	"github.com/ghbmrk/agentos/broker/clerk/handoff"
	"github.com/ghbmrk/agentos/broker/kernel"
	"github.com/ghbmrk/agentos/broker/procguard"
)

// MainConfig is the kernel process's command line (cmd/agentos-kernel).
type MainConfig struct {
	Log       string // the log file
	OwnerSock string // OwnerSide's socket
	OwnerUID  int    // the owner side's uid, its only peer
	MeterSock string // MeterSide's socket
	MeterUID  int    // the model clerk's uid, its only peer
	Clerks    map[string]Remote
	// Peers are the uids this process must not run as: every peer above
	// (procguard.Isolate). The main fills it from the uids it was given.
	Peers []int
	Tick  time.Duration // how often plans run; 0 is one second
	// Up is a file made once both sockets listen, so the unit can tell a
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

// RunKernel is the kernel process (STO-2b): hardened against its peers, it
// opens the log under keys, serves OwnerSide and MeterSide, and runs plans
// every Tick until ctx ends. anchor is where signed heads go (LOG-2).
func RunKernel(ctx context.Context, cfg MainConfig, keys handoff.KernelKeys, anchor kernel.Anchor) error {
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
	clock := func() int64 { return time.Now().UnixMilli() }
	h, err := OpenKernel(KernelConfig{
		Log: cfg.Log, Anchor: anchor, Key: keys.Log,
		Pub: keys.Head.Public().(ed25519.PublicKey), Sign: keys.Head,
		Anchors: keys.Anchors, Clerks: cfg.Clerks,
	}, clock())
	if err != nil {
		return err
	}
	defer h.Close()
	sides := []struct {
		path string
		uid  int
		side Side
	}{{cfg.OwnerSock, cfg.OwnerUID, OwnerSide}, {cfg.MeterSock, cfg.MeterUID, MeterSide}}
	errs := make(chan error, len(sides))
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
