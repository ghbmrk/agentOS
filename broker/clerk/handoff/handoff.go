// Package handoff is the unlock step's hand-off to the kernel process
// (STO-2b, STO-2a-e). The unlock step opens the sealed store as root,
// derives the kernel's keys, writes them to a pipe, drops to the kernel's
// uid and execs the kernel main with the pipe's read end as descriptor
// KeyFD. So the store key stays with the step that unlocked, which is gone
// once the kernel runs, and the kernel holds only its own keys (CLK-1). The
// package links neither the store nor the kernel, so the unlock step, which
// runs as root, links no more than it needs.
package handoff

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"io"
	"os"
	"syscall"
)

// KeyFD is the descriptor the kernel main reads its keys from.
const KeyFD = 3

// AnchorsEntry is the sealed store's entry holding the owner's hardware keys
// (D-146), each 32 bytes, one after another. The store's MAC covers it, so a
// writer of the drive cannot swap in keys of their own.
const AnchorsEntry = "kernel/anchors"

// MaxAnchors bounds the owner's hardware keys in the hand-off.
const MaxAnchors = 16

const handoffTag = "agentos-kernel-keys/v1\n"

// maxHandoff is the longest hand-off: the tag, the log key, the head seed,
// the count and MaxAnchors keys. It is far below a pipe's buffer, so the
// unlock step's write never waits for a reader.
const maxHandoff = len(handoffTag) + 32 + ed25519.SeedSize + 1 + MaxAnchors*ed25519.PublicKeySize

// ErrHandoff: the hand-off is not one this kernel reads. Nothing in it is
// used.
var ErrHandoff = errors.New("handoff: the unlock step's hand-off is damaged or missing")

// KernelKeys is what the unlock step hands the kernel process: the log's
// key, the head-signing key and the owner's anchors.
type KernelKeys struct {
	Log     [32]byte
	Head    ed25519.PrivateKey
	Anchors []ed25519.PublicKey
}

// ParseAnchors reads AnchorsEntry's value: 1 to MaxAnchors distinct keys.
func ParseAnchors(b []byte) ([]ed25519.PublicKey, error) {
	n := len(b) / ed25519.PublicKeySize
	if len(b)%ed25519.PublicKeySize != 0 || n < 1 || n > MaxAnchors {
		return nil, ErrHandoff
	}
	out := make([]ed25519.PublicKey, n)
	for i := range out {
		k := ed25519.PublicKey(bytes.Clone(b[i*ed25519.PublicKeySize : (i+1)*ed25519.PublicKeySize]))
		for _, prev := range out[:i] {
			if prev.Equal(k) {
				return nil, ErrHandoff
			}
		}
		out[i] = k
	}
	return out, nil
}

// Marshal encodes k for the pipe. The caller wipes the result.
func (k KernelKeys) Marshal() ([]byte, error) {
	if len(k.Head) != ed25519.PrivateKeySize || len(k.Anchors) < 1 || len(k.Anchors) > MaxAnchors {
		return nil, ErrHandoff
	}
	b := make([]byte, 0, maxHandoff)
	b = append(b, handoffTag...)
	b = append(b, k.Log[:]...)
	b = append(b, k.Head.Seed()...)
	b = append(b, byte(len(k.Anchors)))
	for _, a := range k.Anchors {
		if len(a) != ed25519.PublicKeySize {
			clear(b)
			return nil, ErrHandoff
		}
		b = append(b, a...)
	}
	return b, nil
}

// Wipe clears the keys. Copies already taken, such as the kernel's own, are
// the holder's (STO-2a-e: the wipe is best-effort).
func (k *KernelKeys) Wipe() {
	clear(k.Log[:])
	clear(k.Head)
	k.Head = nil
}

// ReadKeys reads the hand-off from f and closes it. f must be a pipe, so a
// file on the drive can never stand in for the unlock step, and must hold
// exactly one hand-off, its writer closed: anything else is ErrHandoff.
func ReadKeys(f *os.File) (KernelKeys, error) {
	defer f.Close()
	var st syscall.Stat_t
	if err := syscall.Fstat(int(f.Fd()), &st); err != nil || st.Mode&syscall.S_IFMT != syscall.S_IFIFO {
		return KernelKeys{}, ErrHandoff
	}
	b, err := io.ReadAll(io.LimitReader(f, int64(maxHandoff)+1))
	defer clear(b)
	if err != nil {
		return KernelKeys{}, ErrHandoff
	}
	return parseKeys(b)
}

func parseKeys(b []byte) (KernelKeys, error) {
	head := len(handoffTag) + 32 + ed25519.SeedSize + 1
	if len(b) < head || len(b) > maxHandoff || string(b[:len(handoffTag)]) != handoffTag {
		return KernelKeys{}, ErrHandoff
	}
	n := int(b[head-1])
	if len(b) != head+n*ed25519.PublicKeySize {
		return KernelKeys{}, ErrHandoff
	}
	anchors, err := ParseAnchors(b[head:])
	if err != nil {
		return KernelKeys{}, err
	}
	var k KernelKeys
	o := len(handoffTag)
	copy(k.Log[:], b[o:o+32])
	k.Head = ed25519.NewKeyFromSeed(b[o+32 : o+32+ed25519.SeedSize])
	k.Anchors = anchors
	return k, nil
}
