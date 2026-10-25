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
	"encoding/binary"
	"errors"
	"io"
	"os"
	"syscall"

	"github.com/ghbmrk/agentos/broker/kernel/key"
)

// KeyFD is the descriptor the kernel main reads its keys from.
const KeyFD = 3

// TPMFD is the descriptor of the kernel's own connection to this PC's TPM,
// which the unlock step opened as root, for the log anchor's counter
// (LOG-2, STO-1). The kernel's uid is in no group that can open the TPM, so
// this one connection is all the TPM it has.
const TPMFD = 4

// CounterEntry is the sealed store's entry holding the log anchor's counter:
// its reference and auth value, which enrollment wrote (STO-2c).
const CounterEntry = "kernel/counter"

// maxName bounds a TPM name or auth value in the hand-off: a name is a
// two-byte algorithm and a digest.
const maxName = 64

// AnchorsEntry is the sealed store's entry holding the owner's hardware keys
// (D-146), in EncodeAnchors' form, or, as first written, 32-byte Ed25519
// keys one after another. The store's MAC covers it, so a writer of the
// drive cannot swap in keys of their own.
const AnchorsEntry = "kernel/anchors"

// MaxAnchors bounds the owner's hardware keys in the hand-off.
const MaxAnchors = 16

const handoffTag = "agentos-kernel-keys/v3\n"

// anchorsTag starts AnchorsEntry's versioned form. A first-form value reads
// as it only if its first key starts with these bytes; only enrollment
// writes the entry, under the store's MAC, so that is not an attacker's
// choice.
const anchorsTag, anchorsTagStem = "agentos-anchors/v1\n", "agentos-anchors/"

// maxAnchor is the longest anchor on the wire: a uint16 length and an ES256
// key's Encode, whose RP ID is at most 253 bytes.
const maxAnchor = 2 + len(key.AlgES256) + 1 + 253 + 1 + 65 + 1

// maxHandoff is the longest hand-off: the tag, the log key, the head seed,
// the counter, the count and MaxAnchors ES256 keys, under 6 KiB. It is far
// below a pipe's 64 KiB buffer, so the unlock step's write never waits for
// a reader.
const maxHandoff = len(handoffTag) + 32 + ed25519.SeedSize + maxCounter + 1 + MaxAnchors*maxAnchor

// maxCounter is the longest counter: three length-prefixed fields and a
// handle.
const maxCounter = 3*(1+maxName) + 4

// ErrHandoff: the hand-off is not one this kernel reads. Nothing in it is
// used.
var ErrHandoff = errors.New("handoff: the unlock step's hand-off is damaged or missing")

// KernelKeys is what the unlock step hands the kernel process: the log's
// key, the head-signing key, the log anchor's counter and the owner's
// anchors, none when the store holds none (the kernel then starts
// setup-only and takes them into its log, kernel.Setup).
type KernelKeys struct {
	Log     [32]byte
	Head    ed25519.PrivateKey
	Counter Counter
	Anchors []key.PublicKey
}

// Counter names the log anchor's TPM counter for the kernel: the storage
// root key's name, which the unlock step's store slot proved is this PC's,
// the counter's NV handle and name, and its auth value. The kernel checks
// none of it beyond its shape; the TPM refuses a wrong name or auth.
type Counter struct {
	SRK    []byte
	Handle uint32
	Name   []byte
	Auth   []byte
}

func (c Counter) valid() bool {
	for _, f := range [][]byte{c.SRK, c.Name, c.Auth} {
		if len(f) == 0 || len(f) > maxName {
			return false
		}
	}
	return c.Handle != 0
}

// ParseAnchors reads AnchorsEntry's value: 1 to MaxAnchors distinct keys,
// in EncodeAnchors' form or the first one.
func ParseAnchors(b []byte) ([]key.PublicKey, error) {
	if bytes.HasPrefix(b, []byte(anchorsTagStem)) {
		b, ok := bytes.CutPrefix(b, []byte(anchorsTag))
		if !ok || len(b) < 1 || b[0] < 1 {
			return nil, ErrHandoff
		}
		return parseAnchors(b[1:], int(b[0]))
	}
	n := len(b) / ed25519.PublicKeySize
	if len(b)%ed25519.PublicKeySize != 0 || n < 1 || n > MaxAnchors {
		return nil, ErrHandoff
	}
	out := make([]key.PublicKey, n)
	for i := range out {
		if out[i] = key.Ed25519(b[i*ed25519.PublicKeySize : (i+1)*ed25519.PublicKeySize]); key.In(out[:i], out[i]) {
			return nil, ErrHandoff
		}
	}
	return out, nil
}

// EncodeAnchors is AnchorsEntry's value for 1 to MaxAnchors distinct keys.
func EncodeAnchors(anchors []key.PublicKey) ([]byte, error) {
	if len(anchors) < 1 {
		return nil, ErrHandoff
	}
	return appendAnchors([]byte(anchorsTag), anchors)
}

// appendAnchors appends a count and each anchor's length and Encode.
func appendAnchors(b []byte, anchors []key.PublicKey) ([]byte, error) {
	if len(anchors) > MaxAnchors {
		return nil, ErrHandoff
	}
	b = append(b, byte(len(anchors)))
	for i, a := range anchors {
		if !a.Valid() || key.In(anchors[:i], a) {
			return nil, ErrHandoff
		}
		e := a.Encode()
		b = binary.BigEndian.AppendUint16(b, uint16(len(e)))
		b = append(b, e...)
	}
	return b, nil
}

// parseAnchors reads exactly n distinct anchors, at most MaxAnchors, and
// nothing after them. The keys are copies of b.
func parseAnchors(b []byte, n int) ([]key.PublicKey, error) {
	if n > MaxAnchors {
		return nil, ErrHandoff
	}
	var out []key.PublicKey
	for range n {
		if len(b) < 2 {
			return nil, ErrHandoff
		}
		l := int(binary.BigEndian.Uint16(b))
		if l == 0 || l > maxAnchor-2 || len(b) < 2+l {
			return nil, ErrHandoff
		}
		a, err := key.DecodePublicKey(b[2 : 2+l])
		if err != nil || !a.Valid() || key.In(out, a) {
			return nil, ErrHandoff
		}
		out, b = append(out, a), b[2+l:]
	}
	if len(b) != 0 {
		return nil, ErrHandoff
	}
	return out, nil
}

// Marshal encodes k for the pipe. The caller wipes the result.
func (k KernelKeys) Marshal() ([]byte, error) {
	if len(k.Head) != ed25519.PrivateKeySize || !k.Counter.valid() || len(k.Anchors) > MaxAnchors {
		return nil, ErrHandoff
	}
	b := make([]byte, 0, maxHandoff)
	b = append(b, handoffTag...)
	b = append(b, k.Log[:]...)
	b = append(b, k.Head.Seed()...)
	b = append(b, byte(len(k.Counter.SRK)))
	b = append(b, k.Counter.SRK...)
	b = binary.BigEndian.AppendUint32(b, k.Counter.Handle)
	b = append(b, byte(len(k.Counter.Name)))
	b = append(b, k.Counter.Name...)
	b = append(b, byte(len(k.Counter.Auth)))
	b = append(b, k.Counter.Auth...)
	out, err := appendAnchors(b, k.Anchors)
	if err != nil {
		clear(b)
	}
	return out, err
}

// Wipe clears the keys. Copies already taken, such as the kernel's own, are
// the holder's (STO-2a-e: the wipe is best-effort).
func (k *KernelKeys) Wipe() {
	clear(k.Log[:])
	clear(k.Head)
	k.Head = nil
	clear(k.Counter.Auth)
	k.Counter.Auth = nil
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
	// One buffer of fixed size, so no grown copy of the keys is left for
	// the collector (#2896 L3 item 2). A hand-off that fills it is too long.
	buf := make([]byte, maxHandoff+1)
	defer clear(buf)
	n, err := io.ReadFull(f, buf)
	if err == nil || !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
		return KernelKeys{}, ErrHandoff
	}
	return parseKeys(buf[:n])
}

// field takes a length-prefixed field of 1 to maxName bytes off b.
func field(b []byte) (f, rest []byte, ok bool) {
	if len(b) < 1 || b[0] == 0 || int(b[0]) > maxName || len(b) < 1+int(b[0]) {
		return nil, nil, false
	}
	return b[1 : 1+int(b[0])], b[1+int(b[0]):], true
}

func parseKeys(b []byte) (KernelKeys, error) {
	o := len(handoffTag) + 32 + ed25519.SeedSize
	if len(b) < o || len(b) > maxHandoff || string(b[:len(handoffTag)]) != handoffTag {
		return KernelKeys{}, ErrHandoff
	}
	var c Counter
	rest := b[o:]
	var ok bool
	if c.SRK, rest, ok = field(rest); !ok || len(rest) < 4 {
		return KernelKeys{}, ErrHandoff
	}
	c.Handle, rest = binary.BigEndian.Uint32(rest), rest[4:]
	if c.Name, rest, ok = field(rest); !ok {
		return KernelKeys{}, ErrHandoff
	}
	if c.Auth, rest, ok = field(rest); !ok || len(rest) < 1 || !c.valid() {
		return KernelKeys{}, ErrHandoff
	}
	// None: the store has no anchors yet, so the kernel starts setup-only.
	anchors, err := parseAnchors(rest[1:], int(rest[0]))
	if err != nil {
		return KernelKeys{}, err
	}
	k := KernelKeys{Anchors: anchors}
	o = len(handoffTag)
	copy(k.Log[:], b[o:o+32])
	k.Head = ed25519.NewKeyFromSeed(b[o+32 : o+32+ed25519.SeedSize])
	// Copies, so clearing the read buffer leaves the kernel its counter.
	k.Counter = Counter{SRK: bytes.Clone(c.SRK), Handle: c.Handle, Name: bytes.Clone(c.Name), Auth: bytes.Clone(c.Auth)}
	return k, nil
}
