// Package clerkkey is the kernel's hand-off of one clerk's key to that
// clerk's process (MAIL-main, Mark's option A, #2682 comment 6428111900):
// the clerk's name and a 32-byte key, read once from a descriptor at each
// start, from which the clerk derives its sealer and its handle secret. One
// clerk's key opens nothing another clerk sealed (CLK-1). It links neither
// the store nor the kernel, so a clerk's process links no more than it
// needs, and it is apart from clerk/handoff, the unlock step's hand-off to
// the kernel, which the trusted core links.
package clerkkey

import (
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/sha256"
	"errors"
	"io"
	"os"
	"regexp"
	"syscall"
)

// FD is the descriptor a clerk main reads its key from: a pipe or a
// connected socket, never a file on the drive.
const FD = 3

// Len is a clerk's key: 32 bytes, from which the clerk derives its
// sealer key and its handle secret (Key.Sealer, Key.HandleSecret).
const Len = 32

// clerkKeyTag starts a clerk's hand-off, so a later form can be told from
// this one, and the unlock step's hand-off never reads as a clerk's.
const clerkKeyTag = "agentos-clerk-key/v1\n"

// maxClerkName bounds a clerk's name.
const maxClerkName = 64

var clerkName = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,63}$`)

// maxClerkKey is the longest clerk hand-off: the tag, the name and its
// length, and the key.
const maxClerkKey = len(clerkKeyTag) + 1 + maxClerkName + Len

// ErrKey: the hand-off is not this clerk's key. Nothing in it is used.
var ErrKey = errors.New("handoff: the clerk's key hand-off is damaged, missing or another clerk's")

// Key is what the kernel hands one clerk's process at each start of it.
type Key struct {
	Name string
	Key  [Len]byte
}

// Marshal encodes k for the clerk's descriptor. The caller wipes the
// result.
func Marshal(k Key) ([]byte, error) {
	if !clerkName.MatchString(k.Name) {
		return nil, ErrKey
	}
	b := make([]byte, 0, maxClerkKey)
	b = append(b, clerkKeyTag...)
	b = append(b, byte(len(k.Name)))
	b = append(b, k.Name...)
	return append(b, k.Key[:]...), nil
}

// Read reads name's key from f and closes it. f must be a pipe or a
// connected socket, so a file on the drive can never stand in for the
// kernel, and must hold exactly one hand-off, naming name, its writer
// closed: anything else is ErrKey.
func Read(f *os.File, name string) (Key, error) {
	defer f.Close()
	var st syscall.Stat_t
	if err := syscall.Fstat(int(f.Fd()), &st); err != nil {
		return Key{}, ErrKey
	}
	if m := st.Mode & syscall.S_IFMT; m != syscall.S_IFIFO && m != syscall.S_IFSOCK {
		return Key{}, ErrKey
	}
	// One buffer of fixed size, as handoff.ReadKeys has, so no grown copy of the
	// key is left for the collector. A hand-off that fills it is too long.
	buf := make([]byte, maxClerkKey+1)
	defer clear(buf)
	n, err := io.ReadFull(f, buf)
	if err == nil || !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
		return Key{}, ErrKey
	}
	return parse(buf[:n], name)
}

func parse(b []byte, name string) (Key, error) {
	rest, ok := cutTag(b, clerkKeyTag)
	if !ok || len(rest) < 1 {
		return Key{}, ErrKey
	}
	n := int(rest[0])
	if len(rest) != 1+n+Len || string(rest[1:1+n]) != name || !clerkName.MatchString(name) {
		return Key{}, ErrKey
	}
	k := Key{Name: name}
	copy(k.Key[:], rest[1+n:])
	return k, nil
}

func cutTag(b []byte, tag string) ([]byte, bool) {
	if len(b) < len(tag) || string(b[:len(tag)]) != tag {
		return nil, false
	}
	return b[len(tag):], true
}

// ValidName reports whether name can be a clerk's: lower-case letters,
// digits and hyphens, at most 64 bytes.
func ValidName(name string) bool { return clerkName.MatchString(name) }

// rootLabel derives one clerk's key from the clerk root key the unlock step
// hands the kernel (handoff.KernelKeys.ClerkRoot, MAIL-keys).
const rootLabel = "agentos.clerk.key.v1"

// Derive is name's key under the clerk root key: what the kernel hands that
// clerk at each start of its unit. The same root and name give the same key
// at every start and after every update, so a clerk's sealed slots open
// again; two names never share one (CLK-1). The caller wipes it.
func Derive(root *[Len]byte, name string) (Key, error) {
	if !clerkName.MatchString(name) || *root == ([Len]byte{}) {
		return Key{}, ErrKey
	}
	b, err := hkdf.Key(sha256.New, root[:], nil, rootLabel+"\x00"+name, Len)
	if err != nil {
		return Key{}, err
	}
	defer clear(b)
	k := Key{Name: name}
	copy(k.Key[:], b)
	return k, nil
}

// Sealer is the key the clerk seals its Secrets file and its records under
// (clerk.NewAESSealer). The caller wipes it.
func (k Key) Sealer() ([]byte, error) { return k.derive("agentos.clerk.sealer.v1") }

// HandleSecret keys the handles the clerk shows the planner in place of an
// account's own names (inbox.NewAccount). The caller wipes it.
func (k Key) HandleSecret() ([]byte, error) { return k.derive("agentos.clerk.handles.v1") }

// Signer is the key a clerk signs with, such as the checker's code
// approvals (kernel.SignCode), which the kernel verifies against the same
// derivation from the clerk root key it holds (MIG-4-exit-c2). The caller
// wipes it.
func (k Key) Signer() (ed25519.PrivateKey, error) {
	seed, err := k.derive("agentos.clerk.signer.v1")
	if err != nil {
		return nil, err
	}
	defer clear(seed)
	return ed25519.NewKeyFromSeed(seed), nil
}

// derive binds the clerk's name into each key, so two clerks handed the same
// bytes by mistake still seal apart.
func (k Key) derive(label string) ([]byte, error) {
	if !clerkName.MatchString(k.Name) {
		return nil, ErrKey
	}
	return hkdf.Key(sha256.New, k.Key[:], nil, label+"\x00"+k.Name, 32)
}

// Wipe clears the key. Keys already derived are the holder's.
func (k *Key) Wipe() { clear(k.Key[:]) }
