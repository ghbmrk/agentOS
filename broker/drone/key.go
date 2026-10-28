package drone

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"

	"github.com/bluenviron/gomavlib/v3/pkg/frame"
)

// KeySize is the MAVLink 2 signing secret's length.
const KeySize = 32

// Key is the MAVLink 2 signing secret (P2). Its bytes live only inside a
// closure: fmt and reflection reach a func value's address, never what it
// captured, so no format of a struct holding a Key (under any verb, a bad
// verb's fallback included) prints the secret, and Key itself formats as a
// fixed placeholder.
type Key struct {
	s func() *frame.V2Key
}

func keyOf(b *frame.V2Key) Key { return Key{s: func() *frame.V2Key { return b }} }

var errNoKey = errors.New("drone: no signing key")

// Format prints a placeholder for every verb, %v, %+v, %#v, %s and %x
// included, so no format string spills the secret.
func (k Key) Format(f fmt.State, _ rune) { io.WriteString(f, "drone.Key(redacted)") }

func (k Key) valid() bool { return k.s != nil }

// NewKey draws a fresh secret from r (crypto/rand when nil). An all-zero
// draw is refused: ArduPilot reads an all-zero key as signing off.
func NewKey(r io.Reader) (Key, error) {
	if r == nil {
		r = rand.Reader
	}
	var b [KeySize]byte
	if _, err := io.ReadFull(r, b[:]); err != nil {
		return Key{}, errors.New("drone: drawing a signing key failed")
	}
	if b == ([KeySize]byte{}) {
		return Key{}, errors.New("drone: drew an all-zero signing key")
	}
	k := frame.V2Key(b)
	clear(b[:])
	return keyOf(&k), nil
}

// WriteKeyFile writes k to path, mode 0600, through a temporary file in the
// same directory that is synced and renamed over path, so a crash leaves the
// old file or the new one.
func WriteKeyFile(path string, k Key) error {
	if !k.valid() {
		return errNoKey
	}
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, ".key-*")
	if err != nil {
		return fmt.Errorf("drone: key file: %w", pathErr(err))
	}
	tmp := f.Name()
	ok := false
	defer func() {
		if !ok {
			f.Close()
			os.Remove(tmp)
		}
	}()
	if err := f.Chmod(0o600); err != nil {
		return fmt.Errorf("drone: key file: %w", pathErr(err))
	}
	if _, err := f.Write(k.s()[:]); err != nil {
		return errors.New("drone: writing the key file failed")
	}
	if err := f.Sync(); err != nil {
		return errors.New("drone: syncing the key file failed")
	}
	if err := f.Close(); err != nil {
		return errors.New("drone: closing the key file failed")
	}
	if err := os.Rename(tmp, path); err != nil { // durable:exempt lifecycle:exempt the drone imports nothing from agentOS (brief decision 1) and durable is old core (tools/old_core.txt), so it cannot list here; this is owner config, not a lifecycle, and the directory is synced below
		return fmt.Errorf("drone: key file: %w", pathErr(err))
	}
	ok = true
	if d, err := os.Open(dir); err == nil {
		d.Sync()
		d.Close()
	}
	return nil
}

// LoadKeyFile reads the secret from path. It refuses a symlink, a file that
// is not regular, one whose mode grants group or other any bit, one owned by
// another user, and one that is not exactly KeySize bytes. No error carries
// the file's bytes.
func LoadKeyFile(path string) (Key, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return Key{}, fmt.Errorf("drone: key file: %w", pathErr(err))
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return Key{}, fmt.Errorf("drone: key file: %w", pathErr(err))
	}
	if !fi.Mode().IsRegular() {
		return Key{}, errors.New("drone: key file is not a regular file")
	}
	if fi.Mode().Perm() != 0o600 {
		return Key{}, fmt.Errorf("drone: key file mode is %#o, want 0600", fi.Mode().Perm())
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || int(st.Uid) != os.Getuid() {
		return Key{}, errors.New("drone: key file is not owned by this process's user")
	}
	if fi.Size() != KeySize {
		return Key{}, fmt.Errorf("drone: key file is %d bytes, want %d", fi.Size(), KeySize)
	}
	var b [KeySize + 1]byte
	n, err := io.ReadFull(f, b[:])
	if err != io.ErrUnexpectedEOF || n != KeySize {
		return Key{}, errors.New("drone: key file changed size while read")
	}
	var kb frame.V2Key
	copy(kb[:], b[:KeySize])
	clear(b[:])
	if kb == (frame.V2Key{}) {
		return Key{}, errors.New("drone: key file holds an all-zero key")
	}
	return keyOf(&kb), nil
}

// pathErr keeps an *os.PathError's operation, path and cause; the path is
// the operator's, never the secret.
func pathErr(err error) error {
	var pe *os.PathError
	if errors.As(err, &pe) {
		return pe
	}
	return errors.New("file operation failed")
}
