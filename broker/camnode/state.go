package camnode

import (
	"crypto/sha256"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/ghbmrk/agentos/broker/camnode/se"
	"github.com/ghbmrk/agentos/broker/camwire"
	"github.com/ghbmrk/agentos/broker/durable"
)

// The node's settings state: the bundle in force, kept on the node's
// writable storage, and the owner pin and settings counter in the
// element. The storage is not trusted: a stored bundle is verified again
// at every boot against the element, so rewriting it offline gives at
// most a bundle the owner already signed at the element's current
// counter, which is the one in force.

// Store names.
const (
	currentName = "bundle"
	pendingName = "bundle.pending"
)

// Store is the node's writable storage for its bundle.
type Store interface {
	// Read returns a file's bytes, or an error satisfying
	// errors.Is(err, fs.ErrNotExist).
	Read(name string) ([]byte, error)
	// Write replaces a file atomically and durably.
	Write(name string, p []byte) error
	// Remove removes a file; a missing file is no error.
	Remove(name string) error
}

// Dir is a Store in one directory of the node's state partition.
type Dir string

func (d Dir) Read(name string) ([]byte, error) {
	f, err := os.Open(filepath.Join(string(d), name))
	if err != nil {
		return nil, err
	}
	defer f.Close()
	p, err := io.ReadAll(io.LimitReader(f, camwire.MaxSigned+1))
	if err != nil {
		return nil, err
	}
	if len(p) > camwire.MaxSigned {
		return nil, camwire.ErrMalformed
	}
	return p, nil
}

func (d Dir) Write(name string, p []byte) error {
	return durable.WriteFile(filepath.Join(string(d), name), p, 0o600)
}

func (d Dir) Remove(name string) error {
	err := os.Remove(filepath.Join(string(d), name))
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	return durable.SyncDir(string(d))
}

// OwnerDigest is the owner pin the element holds for o: SHA-256 over the
// RP ID's length, the RP ID and the credential's point.
func OwnerDigest(o camwire.Owner) [32]byte {
	h := sha256.New()
	h.Write([]byte{byte(len(o.RPID))})
	h.Write([]byte(o.RPID))
	h.Write(o.Point[:])
	var out [32]byte
	h.Sum(out[:0])
	return out
}

// errNoBundle is a node with an owner pinned but no bundle that verifies
// at the element's counter: it admits no client until a button reset.
var errNoBundle = errors.New("camnode: no stored bundle verifies")

// loadBundle is the bundle in force at boot. It first finishes an apply a
// restart cut short (commit), then requires the current bundle to name
// this node and the pinned owner, carry exactly the element's settings
// counter and verify.
func loadBundle(el se.Element, st Store, node [32]byte, pin [32]byte) (camwire.Bundle, []byte, error) {
	ctr, err := el.Counter(se.Settings)
	if err != nil {
		return camwire.Bundle{}, nil, err
	}
	if p, err := st.Read(pendingName); err == nil {
		if b, err := checkStored(p, node, pin, ctr, true); err == nil {
			if err := commit(el, st, b, p, false); err != nil {
				return camwire.Bundle{}, nil, err
			}
			return b, p, nil
		}
		if err := st.Remove(pendingName); err != nil {
			return camwire.Bundle{}, nil, err
		}
	}
	p, err := st.Read(currentName)
	if err != nil {
		return camwire.Bundle{}, nil, errNoBundle
	}
	b, err := checkStored(p, node, pin, ctr, false)
	if err != nil {
		return camwire.Bundle{}, nil, errNoBundle
	}
	return b, p, nil
}

// checkStored verifies a stored signed bundle against the pinned owner.
// A pending bundle may be at the counter (the raise happened) or above it
// (it did not yet); the current one must be at it.
func checkStored(p []byte, node, pin [32]byte, ctr uint64, pending bool) (camwire.Bundle, error) {
	_, b, err := camwire.ParseSignedBundle(p)
	if err != nil {
		return camwire.Bundle{}, err
	}
	if OwnerDigest(b.Owner) != pin {
		return camwire.Bundle{}, camwire.ErrOwner
	}
	floor := ctr
	if b.Counter == ctr {
		if ctr == 0 {
			return camwire.Bundle{}, camwire.ErrCounter
		}
		floor = ctr - 1
	} else if !pending {
		return camwire.Bundle{}, camwire.ErrCounter
	}
	return camwire.VerifyBundle(p, camwire.Pin{Node: node, Owner: b.Owner, Counter: floor})
}

// commit makes a verified bundle the one in force, in an order a restart
// at any step recovers from (loadBundle): write it as pending, pin its
// owner (first bundle only), raise the element's counter to its counter,
// then make it current.
func commit(el se.Element, st Store, b camwire.Bundle, p []byte, first bool) error {
	if err := st.Write(pendingName, p); err != nil {
		return err
	}
	if first {
		if err := el.SetOwnerPin(OwnerDigest(b.Owner)); err != nil {
			return err
		}
	}
	ctr, err := el.Counter(se.Settings)
	if err != nil {
		return err
	}
	if b.Counter > ctr {
		if err := el.Raise(se.Settings, b.Counter); err != nil {
			return err
		}
	} else if b.Counter != ctr {
		return camwire.ErrCounter
	}
	if err := st.Write(currentName, p); err != nil {
		return err
	}
	return st.Remove(pendingName)
}

// reset is the button reset: the bundle files and the owner pin go; the
// device key and both counters stay.
func reset(el se.Element, st Store) error {
	if err := st.Remove(pendingName); err != nil {
		return err
	}
	if err := st.Remove(currentName); err != nil {
		return err
	}
	return el.ClearOwnerPin()
}
