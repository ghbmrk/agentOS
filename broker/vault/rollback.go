package vault

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
)

// Rollback protection (V6). The vault key does not change when a secret is
// revoked, so an older copy of the vault file still opens: someone who
// copied the drive once could later put the copy back and revive a revoked
// credential or the code-generator seed a lost phone held. Nothing on the
// drive can tell an old copy from the current file, so the file is bound to
// a monotonic counter off the drive: a TPM NV counter on each trusted PC
// (P2-4d; the vault process implements Counter over package tpmseal).
//
// Each PC the vault was anchored to has an Anchor inside the sealed file:
// which counter, and the value the file was written against. A file whose
// value is below that PC's counter is an old copy (ErrRolledBack). A write
// stores the counter's next value first and then advances the counter, so
// a crash between the two leaves a file exactly one ahead, which the next
// bind finishes. Writes made on another PC leave this PC's anchor and
// counter alone, so moving the drive between PCs is not a rollback.
//
// The vault package itself never talks to a TPM: Bind and Anchor take the
// counter from the vault process, and Open and OpenSealed check nothing,
// so a restore (REC-1) or an unknown host without a counter still opens.

// idSize is the vault ID length; authSize is the counter's authorization
// value: 16 random bytes as hex, so it holds no zero byte (go-tpm v0.9.8
// cuts an auth value at its first zero byte; tpmseal T7).
const (
	idSize   = 16
	authSize = 32
)

// Anchor binds the vault file to one PC's counter.
type Anchor struct {
	// Host is the counter's PC (Counter.Host).
	Host string `json:"host"`
	// Ref names the counter on that PC (opaque to the vault).
	Ref []byte `json:"ref,omitempty"`
	// Count is the counter value this file was written against.
	Count uint64 `json:"count"`
	// Pending: the anchor was written before its counter was made, so a
	// crash in between is recognized rather than read as a rollback.
	Pending bool `json:"pending,omitempty"`
}

// Counter is a monotonic counter off the drive, on the PC the vault runs
// on. Counters for different vaults on one PC are told apart by the vault
// ID; auth is the vault's authorization value for its counter.
type Counter interface {
	// Host names the PC (for a TPM, its storage root key's name).
	Host() string
	// Find reports whether this PC holds a counter for vault id.
	Find(id []byte) (ref []byte, ok bool, err error)
	// Define returns the counter for vault id, making it if there is none.
	// A new counter starts at whatever value the PC gives it.
	Define(id, auth []byte) (ref []byte, err error)
	// Read returns the counter's value.
	Read(ref, auth []byte) (uint64, error)
	// Increment adds one.
	Increment(ref, auth []byte) error
}

// ErrRolledBack is the answer for a vault file that is older than this
// PC's counter: an earlier copy of the drive put back, or a file that
// disagrees with the counter in a way no crash produces. The vault process
// serves nothing from it. The owner's way forward is a restore with the
// recovery key (REC-1), which rebases the vault (Rebase).
var ErrRolledBack = errors.New("vault: this vault file is older than this PC's rollback counter, so it may be an old copy of the drive")

// ErrCounterMissing means the file is anchored to this PC but the PC's
// counter for it is gone: undefined with the owner hierarchy, or the TPM
// cleared (review of #45, B3). Nothing then shows whether the file is
// current, so the vault is unbound: the vault process refuses this PC's
// unattended slot, lets the owner unlock in person (CRED-8), alerts, and
// makes a new counter when the owner trusts the PC again (Anchor).
var ErrCounterMissing = errors.New("vault: this PC's rollback counter for the vault is gone")

// ensureID gives the vault its ID and counter authorization the first time
// it is written as version 2. Caller holds mu.
func (v *Vault) ensureID() error {
	if v.id != nil {
		return nil
	}
	id := make([]byte, idSize)
	a := make([]byte, authSize/2)
	if _, err := rand.Read(id); err != nil {
		return err
	}
	if _, err := rand.Read(a); err != nil {
		return err
	}
	v.id, v.counterAuth = id, []byte(hex.EncodeToString(a))
	return nil
}

// find returns the index of host's anchor, or -1.
func (v *Vault) find(host string) int {
	for i, a := range v.anchors {
		if a.Host == host {
			return i
		}
	}
	return -1
}

// Bind checks the vault against c, this PC's counter, and from then on
// advances c with every write. It refuses an old copy (ErrRolledBack): a
// file whose anchor for this PC is behind the counter, or a file with no
// anchor for this PC although the PC holds a counter for this vault (a
// copy from before the PC was anchored). Without an anchor and without a
// counter it binds nothing and returns nil: an unknown host, whose
// unlock the owner authorizes in person (CRED-8).
func (v *Vault) Bind(c Counter) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.closed {
		return ErrClosed
	}
	return v.bind(c)
}

func (v *Vault) bind(c Counter) error {
	v.counter, v.bound = nil, -1
	if v.id == nil {
		return errors.New("vault: no vault ID to bind")
	}
	i := v.find(c.Host())
	if i < 0 {
		_, ok, err := c.Find(v.id)
		if err != nil {
			// The PC's TPM does not answer. With no anchor here the
			// file makes no claim to check, and the unlock is the
			// owner's own (CRED-8), so it goes ahead.
			return nil
		}
		if ok {
			return ErrRolledBack
		}
		return nil
	}
	a := v.anchors[i]
	if a.Pending {
		_, ok, err := c.Find(v.id)
		if err != nil {
			return fmt.Errorf("vault: rollback counter: %w", err)
		}
		if !ok {
			// Anchoring stopped before the counter was made; Anchor
			// finishes it.
			return nil
		}
		ref, err := c.Define(v.id, v.counterAuth)
		if err != nil {
			return fmt.Errorf("vault: rollback counter: %w", err)
		}
		return v.adopt(c, i, ref)
	}
	n, err := c.Read(a.Ref, v.counterAuth)
	if err != nil {
		if _, ok, ferr := c.Find(v.id); ferr == nil && !ok {
			return ErrCounterMissing
		}
		// Anchored here, so the check is owed: fail closed.
		return fmt.Errorf("vault: rollback counter: %w", err)
	}
	switch {
	case a.Count == n:
	case a.Count == n+1:
		// The last write landed but the counter did not advance.
		if err := c.Increment(a.Ref, v.counterAuth); err != nil {
			return fmt.Errorf("vault: rollback counter: %w", err)
		}
	default:
		return ErrRolledBack
	}
	v.counter, v.bound = c, i
	return nil
}

// Anchor binds the vault to c, making this PC's counter first if the
// vault has none here. The vault process calls it when the owner trusts a
// PC (CRED-9). An anchor is never removed: a PC that is no longer trusted
// still catches an old copy put back on it.
func (v *Vault) Anchor(c Counter) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.closed {
		return ErrClosed
	}
	if err := v.ensureID(); err != nil {
		return err
	}
	err := v.bind(c)
	if errors.Is(err, ErrCounterMissing) {
		// Trusting the PC again after its counter went: make a new one.
		// It starts at the highest count the TPM has had, so the copy
		// check holds from here.
		i := v.find(c.Host())
		prev := v.anchors[i]
		v.anchors[i] = Anchor{Host: prev.Host, Pending: true}
		if werr := v.write(v.anchors); werr != nil {
			v.anchors[i] = prev
			return werr
		}
	} else if err != nil {
		return err
	}
	if v.counter != nil {
		return nil
	}
	i := v.find(c.Host())
	if i < 0 {
		v.anchors = append(v.anchors, Anchor{Host: c.Host(), Pending: true})
		i = len(v.anchors) - 1
		if err := v.write(v.anchors); err != nil {
			v.anchors = v.anchors[:i]
			return err
		}
	}
	ref, err := c.Define(v.id, v.counterAuth)
	if err != nil {
		// No counter was made (NV full, TPM refusing): take the pending
		// anchor back out, so a pending anchor survives only a crash
		// between the two writes (review of #45, B2). Left in, every
		// later write would carry it, and a copy taken meanwhile would
		// adopt the counter once one is made.
		next := append(append([]Anchor(nil), v.anchors[:i]...), v.anchors[i+1:]...)
		if werr := v.write(next); werr == nil {
			v.anchors = next
		}
		return fmt.Errorf("vault: rollback counter: %w", err)
	}
	return v.adopt(c, i, ref)
}

// adopt points anchor i at the counter ref, binds it, and writes the file.
// Caller holds mu.
func (v *Vault) adopt(c Counter, i int, ref []byte) error {
	n, err := c.Read(ref, v.counterAuth)
	if err != nil {
		return fmt.Errorf("vault: rollback counter: %w", err)
	}
	prev := v.anchors[i]
	v.anchors[i] = Anchor{Host: prev.Host, Ref: ref, Count: n}
	v.counter, v.bound = c, i
	if err := v.advance(); err != nil {
		v.anchors[i] = prev
		v.counter, v.bound = nil, -1
		return err
	}
	return nil
}

// advance writes the file against the bound counter's next value, then
// advances the counter. If the counter fails to advance after the write,
// the file is one ahead, which the next bind or write finishes. Caller
// holds mu.
func (v *Vault) advance() error {
	a := v.anchors[v.bound]
	n, err := v.counter.Read(a.Ref, v.counterAuth)
	if err != nil {
		return fmt.Errorf("vault: rollback counter: %w", err)
	}
	if a.Count == n+1 {
		if err := v.counter.Increment(a.Ref, v.counterAuth); err != nil {
			return fmt.Errorf("vault: rollback counter: %w", err)
		}
		n++
	}
	if a.Count != n {
		// Something else advanced the counter while this vault was
		// open: another copy of it is being written.
		return ErrRolledBack
	}
	next := append([]Anchor(nil), v.anchors...)
	next[v.bound].Count = n + 1
	if err := v.write(next); err != nil {
		return err
	}
	v.anchors = next
	if err := v.counter.Increment(a.Ref, v.counterAuth); err != nil && v.warn != nil {
		// The file is one ahead, which the next bind or write finishes;
		// until then the file before this write still binds.
		v.warn("this change is saved but not yet protected against an older copy of the drive; it will be at the next change or restart")
	}
	return nil
}

// OnWarn sets a function that tells the owner about a rollback check that
// could not finish (V6), such as a counter increment that failed after a
// write.
func (v *Vault) OnWarn(f func(string)) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.warn = f
}

// Rebase gives the vault a new ID and counter authorization, drops every
// anchor and every trusted-host slot, and records the new keys file. A
// restore with the recovery key (REC-1) calls it: putting back a backup is
// a deliberate rollback, and REC-2's restricted mode, not the counter,
// keeps it from reviving revoked grants. It takes the recovery key, which
// must open the recovery slot, so nothing but the owner's restore can
// reset the rollback binding; an import fence (imports_test.go) keeps it
// to package recovery. Trusted-host slots go with it (security review of
// #45, F2): left in place, they would open the rebased vault unattended on
// a PC whose counter no longer applies, laundering an old copy there. The
// owner trusts PCs again after a restore (CRED-9).
//
// Like a slot change (keysbind.go), the vault is written first holding the
// new keys file, then the keys file: a crash between rolls forward at the
// next OpenSealed, where a trusted-host slot from the file before opens
// nothing.
func (v *Vault) Rebase(recovery Factor) (dropped int, err error) {
	defer wipeFactor(recovery)
	v.mu.Lock()
	defer v.mu.Unlock()
	if recovery == nil || recovery.Kind() != SlotRecovery {
		return 0, errors.New("vault: Rebase takes the recovery key")
	}
	kf, err := v.slotsForChange()
	if err != nil {
		return 0, err
	}
	if !proveSlotOfKind(kf, v.key, recovery) {
		return 0, ErrNoSlotOpens
	}
	var keep []Slot
	for _, s := range kf.Slots {
		if s.Kind != SlotTPM {
			keep = append(keep, s)
		}
	}
	raw, err := json.Marshal(&keyFile{Magic: kf.Magic, Version: kf.Version, Slots: keep})
	if err != nil {
		return 0, err
	}
	id, auth, anchors, counter, bound := v.id, v.counterAuth, v.anchors, v.counter, v.bound
	v.id, v.counterAuth, v.anchors, v.counter, v.bound = nil, nil, nil, nil, -1
	v.nextKeys = raw
	err = v.ensureID()
	if err == nil {
		err = v.write(nil)
	}
	if err != nil {
		v.id, v.counterAuth, v.anchors, v.counter, v.bound, v.nextKeys = id, auth, anchors, counter, bound, nil
		return 0, err
	}
	// Decided: the vault holds the new keys file and rolls forward to it.
	if err := v.finishKeys(); err != nil {
		return 0, fmt.Errorf("vault: rebase not finished; it completes when the vault next opens: %w", err)
	}
	return len(kf.Slots) - len(keep), nil
}

// Anchors lists the vault's anchors.
func (v *Vault) Anchors() []Anchor {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return append([]Anchor(nil), v.anchors...)
}
