package tpmseal

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

// Store pins (STO-pins, STO-2a-k). A TPM unlock of a sealed store must be
// given the box's policy public key and the store's anchor, and neither
// may come from the drive, whose writer may be the attacker. Each store
// gets one TPM NV index on the box, holding both. The index is defined by
// the owner hierarchy (empty owner auth, as the storage root key already
// assumes) with:
//
//   - type ordinary, a fixed size, written only through the owner
//     hierarchy (ownerWrite) and read with an empty auth value (authRead,
//     noDA): the pins are public, only their integrity matters;
//   - writeDefine: once written the index is write-locked, and the lock
//     holds across power cycles until the index is undefined;
//   - an authPolicy that is a tag over the store ID, not a satisfiable
//     policy, so the index's name says which store it belongs to.
//
// The index's name is a hash of its public area, attributes included, so
// a reader that asks for the name of a written, write-locked index of
// exactly this shape gets an answer only from such an index: one defined
// with other attributes, or never locked, answers nothing. The read runs
// in a session salted to the storage root key whose name the caller pins,
// so an interposer on a discrete TPM's bus cannot change the answer: the
// response HMAC covers it.

const pinsProbes = 8

const pinsVersion = 1

// pinsSize is the index's data: a version byte, the policy key as an
// uncompressed P-256 point, and the anchor.
const (
	pinsKeyLen    = 65
	PinsAnchorLen = 32
	pinsSize      = 1 + pinsKeyLen + PinsAnchorLen
)

var (
	// ErrNoPins: this TPM holds no written, write-locked pins index for
	// the store. An unlock that needs pins must stop here.
	ErrNoPins = errors.New("tpmseal: no locked pins index for this store on this TPM")
	// ErrPinsDiffer: the store's pins index is already locked with other
	// values; it is never rewritten.
	ErrPinsDiffer = errors.New("tpmseal: this store's pins index is locked with other values")
	// ErrNoPinsSpace: every handle derived from this store ID holds some
	// other index.
	ErrNoPinsSpace = errors.New("tpmseal: no free NV handle for the store pins")
)

// Pins are the values a TPM unlock trusts that the drive cannot supply.
type Pins struct {
	PolicyKey *ecdsa.PublicKey
	Anchor    []byte
}

func (p Pins) marshal() ([]byte, error) {
	if p.PolicyKey == nil || p.PolicyKey.Curve != elliptic.P256() {
		return nil, errors.New("tpmseal: pins policy key is not ECDSA P-256")
	}
	if len(p.Anchor) != PinsAnchorLen {
		return nil, fmt.Errorf("tpmseal: pins anchor is not %d bytes", PinsAnchorLen)
	}
	k, err := p.PolicyKey.Bytes()
	if err != nil {
		return nil, fmt.Errorf("tpmseal: pins policy key: %w", err)
	}
	return append(append([]byte{pinsVersion}, k...), p.Anchor...), nil
}

func parsePins(b []byte) (Pins, error) {
	if len(b) != pinsSize || b[0] != pinsVersion {
		return Pins{}, errors.New("tpmseal: pins index holds no known format")
	}
	k, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), b[1:1+pinsKeyLen])
	if err != nil {
		return Pins{}, fmt.Errorf("tpmseal: pins policy key: %w", err)
	}
	return Pins{PolicyKey: k, Anchor: bytes.Clone(b[1+pinsKeyLen:])}, nil
}

func pinsTag(id []byte) []byte {
	h := sha256.New()
	h.Write([]byte("agentos-store-pins/v1\x00"))
	h.Write(id)
	return h.Sum(nil)
}

// pinsHandles derives the handles tried for store id, in the owner NV
// range the counters use.
func pinsHandles(id []byte) []tpm2.TPMHandle {
	t := pinsTag(id)
	out := make([]tpm2.TPMHandle, pinsProbes)
	for i := range out {
		h := sha256.Sum256(append(append([]byte(nil), t...), byte(i)))
		out[i] = tpm2.TPMHandle(counterBase + binary.BigEndian.Uint32(h[:4])%counterSpan)
	}
	return out
}

func pinsPublic(h tpm2.TPMHandle, id []byte, written, locked bool) tpm2.TPMSNVPublic {
	return tpm2.TPMSNVPublic{
		NVIndex: h,
		NameAlg: tpm2.TPMAlgSHA256,
		Attributes: tpm2.TPMANV{
			NT:          tpm2.TPMNTOrdinary,
			OwnerWrite:  true,
			AuthRead:    true,
			NoDA:        true,
			WriteDefine: true,
			Written:     written,
			WriteLocked: locked,
		},
		AuthPolicy: tpm2.TPM2BDigest{Buffer: pinsTag(id)},
		DataSize:   pinsSize,
	}
}

// pinsState is what one candidate handle holds.
type pinsState int

const (
	pinsFree pinsState = iota
	pinsOther
	pinsLocked   // ours, written and write-locked
	pinsUnlocked // ours, defined (maybe written) but not yet locked
)

func probePins(t transport.TPM, h tpm2.TPMHandle, id []byte) (pinsState, error) {
	st, _, err := probePinsName(t, h, id)
	return st, err
}

// probePinsName is probePins that also returns the index's name.
func probePinsName(t transport.TPM, h tpm2.TPMHandle, id []byte) (pinsState, []byte, error) {
	name, err := readName(t, h)
	if err != nil || name == nil {
		return pinsFree, nil, err
	}
	st, err := pinsStateOf(h, id, name)
	return st, name, err
}

func pinsStateOf(h tpm2.TPMHandle, id, name []byte) (pinsState, error) {
	for _, s := range []struct {
		written, locked bool
		st              pinsState
	}{{true, true, pinsLocked}, {false, false, pinsUnlocked}, {true, false, pinsUnlocked}} {
		n, err := nvName(pinsPublic(h, id, s.written, s.locked))
		if err != nil {
			return 0, err
		}
		if bytes.Equal(name, n) {
			return s.st, nil
		}
	}
	return pinsOther, nil
}

// ReadPins returns store id's pins from this TPM. Only a written,
// write-locked index of the pins' exact shape answers; anything else is
// ErrNoPins, so a caller fails closed.
func ReadPins(t transport.TPM, srkName, id []byte) (Pins, error) {
	for _, h := range pinsHandles(id) {
		st, err := probePins(t, h, id)
		if err != nil {
			return Pins{}, err
		}
		if st == pinsLocked {
			return readPins(t, srkName, h, id)
		}
	}
	return Pins{}, ErrNoPins
}

func readPins(t transport.TPM, srkName []byte, h tpm2.TPMHandle, id []byte) (Pins, error) {
	name, err := nvName(pinsPublic(h, id, true, true))
	if err != nil {
		return Pins{}, err
	}
	s, err := pinnedSRK(t, srkName)
	if err != nil {
		return Pins{}, err
	}
	defer flush(t, s.handle)
	n := tpm2.TPM2BName{Buffer: name}
	rsp, err := tpm2.NVRead{
		AuthHandle: tpm2.AuthHandle{Handle: h, Name: n, Auth: session(s, nil, nil)},
		NVIndex:    tpm2.NamedHandle{Handle: h, Name: n},
		Size:       pinsSize,
	}.Execute(t)
	if err != nil {
		// The TPM checks the name in the session: an index swapped in
		// between the probe and the read answers nothing.
		return Pins{}, fmt.Errorf("%w: %w", ErrNoPins, err)
	}
	return parsePins(rsp.Data.Buffer)
}

// WritePins defines store id's pins index on this TPM, writes p and
// write-locks it, so nothing rewrites it while it is defined. If the
// index is already locked with p it returns nil; with other values,
// ErrPinsDiffer, and the index is left as it was. An index defined but
// never locked (an interrupted enrollment) is written and locked.
func WritePins(t transport.TPM, srkName, id []byte, p Pins) error {
	data, err := p.marshal()
	if err != nil {
		return err
	}
	free := tpm2.TPMHandle(0)
	for _, h := range pinsHandles(id) {
		st, err := probePins(t, h, id)
		if err != nil {
			return err
		}
		switch st {
		case pinsLocked:
			got, err := readPins(t, srkName, h, id)
			if err != nil {
				return err
			}
			if !got.PolicyKey.Equal(p.PolicyKey) || !bytes.Equal(got.Anchor, p.Anchor) {
				return ErrPinsDiffer
			}
			return nil
		case pinsUnlocked:
			return lockPins(t, srkName, h, id, data)
		case pinsFree:
			if free == 0 {
				free = h
			}
		}
	}
	if free == 0 {
		return ErrNoPinsSpace
	}
	if err := ownerCmd(t, srkName, func(auth tpm2.Session) error {
		_, err := tpm2.NVDefineSpace{
			AuthHandle: tpm2.AuthHandle{Handle: tpm2.TPMRHOwner, Auth: auth},
			PublicInfo: tpm2.New2B(pinsPublic(free, id, false, false)),
		}.Execute(t)
		return err
	}); err != nil {
		return fmt.Errorf("tpmseal: define store pins: %w", err)
	}
	return lockPins(t, srkName, free, id, data)
}

// lockPins writes data to the unlocked index at h, locks it and reads it
// back.
func lockPins(t transport.TPM, srkName []byte, h tpm2.TPMHandle, id, data []byte) error {
	rsp, err := tpm2.NVReadPublic{NVIndex: h}.Execute(t)
	if err != nil {
		return fmt.Errorf("tpmseal: read NV index: %w", err)
	}
	idx := tpm2.NamedHandle{Handle: h, Name: rsp.NVName}
	if err := ownerCmd(t, srkName, func(auth tpm2.Session) error {
		_, err := tpm2.NVWrite{
			AuthHandle: tpm2.AuthHandle{Handle: tpm2.TPMRHOwner, Auth: auth},
			NVIndex:    idx,
			Data:       tpm2.TPM2BMaxNVBuffer{Buffer: data},
		}.Execute(t)
		return err
	}); err != nil {
		return fmt.Errorf("tpmseal: write store pins: %w", err)
	}
	written, err := nvName(pinsPublic(h, id, true, false))
	if err != nil {
		return err
	}
	idx.Name = tpm2.TPM2BName{Buffer: written}
	if err := ownerCmd(t, srkName, func(auth tpm2.Session) error {
		_, err := tpm2.NVWriteLock{
			AuthHandle: tpm2.AuthHandle{Handle: tpm2.TPMRHOwner, Auth: auth},
			NVIndex:    idx,
		}.Execute(t)
		return err
	}); err != nil {
		return fmt.Errorf("tpmseal: lock store pins: %w", err)
	}
	got, err := readPins(t, srkName, h, id)
	if err != nil {
		return err
	}
	if want, _ := got.marshal(); !bytes.Equal(want, data) {
		return ErrPinsDiffer
	}
	return nil
}

// ownerCmd runs one owner-hierarchy command in a session salted to the
// pinned storage root key.
func ownerCmd(t transport.TPM, srkName []byte, run func(tpm2.Session) error) error {
	s, err := pinnedSRK(t, srkName)
	if err != nil {
		return err
	}
	defer flush(t, s.handle)
	return run(session(s, nil, nil))
}
