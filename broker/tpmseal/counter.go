package tpmseal

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

// Rollback counters (V6, P2-4d). Each vault gets one TPM NV counter on
// each PC it is anchored to. The index is defined by the owner hierarchy
// (empty owner auth, as the storage root key already assumes) with:
//
//   - type counter, so it only ever goes up, and a new counter starts at
//     the highest value any counter on the TPM has had: deleting and
//     redefining one cannot lower it;
//   - an authPolicy that is a tag over the vault ID, not a satisfiable
//     policy, so the index's name (a hash of its public area) says which
//     vault it belongs to, and Find can tell it from any other index;
//   - read and increment by its auth value only, which lives inside the
//     vault, so nothing outside the vault process can advance it (a denial
//     of service) or read it; noDA, since the auth value is 128 random
//     bits and a wrong one must not spend the boot PIN's lockout;
//   - not orderly: an orderly counter may jump ahead after a power cut,
//     which would read as a rollback.
//
// Every command that carries the auth value or returns the count runs in
// a session salted to the storage root key whose name the caller pins, so
// an interposer on a discrete TPM's bus can neither read the auth value
// nor forge the count: the response HMAC covers it.

// counterBase is the start of the TPM's owner NV index range
// (0x01800000-0x01BFFFFF, TCG handle registry); counterProbes is how many
// handles derived from a vault ID are tried before giving up.
const (
	counterBase   = 0x01800000
	counterSpan   = 0x00400000
	counterProbes = 8
)

// ErrNoCounterSpace: every handle derived from this vault ID holds some
// other index.
var ErrNoCounterSpace = errors.New("tpmseal: no free NV handle for the rollback counter")

// CounterRef names one vault's counter on one TPM.
type CounterRef struct {
	Handle uint32 `json:"handle"`
	// Name is the index's name once written: the TPM checks it in every
	// authorized command, so a different index at the handle answers
	// nothing.
	Name []byte `json:"name"`
}

// Marshal and ParseCounterRef store a ref in a vault anchor.
func (r CounterRef) Marshal() []byte { b, _ := json.Marshal(r); return b }

func ParseCounterRef(b []byte) (CounterRef, error) {
	var r CounterRef
	if err := json.Unmarshal(b, &r); err != nil || r.Handle&^(counterSpan-1) != counterBase || len(r.Name) == 0 {
		return CounterRef{}, errors.New("tpmseal: bad counter reference")
	}
	return r, nil
}

func counterTag(id []byte) []byte {
	h := sha256.New()
	h.Write([]byte("agentos-vault-rollback-counter/v1\x00"))
	h.Write(id)
	return h.Sum(nil)
}

// counterHandles derives the handles tried for vault id.
func counterHandles(id []byte) []tpm2.TPMHandle {
	t := counterTag(id)
	out := make([]tpm2.TPMHandle, counterProbes)
	for i := range out {
		h := sha256.Sum256(append(append([]byte(nil), t...), byte(i)))
		out[i] = tpm2.TPMHandle(counterBase + binary.BigEndian.Uint32(h[:4])%counterSpan)
	}
	return out
}

func counterPublic(h tpm2.TPMHandle, id []byte, written bool) tpm2.TPMSNVPublic {
	return tpm2.TPMSNVPublic{
		NVIndex: h,
		NameAlg: tpm2.TPMAlgSHA256,
		Attributes: tpm2.TPMANV{
			NT:        tpm2.TPMNTCounter,
			AuthWrite: true,
			AuthRead:  true,
			NoDA:      true,
			Written:   written,
		},
		AuthPolicy: tpm2.TPM2BDigest{Buffer: counterTag(id)},
		DataSize:   8,
	}
}

func nvName(p tpm2.TPMSNVPublic) ([]byte, error) {
	n, err := tpm2.NVName(&p)
	if err != nil {
		return nil, err
	}
	return n.Buffer, nil
}

// slotState is what one candidate handle holds.
type slotState int

const (
	slotFree slotState = iota
	slotOther
	slotOurs      // ours, written
	slotOursFresh // ours, defined but never incremented
)

func probe(t transport.TPM, h tpm2.TPMHandle, id []byte) (slotState, error) {
	rsp, err := tpm2.NVReadPublic{NVIndex: h}.Execute(t)
	if err != nil {
		if errors.Is(err, tpm2.TPMRCHandle) {
			return slotFree, nil
		}
		return 0, fmt.Errorf("tpmseal: read NV index: %w", err)
	}
	written, err := nvName(counterPublic(h, id, true))
	if err != nil {
		return 0, err
	}
	fresh, err := nvName(counterPublic(h, id, false))
	if err != nil {
		return 0, err
	}
	switch {
	case bytes.Equal(rsp.NVName.Buffer, written):
		return slotOurs, nil
	case bytes.Equal(rsp.NVName.Buffer, fresh):
		return slotOursFresh, nil
	}
	return slotOther, nil
}

// pinnedSRK loads the storage root key and checks it is the one srkName
// names, so a session salted to it is salted to this TPM.
func pinnedSRK(t transport.TPM, srkName []byte) (*srk, error) {
	s, err := loadSRK(t)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(s.name.Buffer, srkName) {
		flush(t, s.handle)
		return nil, ErrOtherTPM
	}
	return s, nil
}

// FindCounter reports whether this TPM holds vault id's counter.
func FindCounter(t transport.TPM, id []byte) (bool, error) {
	for _, h := range counterHandles(id) {
		st, err := probe(t, h, id)
		if err != nil {
			return false, err
		}
		if st == slotOurs || st == slotOursFresh {
			return true, nil
		}
	}
	return false, nil
}

// DefineCounter returns vault id's counter on this TPM, defining it at the
// first free derived handle if there is none. auth is its auth value,
// which travels encrypted.
func DefineCounter(t transport.TPM, srkName, id, auth []byte) (CounterRef, error) {
	if len(auth) == 0 || bytes.IndexByte(auth, 0) >= 0 {
		// go-tpm v0.9.8 cuts an auth value at its first zero byte (T7).
		return CounterRef{}, errors.New("tpmseal: counter auth must be non-empty without zero bytes")
	}
	free := tpm2.TPMHandle(0)
	for _, h := range counterHandles(id) {
		st, err := probe(t, h, id)
		if err != nil {
			return CounterRef{}, err
		}
		switch st {
		case slotOurs:
			name, err := nvName(counterPublic(h, id, true))
			return CounterRef{Handle: uint32(h), Name: name}, err
		case slotOursFresh:
			return initCounter(t, srkName, h, id, auth)
		case slotFree:
			if free == 0 {
				free = h
			}
		}
	}
	if free == 0 {
		return CounterRef{}, ErrNoCounterSpace
	}
	s, err := pinnedSRK(t, srkName)
	if err != nil {
		return CounterRef{}, err
	}
	pub := counterPublic(free, id, false)
	_, err = tpm2.NVDefineSpace{
		AuthHandle: tpm2.AuthHandle{
			Handle: tpm2.TPMRHOwner,
			Auth: tpm2.HMAC(tpm2.TPMAlgSHA256, 16,
				tpm2.AESEncryption(128, tpm2.EncryptIn),
				tpm2.Salted(s.handle, s.pub)),
		},
		Auth:       tpm2.TPM2BAuth{Buffer: auth},
		PublicInfo: tpm2.New2B(pub),
	}.Execute(t)
	flush(t, s.handle)
	if err != nil {
		return CounterRef{}, fmt.Errorf("tpmseal: define rollback counter: %w", err)
	}
	return initCounter(t, srkName, free, id, auth)
}

// initCounter makes the first increment, which sets the counter to the
// TPM's highest counter value so far and marks it written.
func initCounter(t transport.TPM, srkName []byte, h tpm2.TPMHandle, id, auth []byte) (CounterRef, error) {
	fresh, err := nvName(counterPublic(h, id, false))
	if err != nil {
		return CounterRef{}, err
	}
	if err := increment(t, srkName, uint32(h), fresh, auth); err != nil {
		return CounterRef{}, err
	}
	name, err := nvName(counterPublic(h, id, true))
	return CounterRef{Handle: uint32(h), Name: name}, err
}

// session is an HMAC session for the counter's auth value, salted to the
// pinned storage root key.
func session(s *srk, auth []byte, enc tpm2.AuthOption) tpm2.Session {
	opts := []tpm2.AuthOption{tpm2.Auth(auth), tpm2.Salted(s.handle, s.pub)}
	if enc != nil {
		opts = append(opts, enc)
	}
	return tpm2.HMAC(tpm2.TPMAlgSHA256, 16, opts...)
}

// ReadCounter returns the counter's value. The TPM checks ref's name and
// the auth value, and the salted session authenticates the answer.
func ReadCounter(t transport.TPM, srkName []byte, ref CounterRef, auth []byte) (uint64, error) {
	s, err := pinnedSRK(t, srkName)
	if err != nil {
		return 0, err
	}
	defer flush(t, s.handle)
	h := tpm2.TPMHandle(ref.Handle)
	rsp, err := tpm2.NVRead{
		AuthHandle: tpm2.AuthHandle{Handle: h, Name: tpm2.TPM2BName{Buffer: ref.Name},
			Auth: session(s, auth, tpm2.AESEncryption(128, tpm2.EncryptOut))},
		NVIndex: tpm2.NamedHandle{Handle: h, Name: tpm2.TPM2BName{Buffer: ref.Name}},
		Size:    8,
	}.Execute(t)
	if err != nil {
		return 0, fmt.Errorf("tpmseal: read rollback counter: %w", err)
	}
	if len(rsp.Data.Buffer) != 8 {
		return 0, errors.New("tpmseal: rollback counter is not 8 bytes")
	}
	return binary.BigEndian.Uint64(rsp.Data.Buffer), nil
}

// IncrementCounter adds one to the counter.
func IncrementCounter(t transport.TPM, srkName []byte, ref CounterRef, auth []byte) error {
	return increment(t, srkName, ref.Handle, ref.Name, auth)
}

func increment(t transport.TPM, srkName []byte, handle uint32, name, auth []byte) error {
	s, err := pinnedSRK(t, srkName)
	if err != nil {
		return err
	}
	defer flush(t, s.handle)
	h := tpm2.TPMHandle(handle)
	_, err = tpm2.NVIncrement{
		AuthHandle: tpm2.AuthHandle{Handle: h, Name: tpm2.TPM2BName{Buffer: name}, Auth: session(s, auth, nil)},
		NVIndex:    tpm2.NamedHandle{Handle: h, Name: tpm2.TPM2BName{Buffer: name}},
	}.Execute(t)
	if err != nil {
		return fmt.Errorf("tpmseal: advance rollback counter: %w", err)
	}
	return nil
}
