package tpmseal

import (
	"fmt"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

// Freeing a store's NV indexes (STO-2c). A store's pins index is write-once
// and its counter only goes up, so neither is ever rewritten; each is
// undefined through the owner hierarchy instead, when the store is deleted
// or (pins only) its policy key rotated. Both find the store's index by the
// tag over its ID, as ReadPins and FindCounter do, so an index of any other
// store or shape is never touched. Each frees every derived handle that
// holds one of the store's indexes, and returns nil once none is left.

// FreePins undefines store id's pins index on this TPM, locked or not.
func FreePins(t transport.TPM, srkName, id []byte) error {
	for _, h := range pinsHandles(id) {
		st, name, err := probePinsName(t, h, id)
		if err != nil {
			return err
		}
		if st == pinsLocked || st == pinsUnlocked {
			if err := undefine(t, srkName, h, name); err != nil {
				return fmt.Errorf("tpmseal: free store pins: %w", err)
			}
		}
	}
	return nil
}

// FreeCounter undefines id's counter on this TPM, written or never
// incremented. The TPM keeps the highest count any counter had, so a
// counter defined later still starts above it (T11).
func FreeCounter(t transport.TPM, srkName, id []byte) error {
	for _, h := range counterHandles(id) {
		st, name, err := probeName(t, h, id)
		if err != nil {
			return err
		}
		if st == slotOurs || st == slotOursFresh {
			if err := undefine(t, srkName, h, name); err != nil {
				return fmt.Errorf("tpmseal: free counter: %w", err)
			}
		}
	}
	return nil
}

// undefine removes the index at h by the name the probe read: the TPM
// refuses the command if another index took the handle in between.
func undefine(t transport.TPM, srkName []byte, h tpm2.TPMHandle, name []byte) error {
	return ownerCmd(t, srkName, func(auth tpm2.Session) error {
		_, err := tpm2.NVUndefineSpace{
			AuthHandle: tpm2.AuthHandle{Handle: tpm2.TPMRHOwner, Auth: auth},
			NVIndex:    tpm2.NamedHandle{Handle: h, Name: tpm2.TPM2BName{Buffer: name}},
		}.Execute(t)
		return err
	})
}

// OtherPins reports whether this TPM holds a written, write-locked index of
// the pins' shape that is not store id's (id may be nil): a store of some
// other ID is enrolled on this PC. It reads the whole owner NV range the
// pins and counters use, since a pins index's handle derives from an ID
// that only its store knows.
func OtherPins(t transport.TPM, id []byte) (bool, error) {
	mine := map[tpm2.TPMHandle]bool{}
	if id != nil {
		for _, h := range pinsHandles(id) {
			if st, err := probePins(t, h, id); err != nil {
				return false, err
			} else if st == pinsLocked {
				mine[h] = true
			}
		}
	}
	want := pinsPublic(0, nil, true, true)
	for next := uint32(counterBase); ; {
		rsp, err := tpm2.GetCapability{
			Capability:    tpm2.TPMCapHandles,
			Property:      next,
			PropertyCount: 64,
		}.Execute(t)
		if err != nil {
			return false, fmt.Errorf("tpmseal: list NV indexes: %w", err)
		}
		hs, err := rsp.CapabilityData.Data.Handles()
		if err != nil {
			return false, err
		}
		for _, h := range hs.Handle {
			if uint32(h) >= counterBase+counterSpan {
				return false, nil
			}
			next = uint32(h) + 1
			if mine[h] {
				continue
			}
			pr, err := tpm2.NVReadPublic{NVIndex: h}.Execute(t)
			if err != nil {
				return false, fmt.Errorf("tpmseal: read NV index: %w", err)
			}
			p, err := pr.NVPublic.Contents()
			if err != nil {
				return false, err
			}
			if p.Attributes == want.Attributes && p.NameAlg == want.NameAlg && p.DataSize == want.DataSize {
				return true, nil
			}
		}
		if !rsp.MoreData || len(hs.Handle) == 0 {
			return false, nil
		}
	}
}
