package tpmseal

import (
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"slices"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

// Capping a slot's policy after its unseal (K6, #2977). The unlock step
// extends one PCR of each boot path's selection once it has the store open,
// so for the rest of the boot no signed policy over those PCRs matches, and
// nothing that can send this TPM commands (the kernel through the
// connection it is handed, row STO-2c-tpm) can unseal the slot again. The
// next boot measures from reset, and the slot opens as before.

// capMax is the highest PCR Cap extends. PCRs 0 to 15 are extendable from
// locality 0 and reset only by a power cycle; 16 and 23 can be reset from
// locality 0, and 17 to 22 cannot be extended from it.
const capMax = 15

// CapPCR is the PCR Cap extends for a boot path selecting pcrs: the highest
// of them that only a power cycle resets. A selection with none cannot be
// capped, and is refused.
func CapPCR(pcrs []uint) (uint, error) {
	pcrs, err := normPCRs(pcrs)
	if err != nil {
		return 0, err
	}
	for _, p := range slices.Backward(pcrs) {
		if p <= capMax {
			return p, nil
		}
	}
	return 0, fmt.Errorf("tpmseal: the selection %v has no PCR from 0 to %d, so it cannot be capped after an unseal", pcrs, capMax)
}

// Cap extends each selection's CapPCR (SHA-256 bank, the one policies
// select) with a fresh random value, so no policy over any of sels matches again until
// the TPM is reset. It extends nothing unless there is a selection and every
// one can be capped.
func Cap(t transport.TPM, sels [][]uint) error {
	if len(sels) == 0 {
		return errors.New("tpmseal: no boot path to cap")
	}
	var pcrs []uint
	for _, s := range sels {
		p, err := CapPCR(s)
		if err != nil {
			return err
		}
		if !slices.Contains(pcrs, p) {
			pcrs = append(pcrs, p)
		}
	}
	// A fresh random value each time, never a fixed tag: a fixed one would
	// give the same capped value every boot, so a policy ever signed over
	// capped PCRs would open after the cap on each later boot (#3001
	// Security 1). Random, it never recurs, and such a policy fails closed.
	var ev [sha256.Size]byte
	if _, err := rand.Read(ev[:]); err != nil {
		return err
	}
	for _, p := range pcrs {
		if _, err := (tpm2.PCRExtend{
			PCRHandle: tpm2.AuthHandle{Handle: tpm2.TPMHandle(p), Auth: tpm2.PasswordAuth(nil)},
			Digests: tpm2.TPMLDigestValues{Digests: []tpm2.TPMTHA{{
				HashAlg: tpm2.TPMAlgSHA256,
				Digest:  ev[:],
			}}},
		}).Execute(t); err != nil {
			return fmt.Errorf("tpmseal: cap PCR %d: %w", p, err)
		}
	}
	return nil
}
