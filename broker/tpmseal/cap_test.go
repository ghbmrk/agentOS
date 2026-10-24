package tpmseal_test

// REQ: STO-2, CLK-1, HW-5a

import (
	"bytes"
	"errors"
	"testing"

	"github.com/ghbmrk/agentos/broker/tpmseal"
	"github.com/ghbmrk/agentos/broker/tpmseal/swtpm"
)

// K6 (#2977): once capped, the slot unseals on no connection to this TPM
// for the rest of the boot, and the next boot opens it as before. A policy
// re-signed from the slot's stored values (a rotation after the cap) opens
// on the next boot too; one signed over the capped PCRs would not.
func TestCapLocksTheSlotUntilTheNextBoot(t *testing.T) {
	s := swtpm.Start(t)
	boot(s, releaseA)
	key := newKey(t)
	sec, sealed, pols := enroll(t, s, key, "")
	if got, err := tpmseal.Unseal(s.TPM(), sealed, pols, ""); err != nil || !bytes.Equal(got, sec) {
		t.Fatalf("before the cap: %v", err)
	}
	if err := tpmseal.Cap(s.TPM(), [][]uint{pcrs}); err != nil {
		t.Fatal(err)
	}
	if _, err := tpmseal.Unseal(s.TPM(), sealed, pols, ""); !errors.Is(err, tpmseal.ErrNoPolicy) {
		t.Fatalf("after the cap: got %v, want ErrNoPolicy", err)
	}
	next := newKey(t)
	resigned, err := tpmseal.Resign(next, pols[0])
	if err != nil {
		t.Fatal(err)
	}
	capped, err := tpmseal.SignCurrent(s.TPM(), next, pcrs)
	if err != nil {
		t.Fatal(err)
	}
	sealedNext, err := tpmseal.Seal(s.TPM(), sec, &next.PublicKey, "", "Test PC")
	if err != nil {
		t.Fatal(err)
	}

	boot(s, releaseA)
	if got, err := tpmseal.Unseal(s.TPM(), sealed, pols, ""); err != nil || !bytes.Equal(got, sec) {
		t.Fatalf("the next boot: %v", err)
	}
	if got, err := tpmseal.Unseal(s.TPM(), sealedNext, []tpmseal.Policy{resigned}, ""); err != nil || !bytes.Equal(got, sec) {
		t.Fatalf("re-signed after the cap, the next boot: %v", err)
	}
	if _, err := tpmseal.Unseal(s.TPM(), sealedNext, []tpmseal.Policy{capped}, ""); !errors.Is(err, tpmseal.ErrNoPolicy) {
		t.Fatalf("signed over the capped PCRs: got %v, want ErrNoPolicy", err)
	}
}

// The cap extends the highest PCR of a selection that only a power cycle
// resets, and refuses a selection with none, extending nothing.
func TestCapPCR(t *testing.T) {
	for _, c := range []struct {
		sel  []uint
		want uint
	}{{[]uint{4, 7, 9, 12}, 12}, {[]uint{12, 9}, 12}, {[]uint{7, 16, 23}, 7}, {[]uint{0}, 0}, {[]uint{15, 17}, 15}} {
		if got, err := tpmseal.CapPCR(c.sel); err != nil || got != c.want {
			t.Errorf("CapPCR(%v) = %d, %v; want %d", c.sel, got, err, c.want)
		}
	}
	for _, sel := range [][]uint{{16}, {16, 23}, {17, 18, 22}, nil, {24}} {
		if _, err := tpmseal.CapPCR(sel); err == nil {
			t.Errorf("CapPCR(%v): accepted", sel)
		}
	}
	s := swtpm.Start(t)
	boot(s, releaseA)
	before, err := tpmseal.ReadPCRs(s.TPM(), []uint{9, 12})
	if err != nil {
		t.Fatal(err)
	}
	for _, sels := range [][][]uint{{{9}, {16}}, nil} {
		if err := tpmseal.Cap(s.TPM(), sels); err == nil {
			t.Fatalf("Cap(%v): accepted", sels)
		}
	}
	after, err := tpmseal.ReadPCRs(s.TPM(), []uint{9, 12})
	if err != nil {
		t.Fatal(err)
	}
	for i := range before {
		if !bytes.Equal(before[i], after[i]) {
			t.Fatal("a refused cap extended a PCR")
		}
	}
}
