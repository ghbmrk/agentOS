package recovery

import (
	"bytes"
	"errors"
	"testing"

	"github.com/ghbmrk/agentos/broker/vault"
)

// REQ: CRED-7

// ROTATE-card-atomic (#1440): the card's setup secret is its own vault
// entry so the redactor, which matches whole values,
// covers it in agent-bound output. Storing a card must change the card
// and that entry together. A save failing or the box crashing at any
// save boundary of setup or a rotation leaves the vault, in memory and as
// reopened from the drive, with entries matching the card it holds.

// failingCounter is a PC counter whose Read fails from the armed call on:
// a bound vault reads its counter at the start of every save, so the save
// at that boundary fails before it writes anything.
type failingCounter struct {
	*pcCounter
	reads, failAt int
}

var errCounterGone = errors.New("tpm: not answering")

func (f *failingCounter) Read(ref, auth []byte) (uint64, error) {
	f.reads++
	if f.failAt > 0 && f.reads >= f.failAt {
		return 0, errCounterGone
	}
	return f.pcCounter.Read(ref, auth)
}

// cardCovered checks that v holds a card whose setup secret is a whole
// entry value, so the redactor covers it.
func cardCovered(t *testing.T, v *vault.Vault, at string) Card {
	t.Helper()
	c, err := (&Box{V: v}).LoadCard()
	if err != nil {
		t.Fatalf("%s: %v", at, err)
	}
	r, err := v.Redactor()
	if err != nil {
		t.Fatalf("%s: %v", at, err)
	}
	for name, s := range map[string]string{"setup": c.SetupSecret} {
		out := r.Redact([]byte("the card says " + s + "."))
		if bytes.Contains(out, []byte(s)) {
			t.Fatalf("%s: card %s secret not redacted", at, name)
		}
	}
	return c
}

func TestRotationCardStaysRedactedAtEverySaveBoundary(t *testing.T) {
	parts := []Part{PartSetup, PartGrid}
	for n := 1; ; n++ {
		if n > 50 {
			t.Fatal("rotation never finished")
		}
		x := newBox(t)
		fc := &failingCounter{pcCounter: newPCCounter("host-a")}
		must(t, x.b.V.Anchor(fc))
		before := cardCovered(t, x.b.V, "before")
		p, err := BeginRotate(x.b, parts, Auth{Code: true, Local: true}, Proof{}, t0)
		must(t, err)
		next := newParts(p)
		fc.failAt = fc.reads + n
		_, err = p.Commit(x.b, next, t0)
		fc.failAt = 0
		got := cardCovered(t, x.b.V, "in memory")
		x.b.V.Close()
		v, oerr := vault.OpenSealed(x.b.VaultPath, x.b.KeysPath, Factor(x.rk))
		must(t, oerr)
		onDrive := cardCovered(t, v, "reopened")
		v.Close()
		if err == nil {
			if got.SetupSecret != next.SetupSecret || !bytes.Equal(got.GridSeed, next.GridSeed) {
				t.Fatal("rotation finished without the new card")
			}
			if n == 1 {
				t.Fatal("no save boundary was tested")
			}
			return
		}
		if !errors.Is(err, errCounterGone) {
			t.Fatalf("save %d: %v", n, err)
		}
		// Setup and grid rotate without a slot write, so a failed
		// rotation keeps the old card whole.
		for _, c := range []Card{got, onDrive} {
			if c.SetupSecret != before.SetupSecret || !bytes.Equal(c.GridSeed, before.GridSeed) {
				t.Fatalf("save %d: card changed by a failed rotation", n)
			}
		}
	}
}

// Setup stores the first card the same way: a save failing at any
// boundary leaves no card part, or the whole card.
func TestProvisionCardStaysRedactedAtEverySaveBoundary(t *testing.T) {
	for n := 1; ; n++ {
		if n > 10 {
			t.Fatal("store never finished")
		}
		x := newBox(t)
		fc := &failingCounter{pcCounter: newPCCounter("host-a")}
		must(t, x.b.V.Anchor(fc))
		for _, e := range x.b.V.List() {
			if e.Kind == KindCard || e.Kind == KindCardPart {
				must(t, x.b.V.Delete(e.Name))
			}
		}
		fc.failAt = fc.reads + n
		err := storeCard(x.b, x.card)
		fc.failAt = 0
		if err == nil {
			cardCovered(t, x.b.V, "stored")
			return
		}
		if !errors.Is(err, errCounterGone) {
			t.Fatalf("save %d: %v", n, err)
		}
		for _, e := range x.b.V.List() {
			if e.Kind == KindCard || e.Kind == KindCardPart {
				t.Fatalf("save %d: stray %s after a failed store", n, e.Name)
			}
		}
	}
}
