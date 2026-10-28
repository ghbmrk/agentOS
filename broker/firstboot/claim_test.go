package firstboot

// REQ: HW-10, HW-1

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/ghbmrk/agentos/broker/card"
	"github.com/ghbmrk/agentos/broker/change"
	"github.com/ghbmrk/agentos/broker/claim"
	"github.com/ghbmrk/agentos/broker/recovery"
)

// canaryRand is the box's randomness in this test: a fixed canary stream
// that counts what is drawn, so any secret made from it is both counted
// and findable on disk.
type canaryRand struct{ n int }

var canary = []byte("CANARY-BOX-RAND-")

func (c *canaryRand) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = canary[(c.n+i)%len(canary)]
	}
	c.n += len(p)
	return len(p), nil
}

// claimBoot is one start of a preloaded box from the partition at dir.
type claimBoot struct {
	step      *ClaimedCard
	generated int
	shown     *card.Card
	b         *boot
}

func startPreloaded(t *testing.T, dir, bootID string, rnd io.Reader) *claimBoot {
	t.Helper()
	cl, err := claim.Open(claim.Config{
		Store:  change.FileStore{Path: filepath.Join(dir, "var", "lib", "agentos", "claim.json")},
		BootID: func() (string, error) { return bootID, nil },
		Rand:   rnd,
	})
	if err != nil {
		t.Fatal(err)
	}
	cb := &claimBoot{b: &boot{t: t, dir: dir}}
	cb.step, err = NewClaimedCard(cl, change.FileStore{Path: filepath.Join(dir, "var", "lib", "agentos", "firstboot-card.json")},
		card.DisplayConfig{Authority: testAuthority(t),
			Rand: rnd,
			Generate: func(r io.Reader) (*card.Card, error) {
				cb.generated++
				c, err := card.Generate(r)
				if err == nil {
					cp := *c
					cp.GridSeed = bytes.Clone(c.GridSeed)
					cb.shown = &cp
				}
				return c, err
			},
			Provision: cb.b.provision,
		})
	if err != nil {
		t.Fatal(err)
	}
	return cb
}

// Acceptance 2: before the claim, a scan of the disk finds no vault key,
// card text or approval-code seed. The box draws no randomness for a
// secret before the claim (the canary stream is untouched), no card is
// generated, and no vault exists; the card made at the claim was nowhere
// on the pre-claim disk.
func TestNoSecretBeforeClaim(t *testing.T) {
	dir := t.TempDir()
	for _, d := range []string{"var/lib/agentos", "var/log/agentos", "egress"} {
		if err := os.MkdirAll(filepath.Join(dir, d), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	captureLogs(t, dir)
	code, err := claim.NewCode(nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := claim.Seal(change.FileStore{Path: filepath.Join(dir, "var", "lib", "agentos", "claim.json")}, code, nil, nil); err != nil {
		t.Fatal(err)
	}
	rnd := &canaryRand{}
	cb := startPreloaded(t, dir, "boot-1", rnd)
	if err := cb.step.Hold(); !errors.Is(err, ErrUnclaimed) {
		t.Fatalf("hold before claim: %v", err)
	}
	if cb.step.Card() != nil {
		t.Fatal("card step before claim")
	}
	bad := []byte(code)
	bad[0] ^= 1
	if _, err := cb.step.Claim(string(bad)); !errors.Is(err, claim.ErrWrongCode) {
		t.Fatalf("wrong code: %v", err)
	}
	cb = startPreloaded(t, dir, "boot-2", rnd)

	if rnd.n != 0 || cb.generated != 0 {
		t.Fatalf("before the claim the box drew %d random bytes and made %d cards", rnd.n, cb.generated)
	}
	for _, f := range []string{"egress/vault", "egress/vault.keys", "egress/setup.key", "egress/unlock.json", "var/lib/agentos/firstboot-card.json"} {
		if _, err := os.Stat(filepath.Join(dir, f)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("%s exists before the claim", f)
		}
	}
	snap := t.TempDir()
	if err := os.CopyFS(snap, os.DirFS(dir)); err != nil {
		t.Fatal(err)
	}
	s, err := recovery.NewScanner([]recovery.Needle{{Name: "box randomness", Value: canary}})
	if err != nil {
		t.Fatal(err)
	}
	if found, skipped, err := s.Tree(snap); err != nil || len(found)+len(skipped) > 0 {
		t.Fatalf("canary before claim: %v %v %v", found, skipped, err)
	}

	tok, err := cb.step.Claim(code)
	if err != nil {
		t.Fatalf("claim: %v", err)
	}
	if !cb.step.Claimant(tok) || cb.step.Card() == nil || cb.generated != 1 || rnd.n == 0 {
		t.Fatal("claim did not start the card step from the box's randomness")
	}
	if err := cb.step.Hold(); !errors.Is(err, ErrCardPending) {
		t.Fatalf("hold after claim: %v", err)
	}
	// The card made at the claim was not on the disk before it.
	scan(t, snap, cb.shown)

	// A second phone, and a restart, find the box claimed; the card step
	// comes back on its own.
	again := startPreloaded(t, dir, "boot-3", &canaryRand{})
	if _, err := again.step.Claim(code); !errors.Is(err, claim.ErrAlreadyClaimed) {
		t.Fatalf("second claim: %v", err)
	}
	if again.step.Card() == nil || !again.step.Claimant(tok) {
		t.Fatal("claimed box lost its card step or claimant on restart")
	}
}
