package followclerk_test

// REQ: CLK-2, KRN-4

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/clock"
	"github.com/ghbmrk/agentos/broker/follow"
	"github.com/ghbmrk/agentos/broker/follow/followclerk"
	"github.com/ghbmrk/agentos/broker/kernel"
	"github.com/ghbmrk/agentos/broker/kernel/key"
	"github.com/ghbmrk/agentos/broker/update"
)

// shipped is a fresh one-key repository's first root.
func shipped(t *testing.T) []byte {
	t.Helper()
	pub := func() []ed25519.PublicKey {
		p, _, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		return []ed25519.PublicKey{p}
	}
	_, signer, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signers := []ed25519.PublicKey{signer.Public().(ed25519.PublicKey)}
	dir := filepath.Join(t.TempDir(), "repo")
	repo, err := update.Init(dir, update.RootConfig{Root: signers, Targets: signers, Snapshot: pub(), Timestamp: pub(),
		RootThreshold: 1, TargetsThreshold: 1})
	if err != nil {
		t.Fatal(err)
	}
	if err := repo.Sign("root", signer); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(dir, "staged", "root.json"))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// fixedClock is a clock guard that always reads one time.
type fixedClock struct{}

func (fixedClock) Latest(context.Context) (time.Time, clock.Status) {
	return time.Unix(1, 0), clock.Status{}
}

// untouched is a store no test here reaches: a refused step switches nothing.
type untouched struct{ follow.Store }

// A step the clerk's own check refuses fails with the check's code before
// the clerk reads the step or touches the store (CLK-2, #6023).
func TestAStepTheCheckRefusesFailsWithItsCode(t *testing.T) {
	x, err := follow.New(follow.Config{Store: untouched{}, Shipped: shipped(t), Clock: fixedClock{},
		Alert: func(context.Context, string) error { return nil }, Pending: filepath.Join(t.TempDir(), "pending")})
	if err != nil {
		t.Fatal(err)
	}
	st := kernel.PlanStep{Verb: key.ChangeAccount, Clerk: "elsewhere", Args: map[string]string{followclerk.ArgRoot: "d", followclerk.ArgName: "n"}}
	res := followclerk.New(x, nil).Do(kernel.Request{Plan: kernel.Plan{ID: "p", Steps: []kernel.PlanStep{st}}}, nil)
	if res.Outcome != "failed" || res.Detail != "clerk" {
		t.Fatalf("%+v", res)
	}
}
