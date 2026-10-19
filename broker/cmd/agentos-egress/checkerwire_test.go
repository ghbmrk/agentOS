package main

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/checker"
	"github.com/ghbmrk/agentos/broker/owner"
	"github.com/ghbmrk/agentos/broker/vault"
)

// REQ: CH-4, CH-10, ARC-1, CRED-1
// SIM-split-wire part 3: with -checker the seed lives in the checker while
// the vault is open, and the broker's code checks and the unlock's share
// the checker's one last-spent step.

// checkerAt serves a checker on r's clock in a fresh socket directory,
// sets it as r's -checker, and returns the checker and its verify client.
func checkerAt(t *testing.T, r *fastRig) (*checker.Checker, *checker.Client) {
	t.Helper()
	dir, err := os.MkdirTemp("", "ck")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	ck, err := checker.New(checker.Config{StatePath: filepath.Join(t.TempDir(), "checker.json"), Now: r.clk.now})
	if err != nil {
		t.Fatal(err)
	}
	var ls []net.Listener
	for _, name := range []string{checker.HandSocket, checker.VerifySocket, checker.RedeemSocket} {
		l, err := checker.Listen(filepath.Join(dir, name), os.Getuid())
		if err != nil {
			t.Fatal(err)
		}
		ls = append(ls, l)
	}
	go ck.Serve(ls[0], ls[1], ls[2])
	t.Cleanup(func() {
		for _, l := range ls {
			l.Close()
		}
	})
	r.c.checker = dir
	r.c.keepEvery = 5 * time.Millisecond
	return ck, checker.VerifyClient(filepath.Join(dir, checker.VerifySocket))
}

// The unlock hands the checker the seed; the broker's code is checked
// there; a lock takes the seed back, and no keeper hands it after.
func TestCheckerHoldsTheSeedWhileOpen(t *testing.T) {
	r := newFastRig(t, true)
	ck, broker := checkerAt(t, r)
	if err := r.c.confirm(r.unlock(t), r.code()); err != nil {
		t.Fatal(err)
	}
	waitUntil(t, "the checker's seed", ck.Held)
	r.clk.add(30 * time.Second)
	if _, ok, err := broker.VerifyTOTP(r.code(), 0, true); !ok || err != nil {
		t.Fatalf("broker's code on the checker: %t %v", ok, err)
	}
	r.c.lock()
	if ck.Held() {
		t.Fatal("the checker kept the seed after the lock")
	}
	time.Sleep(30 * time.Millisecond) // several keeper rounds
	if ck.Held() {
		t.Fatal("a keeper handed the seed after the lock")
	}
	if _, _, err := broker.VerifyTOTP(r.code(), 0, true); err != checker.ErrNoSeed {
		t.Fatalf("checker verified with the vault locked: %v", err)
	}
}

// One store: a code the broker spent on the checker does not then unlock
// the vault, and a pending unlock leaves no seed in the checker.
func TestBrokerAndUnlockSpendOneStep(t *testing.T) {
	r := newFastRig(t, true)
	ck, broker := checkerAt(t, r)
	ck.Hand(r.seed) // as a still-open session would have
	tk := r.unlock(t)
	code := r.code()
	if _, ok, err := broker.VerifyTOTP(code, 0, true); !ok || err != nil {
		t.Fatalf("broker's code: %t %v", ok, err)
	}
	if err := r.c.confirm(tk, code); err == nil || !strings.HasPrefix(err.Error(), "wrong code") {
		t.Fatalf("a code the broker spent unlocked: %v", err)
	}
	if ck.Held() {
		t.Fatal("a pending unlock left the seed in the checker")
	}
	r.clk.add(30 * time.Second)
	if err := r.c.confirm(tk, r.code()); err != nil {
		t.Fatal(err)
	}
	// And the other way: the step the unlock spent is spent for the broker.
	waitUntil(t, "the checker's seed", ck.Held)
	if _, ok, _ := broker.VerifyTOTP(r.code(), 0, true); ok {
		t.Fatal("the broker spent the step the unlock spent")
	}
}

// With -checker this process's verify socket refuses code-generator codes
// and still redeems the unlock proof once.
func TestVaultVerifyKeepsOnlyTheProof(t *testing.T) {
	r := newFastRig(t, true)
	checkerAt(t, r)
	tk := r.unlock(t)
	if err := r.c.confirm(tk, r.code()); err != nil {
		t.Fatal(err)
	}
	r.clk.add(30 * time.Second)
	if _, ok, err := r.c.verify(r.code(), 0, true); ok || err != errOnChecker {
		t.Fatalf("vault process verified a code: %t %v", ok, err)
	}
	if _, ok, err := r.c.verify(owner.UnlockProofPrefix+tk, 0, true); !ok || err != nil {
		t.Fatalf("proof: %t %v", ok, err)
	}
}

// A replaced seed reaches the checker: codes from the old one stop there.
func TestCheckerGetsAReplacedSeed(t *testing.T) {
	r := newFastRig(t, true)
	ck, broker := checkerAt(t, r)
	if err := r.c.confirm(r.unlock(t), r.code()); err != nil {
		t.Fatal(err)
	}
	waitUntil(t, "the checker's seed", ck.Held)
	fresh := []byte(synthetic(t, "seed-new-"))
	r.c.mu.Lock()
	err := r.c.v.Put(SeedName, vault.KindTOTPSeed, fresh)
	r.c.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	waitUntil(t, "the new seed", func() bool {
		r.clk.add(30 * time.Second)
		_, ok, _ := broker.VerifyTOTP(totp(fresh, r.clk.now()), 0, true)
		return ok
	})
	r.clk.add(30 * time.Second)
	if _, ok, _ := broker.VerifyTOTP(r.code(), 0, true); ok {
		t.Fatal("the old seed's code still verifies")
	}
}

// -checker names an absolute directory.
func TestCheckerFlag(t *testing.T) {
	if checkerFlagOK("run/agentos-checker") == nil {
		t.Error("accepted a relative -checker")
	}
	for _, ok := range []string{"", "/run/agentos-checker"} {
		if err := checkerFlagOK(ok); err != nil {
			t.Errorf("-checker %q: %v", ok, err)
		}
	}
}
