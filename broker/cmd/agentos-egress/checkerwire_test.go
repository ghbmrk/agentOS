package main

import (
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/checker"
	"github.com/ghbmrk/agentos/broker/checker/checkersock"
	"github.com/ghbmrk/agentos/broker/owner"
	"github.com/ghbmrk/agentos/broker/vault"
)

// REQ: CH-4, CH-10, ARC-1, CRED-1
// SIM-split-wire part 3: with -checker the seed lives in the checker while
// the vault is open, and the broker's code checks and the unlock's share
// the checker's one last-spent step.

// checkerAt serves a checker on r's clock in a fresh socket directory,
// sets it as r's -checker, and returns the checker and its verify client.
func checkerAt(t *testing.T, r *fastRig) (*checker.Checker, *checkersock.Client) {
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
	return ck, checkersock.VerifyClient(filepath.Join(dir, checker.VerifySocket))
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

// The broker's wrong codes never pause the owner's unlock, and a wrong
// unlock code is charged to no bucket of the broker's: the hand socket's
// check counts against the vault's own cap only.
func TestBrokerWrongCodesLeaveTheUnlockOpen(t *testing.T) {
	r := newFastRig(t, true)
	ck, broker := checkerAt(t, r)
	if err := r.c.confirm(r.unlock(t), r.code()); err != nil {
		t.Fatal(err)
	}
	waitUntil(t, "the checker's seed", ck.Held)
	for range checker.MaxWrongCounted - 1 {
		if _, ok, err := broker.VerifyTOTP(wrongOf(r.code()), 0, true); ok || err != nil {
			t.Fatalf("broker's wrong code: %t %v", ok, err)
		}
	}
	r.c.lock()
	r.clk.add(30 * time.Second)
	tk := r.unlock(t)
	if err := r.c.confirm(tk, wrongOf(r.code())); err == nil || !strings.HasPrefix(err.Error(), "wrong code") {
		t.Fatalf("a wrong unlock code: %v", err)
	}
	if err := r.c.confirm(tk, r.code()); err != nil {
		t.Fatal(err)
	}
	waitUntil(t, "the checker's seed", ck.Held)
	r.clk.add(30 * time.Second)
	if _, ok, err := broker.VerifyTOTP(r.code(), 0, true); !ok || err != nil {
		t.Fatalf("the wrong unlock code filled the broker's bucket: %t %v", ok, err)
	}
	if _, _, err := broker.VerifyTOTP(wrongOf(r.code()), 0, true); err != nil {
		t.Fatal(err)
	}
	r.clk.add(30 * time.Second)
	if _, _, err := broker.VerifyTOTP(r.code(), 0, true); err == nil {
		t.Fatal("the broker's bucket did not fill")
	}
	r.c.lock()
	if err := r.c.confirm(r.unlock(t), r.code()); err != nil {
		t.Fatalf("the broker's wrong codes paused the unlock: %v", err)
	}
}

// wrongOf is a code that is not code: its last digit moved on by one.
func wrongOf(code string) string {
	b := []byte(code)
	b[len(b)-1] = '0' + (b[len(b)-1]-'0'+1)%10
	return string(b)
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

// A checker that is down or fails refuses the unlock and every tier-4
// approval: no code passes without the checker's match.
func TestACheckerErrorRefuses(t *testing.T) {
	failing := func(t *testing.T) string {
		dir, err := os.MkdirTemp("", "ck")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { os.RemoveAll(dir) })
		l, err := net.Listen("unix", filepath.Join(dir, checker.HandSocket))
		if err != nil {
			t.Fatal(err)
		}
		mux := http.NewServeMux()
		mux.HandleFunc("GET /state", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(`{"held":false}`)) })
		mux.HandleFunc("PUT /secret", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) })
		mux.HandleFunc("DELETE /secret", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) })
		mux.HandleFunc("POST /verify", func(w http.ResponseWriter, r *http.Request) { http.Error(w, "broken", http.StatusInternalServerError) })
		go http.Serve(l, mux)
		t.Cleanup(func() { l.Close() })
		return dir
	}
	for name, dir := range map[string]func(*testing.T) string{
		"down":    func(t *testing.T) string { return t.TempDir() },
		"failing": failing,
	} {
		t.Run(name, func(t *testing.T) {
			r := newFastRig(t, true)
			r.c.checker = dir(t)
			if err := r.c.confirm(r.unlock(t), r.code()); err != errInternal {
				t.Fatalf("unlock with the checker %s: %v", name, err)
			}
			if r.phase() == open {
				t.Fatal("the vault opened")
			}

			r = newFastRig(t, true)
			checkerAt(t, r)
			if err := r.c.confirm(r.unlock(t), r.code()); err != nil {
				t.Fatal(err)
			}
			r.c.checker = dir(t)
			r.clk.add(30 * time.Second)
			r.c.mu.Lock()
			err := r.c.approvedLocked(r.code(), "a test change")
			r.c.mu.Unlock()
			if err != errInternal {
				t.Fatalf("approval with the checker %s: %v", name, err)
			}
		})
	}
}

// Steps the vault spent stay spent on a checker that starts with fresh
// state (a lost state file, a box newly switched to -checker).
func TestAFreshCheckerKeepsTheVaultsLastStep(t *testing.T) {
	r := newFastRig(t, true)
	code := r.code()
	if err := r.c.confirm(r.unlock(t), code); err != nil {
		t.Fatal(err)
	}
	r.c.lock()
	checkerAt(t, r)
	if err := r.c.confirm(r.unlock(t), code); err == nil || !strings.HasPrefix(err.Error(), "wrong code") {
		t.Fatalf("a code the vault spent unlocked on a fresh checker: %v", err)
	}
}

// The code that confirms a new seed spends its step on the checker too, so
// the broker cannot spend it again; a confirmation the checker refuses
// leaves the channel's seed in the checker.
func TestEnrollCodeSpentOnTheChecker(t *testing.T) {
	r := newSetupRig(t)
	ck, broker := checkerAt(t, r)
	// The keeper hands once, at the unlock, and no later round can put the
	// channel seed back: only confirmEnroll's own hand-back can.
	r.c.keepEvery = time.Hour
	if err := r.c.confirm(r.unlock(t), r.code()); err != nil {
		t.Fatal(err)
	}
	waitUntil(t, "the checker's seed", ck.Held)
	uri, err := r.c.enroll()
	if err != nil {
		t.Fatal(err)
	}
	fresh := enrolledSeed(t, uri)

	// The broker spends this step on the checker first: the vault's own
	// match passes, the checker's refuses, and the channel seed stays.
	r.clk.add(30 * time.Second)
	if _, ok, err := broker.VerifyTOTP(r.code(), 0, true); !ok || err != nil {
		t.Fatalf("broker's code: %t %v", ok, err)
	}
	if ok, err := r.c.confirmEnroll(totp(fresh, r.clk.now())); ok || err != nil {
		t.Fatalf("a step the broker spent confirmed: %t %v", ok, err)
	}
	r.clk.add(30 * time.Second)
	if _, ok, err := broker.VerifyTOTP(r.code(), 0, true); !ok || err != nil {
		t.Fatalf("the checker lost the channel's seed: %t %v", ok, err)
	}

	r.clk.add(30 * time.Second)
	code := totp(fresh, r.clk.now())
	if ok, err := r.c.confirmEnroll(code); !ok || err != nil {
		t.Fatalf("confirm: %t %v", ok, err)
	}
	if _, ok, _ := broker.VerifyTOTP(code, 0, true); ok {
		t.Fatal("the broker spent the code the confirmation spent")
	}
	r.clk.add(30 * time.Second)
	if _, ok, err := broker.VerifyTOTP(totp(fresh, r.clk.now()), 0, true); !ok || err != nil {
		t.Fatalf("the new seed on the checker: %t %v", ok, err)
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
