package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/checker"
	"github.com/ghbmrk/agentos/broker/checker/checkersock"
	"github.com/ghbmrk/agentos/broker/owner"
	"github.com/ghbmrk/agentos/broker/sockets"
	"github.com/ghbmrk/agentos/broker/vault"
)

// REQ: CH-4, CH-10, ARC-1, CRED-1
// SIM-split-wire part 3: with -checker the seed lives in the checker while
// the vault is open, and the broker's code checks and the unlock's share
// the checker's one last-spent step.

// fakeChecker serves the checker's hand socket in the protocol this
// process's clients speak (holder.Keeper's GET /state, PUT and DELETE
// /secret, and checkersock's POST /verify), and a broker verify socket on
// the same seed and last spent step. Wrong codes on the broker socket are
// counted toward a pause; the hand socket's are charged to nothing.
type fakeChecker struct {
	now   func() time.Time
	mu    sync.Mutex
	seed  []byte
	last  int64
	wrong int
}

// fakeMaxWrong is the broker's wrong codes the fake counts before it
// pauses its checks.
const fakeMaxWrong = 20

func (f *fakeChecker) Held() bool { f.mu.Lock(); defer f.mu.Unlock(); return len(f.seed) > 0 }

func (f *fakeChecker) Hand(seed []byte) { f.mu.Lock(); f.seed = bytes.Clone(seed); f.mu.Unlock() }

func (f *fakeChecker) verify(counted bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req checkersock.VerifyRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		f.mu.Lock()
		defer f.mu.Unlock()
		switch {
		case len(f.seed) == 0:
			http.Error(w, checkersock.ErrNoSeed.Error(), http.StatusServiceUnavailable)
			return
		case counted && f.wrong >= fakeMaxWrong:
			w.Header().Set(checkersock.PausedHeader, strconv.FormatInt(f.now().Add(time.Minute).Unix(), 10))
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		step, ok := owner.MatchTOTP(f.seed, req.Code, f.now(), max(req.After, f.last))
		if ok {
			f.last = step
		} else if counted {
			f.wrong++
		}
		json.NewEncoder(w).Encode(checkersock.VerifyResponse{Step: step, OK: ok})
	}
}

func (f *fakeChecker) handMux() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /state", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]bool{"held": f.Held()})
	})
	mux.HandleFunc("PUT /secret", func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		f.Hand(b)
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("DELETE /secret", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.seed = nil
		f.mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("POST /verify", f.verify(false))
	return mux
}

// checkerAt serves a fake checker on r's clock in a fresh socket
// directory, sets it as r's -checker, and returns the checker and a
// verify client for its broker socket.
func checkerAt(t *testing.T, r *fastRig) (*fakeChecker, *checkersock.Client) {
	t.Helper()
	dir, err := os.MkdirTemp("", "ck")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	ck := &fakeChecker{now: r.clk.now}
	brokerMux := http.NewServeMux()
	brokerMux.HandleFunc("POST /verify", ck.verify(true))
	for name, h := range map[string]http.Handler{checker.HandSocket: ck.handMux(), "verify.sock": brokerMux} {
		l, err := sockets.ListenPeers(filepath.Join(dir, name), os.Getuid())
		if err != nil {
			t.Fatal(err)
		}
		srv := &http.Server{Handler: h}
		go srv.Serve(l)
		t.Cleanup(func() { srv.Close() })
	}
	r.c.checker = dir
	r.c.keepEvery = 5 * time.Millisecond
	return ck, checkersock.VerifyClient(filepath.Join(dir, "verify.sock"))
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
	if _, _, err := broker.VerifyTOTP(r.code(), 0, true); err != checkersock.ErrNoSeed {
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
	for range fakeMaxWrong - 1 {
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

// The hand socket's check is charged to no checker bucket, so the vault's
// durable cap alone limits tier-4 codes: once it is reached, the right code
// is refused too.
func TestCapRefusesTheRightTier4Code(t *testing.T) {
	r := newFastRig(t, true)
	ck, _ := checkerAt(t, r)
	if err := r.c.confirm(r.unlock(t), r.code()); err != nil {
		t.Fatal(err)
	}
	waitUntil(t, "the checker's seed", ck.Held)
	r.clk.add(30 * time.Second)
	r.c.mu.Lock()
	defer r.c.mu.Unlock()
	for i := range MaxWrongCodes {
		if err := r.c.approvedLocked(wrongOf(r.code()), "a test change"); err == nil {
			t.Fatalf("wrong code %d approved", i)
		}
	}
	if err := r.c.approvedLocked(r.code(), "a test change"); err == nil || !strings.HasPrefix(err.Error(), "Too many wrong codes") {
		t.Fatalf("the right code after the cap: %v", err)
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

// REQ: CH-4
// -checker fails closed on a directory where a uid other than root or this
// one could plant a listener at hand.sock and take the seed (#5649, W-3).
func TestCheckerFlag(t *testing.T) {
	euid := uint32(os.Geteuid())
	if err := checkerFlagOK(""); err != nil {
		t.Errorf("empty -checker: %v", err)
	}
	if checkerFlagOK("run/agentos-checker") == nil {
		t.Error("accepted a relative -checker")
	}
	ok := filepath.Join(t.TempDir(), "checker")
	if err := os.Mkdir(ok, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := checkerFlagAs(ok, euid); err != nil {
		t.Fatalf("a directory only this uid writes: %v", err)
	}
	// A relative name is refused even where it would name a safe
	// directory: the kernel resolves it from the real working directory.
	t.Chdir(filepath.Dir(ok))
	if checkerFlagAs(filepath.Base(ok), euid) == nil {
		t.Error("accepted a relative -checker naming a safe directory")
	}
	shared := filepath.Join(t.TempDir(), "shared")
	open := filepath.Join(t.TempDir(), "open")
	under := filepath.Join(open, "checker")
	other := filepath.Join(t.TempDir(), "other")
	link := filepath.Join(t.TempDir(), "link")
	for _, d := range []string{shared, open, under, other} {
		if err := os.Mkdir(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for _, d := range []string{shared, open} {
		if err := os.Chmod(d, 0o777); err != nil { // no sticky bit
			t.Fatal(err)
		}
	}
	if err := os.Symlink(ok, link); err != nil {
		t.Fatal(err)
	}
	// ok/lnk/../y is ok/y to Clean, but the kernel follows lnk first and
	// lands in open/y, a directory every uid writes (#5663).
	for _, d := range []string{filepath.Join(ok, "y"), filepath.Join(open, "sub"), filepath.Join(open, "y")} {
		if err := os.Mkdir(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(filepath.Join(open, "sub"), filepath.Join(ok, "lnk")); err != nil {
		t.Fatal(err)
	}
	dotdot := ok + "/lnk/../y"
	file := filepath.Join(ok, "file")
	if err := os.WriteFile(file, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	trust := euid
	if euid == 0 {
		// root is always trusted, so the owner case needs another owner.
		if err := os.Chown(other, 4242, 4242); err != nil {
			t.Fatal(err)
		}
	} else {
		trust = euid + 1
	}
	for name, c := range map[string]struct {
		dir  string
		euid uint32
	}{
		"writable by others":       {shared, euid},
		"a parent writable by all": {under, euid},
		"another uid's":            {other, trust},
		"a link":                   {link, euid},
		"a link then ..":           {dotdot, euid},
		"a file":                   {file, euid},
		"a trailing slash":         {ok + "/", euid},
		"missing":                  {filepath.Join(ok, "absent"), euid},
	} {
		if checkerFlagAs(c.dir, c.euid) == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// handSock is a checker hand socket whose n-th PUT /secret (from 0) gets
// put(n) as its status, holding the seed only on 204, and whose POST
// /verify is verify. GET /state and DELETE /secret keep the seed held.
type handSock struct {
	mu   sync.Mutex
	puts int
	held bool
}

func (h *handSock) Held() bool { h.mu.Lock(); defer h.mu.Unlock(); return h.held }

func handAt(t *testing.T, put func(n int) int, verify http.HandlerFunc) (string, *handSock) {
	t.Helper()
	dir, err := os.MkdirTemp("", "ck")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	h := &handSock{}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /state", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]bool{"held": h.Held()})
	})
	mux.HandleFunc("PUT /secret", func(w http.ResponseWriter, r *http.Request) {
		h.mu.Lock()
		code := put(h.puts)
		h.puts++
		h.held = h.held || code == http.StatusNoContent
		h.mu.Unlock()
		w.WriteHeader(code)
	})
	mux.HandleFunc("DELETE /secret", func(w http.ResponseWriter, r *http.Request) {
		h.mu.Lock()
		h.held = false
		h.mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("POST /verify", verify)
	l, err := sockets.ListenPeers(filepath.Join(dir, checker.HandSocket), os.Getuid())
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: mux}
	go srv.Serve(l)
	t.Cleanup(func() { srv.Close() })
	return dir, h
}

// verifyAnswer answers every POST /verify with match, whatever the code.
func verifyAnswer(match bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(checkersock.VerifyResponse{Step: 1 << 40, OK: match})
	}
}

// pausedUntil answers every POST /verify with a paused bucket ending at until.
func pausedUntil(until time.Time) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set(checkersock.PausedHeader, strconv.FormatInt(until.Unix(), 10))
		w.WriteHeader(http.StatusTooManyRequests)
	}
}

func always(code int) func(int) int { return func(int) int { return code } }

// CH-4 (#5050 item 5): a checker that refuses the seed refuses the unlock,
// even though its verify would match: no code is checked on a checker the
// seed did not reach.
func TestAFailedHandRefusesTheUnlock(t *testing.T) {
	r := newFastRig(t, true)
	r.c.checker, _ = handAt(t, always(http.StatusInternalServerError), verifyAnswer(true))
	if err := r.c.confirm(r.unlock(t), r.code()); err != errInternal {
		t.Fatalf("unlock with a checker that refused the seed: %v", err)
	}
	if r.phase() == open {
		t.Fatal("the vault opened")
	}
}

// CH-4 (#5050 item 6): a refused enrolment whose hand-back of the channel
// seed fails takes the pending seed back, so the checker holds none.
func TestAFailedHandBackLeavesNoSeed(t *testing.T) {
	r := newSetupRig(t)
	checkerAt(t, r)
	r.c.keepEvery = time.Hour
	if err := r.c.confirm(r.unlock(t), r.code()); err != nil {
		t.Fatal(err)
	}
	uri, err := r.c.enroll()
	if err != nil {
		t.Fatal(err)
	}
	fresh := enrolledSeed(t, uri)
	// The pending seed's hand succeeds and the checker refuses its code;
	// the hand-back of the channel's seed then fails.
	dir, h := handAt(t, func(n int) int {
		if n == 0 {
			return http.StatusNoContent
		}
		return http.StatusInternalServerError
	}, verifyAnswer(false))
	r.c.checker = dir
	r.clk.add(30 * time.Second)
	if ok, err := r.c.confirmEnroll(totp(fresh, r.clk.now())); ok || err != nil {
		t.Fatalf("a code the checker refused confirmed: %t %v", ok, err)
	}
	if h.puts != 2 {
		t.Fatalf("%d hands, want the pending seed's and the failed hand-back", h.puts)
	}
	if h.Held() {
		t.Fatal("the checker kept the pending seed after a failed hand-back")
	}
}

// CH-18 (#5050 items 7 and 8): a paused checker reads as locked out at the
// unlock and as paused at the enrolment, never as an internal error.
func TestAPausedCheckerReadsAsPaused(t *testing.T) {
	r := newFastRig(t, true)
	until := r.clk.now().Add(time.Minute)
	r.c.checker, _ = handAt(t, always(http.StatusNoContent), pausedUntil(until))
	err := r.c.confirm(r.unlock(t), r.code())
	if err == nil || err.Error() != errLockedOut(until).Error() {
		t.Fatalf("unlock on a paused checker: %v", err)
	}

	r = newSetupRig(t)
	checkerAt(t, r)
	r.c.keepEvery = time.Hour
	if err := r.c.confirm(r.unlock(t), r.code()); err != nil {
		t.Fatal(err)
	}
	uri, err := r.c.enroll()
	if err != nil {
		t.Fatal(err)
	}
	fresh := enrolledSeed(t, uri)
	until = r.clk.now().Add(time.Minute)
	r.c.checker, _ = handAt(t, always(http.StatusNoContent), pausedUntil(until))
	r.clk.add(30 * time.Second)
	_, err = r.c.confirmEnroll(totp(fresh, r.clk.now()))
	var pe *pausedError
	if !errors.As(err, &pe) || !pe.until.Equal(until) {
		t.Fatalf("enrolment on a paused checker: %v", err)
	}
}

// CH-4 (#5050 item 9): a checker that drops the connection mid-request
// refuses, and is not read as one that is not running.
func TestAMidRequestResetIsNotDown(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "v.sock")
	l, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			c.Read(make([]byte, 1)) // leave the rest unread so the close resets
			c.Close()
		}
	}()
	_, ok, err := checkersock.VerifyClient(path).VerifyTOTP("123456", 0, true)
	if ok || err == nil || errors.Is(err, checkersock.ErrDown) {
		t.Fatalf("a reset mid-request: %t %v", ok, err)
	}
	var oe *net.OpError
	if !errors.As(err, &oe) || oe.Op == "dial" {
		t.Fatalf("the reset is not a non-dial OpError, so this test checks nothing: %v", err)
	}
}

// REQ: CH-4
// The -checker help leads with the safe value, then says why any other
// directory is refused: a planted listener receives the seed and approves
// every act (W-3, #5633, #5649).
func TestCheckerHelpNamesTheListenerCaveat(t *testing.T) {
	if !strings.HasPrefix(checkerHelp, "leave empty") {
		t.Errorf("-checker help does not lead with the safe value: %s", checkerHelp)
	}
	for _, want := range []string{"receives the seed", "is refused at start"} {
		if !strings.Contains(checkerHelp, want) {
			t.Errorf("-checker help lacks %q: %s", want, checkerHelp)
		}
	}
}
