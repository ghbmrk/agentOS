package codecheck

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/clerk/clerkkey"
	"github.com/ghbmrk/agentos/broker/clerk/codecheck/totp"
	"github.com/ghbmrk/agentos/broker/clerk/codecheck/wire"
	"github.com/ghbmrk/agentos/broker/clerk/handoff"
	"github.com/ghbmrk/agentos/broker/kernel"
)

// REQ: CH-4, CH-10, CLK-1, STO-2

type clock struct{ t time.Time }

func (c *clock) now() time.Time            { return c.t }
func (c *clock) add(d time.Duration)       { c.t = c.t.Add(d) }
func code(seed []byte, t time.Time) string { return totp.At(seed, t) }

// checkerKey is a synthetic clerk key for the checker, as the kernel
// derives it from its clerk root key.
func checkerKey(t *testing.T) (sealer []byte, sign ed25519.PrivateKey) {
	t.Helper()
	var root [clerkkey.Len]byte
	for i := range root {
		root[i] = byte(0x30 + i)
	}
	k, err := clerkkey.Derive(&root, handoff.CheckerName)
	if err != nil {
		t.Fatal(err)
	}
	defer k.Wipe()
	if sealer, err = k.Sealer(); err != nil {
		t.Fatal(err)
	}
	if sign, err = k.Signer(); err != nil {
		t.Fatal(err)
	}
	return sealer, sign
}

func syntheticSeed() []byte {
	h := sha256.Sum256([]byte("codecheck synthetic seed"))
	return h[:20]
}

func newChecker(t *testing.T, clk *clock) (*Checker, string) {
	t.Helper()
	state := filepath.Join(t.TempDir(), "state.json")
	c, err := New(Config{StatePath: state, Now: clk.now})
	if err != nil {
		t.Fatal(err)
	}
	return c, state
}

// open hands c the seed as the unlock step and the kernel do: sealed under
// the checker's key, with the step setup's confirming code spent.
func open(t *testing.T, c *Checker, seed []byte, step int64) ed25519.PublicKey {
	t.Helper()
	sealer, sign := checkerKey(t)
	blob, err := handoff.SealCodeSeed(sealer, handoff.CodeSeed{Seed: seed, Step: step})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Open(sealer, sign, blob); err != nil {
		t.Fatal(err)
	}
	return sign.Public().(ed25519.PublicKey)
}

func steps(n int) []kernel.CodeStep {
	s := make([]kernel.CodeStep, n)
	for i := range s {
		s[i] = kernel.CodeStep{Plan: "p1", Index: i, Hash: sha256.Sum256([]byte("plan p1"))}
	}
	return s
}

// Acceptance (brief MIG-4-exit c2): a checker started without the unlock
// step's hand-off verifies nothing, however right the code; a hand-off
// sealed under another key, or a changed one, gives it nothing either.
// Fails if the seed could reach the checker any other way, or if a
// checker with no seed answered as if a code were wrong rather than off.
func TestSeedComesOnlyFromTheUnlockStep(t *testing.T) {
	clk := &clock{t: time.Unix(1_800_000_000, 0)}
	c, _ := newChecker(t, clk)
	seed := syntheticSeed()
	if _, err := c.Verify(code(seed, clk.now()), 0, true, steps(1)); !errors.Is(err, ErrNoSeed) {
		t.Fatalf("a checker with no hand-off: %v", err)
	}
	sealer, sign := checkerKey(t)
	other := bytes.Repeat([]byte{9}, 32)
	blob, _ := handoff.SealCodeSeed(other, handoff.CodeSeed{Seed: seed})
	if err := c.Open(sealer, sign, blob); err == nil {
		t.Fatal("a hand-off sealed under another key opened")
	}
	blob, _ = handoff.SealCodeSeed(sealer, handoff.CodeSeed{Seed: seed})
	cut := bytes.Clone(blob)
	cut[len(cut)-1] ^= 1
	if err := c.Open(sealer, sign, cut); err == nil {
		t.Fatal("a changed hand-off opened")
	}
	if c.Held() || c.Public() != nil {
		t.Fatal("a refused hand-off left a seed or a key")
	}
	if _, err := c.Verify(code(seed, clk.now()), 0, true, nil); !errors.Is(err, ErrNoSeed) {
		t.Fatalf("after refused hand-offs: %v", err)
	}
	if err := c.Open(sealer, sign, blob); err != nil || !c.Held() {
		t.Fatalf("the unlock step's hand-off: %v", err)
	}
	if r, err := c.Verify(code(seed, clk.now()), 0, true, nil); err != nil || !r.OK {
		t.Fatalf("a right code after the hand-off: %+v %v", r, err)
	}
}

// Acceptance: a verified code signs one approval of exactly the steps it
// was given, under the checker's key, in the form the kernel checks
// (kernel.CodeMsg); it verifies for no other list of steps and under no
// other key; a wrong code and a code with no steps sign nothing. Fails if
// an approval could be moved to steps the code was not given.
func TestVerifiedCodeSignsOnlyTheNamedSteps(t *testing.T) {
	clk := &clock{t: time.Unix(1_800_000_000, 0)}
	c, _ := newChecker(t, clk)
	seed := syntheticSeed()
	pub := open(t, c, seed, 0)
	named := steps(3)
	wrong := "000000"
	if wrong == code(seed, clk.now()) {
		wrong = "000001"
	}
	if r, err := c.Verify(wrong, 0, true, named); err != nil || r.OK || r.Approval != nil {
		t.Fatalf("a wrong code: %+v %v", r, err)
	}
	r, err := c.Verify(code(seed, clk.now()), 0, true, named)
	if err != nil || !r.OK || r.Approval == nil {
		t.Fatalf("a right code: %+v %v", r, err)
	}
	a := *r.Approval
	if !a.By.Equal(pub) || !ed25519.Verify(pub, kernel.CodeMsg(named), a.Sig) {
		t.Fatal("the approval is not the checker's signature over the named steps")
	}
	moved := steps(3)
	moved[2].Index = 7
	for name, s := range map[string][]kernel.CodeStep{"fewer": named[:2], "another step": moved, "more": steps(4)} {
		if ed25519.Verify(pub, kernel.CodeMsg(s), a.Sig) {
			t.Errorf("the approval verifies for %s steps", name)
		}
	}
	_, otherSign, _ := ed25519.GenerateKey(nil)
	if ed25519.Verify(otherSign.Public().(ed25519.PublicKey), kernel.CodeMsg(named), a.Sig) {
		t.Fatal("the approval verifies under another key")
	}
	clk.add(30 * time.Second)
	if r, err := c.Verify(code(seed, clk.now()), 0, true, nil); err != nil || !r.OK || r.Approval != nil {
		t.Fatalf("a code with no steps: %+v %v", r, err)
	}
	if _, err := c.Verify(code(seed, clk.now()), 0, true, steps(kernel.MaxCodeSteps+1)); err == nil {
		t.Fatal("a code approved more steps than the kernel admits")
	}
	clk.add(30 * time.Second)
	most := steps(kernel.MaxCodeSteps)
	if r, err := c.Verify(code(seed, clk.now()), 0, true, most); err != nil || !r.OK || r.Approval == nil ||
		!ed25519.Verify(pub, kernel.CodeMsg(most), r.Approval.Sig) {
		t.Fatalf("a code for the most steps the kernel admits: %+v %v", r, err)
	}
}

// The state file reads back at its edges: a last step of 0 opens, a
// negative one does not. Fails if New's bound on the step is off by one.
func TestStateFileStepBound(t *testing.T) {
	for raw, ok := range map[string]bool{`{"last_step":0}`: true, `{"last_step":-1}`: false} {
		state := filepath.Join(t.TempDir(), "state.json")
		if err := os.WriteFile(state, []byte(raw), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := New(Config{StatePath: state}); (err == nil) != ok {
			t.Errorf("%s: %v", raw, err)
		}
	}
}

// The lockout (CH-4): MaxWrongCounted wrong codes pause the counted bucket,
// even for the right code, and leave the silent bucket open; the pause ends
// once the oldest wrong code leaves the window.
func TestWrongCodesPauseTheirBucket(t *testing.T) {
	clk := &clock{t: time.Unix(1_800_000_000, 0)}
	c, _ := newChecker(t, clk)
	seed := syntheticSeed()
	open(t, c, seed, 0)
	wrong := "000000"
	if wrong == code(seed, clk.now()) {
		wrong = "000001"
	}
	for i := 0; i < MaxWrongCounted; i++ {
		if r, err := c.Verify(wrong, 0, true, steps(1)); r.OK || err != nil {
			t.Fatalf("try %d: %+v %v", i, r, err)
		}
	}
	var p *PausedError
	if r, err := c.Verify(code(seed, clk.now()), 0, true, steps(1)); r.OK || !errors.As(err, &p) {
		t.Fatalf("not paused: %+v %v", r, err)
	}
	if r, err := c.Verify(code(seed, clk.now()), 0, false, nil); !r.OK || err != nil {
		t.Fatalf("the silent bucket: %+v %v", r, err)
	}
	clk.add(Window + time.Second)
	if _, err := c.Verify(wrong, 0, true, nil); err != nil {
		t.Fatalf("still paused after the window: %v", err)
	}
	for i := 0; i < MaxWrongSilent; i++ {
		c.Verify(wrong, 0, false, nil)
	}
	if _, err := c.Verify(code(seed, clk.now()), 0, false, nil); !errors.As(err, &p) {
		t.Fatalf("the silent bucket did not pause: %v", err)
	}
	if r, err := c.Verify(code(seed, clk.now()), 0, true, nil); !r.OK || err != nil {
		t.Fatalf("silent codes paused the owner's: %+v %v", r, err)
	}
}

// A spent step stays spent across a restart, and the state file holds no
// run of the seed; the step setup's confirming code spent is spent here
// too, and after is honoured.
func TestSpentStepSurvivesRestart(t *testing.T) {
	clk := &clock{t: time.Unix(1_800_000_000, 0)}
	c, state := newChecker(t, clk)
	seed := syntheticSeed()
	open(t, c, seed, 0)
	now := code(seed, clk.now())
	if r, err := c.Verify(now, 0, true, nil); !r.OK || err != nil {
		t.Fatalf("%+v %v", r, err)
	}
	again, err := New(Config{StatePath: state, Now: clk.now})
	if err != nil {
		t.Fatal(err)
	}
	open(t, again, seed, 0)
	if r, _ := again.Verify(now, 0, true, nil); r.OK {
		t.Fatal("a spent step verified after a restart")
	}
	raw, err := os.ReadFile(state)
	if err != nil || bytes.Contains(raw, seed[:8]) {
		t.Fatalf("state file: %v", err)
	}
	clk.add(30 * time.Second)
	fresh, _ := newChecker(t, clk)
	open(t, fresh, seed, clk.now().Unix()/30)
	if r, _ := fresh.Verify(code(seed, clk.now()), 0, true, nil); r.OK {
		t.Fatal("setup's confirming step verified again")
	}
	clk.add(30 * time.Second)
	if r, _ := fresh.Verify(code(seed, clk.now()), clk.now().Unix()/30, true, nil); r.OK {
		t.Fatal("a step at after verified")
	}
}

// verify.sock serves POST /verify alone, answers each refusal with its own
// status, and the dial-only client reads each back.
func TestSocketServesVerifyAlone(t *testing.T) {
	clk := &clock{t: time.Unix(1_800_000_000, 0)}
	c, _ := newChecker(t, clk)
	srv := httptest.NewServer(c.Handler())
	defer srv.Close()
	for _, p := range []string{"/redeem", "/allow", "/release", "/revoke", "/secret", "/state"} {
		resp, err := http.Post(srv.URL+p, "application/json", strings.NewReader("{}"))
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound && resp.StatusCode != http.StatusMethodNotAllowed {
			t.Errorf("%s: %d", p, resp.StatusCode)
		}
	}
	sock := filepath.Join(t.TempDir(), VerifySocket)
	ln, err := Listen(sock, os.Getuid())
	if err != nil {
		t.Fatal(err)
	}
	go c.Serve(ln)
	defer ln.Close()
	cl := wire.NewClient(sock)
	seed := syntheticSeed()
	if _, err := cl.Verify(wire.Request{Code: code(seed, clk.now()), Counted: true}); !errors.Is(err, wire.ErrNoSeed) {
		t.Fatalf("no seed over the socket: %v", err)
	}
	pub := open(t, c, seed, 0)
	r, err := cl.Verify(wire.Request{Code: code(seed, clk.now()), Counted: true, Steps: steps(2)})
	if err != nil || !r.OK || r.Approval == nil || !ed25519.Verify(pub, kernel.CodeMsg(steps(2)), r.Approval.Sig) {
		t.Fatalf("a right code over the socket: %+v %v", r, err)
	}
	if _, err := wire.NewClient(filepath.Join(t.TempDir(), "none.sock")).Verify(wire.Request{}); !errors.Is(err, wire.ErrDown) {
		t.Fatalf("a missing socket: %v", err)
	}
	for i := 0; i < MaxWrongCounted; i++ {
		cl.Verify(wire.Request{Code: "00000x", Counted: true})
	}
	var p *wire.PausedError
	if _, err := cl.Verify(wire.Request{Code: "00000x", Counted: true}); !errors.As(err, &p) || p.Until.IsZero() {
		t.Fatalf("a paused bucket over the socket: %v", err)
	}
}
