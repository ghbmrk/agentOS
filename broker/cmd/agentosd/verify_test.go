package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/checker"
	"github.com/ghbmrk/agentos/broker/checker/checkersock"
	"github.com/ghbmrk/agentos/broker/modelroute"
	"github.com/ghbmrk/agentos/broker/owner"
)

// REQ: CH-18

// Each reason the vault process gives reaches the owner channel as the
// same reason, so the owner gets the matching message.
func TestOwnerVerifyErrKeepsTheReason(t *testing.T) {
	until := time.Unix(1_800_000_000, 0)
	for from, want := range map[modelroute.VerifyFailure]owner.VerifyFailure{
		modelroute.VerifyDown:   owner.VaultDown,
		modelroute.VerifyLocked: owner.VaultLocked,
		modelroute.VerifyPaused: owner.VerifyPaused,
		modelroute.VerifyLost:   owner.VerifyLost,
	} {
		var ve *owner.VerifyError
		err := ownerVerifyErr(&modelroute.VerifyError{Kind: from, Until: until})
		if !errors.As(err, &ve) || ve.Kind != want || !ve.Until.Equal(until) {
			t.Fatalf("%v: %v", from, err)
		}
	}
	if ownerVerifyErr(nil) != nil {
		t.Fatal("nil error changed")
	}
}

// REQ: CH-4
// SIM-split-wire part 3: with -checker-verify, the broker's codes go to
// the checker, which holds the seed while the vault is open; the unlock's
// proof still goes to the vault process. The checker's reasons reach the
// owner channel as the channel's own.
func TestCodesGoToTheChecker(t *testing.T) {
	dir := t.TempDir()
	ck, err := checker.New(checker.Config{StatePath: filepath.Join(dir, "checker.json")})
	if err != nil {
		t.Fatal(err)
	}
	var ls []net.Listener
	for _, name := range []string{checker.HandSocket, checker.VerifySocket, checker.RedeemSocket} {
		l, err := checker.Listen(filepath.Join(dir, name), os.Getuid())
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { l.Close() })
		ls = append(ls, l)
	}
	go ck.Serve(ls[0], ls[1], ls[2])
	o := ownerVerifier{
		v:       modelroute.NewVerifier(filepath.Join(dir, "no-egress.sock")),
		checker: checkersock.VerifyClient(filepath.Join(dir, checker.VerifySocket)),
	}
	kind := func(err error) owner.VerifyFailure {
		t.Helper()
		var ve *owner.VerifyError
		if !errors.As(err, &ve) {
			t.Fatalf("not a channel reason: %v", err)
		}
		return ve.Kind
	}

	if _, _, err := o.VerifyTOTP("123456", 0, true); kind(err) != owner.VaultLocked {
		t.Fatalf("no seed in the checker: %v", err)
	}
	seed := make([]byte, 20)
	if _, err := rand.Read(seed); err != nil {
		t.Fatal(err)
	}
	ck.Hand(seed)
	step, ok, err := o.VerifyTOTP(code(seed, time.Now()), 0, true)
	if !ok || err != nil || step == 0 {
		t.Fatalf("code on the checker: %d %t %v", step, ok, err)
	}
	if _, ok, _ := o.VerifyTOTP(code(seed, time.Now()), 0, true); ok {
		t.Fatal("the checker took a spent step again")
	}
	// The proof is the vault process's alone; here it is not running.
	if _, _, err := o.VerifyTOTP(owner.UnlockProofPrefix+"ticket", 0, true); kind(err) != owner.VaultDown {
		t.Fatalf("unlock proof: %v", err)
	}

	down := ownerVerifier{checker: checkersock.VerifyClient(filepath.Join(dir, "gone.sock"))}
	if _, _, err := down.VerifyTOTP("123456", 0, true); kind(err) != owner.VaultDown {
		t.Fatalf("checker not running: %v", err)
	}
	until := time.Unix(1_800_000_000, 0)
	var ve *owner.VerifyError
	if err := checkerVerifyErr(&checker.PausedError{Until: until}); !errors.As(err, &ve) || ve.Kind != owner.VerifyPaused || !ve.Until.Equal(until) {
		t.Fatalf("paused: %v", err)
	}
	if kind(checkerVerifyErr(errors.New("checker: verify: 500"))) != owner.VerifyLost {
		t.Fatal("an unknown failure is not lost")
	}
}

// code computes the code-generator code at t (RFC 6238, SHA-1, 30 s,
// 6 digits), as the owner's phone does.
func code(seed []byte, t time.Time) string {
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], uint64(t.Unix()/30))
	m := hmac.New(sha1.New, seed)
	m.Write(msg[:])
	sum := m.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	return fmt.Sprintf("%06d", (binary.BigEndian.Uint32(sum[off:off+4])&0x7fffffff)%1_000_000)
}
