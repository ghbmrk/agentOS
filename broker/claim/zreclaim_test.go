package claim

// REQ: HW-10

import (
	"bytes"
	"errors"
	"os"
	"strings"
	"testing"
)

// CTRL-card-sock s3 (#1273): a right code whose answer never reached the
// phone claims again on the same start, until a phone presents the
// claimant token; the disk keeps no code after the first claim.
func TestALostClaimAnswerClaimsAgain(t *testing.T) {
	b, code := newBox(t)
	c := b.start()
	lost, err := c.Try(code)
	if err != nil {
		t.Fatal(err)
	}
	if st := c.Status(); !st.Claimed || !st.Reclaim {
		t.Fatalf("status after a claim no phone has shown: %+v", st)
	}
	raw, _ := os.ReadFile(b.st.Path)
	if bytes.Contains(raw, []byte("verifier")) || bytes.Contains(raw, []byte("salt")) {
		t.Fatalf("code hash on disk after the claim: %s", raw)
	}
	if _, err := c.Try(wrongCode(code)); !errors.Is(err, ErrAlreadyClaimed) {
		t.Fatalf("wrong code in the window: %v", err)
	}
	tok, err := c.Try(strings.ToLower(code))
	if err != nil || tok == "" || tok == lost {
		t.Fatalf("right code again: %q %v", tok, err)
	}
	if c.Claimant(lost) {
		t.Fatal("the lost token still names the claimant")
	}
	if !c.Claimant(tok) {
		t.Fatal("the re-delivered token is not the claimant")
	}
	// The claimant's phone came back: the code is dead.
	if st := c.Status(); !st.Claimed || st.Reclaim {
		t.Fatalf("status after the claimant came back: %+v", st)
	}
	if _, err := c.Try(code); !errors.Is(err, ErrAlreadyClaimed) {
		t.Fatalf("right code after the claimant came back: %v", err)
	}
	if !c.Claimant(tok) {
		t.Fatal("claimant lost")
	}
	raw, _ = os.ReadFile(b.st.Path)
	if bytes.Contains(raw, []byte("verifier")) || bytes.Contains(raw, []byte("salt")) {
		t.Fatalf("code hash on disk after the re-claim: %s", raw)
	}
}

// The window lives only in this start: a restart, the same boot or not,
// refuses the right code, and a reopened claim still knows the claimant.
func TestTheReclaimWindowEndsAtARestart(t *testing.T) {
	b, code := newBox(t)
	c := b.start()
	tok, err := c.Try(code)
	if err != nil {
		t.Fatal(err)
	}
	c = b.start()
	if st := c.Status(); st.Reclaim {
		t.Fatalf("window open after a restart: %+v", st)
	}
	if _, err := c.Try(code); !errors.Is(err, ErrAlreadyClaimed) {
		t.Fatalf("right code after a restart: %v", err)
	}
	if !c.Claimant(tok) {
		t.Fatal("claimant lost across the restart")
	}
}

// Wrong codes in the window close it after this boot's allowance, so the
// window gives a guesser no more tries than the unclaimed screen did.
func TestWrongCodesCloseTheReclaimWindow(t *testing.T) {
	b, code := newBox(t)
	c := b.start()
	if _, err := c.Try(code); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < MaxWrong; i++ {
		if _, err := c.Try(wrongCode(code)); !errors.Is(err, ErrAlreadyClaimed) {
			t.Fatalf("wrong code %d: %v", i, err)
		}
	}
	if st := c.Status(); st.Reclaim {
		t.Fatalf("window open after %d wrong codes", MaxWrong)
	}
	if _, err := c.Try(code); !errors.Is(err, ErrAlreadyClaimed) {
		t.Fatalf("right code after the window closed: %v", err)
	}
}

// A re-claim whose save fails keeps the earlier token and the window.
func TestAnUnsavableReclaimKeepsTheClaimant(t *testing.T) {
	b, code := newBox(t)
	c := b.start()
	tok, err := c.Try(code)
	if err != nil {
		t.Fatal(err)
	}
	c.store = failStore{c.store}
	if got, err := c.Try(code); err == nil || got != "" {
		t.Fatalf("unsavable re-claim: %q %v", got, err)
	}
	if !c.Claimant(tok) {
		t.Fatal("an unsavable re-claim dropped the claimant")
	}
}
