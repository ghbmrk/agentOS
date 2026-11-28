package claim

// REQ: HW-10

import (
	"bytes"
	"errors"
	"os"
	"strings"
	"testing"
)

// Synthetic page nonces of two phones.
const (
	phoneA = "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1"
	phoneB = "b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2"
)

// CTRL-card-sock s3 (#1273): a right code whose answer never reached the
// phone claims again from that phone on the same start, until a phone
// presents the claimant token; the disk keeps no code after the claim.
func TestALostClaimAnswerClaimsAgain(t *testing.T) {
	b, code := newBox(t)
	c := b.start()
	lost, err := c.TryFrom(code, phoneA)
	if err != nil {
		t.Fatal(err)
	}
	if !c.Reclaims(phoneA) || c.Reclaims(phoneB) || c.Reclaims("") {
		t.Fatal("the window is not the claiming phone's alone")
	}
	raw, _ := os.ReadFile(b.st.Path)
	if bytes.Contains(raw, []byte("verifier")) || bytes.Contains(raw, []byte("salt")) {
		t.Fatalf("code hash on disk after the claim: %s", raw)
	}
	if _, err := c.TryFrom(wrongCode(code), phoneA); !errors.Is(err, ErrAlreadyClaimed) {
		t.Fatalf("wrong code in the window: %v", err)
	}
	tok, err := c.TryFrom(strings.ToLower(code), phoneA)
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
	if c.Reclaims(phoneA) {
		t.Fatal("window open after the claimant came back")
	}
	if _, err := c.TryFrom(code, phoneA); !errors.Is(err, ErrAlreadyClaimed) {
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

// Security finding 1 on #6598: another phone with the right code, even
// one queued behind the owner's claim, never takes the window, and the
// first claim's token stays the claimant. A claim that names no phone, or
// a nonce too short, opens no window.
func TestOnlyTheClaimingPhoneClaimsAgain(t *testing.T) {
	b, code := newBox(t)
	c := b.start()
	type res struct {
		phone, tok string
		err        error
	}
	out := make(chan res, 2)
	for _, p := range []string{phoneA, phoneB} {
		go func() { tok, err := c.TryFrom(code, p); out <- res{p, tok, err} }()
	}
	var win res
	for i := 0; i < 2; i++ {
		r := <-out
		switch {
		case r.err == nil:
			if win.tok != "" {
				t.Fatal("two phones claimed")
			}
			win = r
		case !errors.Is(r.err, ErrAlreadyClaimed):
			t.Fatal(r.err)
		}
	}
	other := phoneA
	if win.phone == phoneA {
		other = phoneB
	}
	if _, err := c.TryFrom(code, other); !errors.Is(err, ErrAlreadyClaimed) {
		t.Fatalf("other phone, right code: %v", err)
	}
	if !c.Claimant(win.tok) {
		t.Fatal("the first claim's token is dead")
	}

	for _, phone := range []string{"", "short"} {
		b, code := newBox(t)
		c := b.start()
		if _, err := c.TryFrom(code, phone); err != nil {
			t.Fatal(err)
		}
		if c.Reclaims(phone) {
			t.Fatalf("phone %q opened a window", phone)
		}
		if _, err := c.TryFrom(code, phone); !errors.Is(err, ErrAlreadyClaimed) {
			t.Fatalf("phone %q, right code again: %v", phone, err)
		}
	}
}

// The window lives only in this start: a restart refuses the right code,
// and a reopened claim still knows the claimant.
func TestTheReclaimWindowEndsAtARestart(t *testing.T) {
	b, code := newBox(t)
	c := b.start()
	tok, err := c.TryFrom(code, phoneA)
	if err != nil {
		t.Fatal(err)
	}
	c = b.start()
	if c.Reclaims(phoneA) {
		t.Fatal("window open after a restart")
	}
	if _, err := c.TryFrom(code, phoneA); !errors.Is(err, ErrAlreadyClaimed) {
		t.Fatalf("right code after a restart: %v", err)
	}
	if !c.Claimant(tok) {
		t.Fatal("claimant lost across the restart")
	}
}

// Security finding 2 on #6598: the window shares this boot's allowance,
// so wrong codes before the claim leave fewer in the window.
func TestWrongCodesCloseTheReclaimWindow(t *testing.T) {
	for _, before := range []int{0, MaxWrong - 1} {
		b, code := newBox(t)
		c := b.start()
		for i := 0; i < before; i++ {
			if _, err := c.TryFrom(wrongCode(code), phoneA); !errors.Is(err, ErrWrongCode) {
				t.Fatalf("wrong code %d before the claim: %v", i, err)
			}
		}
		if _, err := c.TryFrom(code, phoneA); err != nil {
			t.Fatal(err)
		}
		for i := 0; i < MaxWrong-before; i++ {
			if !c.Reclaims(phoneA) {
				t.Fatalf("%d before: window closed after %d wrong codes", before, i)
			}
			if _, err := c.TryFrom(wrongCode(code), phoneA); !errors.Is(err, ErrAlreadyClaimed) {
				t.Fatalf("wrong code %d: %v", i, err)
			}
		}
		if c.Reclaims(phoneA) {
			t.Fatalf("%d before: window open after %d wrong codes", before, MaxWrong-before)
		}
		if _, err := c.TryFrom(code, phoneA); !errors.Is(err, ErrAlreadyClaimed) {
			t.Fatalf("right code after the window closed: %v", err)
		}
	}
}

// A re-claim whose save fails keeps the earlier token and the window.
func TestAnUnsavableReclaimKeepsTheClaimant(t *testing.T) {
	b, code := newBox(t)
	c := b.start()
	tok, err := c.TryFrom(code, phoneA)
	if err != nil {
		t.Fatal(err)
	}
	c.store = failStore{c.store}
	if got, err := c.TryFrom(code, phoneA); err == nil || got != "" {
		t.Fatalf("unsavable re-claim: %q %v", got, err)
	}
	if !c.Reclaims(phoneA) || !c.Claimant(tok) {
		t.Fatal("an unsavable re-claim dropped the window or the claimant")
	}
}
