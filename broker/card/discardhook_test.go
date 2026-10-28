package card

// REQ: REC-4, CRED-1

import (
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
)

// hookRig is a rotation display that counts its Discarded calls.
func hookRig(t *testing.T, fail error) (*Display, *Card, *int) {
	t.Helper()
	var gen Card
	n := 0
	d, err := NewDisplay(DisplayConfig{
		Rotate:    &Parts{Recovery: true},
		Authority: testAuthority(t),
		Generate: func(r io.Reader) (*Card, error) {
			c, err := Generate(r)
			if err == nil {
				gen = *c
			}
			return c, err
		},
		Provision: func(*Card) error { return fail },
		Discarded: func() { n++ },
	})
	if err != nil {
		t.Fatal(err)
	}
	return d, &gen, &n
}

func groupOf(d *Display, c *Card) Answers {
	_, g := d.Asks()
	return Answers{Group: strings.Split(c.RecoveryKey, "-")[g-1]}
}

// R2 on #1090: the page's cancel, and a provisioner's ErrDiscard, reach
// the vault's pending rotation through the Discarded hook, once; a
// confirmed card, a card in effect and a plain provisioning failure do
// not discard, so the hook stays quiet.
func TestDisplayDiscardedHook(t *testing.T) {
	d, _, n := hookRig(t, nil)
	d.Discard()
	d.Discard()
	if *n != 1 {
		t.Fatalf("cancel: hook ran %d times", *n)
	}

	d, gen, n := hookRig(t, fmt.Errorf("lapsed: %w", ErrDiscard))
	if err := d.ConfirmAnswers(groupOf(d, gen)); !errors.Is(err, ErrDiscard) || *n != 1 {
		t.Fatalf("lapsed commit: %v, hook ran %d times", err, *n)
	}

	d, gen, n = hookRig(t, nil)
	if err := d.ConfirmAnswers(groupOf(d, gen)); err != nil || *n != 0 {
		t.Fatalf("confirm: %v, hook ran %d times", err, *n)
	}
	d.Discard()
	if *n != 0 {
		t.Fatal("discard after a confirm ran the hook")
	}

	d, gen, n = hookRig(t, fmt.Errorf("partly written: %w", ErrInEffect))
	d.ConfirmAnswers(groupOf(d, gen))
	d.Discard()
	if *n != 0 {
		t.Fatal("a card in effect ran the hook")
	}

	d, gen, n = hookRig(t, errors.New("socket down"))
	d.ConfirmAnswers(groupOf(d, gen))
	if *n != 0 {
		t.Fatal("a plain provisioning failure ran the hook")
	}
}
