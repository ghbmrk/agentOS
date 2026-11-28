package sim

// REQ: EVL-1, LOG-2

import (
	"bytes"
	"errors"
	"math/rand/v2"
	"testing"

	"github.com/ghbmrk/agentos/broker/kernel"
)

// The fake disk keeps what reached it: an armed crash cuts its append to a
// strict prefix and fails every read and write until Reboot, which keeps the
// bytes; a full disk refuses an append whole and counts it; Truncate keeps a
// prefix of what is there and refuses any other length (LOG-2's torn frame).
func TestTheDiskKeepsWhatReachedIt(t *testing.T) {
	d := &Disk{rng: rand.New(rand.NewPCG(1, 2))}
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(d.Append([]byte("ab")))
	d.Arm(2)
	must(d.Append([]byte("cd")))
	if err := d.Append([]byte("efghijkl")); !errors.Is(err, errCrash) {
		t.Fatalf("the armed append: %v, want a crash", err)
	}
	if !bytes.HasPrefix(d.b, []byte("abcd")) || len(d.b) >= len("abcdefghijkl") || !bytes.HasPrefix([]byte("abcdefghijkl"), d.b) {
		t.Fatalf("after the crash the disk holds %q, want abcd and a strict prefix of the frame", d.b)
	}
	torn := len(d.b)
	if err := d.Append([]byte("m")); !errors.Is(err, errCrash) || len(d.b) != torn {
		t.Fatalf("an append while crashed: %v, %d bytes", err, len(d.b))
	}
	if b, err := d.ReadAll(); !errors.Is(err, errCrash) || b != nil {
		t.Fatalf("a read while crashed: %q, %v", b, err)
	}
	if err := d.Truncate(0); !errors.Is(err, errCrash) || len(d.b) != torn {
		t.Fatalf("a truncate while crashed: %v, %d bytes", err, len(d.b))
	}
	d.Fill()
	d.Reboot()
	b, err := d.ReadAll()
	must(err)
	if len(b) != torn || !bytes.Equal(b, d.b) {
		t.Fatalf("after the reboot: %q, want the %d bytes kept", b, torn)
	}
	b[0] = 'x' // a copy: the medium is not the caller's
	if d.b[0] != 'a' {
		t.Fatal("ReadAll handed out the medium itself")
	}
	must(d.Append([]byte("n"))) // the reboot cleared the fill and the crash
	d.Arm(1)
	d.Arm(0) // disarmed: no crash
	must(d.Append([]byte("o")))
	d.Fill()
	for range 2 {
		if err := d.Append([]byte("p")); !errors.Is(err, errFull) {
			t.Fatalf("an append to a full disk: %v", err)
		}
	}
	if d.refused != 2 || len(d.b) != torn+2 {
		t.Fatalf("a full disk wrote %d bytes and counted %d refusals, want none and 2", len(d.b)-torn-2, d.refused)
	}
	for _, n := range []int{-1, torn + 3} {
		if err := d.Truncate(n); !errors.Is(err, kernel.ErrCorrupt) {
			t.Fatalf("truncate to %d of %d: %v", n, torn+2, err)
		}
	}
	must(d.Truncate(torn + 2)) // its whole length: a no-op
	must(d.Truncate(2))
	if string(d.b) != "ab" {
		t.Fatalf("truncated to %q, want ab", d.b)
	}
}
