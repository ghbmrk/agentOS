package proc

// REQ: LOG-2
//
// MUT-kill-6305-proc (#6367): the counter anchor's refusals, each checked
// by what it returns.

import (
	"crypto/ed25519"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/ghbmrk/agentos/broker/kernel"
)

// readFails is a counter whose Read fails.
type readFails struct{ fakeCounter }

func (*readFails) Read() (uint64, error) { return 0, errFault }

// writeRec puts rec, signed by priv, as dir's head file.
func writeRec(t *testing.T, dir string, priv ed25519.PrivateKey, rec anchorRec) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, anchorName), signAnchor(priv, rec), 0o600); err != nil {
		t.Fatal(err)
	}
}

// Enrollment and the open refuse a folder open to other uids and a counter
// they cannot read; the open refuses a head file that is a link or open to
// other uids, and keeps no descriptor to it.
func TestCounterAnchorRefusesWhatItCannotTrust(t *testing.T) {
	priv := headKey(t)
	open := ownDir(t)
	if err := os.Chmod(open, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := InitCounterAnchor(open, noLog(t), &fakeCounter{n: 5}, priv); err == nil {
		t.Fatal("enrollment in a folder open to other uids")
	}
	if err := InitCounterAnchor(ownDir(t), noLog(t), &readFails{}, priv); !errors.Is(err, errFault) {
		t.Fatalf("enrollment on a counter it cannot read: %v", err)
	}
	dir, c, priv, _ := newAnchor(t)
	if _, err := OpenCounterAnchor(dir, &readFails{}, priv); !errors.Is(err, errFault) {
		t.Fatalf("an open on a counter it cannot read: %v", err)
	}
	p := filepath.Join(dir, anchorName)
	for range 3 {
		if _, err := readAnchor(dir, priv.Public().(ed25519.PublicKey)); err != nil {
			t.Fatal(err)
		}
		if n := openFDsTo(t, p); n != 0 {
			t.Fatalf("%d descriptors to the head file stay open", n)
		}
	}
	if err := os.Chmod(p, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenCounterAnchor(dir, c, priv); err == nil {
		t.Fatal("a head file open to other uids was read")
	}
	if err := os.Chmod(p, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenCounterAnchor(dir, c, priv); err == nil || !strings.Contains(err.Error(), "open to other uids") {
		t.Fatal("a head folder open to other uids was read")
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(p, p+".x"); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(p+".x", p); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenCounterAnchor(dir, c, priv); !errors.Is(err, syscall.ELOOP) {
		t.Fatalf("a head file that is a link: %v, want ELOOP", err)
	}
}

// A head file is corrupt when a head in it is not the key's, or when it
// holds a previous head with no head, or one after its head.
func TestCounterAnchorRefusesHeadsThatDoNotHold(t *testing.T) {
	dir, c, priv, _ := newAnchor(t)
	h1, h2 := head(priv, 1), head(priv, 2)
	forged := kernel.Head{Seq: 3, Hash: kernel.Hash{3}, Sig: make([]byte, 64)}
	for name, rec := range map[string]anchorRec{
		"a forged head":         {Head: &forged},
		"a forged previous":     {Head: &h2, Prev: &forged},
		"a previous, no head":   {Prev: &h1},
		"a previous after head": {Head: &h1, Prev: &h2},
	} {
		rec.V, rec.N = 1, c.n
		writeRec(t, dir, priv, rec)
		if _, err := OpenCounterAnchor(dir, c, priv); !errors.Is(err, ErrAnchorCorrupt) {
			t.Fatalf("%s: %v, want ErrAnchorCorrupt", name, err)
		}
	}
	writeRec(t, dir, priv, anchorRec{V: 1, N: c.n, Head: &h2, Prev: &h1})
	if got := latest(t, dir, c, priv); got.Seq != 2 {
		t.Fatalf("a whole head file gives seq %d, want 2", got.Seq)
	}
}

// A counter at its limit takes no further write, so the open refuses.
func TestCounterAnchorAtItsLimit(t *testing.T) {
	dir, c, priv := ownDir(t), &fakeCounter{n: ^uint64(0)}, headKey(t)
	if err := InitCounterAnchor(dir, noLog(t), c, priv); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenCounterAnchor(dir, c, priv); err == nil || !strings.Contains(err.Error(), "limit") {
		t.Fatalf("an open at the counter's limit: %v", err)
	}
}
