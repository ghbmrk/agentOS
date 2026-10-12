package claim

// REQ: HW-10

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/change"
)

// box is one preloaded box's claim state on disk, opened per start.
type box struct {
	t       *testing.T
	st      change.FileStore
	boot    string
	journal []string
}

func newBox(t *testing.T) (*box, string) {
	t.Helper()
	b := &box{t: t, st: change.FileStore{Path: filepath.Join(t.TempDir(), "claim.json")}, boot: "boot-1"}
	code, err := NewCode(nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := Seal(b.st, code, nil, nil); err != nil {
		t.Fatal(err)
	}
	return b, code
}

// start opens the claim as the daemon does on each start.
func (b *box) start() *Claim {
	b.t.Helper()
	c, err := Open(Config{Store: b.st, BootID: func() (string, error) { return b.boot, nil },
		Journal: func(e string) { b.journal = append(b.journal, e) }})
	if err != nil {
		b.t.Fatal(err)
	}
	return c
}

func wrongCode(code string) string {
	if code[0] == 'A' {
		return "B" + code[1:]
	}
	return "A" + code[1:]
}

// Acceptance 1: a second claim on a claimed box is refused with "already
// claimed", also with the right code and after a restart.
func TestSecondClaimRefusedAlreadyClaimed(t *testing.T) {
	b, code := newBox(t)
	c := b.start()
	tok, err := c.Try(strings.ToLower(strings.ReplaceAll(code, "-", " ")))
	if err != nil {
		t.Fatalf("first claim: %v", err)
	}
	if !c.Claimant(tok) || c.Claimant(strings.Repeat("0", 64)) {
		t.Fatal("claimant token does not name the claiming phone alone")
	}
	if _, err := c.Try(code); !errors.Is(err, ErrAlreadyClaimed) {
		t.Fatalf("second claim, same start: %v", err)
	}
	b.boot = "boot-2"
	c = b.start()
	for _, try := range []string{code, wrongCode(code), ""} {
		if _, err := c.Try(try); !errors.Is(err, ErrAlreadyClaimed) {
			t.Fatalf("claim %q after restart: %v", try, err)
		}
	}
	if !c.Claimant(tok) {
		t.Fatal("claimant lost across restart")
	}
	if st := c.Status(); !st.Claimed || st.Locked {
		t.Fatalf("status %+v", st)
	}
	if !strings.Contains(ErrAlreadyClaimed.Error(), "already claimed") {
		t.Fatal("refusal text")
	}
}

// The code is burned: after the claim neither the code nor its hash is on
// disk; before it the code is there as a salted hash only.
func TestCodeKeptHashedAndBurnedAtClaim(t *testing.T) {
	b, code := newBox(t)
	raw, _ := os.ReadFile(b.st.Path)
	if bytes.Contains(raw, []byte(code)) || bytes.Contains(raw, []byte(Normalize(code))) {
		t.Fatal("claim code in plaintext on disk")
	}
	c := b.start()
	if _, err := c.Try(code); err != nil {
		t.Fatal(err)
	}
	raw, _ = os.ReadFile(b.st.Path)
	if bytes.Contains(raw, []byte("verifier")) || bytes.Contains(raw, []byte("salt")) {
		t.Fatalf("code hash kept after claim: %s", raw)
	}
}

// Two phones racing with the right code: exactly one claims the box.
func TestRacingClaimsOneWins(t *testing.T) {
	b, code := newBox(t)
	c := b.start()
	res := make(chan error, 8)
	for i := 0; i < 8; i++ {
		go func() { _, err := c.Try(code); res <- err }()
	}
	wins := 0
	for i := 0; i < 8; i++ {
		err := <-res
		switch {
		case err == nil:
			wins++
		case !errors.Is(err, ErrAlreadyClaimed):
			t.Fatal(err)
		}
	}
	if wins != 1 {
		t.Fatalf("%d claims won", wins)
	}
}

// Acceptance 3: a wrong code is refused and counted; MaxWrong wrong codes
// lock the screen, and the lock holds, the right code included, until
// the box restarts. A daemon restart (same kernel boot) does not lift it
// (the #1056 hint: the lockout persists across restarts).
func TestWrongCodesLockUntilBoxRestarts(t *testing.T) {
	b, code := newBox(t)
	c := b.start()
	for i := 1; i < MaxWrong; i++ {
		if _, err := c.Try(wrongCode(code)); !errors.Is(err, ErrWrongCode) {
			t.Fatalf("wrong code %d: %v", i, err)
		}
		if got := c.Status().TriesLeft; got != MaxWrong-i {
			t.Fatalf("tries left %d after %d wrong", got, i)
		}
	}
	// A daemon restart mid-count gives no tries back.
	c = b.start()
	if got := c.Status().TriesLeft; got != 1 {
		t.Fatalf("tries left after daemon restart: %d", got)
	}
	if _, err := c.Try(wrongCode(code)); !errors.Is(err, ErrLocked) {
		t.Fatalf("last wrong code: %v", err)
	}
	if _, err := c.Try(code); !errors.Is(err, ErrLocked) {
		t.Fatalf("right code while locked: %v", err)
	}
	c = b.start() // daemon restart, same boot
	if st := c.Status(); !st.Locked {
		t.Fatal("daemon restart lifted the lock")
	}
	if _, err := c.Try(code); !errors.Is(err, ErrLocked) {
		t.Fatalf("right code after daemon restart: %v", err)
	}
	wrongs := 0
	for _, e := range b.journal {
		if strings.HasPrefix(e, EventWrong) {
			wrongs++
		}
		if strings.Contains(e, code) || strings.Contains(e, Normalize(wrongCode(code))) {
			t.Fatal("journal holds a typed code")
		}
	}
	if wrongs != MaxWrong {
		t.Fatalf("journal counts %d wrong codes", wrongs)
	}
	// The owner restarts the box: the screen opens with fewer tries.
	b.boot = "boot-2"
	c = b.start()
	st := c.Status()
	if st.Locked || st.TriesLeft != MaxWrong/2 {
		t.Fatalf("after box restart: %+v", st)
	}
	for i := 0; i < MaxWrong/2; i++ {
		c.Try(wrongCode(code))
	}
	if !c.Status().Locked {
		t.Fatal("second lock")
	}
	b.boot = "boot-3"
	c = b.start()
	if st := c.Status(); st.TriesLeft != 1 {
		t.Fatalf("third boot: %+v", st)
	}
	if _, err := c.Try(code); err != nil {
		t.Fatalf("right code after restart: %v", err)
	}
}

// A wrong count that cannot be saved locks the screen (fail closed).
func TestUnsavableWrongCountLocks(t *testing.T) {
	b, code := newBox(t)
	c := b.start()
	c.store = failStore{c.store}
	if _, err := c.Try(wrongCode(code)); !errors.Is(err, ErrLocked) {
		t.Fatalf("unsaved wrong code: %v", err)
	}
	c.store = b.st
	if _, err := c.Try(code); !errors.Is(err, ErrLocked) {
		t.Fatalf("right code after unsaved count: %v", err)
	}
}

type failStore struct{ Store }

func (failStore) Save([]byte) error { return errors.New("disk full") }

func TestOpenUnsealedAndSealTwice(t *testing.T) {
	st := change.FileStore{Path: filepath.Join(t.TempDir(), "claim.json")}
	if _, err := Open(Config{Store: st, BootID: func() (string, error) { return "b", nil }}); !errors.Is(err, ErrNoCode) {
		t.Fatalf("unsealed: %v", err)
	}
	if err := Seal(st, "not-a-code", nil, nil); err == nil {
		t.Fatal("sealed a malformed code")
	}
	code, _ := NewCode(nil)
	if err := Seal(st, code, nil, nil); err != nil {
		t.Fatal(err)
	}
	if err := Seal(st, code, nil, nil); err == nil {
		t.Fatal("resealed a sealed box")
	}
}
