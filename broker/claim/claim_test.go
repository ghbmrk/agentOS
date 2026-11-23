package claim

// REQ: HW-10

import (
	"bytes"
	"encoding/json"
	"errors"
	mrand "math/rand"
	"os"
	"path/filepath"
	"strconv"
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
// lock the screen, and the lock holds until the box restarts for every
// code not starting with the sticker's first groups (the sticker holder's
// reserve is reserve_test.go). A daemon restart (same kernel boot) does not lift it
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
	if _, err := c.Try(wrongCode(code)); !errors.Is(err, ErrLocked) {
		t.Fatalf("a code while locked: %v", err)
	}
	c = b.start() // daemon restart, same boot
	if st := c.Status(); !st.Locked {
		t.Fatal("daemon restart lifted the lock")
	}
	if _, err := c.Try(wrongCode(code)); !errors.Is(err, ErrLocked) {
		t.Fatalf("a code after daemon restart: %v", err)
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

// tryFresh presents one code to a box opened from sealed, so each try
// meets a fresh count and the lockout never masks the compare.
func tryFresh(t *testing.T, sealed []byte, code string) error {
	t.Helper()
	ms := &change.MemStore{}
	if err := ms.Save(sealed); err != nil {
		t.Fatal(err)
	}
	c, err := Open(Config{Store: ms, BootID: func() (string, error) { return "boot-1", nil }})
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.Try(code)
	return err
}

// Acceptance 3: a near miss is a wrong code. Only the whole code, every
// symbol, claims the box (B1 of the #1067 review).
func TestNearMissCodesRefused(t *testing.T) {
	b, code := newBox(t)
	sealed, err := b.st.Load()
	if err != nil {
		t.Fatal(err)
	}
	n := Normalize(code)
	other := func(r byte) byte {
		i := strings.IndexByte(alphabet, r)
		return alphabet[(i+1)%len(alphabet)]
	}
	misses := map[string]string{
		"last symbol changed": n[:CodeSymbols-1] + string(other(n[CodeSymbols-1])),
		"15-symbol prefix":    n[:CodeSymbols-1],
		"12-symbol prefix":    n[:12],
		"one extra symbol":    n + "A",
		"code twice":          n + n,
		"empty":               "",
	}
	for i := 0; i < CodeSymbols; i++ {
		m := []byte(n)
		m[i] = other(m[i])
		misses["symbol "+strconv.Itoa(i+1)+" changed"] = string(m)
	}
	for name, try := range misses {
		if err := tryFresh(t, sealed, try); !errors.Is(err, ErrWrongCode) {
			t.Fatalf("%s: %v", name, err)
		}
	}
	// A few hundred random wrong codes, and one whose verifier shares its
	// first byte with the right code's, so a short compare cannot pass.
	var st state
	if err := json.Unmarshal(sealed, &st); err != nil {
		t.Fatal(err)
	}
	rng := mrand.New(mrand.NewSource(1067))
	random := func() string {
		s := make([]byte, CodeSymbols)
		for i := range s {
			s[i] = alphabet[rng.Intn(len(alphabet))]
		}
		return string(s)
	}
	for i := 0; i < 300; i++ {
		if try := random(); try != n {
			if err := tryFresh(t, sealed, try); !errors.Is(err, ErrWrongCode) {
				t.Fatalf("random code %d: %v", i, err)
			}
		}
	}
	for i := 0; ; i++ {
		if i > 1<<16 {
			t.Fatal("no code with the same first verifier byte found")
		}
		try := random()
		if try == n || st.verifier(try)[0] != st.Verifier[0] {
			continue
		}
		if err := tryFresh(t, sealed, try); !errors.Is(err, ErrWrongCode) {
			t.Fatalf("code sharing the first verifier byte: %v", err)
		}
		break
	}
	if err := tryFresh(t, sealed, code); err != nil {
		t.Fatalf("right code: %v", err)
	}
}

// lockedBox is a box whose screen locked in boot-1, and its state bytes.
func lockedBox(t *testing.T) (*box, string, []byte) {
	t.Helper()
	b, code := newBox(t)
	c := b.start()
	for i := 0; i < MaxWrong; i++ {
		c.Try(wrongCode(code))
	}
	if !c.Status().Locked {
		t.Fatal("not locked")
	}
	raw, err := b.st.Load()
	if err != nil {
		t.Fatal(err)
	}
	return b, code, raw
}

type loadFail struct{ change.MemStore }

func (*loadFail) Load() ([]byte, error) { return nil, errors.New("read error") }

// Acceptance 3: a state the box cannot read is never an unclaimed or
// unlocked box. Open fails, not ErrNoCode, and the lock on disk stays
// (B2 of the #1067 review).
func TestUnreadableStateKeepsLock(t *testing.T) {
	b, code, raw := lockedBox(t)
	boot2 := func() (string, error) { return "boot-2", nil }
	refused := func(name string, err error) {
		t.Helper()
		if err == nil || errors.Is(err, ErrNoCode) {
			t.Fatalf("%s: Open gave %v", name, err)
		}
	}

	_, err := Open(Config{Store: &loadFail{}, BootID: boot2})
	refused("read error", err)
	_, err = Open(Config{Store: change.FileStore{Path: t.TempDir()}, BootID: boot2})
	refused("state path is a directory", err)

	partly := bytes.Replace(raw, []byte(`"wrong":`+strconv.Itoa(MaxWrong)), []byte(`"wrong":"`+strconv.Itoa(MaxWrong)+`"`), 1)
	if bytes.Equal(partly, raw) {
		t.Fatal("test setup: wrong count not found in state")
	}
	for name, bad := range map[string][]byte{
		"empty":          {},
		"truncated":      raw[:len(raw)/2],
		"garbage":        []byte("\x00\xffclaim"),
		"null":           []byte("null"),
		"empty object":   []byte("{}"),
		"partly decoded": partly,
	} {
		fs := change.FileStore{Path: filepath.Join(t.TempDir(), "claim.json")}
		if err := os.WriteFile(fs.Path, bad, 0o600); err != nil {
			t.Fatal(err)
		}
		_, err := Open(Config{Store: fs, BootID: boot2})
		refused(name, err)
		if got, _ := os.ReadFile(fs.Path); !bytes.Equal(got, bad) {
			t.Fatalf("%s: Open rewrote the state", name)
		}
	}

	_, err = Open(Config{Store: b.st, BootID: func() (string, error) { return "", errors.New("no boot_id") }})
	refused("boot id error", err)
	if got, _ := b.st.Load(); !bytes.Equal(got, raw) {
		t.Fatal("boot id error: Open rewrote the state")
	}
	c := b.start() // still boot-1: the lock holds
	if _, err := c.Try(wrongCode(code)); !errors.Is(err, ErrLocked) || !c.Status().Locked {
		t.Fatalf("a code after the failed opens: %v", err)
	}
}

// CTRL-setup-open-r2 (HW-10): the vault process asks whether the box is
// claimed before it makes the setup vault. The answer reads the state
// without changing it: no state is ErrNoCode, a sealed box is unclaimed
// until the claim, and an unreadable state is an error, never a claim.
func TestClaimedReadsTheStateWithoutWriting(t *testing.T) {
	missing := change.FileStore{Path: filepath.Join(t.TempDir(), "claim.json")}
	if ok, err := Claimed(missing); ok || !errors.Is(err, ErrNoCode) {
		t.Fatalf("no state: %v %v", ok, err)
	}
	b, code := newBox(t)
	before, err := os.ReadFile(b.st.Path)
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := Claimed(b.st); ok || err != nil {
		t.Fatalf("sealed: %v %v", ok, err)
	}
	if after, _ := os.ReadFile(b.st.Path); !bytes.Equal(before, after) {
		t.Fatal("Claimed wrote the state")
	}
	if _, err := b.start().Try(code); err != nil {
		t.Fatal(err)
	}
	if ok, err := Claimed(b.st); !ok || err != nil {
		t.Fatalf("claimed: %v %v", ok, err)
	}
	for _, bad := range []string{"{", `{"claimed":false}`, "null"} {
		if err := os.WriteFile(b.st.Path, []byte(bad), 0o600); err != nil {
			t.Fatal(err)
		}
		if ok, err := Claimed(b.st); ok || err == nil {
			t.Fatalf("state %q: %v %v", bad, ok, err)
		}
	}
}
