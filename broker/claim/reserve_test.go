package claim

// REQ: HW-10, HW-1

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	mrand "math/rand"
	"os"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/argon2"

	"github.com/ghbmrk/agentos/broker/change"
)

// The production cost, before TestMain lowers it.
var prodSealKDF, prodKDFFloor = sealKDF, kdfFloor

// TestMain runs the package's tests at Argon2id's lowest cost; only
// TestProductionKDF runs the real one.
func TestMain(m *testing.M) {
	sealKDF = KDF{Time: 1, MemoryKiB: 8, Threads: 1}
	kdfFloor = sealKDF
	os.Exit(m.Run())
}

// ownerTypo is a code a sticker holder might mistype: the first two
// groups right, a later symbol wrong.
func ownerTypo(code string) string {
	n := Normalize(code)
	last := n[CodeSymbols-1]
	r := alphabet[(strings.IndexByte(alphabet, last)+1)%len(alphabet)]
	return n[:CodeSymbols-1] + string(r)
}

// R3 (CTRL-claim-wire): after three locks each boot allows one wrong code.
// A client on the Wi-Fi that posts a wrong code after every restart used
// to burn it, so the sticker holder could never claim. Codes that do not
// start with the sticker's first two groups count against that shared
// allowance only; the sticker holder's tries come from a per-boot reserve
// a client without the sticker cannot reach.
func TestTheStickerHolderBeatsAClientThatBurnsEveryBootsTry(t *testing.T) {
	b, code := newBox(t)
	for boot := 1; boot <= 3; boot++ {
		b.boot = "boot-" + string(rune('0'+boot))
		c := b.start()
		for {
			if _, err := c.Try(wrongCode(code)); errors.Is(err, ErrLocked) {
				break
			} else if !errors.Is(err, ErrWrongCode) {
				t.Fatal(err)
			}
		}
	}
	// The owner restarts the box; the other client gets there first.
	b.boot = "boot-4"
	c := b.start()
	if st := c.Status(); st.Locked {
		t.Fatalf("fourth boot opened locked: %+v", st)
	}
	if _, err := c.Try(wrongCode(code)); !errors.Is(err, ErrLocked) {
		t.Fatalf("the boot's one shared try: %v", err)
	}
	if _, err := c.Try(wrongCode(code)); !errors.Is(err, ErrLocked) {
		t.Fatalf("a second foreign try: %v", err)
	}
	// The screen is locked to everyone but the sticker holder.
	if st := c.Status(); !st.Locked || st.Reserve != ReserveTries {
		t.Fatalf("screen after the foreign client: %+v", st)
	}
	// A daemon restart gives the reserve nothing back.
	if _, err := c.Try(ownerTypo(code)); !errors.Is(err, ErrWrongCode) {
		t.Fatalf("owner's typo: %v", err)
	}
	c = b.start()
	if st := c.Status(); st.Reserve != ReserveTries-1 {
		t.Fatalf("reserve after a daemon restart: %+v", st)
	}
	if _, err := c.Try(code); err != nil {
		t.Fatalf("the sticker's code after a burned boot: %v", err)
	}
	if !c.Claimed() {
		t.Fatal("not claimed")
	}
	for _, e := range b.journal {
		if strings.Contains(e, Normalize(code)[:8]) {
			t.Fatal("journal holds the code's first groups")
		}
	}
}

// The reserve is per boot and bounded: ReserveTries codes starting with
// the sticker's first groups, then the screen locks until a restart, which
// refills it. Those codes never count against the shared allowance.
func TestTheReserveIsPerBootAndBounded(t *testing.T) {
	b, code := newBox(t)
	c := b.start()
	for i := 0; i < ReserveTries; i++ {
		if _, err := c.Try(ownerTypo(code)); !errors.Is(err, ErrWrongCode) {
			t.Fatalf("typo %d: %v", i, err)
		}
	}
	if st := c.Status(); st.Locked || st.TriesLeft != MaxWrong || st.Reserve != 0 {
		t.Fatalf("the reserve touched the shared allowance: %+v", st)
	}
	// Spent: a further typo counts as any wrong code.
	if _, err := c.Try(ownerTypo(code)); !errors.Is(err, ErrWrongCode) {
		t.Fatal(err)
	}
	if st := c.Status(); st.TriesLeft != MaxWrong-1 {
		t.Fatalf("spent reserve: %+v", st)
	}
	b.boot = "boot-2"
	c = b.start()
	if st := c.Status(); st.Reserve != ReserveTries {
		t.Fatalf("a new boot did not refill the reserve: %+v", st)
	}
	for i := 0; i < ReserveTries; i++ {
		if _, err := c.Try(ownerTypo(code)); !errors.Is(err, ErrWrongCode) {
			t.Fatalf("new boot's typo %d: %v", i, err)
		}
	}
	if _, err := c.Try(code); err != nil {
		t.Fatal(err)
	}
}

// A box sealed before the reserve existed has none: its claim behaves as
// before (K3).
func TestAStateWithoutAPrefixHasNoReserve(t *testing.T) {
	_, code, raw := lockedBox(t)
	s := strings.Replace(string(raw), `"prefix":`, `"unused":`, 1)
	if s == string(raw) {
		t.Fatal("sealed state holds no prefix verifier")
	}
	if err := tryFresh(t, []byte(s), code); !errors.Is(err, ErrLocked) {
		t.Fatalf("old state: %v", err)
	}
}

// A wrong count the reserve cannot save locks the screen (fail closed).
func TestUnsavableReserveCountLocks(t *testing.T) {
	b, code := newBox(t)
	c, err := Open(Config{Store: failStore{b.st}, BootID: func() (string, error) { return "boot-1", nil }})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Try(ownerTypo(code)); !errors.Is(err, ErrLocked) {
		t.Fatalf("unsaved reserve try: %v", err)
	}
	if _, err := c.Try(code); !errors.Is(err, ErrLocked) {
		t.Fatalf("right code after an unsaved count: %v", err)
	}
}

// The disk keeps a full-length prefix verifier (N1 of the #1080 delta
// review): a short tag let a client without the sticker find a prefix that
// spends the reserve in about 2^16 posts.
func TestThePrefixVerifierIsFullLength(t *testing.T) {
	b, _ := newBox(t)
	s := sealedState(t, b)
	if len(s.Prefix) != verifierSize || len(s.Verifier) != verifierSize || verifierSize < 32 {
		t.Fatalf("prefix verifier %d bytes, verifier %d", len(s.Prefix), len(s.Verifier))
	}
}

func sealedState(t *testing.T, b *box) state {
	t.Helper()
	raw, err := b.st.Load()
	if err != nil {
		t.Fatal(err)
	}
	var s state
	if err := json.Unmarshal(raw, &s); err != nil {
		t.Fatal(err)
	}
	return s
}

// N1 (#1080 delta review): a client without the sticker locks the shared
// count, then sprays codes at the locked screen for free hoping one starts
// with the sticker's first groups. 2^20 of them never reach the reserve,
// and whatever the spray found, replayed after the next restart, does not
// stop the owner claiming on that boot. The KDF is swapped for a cheap
// hash here so 2^20 tries run in seconds; the reserve logic is the same,
// and TestProductionKDF pins the real cost.
func TestALockedOutSprayNeverReachesTheReserve(t *testing.T) {
	old := derive
	derive = func(_ KDF, salt []byte, domain, s string) []byte {
		h := sha256.Sum256([]byte(domain + "\x00" + string(salt) + s))
		return h[:]
	}
	t.Cleanup(func() { derive = old })
	sprays := 1 << 20
	if testing.Short() {
		sprays = 1 << 16
	}

	b, code := newBox(t)
	lockShared := func(c *Claim) {
		t.Helper()
		for i := 0; !c.Status().Locked; i++ {
			if i > MaxWrong {
				t.Fatal("shared count never locked")
			}
			if _, err := c.Try(wrongCode(code)); err != nil && !errors.Is(err, ErrLocked) && !errors.Is(err, ErrWrongCode) {
				t.Fatal(err)
			}
		}
	}
	c := b.start()
	lockShared(c)
	rng := mrand.New(mrand.NewSource(1080))
	var hits []string
	for i := 0; i < sprays; i++ {
		try, err := NewCode(rng)
		if err != nil {
			t.Fatal(err)
		}
		switch _, err := c.Try(try); {
		case errors.Is(err, ErrLocked):
		case errors.Is(err, ErrWrongCode):
			hits = append(hits, try)
		default:
			t.Fatalf("spray %d: %v", i, err)
		}
	}
	if st := c.Status(); len(hits) != 0 || st.Reserve != ReserveTries || st.Claimed {
		t.Fatalf("%d of %d sprayed codes reached the reserve: %+v", len(hits), sprays, st)
	}

	// Next boot: the burner gets there first, locks the shared count and
	// replays every code the spray found; the owner still claims.
	b.boot = "boot-2"
	c = b.start()
	lockShared(c)
	for _, h := range hits {
		for i := 0; i <= ReserveTries; i++ {
			c.Try(h)
		}
	}
	if _, err := c.Try(code); err != nil || !c.Claimed() {
		t.Fatalf("owner after the spray: %v", err)
	}
}

// The production cost (K2, K9): both verifiers are Argon2id with 64 MiB,
// three passes and four lanes, about 50 to 100 ms each on the controller.
// TestMain lowers the cost for the other tests; this one seals and claims
// at the real one, and checks Open refuses a state below the floor or
// above the ceiling.
func TestProductionKDF(t *testing.T) {
	want := KDF{Time: 3, MemoryKiB: 64 << 10, Threads: 4}
	if productionKDF != want || prodSealKDF != want || prodKDFFloor != want {
		t.Fatalf("production KDF %+v, seal %+v, floor %+v; want %+v", productionKDF, prodSealKDF, prodKDFFloor, want)
	}
	defer func(s, f KDF) { sealKDF, kdfFloor = s, f }(sealKDF, kdfFloor)
	sealKDF, kdfFloor = prodSealKDF, prodKDFFloor

	b, code := newBox(t)
	s := sealedState(t, b)
	if s.KDF == nil || *s.KDF != want {
		t.Fatalf("sealed cost %+v", s.KDF)
	}
	n := Normalize(code)
	if !bytes.Equal(s.Verifier, argon2.IDKey([]byte("agentos claim v2\x00"+n), s.Salt, 3, 64<<10, 4, 32)) {
		t.Fatal("verifier is not Argon2id(64 MiB, 3, 4) of the code")
	}
	if !bytes.Equal(s.Prefix, argon2.IDKey([]byte("agentos claim prefix v2\x00"+n[:PrefixSymbols]), s.Salt, 3, 64<<10, 4, 32)) {
		t.Fatal("prefix verifier is not Argon2id(64 MiB, 3, 4) of the first groups")
	}
	raw, err := b.st.Load()
	if err != nil {
		t.Fatal(err)
	}
	for name, k := range map[string]KDF{
		"cheaper time":    {Time: 2, MemoryKiB: 64 << 10, Threads: 4},
		"less memory":     {Time: 3, MemoryKiB: 32 << 10, Threads: 4},
		"no lanes":        {Time: 3, MemoryKiB: 64 << 10, Threads: 0},
		"over the memory": {Time: 3, MemoryKiB: 2 << 20, Threads: 4},
		"over the time":   {Time: 100, MemoryKiB: 64 << 10, Threads: 4},
	} {
		var m map[string]any
		if err := json.Unmarshal(raw, &m); err != nil {
			t.Fatal(err)
		}
		m["kdf"] = k
		bad, _ := json.Marshal(m)
		ms := &change.MemStore{}
		ms.Save(bad)
		if _, err := Open(Config{Store: ms, BootID: func() (string, error) { return "boot-1", nil }}); err == nil {
			t.Fatalf("%s: Open took %+v", name, k)
		}
	}
	noKDF := strings.Replace(string(raw), `"kdf":`, `"unused":`, 1)
	if ms := (&change.MemStore{}); ms.Save([]byte(noKDF)) == nil {
		if _, err := Open(Config{Store: ms, BootID: func() (string, error) { return "boot-1", nil }}); err == nil {
			t.Fatal("Open took a state without a cost")
		}
	}

	c := b.start()
	start := time.Now()
	if _, err := c.Try(ownerTypo(code)); !errors.Is(err, ErrWrongCode) {
		t.Fatal(err)
	}
	t.Logf("a reserve try (two derivations) took %v", time.Since(start))
	if _, err := c.Try(code); err != nil {
		t.Fatal(err)
	}
}
