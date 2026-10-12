package claim

// REQ: HW-10, HW-1

import (
	"errors"
	"strings"
	"testing"
)

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
