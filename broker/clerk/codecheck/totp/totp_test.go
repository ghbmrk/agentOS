package totp

import (
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/owner"
)

// REQ: CH-4

// RFC 6238 Appendix B's SHA-1 vectors (eight digits there; the last six
// here), and the owner channel's own check agreeing on every step of a day,
// so the checker and setup accept exactly the codes the channel did.
func TestCodesMatchTheRFCAndTheOwnerChannel(t *testing.T) {
	seed := []byte("12345678901234567890")
	for unix, want := range map[int64]string{59: "287082", 1111111109: "081804", 1234567890: "005924", 2000000000: "279037"} {
		if got := At(seed, time.Unix(unix, 0)); got != want {
			t.Errorf("At(%d) = %s, want %s", unix, got, want)
		}
	}
	base := time.Unix(1_800_000_000, 0)
	for i := 0; i < 2880; i++ {
		now := base.Add(time.Duration(i) * Step * time.Second)
		c := At(seed, now)
		if c != owner.TOTP(seed, now) {
			t.Fatalf("step %d: %s, the owner channel's %s", i, c, owner.TOTP(seed, now))
		}
		s, ok := Match(seed, c, now.Add(Step*time.Second), 0)
		os, ook := owner.MatchTOTP(seed, c, now.Add(Step*time.Second), 0)
		if !ok || s != os || !ook {
			t.Fatalf("step %d: Match %d %v, the owner channel's %d %v", i, s, ok, os, ook)
		}
	}
	now := time.Unix(1_800_000_000, 0)
	c := At(seed, now)
	if _, ok := Match(seed, c, now, now.Unix()/Step); ok {
		t.Fatal("a code at after matched")
	}
	if _, ok := Match(seed, c, now.Add(2*Step*time.Second), 0); ok {
		t.Fatal("a code two steps old matched")
	}
	if _, ok := Match(nil, c, now, 0); ok {
		t.Fatal("no seed matched")
	}
}
