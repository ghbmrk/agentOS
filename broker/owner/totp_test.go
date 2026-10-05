package owner

import (
	"testing"
	"time"
)

// REQ: CH-4, CRED-8

func TestMatchTOTPAcceptsCurrentAndPreviousStepOnce(t *testing.T) {
	seed := []byte("synthetic-seed-0123456789")
	now := time.Unix(1_800_000_015, 0)
	cur := now.Unix() / totpStep
	if s, ok := MatchTOTP(seed, totpAt(seed, now.Unix()), now, 0); !ok || s != cur {
		t.Fatalf("current step: %d %v", s, ok)
	}
	if s, ok := MatchTOTP(seed, totpAt(seed, now.Unix()-totpStep), now, 0); !ok || s != cur-1 {
		t.Fatalf("previous step: %d %v", s, ok)
	}
	if _, ok := MatchTOTP(seed, totpAt(seed, now.Unix()-2*totpStep), now, 0); ok {
		t.Fatal("two steps old accepted")
	}
	if _, ok := MatchTOTP(seed, totpAt(seed, now.Unix()+totpStep), now, 0); ok {
		t.Fatal("next step accepted")
	}
	if _, ok := MatchTOTP(seed, totpAt(seed, now.Unix()), now, cur); ok {
		t.Fatal("spent step accepted again")
	}
	if _, ok := MatchTOTP(nil, "000000", now, 0); ok {
		t.Fatal("no seed matched")
	}
}
