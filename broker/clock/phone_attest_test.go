package clock

import (
	"errors"
	"testing"
	"time"
)

// REQ: HW-8, CH-4
func TestHOST1bT8PhoneAttestBounds(t *testing.T) {
	base := time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)
	p := PhoneAttest{
		Last:      base,
		Floor:     base.Add(-time.Hour),
		HasOffset: true,
		RTC:       base,
		RTCOffset: 0,
	}
	if err := p.Check(base); !errors.Is(err, ErrPhoneAttest) {
		t.Fatalf("not strictly later: %v", err)
	}
	if err := p.Check(base.Add(-2 * time.Hour)); !errors.Is(err, ErrPhoneAttest) {
		t.Fatalf("below floor: %v", err)
	}
	if err := p.Check(base.Add(25 * time.Hour)); !errors.Is(err, ErrPhoneAttest) {
		t.Fatalf("outside ±24h of RTC−offset: %v", err)
	}
	ok := base.Add(time.Minute)
	if err := p.Check(ok); err != nil {
		t.Fatal(err)
	}
	if err := p.Accept(ok); err != nil {
		t.Fatal(err)
	}
	if !p.Last.Equal(ok) {
		t.Fatalf("Last=%v", p.Last)
	}
	if err := p.Check(ok); !errors.Is(err, ErrPhoneAttest) {
		t.Fatal("second accept of same time")
	}
	if got := ErrPhoneAttest.Error(); got != PhoneAttestRefused {
		t.Fatalf("wording %q", got)
	}
}

// REQ: HW-8
func TestHOST1bT8NoOffsetSkipsRTCWindow(t *testing.T) {
	base := time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)
	p := PhoneAttest{Floor: base.Add(-time.Hour)}
	if err := p.Check(base.Add(100 * time.Hour)); err != nil {
		t.Fatal(err)
	}
}
