package update

import (
	"crypto/ed25519"
	"time"
)

// Soak bounds in days (UPD-5: "at least 7"). MaxSoakDays matches
// loops.MaxSoakDays; it is defined here so update imports no loop.
const (
	MinSoakDays = 7
	MaxSoakDays = 60
)

// Reasons a release is not ready yet (Wait.Reason).
const (
	WaitSoak         = "soak"               // Until is when the soak ends
	WaitAttestations = "attestations"       // Need more independent passes
	WaitNoAttestor   = "no attestor listed" // the box lists no attestor
	WaitPinned       = "pinned"             // the box takes no automatic update
)

// Wait is StableReady's answer: Ready, or the Reason it is not, with
// Until or Need where the reason has one. The wiring turns the reason
// into owner text (CH-12).
type Wait struct {
	Ready  bool
	Reason string
	Until  time.Time
	Need   int
}

// StableReady decides whether v may be proposed on a box on channel
// (UPD-7: soak plus attestations, no central staged rollout). In order:
//   - a pinned box, or any channel other than stable or fast, never is;
//   - a security fix, or a release that covers one, on either channel,
//     is exactly SecurityAutoStage, with no soak (UPD-5, UPD-8);
//   - a fast box takes an ordinary release at once (UPD-4): fast boxes
//     produce the attestations;
//   - a stable box takes an ordinary release only once firstSeen plus
//     soakDays (raised to MinSoakDays, capped at MaxSoakDays) has passed
//     and IndependentPasses reaches minPasses (at least 1), and never
//     while it lists no attestor (UPD-5 "whichever is later").
//
// firstSeen is when this box first saw the release's image. now must be
// the clock guard's Earliest (broker/clock), so a clock moved forward
// cannot end a soak early. A zero firstSeen or now, or now before
// firstSeen, is not ready. A nil or unsealed v returns ErrNotChecked.
func (v *Verified) StableReady(atts [][]byte, own ed25519.PublicKey, channel string, firstSeen, now time.Time, soakDays, minPasses int) (Wait, error) {
	if !v.ok() {
		return Wait{}, ErrNotChecked
	}
	if channel != ChannelStable && channel != ChannelFast {
		return Wait{Reason: WaitPinned}, nil
	}
	if v.release.Security || v.coversFix {
		if err := v.SecurityAutoStage(atts, own); err != nil {
			return Wait{Reason: WaitAttestations, Need: 1}, err
		}
		return Wait{Ready: true}, nil
	}
	if channel == ChannelFast {
		return Wait{Ready: true}, nil
	}
	if len(v.allowed) == 0 && len(v.pinned) == 0 {
		return Wait{Reason: WaitNoAttestor}, nil
	}
	soakDays = min(max(soakDays, MinSoakDays), MaxSoakDays)
	minPasses = max(minPasses, 1)
	if firstSeen.IsZero() {
		return Wait{Reason: WaitSoak}, nil
	}
	until := firstSeen.Add(time.Duration(soakDays) * 24 * time.Hour)
	if now.Before(until) { // a zero now is before every until
		return Wait{Reason: WaitSoak, Until: until}, nil
	}
	if n := v.IndependentPasses(atts, own); n < minPasses {
		return Wait{Reason: WaitAttestations, Need: minPasses - n}, nil
	}
	return Wait{Ready: true}, nil
}
