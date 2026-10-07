// Package secfix surfaces held security fixes (UPD-9, OP-9).
package secfix

import (
	"fmt"
	"time"
)

// Hold is why a staged security fix has not installed.
type Hold string

const (
	NeverFree Hold = "never_free" // UPD-6: box never free for 24h
	Pinned    Hold = "pinned"     // UPD-4 PINNED
	Ask       Hold = "ask"        // security updates set to ask
)

// Fix is one staged security release.
type Fix struct {
	N        int
	StagedAt time.Time
	Hold     Hold
	Declined bool
}

// AskAfter is how long a never-free box waits before asking once (UPD-9).
const AskAfter = 24 * time.Hour

// StatusAsk is the one paced ask when the box was never free for 24h.
func StatusAsk(f Fix, now time.Time, restart string) string {
	if f.Hold != NeverFree || f.Declined || f.N == 0 {
		return ""
	}
	if now.Sub(f.StagedAt) < AskAfter {
		return ""
	}
	if restart == "" {
		restart = "a few minutes"
	}
	return fmt.Sprintf("Security fix %d has waited over 24 hours for a quiet moment. Restart takes %s. Reply INSTALL NOW or NEXT WINDOW.", f.N, restart)
}

// DigestLine lists a PINNED/ASK hold every digest until installed or declined.
func DigestLine(f Fix, now time.Time) string {
	if f.Declined || f.N == 0 {
		return ""
	}
	age := now.Sub(f.StagedAt).Truncate(time.Hour)
	hours := int(age / time.Hour)
	switch f.Hold {
	case Pinned:
		return fmt.Sprintf("Security fix %d is held by PINNED (%dh). Reply UPDATES STABLE to take it, or DECLINE %d.", f.N, hours, f.N)
	case Ask:
		return fmt.Sprintf("Security fix %d is waiting for your OK (%dh). Reply INSTALL %d or DECLINE %d.", f.N, hours, f.N, f.N)
	default:
		return ""
	}
}
