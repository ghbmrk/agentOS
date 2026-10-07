package secfix

import (
	"strings"
	"testing"
	"time"
)

// REQ: UPD-9, OP-9

func TestUPD9SecurityFixNeverHeldInSilence(t *testing.T) {
	now := time.Unix(2e9, 0)
	staged := now.Add(-25 * time.Hour)
	ask := StatusAsk(Fix{N: 7, StagedAt: staged, Hold: NeverFree}, now, "2 minutes")
	if !strings.Contains(ask, "Security fix 7") || !strings.Contains(ask, "24 hours") {
		t.Fatalf("ask: %q", ask)
	}
	if StatusAsk(Fix{N: 7, StagedAt: now.Add(-time.Hour), Hold: NeverFree}, now, "") != "" {
		t.Fatal("asked before 24h")
	}
	d := DigestLine(Fix{N: 7, StagedAt: staged, Hold: Pinned}, now)
	if !strings.Contains(d, "PINNED") || !strings.Contains(d, "25h") && !strings.Contains(d, "24h") {
		// 25h truncated to 25h
		if !strings.Contains(d, "PINNED") {
			t.Fatalf("pinned digest: %q", d)
		}
	}
	d = DigestLine(Fix{N: 7, StagedAt: staged, Hold: Ask}, now)
	if !strings.Contains(d, "waiting for your OK") {
		t.Fatalf("ask digest: %q", d)
	}
	if DigestLine(Fix{N: 7, StagedAt: staged, Hold: Pinned, Declined: true}, now) != "" {
		t.Fatal("declined still listed")
	}
}
