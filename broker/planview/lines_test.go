package planview

import (
	"strings"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/planquota"
)

// REQ: ONB-9

func TestONB9PoolLinesOnStatusAndPage(t *testing.T) {
	p := planquota.Pool{ID: "five_hour", Used: 0.42, Reserve: 0, Reset: time.Date(2026, 10, 7, 14, 0, 0, 0, time.Local)}
	line := Line("Claude", p, true)
	if !strings.Contains(line, "42%") || !strings.Contains(line, "5-hour") || !strings.Contains(line, "as closely as I can") {
		t.Fatalf("page line: %q", line)
	}
	p.Used = 0.95
	p.Reserve = 0.1
	st := StatusLine("Claude", p, true)
	if !strings.Contains(st, "at your reserve") || !strings.Contains(st, "API") {
		t.Fatalf("status: %q", st)
	}
	d := DigestFailover("Claude", p.Reset, "$0.42")
	if !strings.Contains(d, "Used the API instead: $0.42") {
		t.Fatalf("digest: %q", d)
	}
	if StatusLine("Claude", planquota.Pool{ID: "five_hour", Used: 0.1, Reserve: 0}, false) != "" {
		t.Fatal("status line when headroom remains")
	}
}
