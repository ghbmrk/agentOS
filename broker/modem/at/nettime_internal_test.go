package at

// REQ: TIM-1

import (
	"testing"
	"time"
)

func TestTIM1ParseNetworkTime(t *testing.T) {
	utc := time.Date(2026, 10, 5, 4, 10, 22, 0, time.UTC)
	for _, c := range []struct {
		parse func([]string) (time.Time, bool)
		line  string
		want  time.Time // zero: rejected
	}{
		{parseQLTS, `+QLTS: "2026/10/05,04:10:22+08,0"`, utc},
		{parseQLTS, `+QLTS: "2026/10/05,04:10:22-20,1"`, utc},
		{parseQLTS, `+QLTS: ""`, time.Time{}},
		{parseQLTS, `+QLTS: "1980/01/06,00:00:10+00,0"`, time.Time{}},
		{parseQLTS, `+QLTS: "garbage"`, time.Time{}},
		{parseCCLK, `+CCLK: "26/10/05,06:10:22+08"`, utc},
		{parseCCLK, `+CCLK: "26/10/04,23:10:22-20"`, utc},
		{parseCCLK, `+CCLK: "26/10/05,09:40:22+22"`, utc},
		{parseCCLK, `+CCLK: "04/01/01,00:01:00+00"`, time.Time{}},
		{parseCCLK, `+CCLK: "26/10/05,06:10:22+99"`, time.Time{}},
		{parseCCLK, `+CCLK: "26/10/05,06:10:22"`, time.Time{}},
		{parseCCLK, `OK`, time.Time{}},
		{parseCCLK, `+CCLK: "26/10/05,06:10:22+-5"`, time.Time{}},
		{parseCCLK, `+CCLK: "26/10/05,06:10:22++8"`, time.Time{}},
		{parseCCLK, `+CCLK: "26/10/05,06:10:22+008"`, time.Time{}},
	} {
		got, ok := c.parse([]string{c.line})
		if ok != !c.want.IsZero() || (ok && !got.Equal(c.want)) {
			t.Errorf("%s: got %v %v, want %v", c.line, got, ok, c.want)
		}
	}
}

func FuzzTIM1ParseNetworkTime(f *testing.F) {
	f.Add(`+CCLK: "26/10/05,06:10:22+08"`)
	f.Add(`+QLTS: "2026/10/05,04:10:22+08,0"`)
	f.Fuzz(func(t *testing.T, l string) {
		parseCCLK([]string{l})
		parseQLTS([]string{l})
	})
}
