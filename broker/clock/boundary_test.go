package clock

// REQ: TIM-1, HW-8

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestTIM1AboutRoundsAtEachUnitsStart(t *testing.T) {
	for d, want := range map[time.Duration]string{
		48 * time.Hour:   "about 2 days",
		2 * time.Hour:    "about 2 hours",
		30 * time.Minute: "about 30 minutes",
		time.Hour:        "about 1 hour",
		-time.Hour:       "about 1 hour",
	} {
		if got := about(d); got != want {
			t.Errorf("about(%v) = %q, want %q", d, got, want)
		}
	}
}

func TestTIM1SkewOfExactlyTheToleranceAgrees(t *testing.T) {
	for _, skew := range []time.Duration{DefaultTolerance, -DefaultTolerance} {
		r := newRig()
		r.carrier = r.wall.Add(-skew)
		if s := r.guard(t, nil).Check(bg); s.State != Agreed {
			t.Errorf("skew %v: status = %+v, want agreed", skew, s)
		}
	}
	// One second past the tolerance disagrees on either sign.
	for _, skew := range []time.Duration{DefaultTolerance + time.Second, -DefaultTolerance - time.Second} {
		r := newRig()
		r.carrier = r.wall.Add(-skew)
		if s := r.guard(t, nil).Check(bg); s.State != Disagree {
			t.Errorf("skew %v: status = %+v, want disagree", skew, s)
		}
	}
}

func TestHW8FloorAheadByExactlyTheToleranceIsKept(t *testing.T) {
	// The floor is replaced only when it is more than the tolerance ahead
	// of NTS-verified time (security R1 on #177).
	path := filepath.Join(t.TempDir(), "clock.json")
	r := newRig()
	rtc := r.wall
	rtcGuard(t, r, path, &rtc).Check(bg)
	v := readSaved(t, path)
	ahead := r.wall.Add(DefaultTolerance)
	v.Floor = ahead
	if b, err := json.Marshal(v); err != nil {
		t.Fatal(err)
	} else if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
	var logs []string
	r.reboot(r.wall)
	g := r.guard(t, func(c *Config) {
		c.StatePath = path
		c.BootID = func() string { return r.boot }
		c.Logf = func(f string, a ...any) { logs = append(logs, f) }
		nts(c)
	})
	g.Check(bg)
	if got := readSaved(t, path).Floor; !got.Equal(ahead) || len(logs) != 0 {
		t.Fatalf("floor %v, want %v kept; logs %q", got, ahead, logs)
	}
}

func TestTIM1SmallSkewIsNotZoneLike(t *testing.T) {
	// Under 14 minutes is never a time-zone shape, even within a minute of
	// a whole quarter hour (zero).
	for _, d := range []time.Duration{30 * time.Second, -30 * time.Second, 13 * time.Minute} {
		if zoneLike(d) {
			t.Errorf("zoneLike(%v) = true", d)
		}
	}
	if !zoneLike(time.Hour) {
		t.Error("zoneLike(1h) = false")
	}
}
