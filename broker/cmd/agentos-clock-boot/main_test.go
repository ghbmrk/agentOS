package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// REQ: HW-8, TIM-1

// Potency C1, security T7: at boot, before the time service, the clock is
// set to the hardware clock less the learned offset; with no offset known
// nothing is set; a failed read sets nothing; the one-shot never fails the
// boot.
func TestBootSetsRTCLessOffset(t *testing.T) {
	dir := t.TempDir()
	state := filepath.Join(dir, "clock.json")
	b, _ := json.Marshal(map[string]any{"have_offset": true, "offset": int64(2 * time.Hour)})
	if err := os.WriteFile(state, b, 0o600); err != nil {
		t.Fatal(err)
	}
	rtc := time.Date(2026, 10, 9, 22, 0, 0, 0, time.UTC) // Windows at UTC+2
	var set []time.Time
	env := bootEnv{
		rtc:  func() (time.Time, error) { return rtc, nil },
		now:  func() time.Time { return rtc },
		set:  func(t time.Time) error { set = append(set, t); return nil },
		logf: func(string, ...any) {},
	}
	if code := run(state, env); code != 0 || len(set) != 1 || !set[0].Equal(rtc.Add(-2*time.Hour)) {
		t.Fatalf("code %d, set %v", code, set)
	}

	// Already right: nothing to set.
	set = nil
	env.now = func() time.Time { return rtc.Add(-2*time.Hour + 300*time.Millisecond) }
	if run(state, env); len(set) != 0 {
		t.Fatalf("set %v", set)
	}

	// No offset, no file, unreadable hardware clock, failed set: no step
	// (or a failed one), exit 0.
	env.now = func() time.Time { return rtc }
	for name, e := range map[string]bootEnv{
		"no rtc":    {rtc: func() (time.Time, error) { return time.Time{}, errors.New("no rtc") }, now: env.now, set: env.set, logf: env.logf},
		"set fails": {rtc: env.rtc, now: env.now, set: func(time.Time) error { return errors.New("EPERM") }, logf: env.logf},
	} {
		if code := run(state, e); code != 0 {
			t.Errorf("%s: exit %d", name, code)
		}
	}
	set = nil
	if code := run(filepath.Join(dir, "none"), env); code != 0 || len(set) != 0 {
		t.Fatalf("no state: code %d, set %v", code, set)
	}
}

// HW-8: the one-shot sets the system clock only; it never opens the
// hardware clock device, runs hwclock, or asks the kernel to copy the
// clock into the hardware clock.
func TestNeverWritesTheRTC(t *testing.T) {
	b, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"/dev/rtc", "RTC_SET", "hwclock", "Adjtimex", "systohc", "os/exec", "OpenFile"} {
		if strings.Contains(string(b), bad) {
			t.Errorf("main.go mentions %s", bad)
		}
	}
}
