package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/clock"
)

// REQ: HW-8, TIM-1

// testHost is a synthetic firmware system UUID.
const testHost = "4a1b2c3d-0000-4000-8000-0000000c10c6"

// Potency C1, security T7: at boot, before the time service, the clock is
// set to the hardware clock less the learned offset; with no offset known
// nothing is set; a failed read sets nothing; the one-shot never fails the
// boot.
func TestBootSetsRTCLessOffset(t *testing.T) {
	dir := t.TempDir()
	state := filepath.Join(dir, "clock.json")
	b, _ := json.Marshal(map[string]any{"have_offset": true, "offset": int64(2 * time.Hour), "offset_host": clock.HostKey(testHost)})
	if err := os.WriteFile(state, b, 0o600); err != nil {
		t.Fatal(err)
	}
	rtc := time.Date(2026, 10, 9, 22, 0, 0, 0, time.UTC) // Windows at UTC+2
	var set []time.Time
	env := bootEnv{
		rtc:    func() (time.Time, error) { return rtc, nil },
		hostID: func() string { return testHost },
		owner:  uint32(os.Geteuid()),
		// The kernel took the hardware clock as UTC, but the box clock has
		// run on a little since (L3 M23 on #177).
		now:  func() time.Time { return rtc.Add(40 * time.Second) },
		set:  func(t time.Time) error { set = append(set, t); return nil },
		logf: func(string, ...any) {},
	}
	if code := run(state, env); code != 0 || len(set) != 1 || !set[0].Equal(rtc.Add(-2*time.Hour)) {
		t.Fatalf("code %d, set %v", code, set)
	}

	// Another PC, or a state file others can read or write or another uid
	// owns: nothing is set (L3 on #177).
	set = nil
	other := env
	other.hostID = func() string { return "4a1b2c3d-0000-4000-8000-0000000c10c7" }
	if run(state, other); len(set) != 0 {
		t.Fatalf("another PC: set %v", set)
	}
	stranger := env
	stranger.owner = uint32(os.Geteuid()) + 1
	if run(state, stranger); len(set) != 0 {
		t.Fatalf("foreign owner: set %v", set)
	}
	for _, mode := range []os.FileMode{0o644, 0o640, 0o660, 0o602} {
		os.Chmod(state, mode)
		if run(state, env); len(set) != 0 {
			t.Fatalf("mode %o: set %v", mode, set)
		}
	}
	os.Chmod(state, 0o600)

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
		"no rtc":    {rtc: func() (time.Time, error) { return time.Time{}, errors.New("no rtc") }, hostID: env.hostID, owner: env.owner, now: env.now, set: env.set, logf: env.logf},
		"set fails": {rtc: env.rtc, hostID: env.hostID, owner: env.owner, now: env.now, set: func(time.Time) error { return errors.New("EPERM") }, logf: env.logf},
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
